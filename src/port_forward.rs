use std::{future::Future, net::SocketAddr, sync::Arc};

use crate::client::{Client, Interface, PortForwardTarget};
#[cfg(windows)]
use std::process::Command;

use hbb_common::{
    anyhow::anyhow,
    bail,
    config::READ_TIMEOUT,
    futures::{SinkExt, StreamExt},
    log,
    message_proto::*,
    protobuf::Message as _,
    rendezvous_proto::ConnType,
    tcp, timeout,
    tokio::{
        self,
        net::TcpStream,
        sync::{mpsc, OwnedSemaphorePermit, Semaphore},
        task::JoinSet,
    },
    tokio_util::codec::{BytesCodec, Framed},
    tokio_util::sync::CancellationToken,
    ResultType, Stream,
};

const MAX_PORT_FORWARD_CONNECTIONS_PER_MAPPING: usize = 32;
const MAX_PORT_FORWARD_CONNECTIONS_PROCESS: usize = 128;
pub(crate) const MAX_OWNED_PORT_FORWARD_MAPPINGS: usize = 32;
const PORT_FORWARD_OWNER_REAPER_CAPACITY: usize = MAX_OWNED_PORT_FORWARD_MAPPINGS;

enum PortForwardOwnerJoinRequest {
    OneOff {
        thread: std::thread::JoinHandle<ResultType<()>>,
        completed: tokio::sync::oneshot::Sender<ResultType<()>>,
    },
    Supervisor {
        thread: std::thread::JoinHandle<()>,
        completed: Option<tokio::sync::oneshot::Sender<Result<(), String>>>,
    },
}

pub(crate) struct PortForwardMappingPermit {
    _permit: OwnedSemaphorePermit,
}

impl PortForwardMappingPermit {
    pub(crate) fn try_acquire() -> Result<Self, String> {
        match PROCESS_PORT_FORWARD_MAPPING_ADMISSION
            .clone()
            .try_acquire_owned()
        {
            Ok(permit) => Ok(Self { _permit: permit }),
            Err(tokio::sync::TryAcquireError::NoPermits) => Err(format!(
                "Port-forward mapping limit ({MAX_OWNED_PORT_FORWARD_MAPPINGS}) reached"
            )),
            Err(tokio::sync::TryAcquireError::Closed) => {
                Err("Port-forward mapping admission is closed".to_owned())
            }
        }
    }
}

lazy_static::lazy_static! {
    static ref PROCESS_PORT_FORWARD_ADMISSION: Arc<Semaphore> =
        Arc::new(Semaphore::new(MAX_PORT_FORWARD_CONNECTIONS_PROCESS));
    static ref PROCESS_PORT_FORWARD_MAPPING_ADMISSION: Arc<Semaphore> =
        Arc::new(Semaphore::new(MAX_OWNED_PORT_FORWARD_MAPPINGS));
    static ref PORT_FORWARD_OWNER_REAPER: std::sync::mpsc::SyncSender<PortForwardOwnerJoinRequest> = {
        let (sender, receiver) =
            std::sync::mpsc::sync_channel(PORT_FORWARD_OWNER_REAPER_CAPACITY);
        if std::thread::Builder::new()
            .name("rustdesk-port-forward-owner-reaper".to_owned())
            .spawn(move || run_port_forward_owner_reaper(receiver))
            .is_err()
        {
            std::process::abort();
        }
        sender
    };
}

fn run_port_forward_owner_reaper(receiver: std::sync::mpsc::Receiver<PortForwardOwnerJoinRequest>) {
    while let Ok(request) = receiver.recv() {
        match request {
            PortForwardOwnerJoinRequest::OneOff { thread, completed } => {
                let result = thread
                    .join()
                    .map_err(|_| anyhow!("Port-forward owner thread panicked"))
                    .and_then(|result| result);
                let _ = completed.send(result);
            }
            PortForwardOwnerJoinRequest::Supervisor { thread, completed } => {
                let result = thread
                    .join()
                    .map_err(|_| "Port-forward owner thread panicked".to_owned());
                if let Some(completed) = completed {
                    let _ = completed.send(result);
                } else if let Err(err) = result {
                    log::error!("{}", err);
                }
            }
        }
    }
}

fn handoff_port_forward_owner(request: PortForwardOwnerJoinRequest) {
    if PORT_FORWARD_OWNER_REAPER.try_send(request).is_err() {
        std::process::abort();
    }
}

pub(crate) fn ensure_port_forward_owner_reaper() {
    lazy_static::initialize(&PORT_FORWARD_OWNER_REAPER);
}

pub(crate) async fn join_port_forward_supervisor_off_runtime(
    thread: std::thread::JoinHandle<()>,
) -> Result<(), String> {
    let (completed, result) = tokio::sync::oneshot::channel();
    handoff_port_forward_owner(PortForwardOwnerJoinRequest::Supervisor {
        thread,
        completed: Some(completed),
    });
    result
        .await
        .map_err(|_| "Port-forward owner reaper dropped its result".to_owned())?
}

pub(crate) fn reap_port_forward_supervisor(thread: std::thread::JoinHandle<()>) {
    handoff_port_forward_owner(PortForwardOwnerJoinRequest::Supervisor {
        thread,
        completed: None,
    });
}

#[derive(Clone)]
pub(crate) struct PortForwardControl {
    close: CancellationToken,
    launch_rdp: mpsc::Sender<()>,
}

pub(crate) struct PortForwardControlReceiver {
    close: CancellationToken,
    launch_rdp: mpsc::Receiver<()>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RdpLaunchRequest {
    Queued,
    Coalesced,
}

pub(crate) fn port_forward_control() -> (PortForwardControl, PortForwardControlReceiver) {
    let close = CancellationToken::new();
    let (launch_rdp, receiver) = mpsc::channel(1);
    (
        PortForwardControl {
            close: close.clone(),
            launch_rdp,
        },
        PortForwardControlReceiver {
            close,
            launch_rdp: receiver,
        },
    )
}

impl PortForwardControl {
    pub(crate) fn close(&self) {
        self.close.cancel();
    }

    pub(crate) fn launch_rdp(&self) -> Result<RdpLaunchRequest, String> {
        match self.launch_rdp.try_send(()) {
            Ok(()) => Ok(RdpLaunchRequest::Queued),
            Err(mpsc::error::TrySendError::Full(())) => Ok(RdpLaunchRequest::Coalesced),
            Err(mpsc::error::TrySendError::Closed(())) => {
                Err("Port-forward mapping is closed".to_owned())
            }
        }
    }
}

impl PortForwardControlReceiver {
    #[cfg(test)]
    pub(crate) async fn wait_closed(mut self) {
        loop {
            tokio::select! {
                _ = self.close.cancelled() => return,
                launch = self.launch_rdp.recv() => {
                    if launch.is_none() {
                        return;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
struct TestMappingAdmission {
    semaphore: Arc<Semaphore>,
}

#[cfg(test)]
impl TestMappingAdmission {
    fn new(limit: usize) -> Self {
        Self {
            semaphore: Arc::new(Semaphore::new(limit)),
        }
    }

    fn try_acquire(&self) -> Option<OwnedSemaphorePermit> {
        self.semaphore.clone().try_acquire_owned().ok()
    }
}

fn rdp_endpoint_arg(port: u16) -> String {
    format!("/v:localhost:{}", port)
}

fn rdp_launch_args(port: u16) -> [String; 2] {
    [rdp_endpoint_arg(port), "/prompt".to_owned()]
}

#[cfg(windows)]
fn run_rdp(port: u16) -> ResultType<()> {
    let mstsc = crate::platform::windows::trusted_system_tool_path("mstsc.exe")?;
    Command::new(&mstsc).args(rdp_launch_args(port)).spawn()?;
    Ok(())
}

#[cfg(not(windows))]
fn run_rdp(port: u16) -> ResultType<()> {
    log::info!(
        "RDP helper launch is Windows-only; connect a local RDP client to 127.0.0.1:{}",
        port
    );
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TunnelPhase {
    ConnectAndKey,
    Login,
    Relay,
}

struct TunnelAdmission {
    mapping: Arc<Semaphore>,
    process: Arc<Semaphore>,
}

struct TunnelPermits {
    _mapping: OwnedSemaphorePermit,
    _process: OwnedSemaphorePermit,
}

impl TunnelAdmission {
    fn new() -> Self {
        Self {
            mapping: Arc::new(Semaphore::new(MAX_PORT_FORWARD_CONNECTIONS_PER_MAPPING)),
            process: PROCESS_PORT_FORWARD_ADMISSION.clone(),
        }
    }

    fn try_admit(&self) -> Option<TunnelPermits> {
        let mapping = match self.mapping.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(tokio::sync::TryAcquireError::NoPermits) => return None,
            Err(tokio::sync::TryAcquireError::Closed) => {
                log::error!("port-forward mapping admission semaphore is closed");
                return None;
            }
        };
        let process = match self.process.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(tokio::sync::TryAcquireError::NoPermits) => return None,
            Err(tokio::sync::TryAcquireError::Closed) => {
                log::error!("process port-forward admission semaphore is closed");
                return None;
            }
        };
        Some(TunnelPermits {
            _mapping: mapping,
            _process: process,
        })
    }

    #[cfg(test)]
    fn for_test(mapping_limit: usize, process: Arc<Semaphore>) -> Self {
        Self {
            mapping: Arc::new(Semaphore::new(mapping_limit)),
            process,
        }
    }
}

async fn cancellable_phase<T, F>(
    cancellation: &CancellationToken,
    phase: TunnelPhase,
    future: F,
) -> ResultType<Option<T>>
where
    F: Future<Output = ResultType<T>>,
{
    tokio::select! {
        biased;
        _ = cancellation.cancelled() => {
            log::debug!("port-forward task cancelled during {:?}", phase);
            Ok(None)
        }
        result = future => result.map(Some),
    }
}

type ConnectionTaskResult = (SocketAddr, ResultType<()>);

async fn drain_join_set<T: 'static, F>(tasks: &mut JoinSet<T>, mut on_join: F)
where
    F: FnMut(Result<T, tokio::task::JoinError>),
{
    while let Some(completed) = tasks.join_next().await {
        on_join(completed);
    }
}

fn reap_ready_tasks<T: 'static, F>(tasks: &mut JoinSet<T>, mut on_join: F) -> usize
where
    F: FnMut(Result<T, tokio::task::JoinError>),
{
    let mut reaped = 0;
    while let Some(completed) = tasks.try_join_next() {
        on_join(completed);
        reaped += 1;
    }
    reaped
}

async fn relay_after_authorization<S, Setup, Relay, RelayFuture>(
    setup: Setup,
    relay: Relay,
) -> ResultType<()>
where
    Setup: Future<Output = ResultType<Option<S>>>,
    Relay: FnOnce(S) -> RelayFuture,
    RelayFuture: Future<Output = ResultType<()>>,
{
    let Some(stream) = setup.await? else {
        return Ok(());
    };
    relay(stream).await
}

fn report_connection_result(
    interface: &impl Interface,
    result: Result<ConnectionTaskResult, tokio::task::JoinError>,
) {
    match result {
        Ok((addr, Ok(()))) => log::info!("connection from {:?} closed", addr),
        Ok((addr, Err(err))) => {
            log::warn!("port-forward connection from {:?} failed: {}", addr, err);
            interface.msgbox("error", "Error", &err.to_string(), "");
        }
        Err(err) => {
            log::error!("port-forward connection task failed: {}", err);
            interface.msgbox(
                "error",
                "Error",
                &format!("Port-forward connection task failed: {err}"),
                "",
            );
        }
    }
}

// R-F1/R-D6/R-S5/PF-1..PF-5: one mapping owns its exclusive listener, immutable
// target, cancellation domain, and every setup/relay task. Local application bytes are not read
// until PeerInfo authorizes the connection; mapping shutdown cancels and joins all accepted work.
pub(crate) async fn listen(
    id: String,
    port: i32,
    interface: impl Interface,
    control: PortForwardControlReceiver,
    key: &str,
    token: &str,
    remote_host: String,
    remote_port: i32,
) -> ResultType<()> {
    ensure_port_forward_owner_reaper();
    let mapping_permit = PortForwardMappingPermit::try_acquire().map_err(|err| anyhow!(err))?;
    let key = key.to_owned();
    let token = token.to_owned();
    let thread = std::thread::Builder::new()
        .name("rustdesk-port-forward-one-off".to_owned())
        .spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|err| anyhow!("Failed to create port-forward runtime: {err}"))?;
            runtime.block_on(listen_admitted(
                id,
                port,
                interface,
                control,
                &key,
                &token,
                remote_host,
                remote_port,
                &mapping_permit,
            ))
        })
        .map_err(|err| anyhow!("Failed to start port-forward owner thread: {err}"))?;
    join_one_off_owner_off_runtime(thread).await
}

async fn join_one_off_owner_off_runtime(
    thread: std::thread::JoinHandle<ResultType<()>>,
) -> ResultType<()> {
    let (completed, result) = tokio::sync::oneshot::channel();
    handoff_port_forward_owner(PortForwardOwnerJoinRequest::OneOff { thread, completed });
    result
        .await
        .map_err(|_| anyhow!("Port-forward owner reaper dropped its result"))?
}

pub(crate) async fn listen_admitted(
    id: String,
    port: i32,
    interface: impl Interface,
    control: PortForwardControlReceiver,
    key: &str,
    token: &str,
    remote_host: String,
    remote_port: i32,
    _mapping_permit: &PortForwardMappingPermit,
) -> ResultType<()> {
    let target = PortForwardTarget::new(remote_host, remote_port)?;
    let listener = tcp::new_exclusive_listener(format!("127.0.0.1:{}", port)).await?;
    let addr = listener.local_addr()?;
    log::info!("listening on port {:?}", addr);
    let is_rdp = port == 0;
    if is_rdp {
        run_rdp(addr.port())?;
    }
    let cancellation = CancellationToken::new();
    let admission = TunnelAdmission::new();
    let mut tasks = JoinSet::<ConnectionTaskResult>::new();
    let mut control = control;
    let listener_result = loop {
        if control.close.is_cancelled() {
            break Ok(());
        }
        match control.launch_rdp.try_recv() {
            Ok(()) => {
                if let Err(err) = run_rdp(addr.port()) {
                    log::error!("failed to launch RDP client: {}", err);
                    interface.msgbox("error", "Error", &err.to_string(), "");
                }
            }
            Err(mpsc::error::TryRecvError::Disconnected) => break Ok(()),
            Err(mpsc::error::TryRecvError::Empty) => {}
        }
        reap_ready_tasks(&mut tasks, |completed| {
            report_connection_result(&interface, completed)
        });
        tokio::select! {
            biased;
            _ = control.close.cancelled() => break Ok(()),
            launch = control.launch_rdp.recv() => {
                let Some(()) = launch else {
                    break Ok(());
                };
                if let Err(err) = run_rdp(addr.port()) {
                    log::error!("failed to launch RDP client: {}", err);
                    interface.msgbox("error", "Error", &err.to_string(), "");
                }
            }
            completed = tasks.join_next(), if !tasks.is_empty() => {
                if let Some(completed) = completed {
                    report_connection_result(&interface, completed);
                }
            }
            accepted = listener.accept() => {
                let (forward, peer_addr) = match accepted {
                    Ok(accepted) => accepted,
                    Err(err) => break Err(anyhow!("port-forward listener accept failed: {err}")),
                };
                let Some(permits) = admission.try_admit() else {
                    log::warn!(
                        "rejecting local port-forward connection from {:?}: active connection limit reached",
                        peer_addr
                    );
                    drop(forward);
                    continue;
                };
                log::info!("new connection from {:?}", peer_addr);
                let id = id.clone();
                let key = key.to_owned();
                let token = token.to_owned();
                let target = target.clone();
                let interface = interface.clone();
                let task_cancellation = cancellation.clone();
                tasks.spawn(async move {
                    let _permits = permits;
                    let result = serve_connection(
                        id,
                        key,
                        token,
                        target,
                        is_rdp,
                        interface,
                        forward,
                        task_cancellation,
                    )
                    .await;
                    (peer_addr, result)
                });
            }
        }
    };

    cancellation.cancel();
    drop(listener);
    drain_join_set(&mut tasks, |completed| {
        report_connection_result(&interface, completed)
    })
    .await;
    listener_result
}

async fn serve_connection(
    id: String,
    key: String,
    token: String,
    target: PortForwardTarget,
    is_rdp: bool,
    interface: impl Interface,
    forward: TcpStream,
    cancellation: CancellationToken,
) -> ResultType<()> {
    let setup_interface = interface.clone();
    let setup_cancellation = cancellation.clone();
    let setup = async move {
        let result = connect_and_login(
            &id,
            setup_interface.clone(),
            &key,
            &token,
            target,
            is_rdp,
            &setup_cancellation,
        )
        .await;
        if let Err(err) = &result {
            setup_interface.on_establish_connection_error(err.to_string());
        }
        result
    };
    relay_after_authorization(setup, |stream| async move {
        // Creating the framed local reader only after PeerInfo is the PF-5 admission boundary. Before
        // this point the OS socket receive buffer is the only bounded buffering for local application data.
        let forward = Framed::new(forward, BytesCodec::new());
        run_forward(forward, stream, &cancellation).await
    })
    .await
}

async fn connect_and_login(
    id: &str,
    interface: impl Interface,
    key: &str,
    token: &str,
    target: PortForwardTarget,
    is_rdp: bool,
    cancellation: &CancellationToken,
) -> ResultType<Option<Stream>> {
    let conn_type = if is_rdp {
        ConnType::RDP
    } else {
        ConnType::PORT_FORWARD
    };
    let Some(((mut stream, direct, _stream_type), (_feedback, _rendezvous_server))) =
        cancellable_phase(
            cancellation,
            TunnelPhase::ConnectAndKey,
            Client::start_port_forward(id, key, token, conn_type, target, interface.clone()),
        )
        .await?
    else {
        return Ok(None);
    };
    interface.update_direct(Some(direct));

    // R-S5 note / R-S13 (§4.4): the fork's direct-IP initiator MUST tunnel only over a PAKE-keyed
    // stream. `Client::start`/`_start` already key and assert is_secured, but assert AGAIN here —
    // before a single tunnelled byte, at the exact choke where the raw relay begins — and abort
    // fail-closed otherwise. A forward that rode an unkeyed stream would put the RDP/port-forward
    // payload on the wire in plaintext, exactly the leak R-A9 forbids.
    if !stream.is_secured() {
        bail!("R-S5/R-S13: refusing to port-forward over an unkeyed stream (fail-closed)");
    }

    let login = async move {
        let mut received = false;
        loop {
            match timeout(READ_TIMEOUT, stream.next()).await {
                Err(_) => {
                    bail!("Timeout");
                }
                Ok(Some(Ok(bytes))) => {
                    if !received {
                        received = true;
                        interface.update_received(true);
                    }
                    let msg_in = Message::parse_from_bytes(&bytes)?;
                    match msg_in.union {
                        Some(message::Union::LoginResponse(lr)) => match lr.union {
                            Some(login_response::Union::Error(err)) => {
                                if !interface.handle_login_error(&err) {
                                    return Ok((false, stream));
                                }
                            }
                            Some(login_response::Union::PeerInfo(pi)) => {
                                interface.handle_peer_info(pi);
                                return Ok((true, stream));
                            }
                            _ => {}
                        },
                        // R-F1/R-S5/R-A9: do NOT reply to a latency-probe TestDelay in port-forward
                        // mode. The box switches to the raw tunnel relay the instant it authorizes
                        // (connection.rs breaks to try_port_forward_loop), so a TestDelay reply sent
                        // afterwards would be relayed as DATA into the forwarded (RDP) stream and
                        // corrupt it. The port-forward viewer commits to the tunnel and silently drops
                        // TestDelay (a port forward has no video QoS to tune). The frame is still
                        // consumed here (read + dropped), so it never leaks into run_forward either.
                        Some(message::Union::TestDelay(_t)) => {}
                        _ => {}
                    }
                }
                Ok(Some(Err(err))) => {
                    bail!("Connection closed: {}", err);
                }
                _ => {
                    bail!("Reset by the peer");
                }
            }
        }
    };
    match cancellable_phase(cancellation, TunnelPhase::Login, login).await? {
        Some((true, stream)) => Ok(Some(stream)),
        Some((false, _)) | None => Ok(None),
    }
}

// The raw relay: shuttle bytes between the LOCAL socket (`forward`, plaintext to the operator's RDP /
// port-forward client) and the KEYED session `stream`. `send_bytes` SEALS on the keyed stream, so the
// wire bytes are ciphertext (R-A9); `stream.next()` yields already-DECRYPTED frames. No `set_raw` —
// the secretbox rides the whole tunnel end-to-end.
async fn run_forward(
    forward: Framed<TcpStream, BytesCodec>,
    stream: Stream,
    cancellation: &CancellationToken,
) -> ResultType<()> {
    log::info!("new port forwarding connection started");
    let mut forward = forward;
    let mut stream = stream;
    loop {
        tokio::select! {
            biased;
            _ = cancellation.cancelled() => return Ok(()),
            res = forward.next() => {
                match res {
                    Some(Ok(bytes)) => {
                        let send = async { stream.send_bytes(bytes.into()).await };
                        if cancellable_phase(cancellation, TunnelPhase::Relay, send).await?.is_none() {
                            return Ok(());
                        }
                    }
                    Some(Err(err)) => return Err(anyhow!("local tunnel read failed: {err}")),
                    None => return Ok(()),
                }
            },
            res = stream.next() => {
                match res {
                    Some(Ok(bytes)) => {
                        let send = async {
                            forward
                                .send(bytes)
                                .await
                                .map_err(|err| anyhow!("local tunnel write failed: {err}"))
                        };
                        if cancellable_phase(cancellation, TunnelPhase::Relay, send).await?.is_none() {
                            return Ok(());
                        }
                    }
                    Some(Err(err)) => return Err(anyhow!("remote tunnel read failed: {err}")),
                    None => return Ok(()),
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    #[test]
    fn rdp_launch_only_passes_endpoint_and_prompt() {
        assert_eq!(
            rdp_launch_args(3389),
            ["/v:localhost:3389".to_owned(), "/prompt".to_owned()]
        );
    }

    async fn assert_phase_cancellation(phase: TunnelPhase) {
        let cancellation = CancellationToken::new();
        let task_cancellation = cancellation.clone();
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            cancellable_phase(&task_cancellation, phase, async move {
                entered_tx
                    .send(())
                    .expect("phase-entry observer must remain alive");
                std::future::pending::<ResultType<()>>().await
            })
            .await
        });
        entered_rx.await.expect("phase must start");
        cancellation.cancel();
        assert!(task
            .await
            .expect("phase task must join")
            .expect("cancellation is not an error")
            .is_none());
    }

    #[tokio::test]
    async fn cancellation_covers_connect_keying_login_and_relay() {
        assert_phase_cancellation(TunnelPhase::ConnectAndKey).await;
        assert_phase_cancellation(TunnelPhase::Login).await;
        assert_phase_cancellation(TunnelPhase::Relay).await;
    }

    #[tokio::test]
    async fn control_eof_and_close_are_terminal_and_rdp_launch_coalesces() {
        let (control, mut receiver) = port_forward_control();
        assert_eq!(control.launch_rdp().unwrap(), RdpLaunchRequest::Queued);
        assert_eq!(control.launch_rdp().unwrap(), RdpLaunchRequest::Coalesced);
        assert_eq!(receiver.launch_rdp.recv().await, Some(()));
        control.close();
        receiver.close.cancelled().await;

        let (control, mut receiver) = port_forward_control();
        drop(control);
        assert_eq!(receiver.launch_rdp.recv().await, None);
    }

    #[tokio::test]
    async fn mapping_shutdown_drains_every_owned_task() {
        let cancellation = CancellationToken::new();
        let completed = Arc::new(AtomicUsize::new(0));
        let mut tasks = JoinSet::new();
        for _ in 0..4 {
            let task_cancellation = cancellation.clone();
            let completed = completed.clone();
            tasks.spawn(async move {
                task_cancellation.cancelled().await;
                completed.fetch_add(1, Ordering::SeqCst);
            });
        }
        cancellation.cancel();
        let joined = Arc::new(AtomicUsize::new(0));
        let joined_from_callback = joined.clone();
        drain_join_set(&mut tasks, move |result| {
            result.expect("owned task must join cleanly");
            joined_from_callback.fetch_add(1, Ordering::SeqCst);
        })
        .await;
        assert_eq!(completed.load(Ordering::SeqCst), 4);
        assert_eq!(joined.load(Ordering::SeqCst), 4);
        assert!(tasks.is_empty());
    }

    #[tokio::test]
    async fn process_reaper_joins_one_off_owner_and_reports_result() {
        let thread = std::thread::Builder::new()
            .name("port-forward-one-off-reaper-test".to_owned())
            .spawn(|| Ok(()))
            .expect("test owner thread");
        join_one_off_owner_off_runtime(thread)
            .await
            .expect("process reaper must report the owner result");
    }

    #[test]
    fn cancellation_reaper_handoff_returns_before_owner_exit() {
        let (release, wait_for_release) = std::sync::mpsc::sync_channel(1);
        let (owner_exited, exit_observer) = std::sync::mpsc::sync_channel(1);
        let owner = std::thread::Builder::new()
            .name("port-forward-cancellation-reaper-test".to_owned())
            .spawn(move || {
                wait_for_release.recv().expect("release signal");
                owner_exited.send(()).expect("exit observer");
            })
            .expect("test owner thread");
        let (returned, return_observer) = std::sync::mpsc::sync_channel(1);
        let handoff = std::thread::Builder::new()
            .name("port-forward-cancellation-handoff-test".to_owned())
            .spawn(move || {
                reap_port_forward_supervisor(owner);
                returned.send(()).expect("handoff observer");
            })
            .expect("test handoff thread");

        let returned_before_release = return_observer
            .recv_timeout(std::time::Duration::from_secs(5))
            .is_ok();
        release.send(()).expect("owner release");
        exit_observer
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("owner exit");
        handoff.join().expect("handoff thread");
        assert!(returned_before_release);
    }

    #[test]
    fn mapping_admission_rejects_literal_33rd_and_recovers() {
        let admission = TestMappingAdmission::new(32);
        let mut permits = Vec::new();
        for _ in 0..32 {
            permits.push(admission.try_acquire().expect("mapping within limit"));
        }
        assert!(
            admission.try_acquire().is_none(),
            "33rd mapping must reject"
        );
        drop(permits.pop());
        assert!(
            admission.try_acquire().is_some(),
            "released mapping permit must recover"
        );
    }

    #[tokio::test]
    async fn local_relay_is_not_entered_before_authorization() {
        let (setup_entered_tx, setup_entered_rx) = tokio::sync::oneshot::channel();
        let (authorize_tx, authorize_rx) = tokio::sync::oneshot::channel();
        let relay_entered = Arc::new(AtomicBool::new(false));
        let relay_observer = relay_entered.clone();
        let task = tokio::spawn(async move {
            relay_after_authorization(
                async move {
                    setup_entered_tx
                        .send(())
                        .expect("setup-entry observer must remain alive");
                    authorize_rx
                        .await
                        .expect("authorization result must arrive");
                    Ok(Some(()))
                },
                move |_| async move {
                    relay_observer.store(true, Ordering::SeqCst);
                    Ok(())
                },
            )
            .await
        });
        setup_entered_rx.await.expect("setup must start");
        assert!(!relay_entered.load(Ordering::SeqCst));
        authorize_tx.send(()).expect("setup must remain pending");
        task.await
            .expect("pipeline task must join")
            .expect("pipeline must complete");
        assert!(relay_entered.load(Ordering::SeqCst));
    }

    #[test]
    fn connection_admission_enforces_literal_32_and_128_boundaries_and_recovers() {
        let process = Arc::new(Semaphore::new(128));
        let first = TunnelAdmission::for_test(32, process.clone());
        let mut first_permits = Vec::new();
        for _ in 0..32 {
            first_permits.push(first.try_admit().expect("permit within mapping limit"));
        }
        assert!(
            first.try_admit().is_none(),
            "33rd mapping connection must reject"
        );

        let mut aggregate_permits = Vec::new();
        for _ in 0..3 {
            let admission = TunnelAdmission::for_test(32, process.clone());
            for _ in 0..32 {
                aggregate_permits.push(
                    admission
                        .try_admit()
                        .expect("permit within process aggregate limit"),
                );
            }
        }
        let over_process = TunnelAdmission::for_test(32, process);
        assert!(
            over_process.try_admit().is_none(),
            "129th process connection must reject"
        );

        drop(first_permits.pop());
        assert!(
            over_process.try_admit().is_some(),
            "released mapping and process permits must recover"
        );
    }

    #[tokio::test]
    async fn sustained_ready_completion_reaping_keeps_join_set_bounded() {
        const BATCH: usize = 32;
        const ROUNDS: usize = 256;
        let mut tasks = JoinSet::<ConnectionTaskResult>::new();
        let mut maximum_owned = 0;

        for round in 0..ROUNDS {
            for offset in 0..BATCH {
                tasks.spawn(async move {
                    (
                        format!("127.0.0.1:{}", 20000 + ((round + offset) % 1000))
                            .parse::<SocketAddr>()
                            .expect("test socket address"),
                        Ok(()),
                    )
                });
            }
            maximum_owned = maximum_owned.max(tasks.len());
            while !tasks.is_empty() {
                tokio::task::yield_now().await;
                reap_ready_tasks(&mut tasks, |result| {
                    let (_, task_result) = result.expect("ready task must join");
                    task_result.expect("ready task must complete successfully");
                });
            }
        }
        assert_eq!(maximum_owned, BATCH);
    }
}
