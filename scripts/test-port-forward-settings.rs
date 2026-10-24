// Production Session producers, cache methods and viewer mailbox run here. The
// peer-file adapter uses a private native file; it does not test TOML/encryption,
// installed settings, the full parent application or a remote tunnel peer.
use crate::{anyhow::{anyhow, bail}, message_proto::*, ResultType, tokio, log};
use protobuf::Message as _;
use std::{path::PathBuf, sync::{Arc, Mutex, RwLock}, time::Duration};
use tokio::time::Duration as TokioDuration;
#[cfg(pf_settings_results)]
use std::{collections::HashMap, net::SocketAddr, sync::atomic::{AtomicUsize, Ordering}};
#[cfg(pf_settings_results)]
use tokio::sync::{mpsc, Semaphore, OwnedSemaphorePermit};
#[cfg(pf_settings_results)]
use tokio_util::sync::CancellationToken;

type JobType = ();
#[derive(Clone)]
pub struct DisplaySelectionCommand;
impl DisplaySelectionCommand { fn payload_bytes(&self) -> Option<usize> { Some(0) } }
#[derive(Clone)]
pub struct KeyboardInputCommand;
impl KeyboardInputCommand { fn payload_bytes(&self) -> Option<usize> { Some(0) } }

include!(env!("PF_SETTINGS_REQUEST"));
include!(env!("PF_SETTINGS_DATA"));
include!(env!("PF_SETTINGS_QUEUE"));
include!(env!("PF_SETTINGS_TARGET"));

const MAX_OWNED_PORT_FORWARD_MAPPINGS: usize = 32;
#[derive(Default, serde_derive::Serialize, serde_derive::Deserialize)]
struct PeerConfig { port_forwards: Vec<(i32, String, i32)> }
impl PeerConfig {
    fn load_for_write(id: &str) -> ResultType<Self> {
        match std::fs::read(id) {
            Ok(bytes) => Ok(serde_json::from_slice(&bytes)?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e.into()),
        }
    }
    fn store(&self, id: &str) -> ResultType<()> {
        std::fs::write(id, serde_json::to_vec(self)?)?;
        Ok(())
    }
}
include!(env!("PF_SETTINGS_PEER_MUTATION"));
struct LoginConfigHandler { id: String, config: PeerConfig }
include!(env!("PF_SETTINGS_CACHE"));

#[derive(Clone)]
struct TestHandler;
trait InvokeUiSession: Clone + Send + Sync + 'static {}
impl InvokeUiSession for TestHandler {}
#[derive(Clone)]
struct Session<T: InvokeUiSession = TestHandler> {
    lc: Arc<RwLock<LoginConfigHandler>>,
    sender: Arc<RwLock<Option<ViewerCommandSender>>>,
    args: Vec<String>,
    rdp: bool,
    ui_handler: T,
    #[cfg(pf_settings_results)]
    listener_starts: Arc<AtomicUsize>,
}
impl<T: InvokeUiSession> Session<T> {
    fn is_port_forward(&self) -> bool { true }
    fn is_rdp(&self) -> bool { self.rdp }
    fn get_id(&self) -> String { self.lc.read().unwrap().id.clone() }
    fn on_error(&self, error: &str) { panic!("unexpected mapping task error: {error}"); }
}
include!(env!("PF_SETTINGS_PRODUCER"));
include!(env!("PF_SETTINGS_SEND"));
include!(env!("PF_SETTINGS_RDP_PRODUCER"));

#[path = "test-rdp-launch.rs"]
mod rdp_launch_tests;

struct Fixture { root: PathBuf, session: Session }
impl Fixture {
    fn new(sender: Option<ViewerCommandSender>) -> Self {
        let root = std::env::temp_dir().join(format!("pf-settings-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        let id = root.join("peer.json").to_str().unwrap().to_owned();
        Self { root, session: Session {
            lc: Arc::new(RwLock::new(LoginConfigHandler { id, config: PeerConfig::default() })),
            sender: Arc::new(RwLock::new(sender)),
            args: Vec::new(),
            rdp: false,
            ui_handler: TestHandler,
            #[cfg(pf_settings_results)]
            listener_starts: Arc::new(AtomicUsize::new(0)),
        } }
    }
    fn bytes(&self) -> Option<Vec<u8>> { std::fs::read(self.root.join("peer.json")).ok() }
    fn seed(&self, port: i32) {
        self.session.lc.write().unwrap().add_port_forward(&(port, "localhost".into(), 22)).unwrap();
    }
}

#[cfg(pf_settings_results)]
include!(env!("PF_SETTINGS_OWNER"));
#[cfg(pf_settings_results)]
include!(env!("PF_SETTINGS_PORT_OWNER"));
#[cfg(pf_settings_results)]
include!(env!("PF_SETTINGS_LISTENER"));
#[cfg(pf_settings_results)]
mod tcp {
    use crate::{anyhow::Context, ResultType, tokio::net::{lookup_host, TcpListener, TcpSocket, ToSocketAddrs}};
    include!(env!("PF_SETTINGS_NATIVE_BIND"));
}

// The production listener's preparation runs, including its native exclusive
// loopback bind. The peer authentication/relay loop is a close-waiting double.
#[cfg(pf_settings_results)]
trait Interface: Clone + Send + 'static { fn listener_started(&self); }
#[cfg(pf_settings_results)]
impl<T: InvokeUiSession> Interface for Session<T> {
    fn listener_started(&self) { self.listener_starts.fetch_add(1, Ordering::SeqCst); }
}
#[cfg(pf_settings_results)]
include!(env!("PF_SETTINGS_LISTEN_WAIT"));
#[cfg(pf_settings_results)]
fn run_rdp(_port: u16) -> ResultType<()> { Ok(()) }

#[cfg(pf_settings_results)]
async fn selected(
    session: &Session,
    receiver: &mut ViewerCommandReceiver,
    supervisor: &PortForwardSupervisorOwner,
) -> bool {
    let command = tokio::time::timeout(Duration::from_secs(2), receiver.recv()).await.unwrap();
    let Some(Ok(Data::SavedPortForward(request))) = command else { panic!("missing owned mapping request") };
    let result = session.apply_saved_port_forward(request.change, supervisor).await;
    request.completed.try_send(result).is_ok()
}

#[cfg(pf_settings_results)]
async fn request_add(session: &Session, port: i32) -> tokio::task::JoinHandle<ResultType<()>> {
    let session = session.clone();
    tokio::spawn(async move { add(&session, port).await })
}

#[cfg(pf_settings_results)]
#[tokio::test(flavor = "current_thread")]
async fn mapping_bind_failure_retries_the_saved_target() {
    let (sender, mut receiver) = viewer_command_channel();
    let fixture = Fixture::new(Some(sender));
    let supervisor = PortForwardSupervisorOwner::start(fixture.session.clone()).unwrap();
    let blocker = tcp::new_exclusive_listener("127.0.0.1:0").await.unwrap();
    let address = blocker.local_addr().unwrap();
    let port = i32::from(address.port());
    let first = request_add(&fixture.session, port).await;
    selected(&fixture.session, &mut receiver, &supervisor).await;
    let error = first.await.unwrap().unwrap_err().to_string();
    assert!(error.contains("was saved but could not be applied"), "{error}");
    let saved = fixture.bytes().unwrap();
    assert_eq!(fixture.session.lc.read().unwrap().config.port_forwards.len(), 1);
    assert_eq!(blocker.local_addr().unwrap(), address);
    drop(blocker);
    let retry = request_add(&fixture.session, port).await;
    selected(&fixture.session, &mut receiver, &supervisor).await;
    retry.await.unwrap().unwrap();
    assert_eq!(fixture.bytes().unwrap(), saved);
    assert!(tcp::new_exclusive_listener(address).await.is_err());
    let session = fixture.session.clone();
    let removal = tokio::spawn(async move { remove(&session, port).await });
    selected(&fixture.session, &mut receiver, &supervisor).await;
    removal.await.unwrap().unwrap();
    let rebound = tcp::new_exclusive_listener(address).await.unwrap();
    drop(rebound);
    let mut mappings = HashMap::new();
    add_owned_port_forward(&mut mappings, &fixture.session, (port, "localhost".into(), 22).into()).await.unwrap();
    let first_task = mappings.get(&port).unwrap().task.id();
    add_owned_port_forward(&mut mappings, &fixture.session, (port, "localhost".into(), 22).into()).await.unwrap();
    assert_eq!(mappings.get(&port).unwrap().task.id(), first_task);
    drain_owned_port_forwards(&mut mappings).await;
    drop(tcp::new_exclusive_listener(address).await.unwrap());
    supervisor.close_and_join().await.unwrap();
    println!("PF_SETTINGS_BIND=pass collision=reported saved=retained retry=listening repeat=not-restarted remove=joined socket=rebindable");
}

#[cfg(pf_settings_results)]
#[tokio::test(flavor = "current_thread")]
async fn mapping_operations_wait_for_selection_and_keep_fifo_order() {
    let (sender, mut receiver) = viewer_command_channel();
    let fixture = Fixture::new(Some(sender));
    let supervisor = PortForwardSupervisorOwner::start(fixture.session.clone()).unwrap();
    let port_owner = tcp::new_exclusive_listener("127.0.0.1:0").await.unwrap();
    let address = port_owner.local_addr().unwrap();
    drop(port_owner);
    let port = i32::from(address.port());
    let addition = request_add(&fixture.session, port).await;
    tokio::time::timeout(Duration::from_secs(2), async {
        while receiver.commands.len() == 0 { tokio::task::yield_now().await; }
    }).await.unwrap();
    assert!(!addition.is_finished());
    assert!(fixture.bytes().is_none());
    let session = fixture.session.clone();
    let removal = tokio::spawn(async move { remove(&session, port).await });
    selected(&fixture.session, &mut receiver, &supervisor).await;
    addition.await.unwrap().unwrap();
    assert!(tcp::new_exclusive_listener(address).await.is_err());
    assert_eq!(PeerConfig::load_for_write(&fixture.session.get_id()).unwrap().port_forwards.len(), 1);
    selected(&fixture.session, &mut receiver, &supervisor).await;
    removal.await.unwrap().unwrap();
    assert!(PeerConfig::load_for_write(&fixture.session.get_id()).unwrap().port_forwards.is_empty());
    drop(tcp::new_exclusive_listener(address).await.unwrap());
    supervisor.close_and_join().await.unwrap();
    println!("PF_SETTINGS_ORDER=pass before-selection=unchanged reply=waits fifo=add-remove effects=file-and-socket cleanup=joined");
}

#[cfg(pf_settings_results)]
#[tokio::test(flavor = "current_thread")]
async fn bridge_exports_return_worker_results() {
    let _: fn(ffi::SessionID, i32, String, i32) -> ResultType<()> = ffi::session_add_port_forward;
    let _: fn(ffi::SessionID, i32) -> ResultType<()> = ffi::session_remove_port_forward;
    assert!(ffi::session_add_port_forward(uuid::Uuid::new_v4(), 31000, "localhost".into(), 22).is_err());
    assert!(ffi::session_remove_port_forward(uuid::Uuid::new_v4(), 31000).is_err());
    println!("PF_SETTINGS_BRIDGE=pass exports=2 mode=worker-results unknown-session=refused futures=absent");
}

#[cfg(pf_settings_results)]
#[tokio::test(flavor = "current_thread")]
async fn mapping_write_refusal_precedes_listener_and_recovers() {
    use std::os::unix::fs::PermissionsExt;
    let (sender, mut receiver) = viewer_command_channel();
    let fixture = Fixture::new(Some(sender));
    let supervisor = PortForwardSupervisorOwner::start(fixture.session.clone()).unwrap();
    let port_owner = tcp::new_exclusive_listener("127.0.0.1:0").await.unwrap();
    let address = port_owner.local_addr().unwrap(); drop(port_owner);
    let port = i32::from(address.port());
    std::fs::set_permissions(&fixture.root, std::fs::Permissions::from_mode(0o500)).unwrap();
    let first = request_add(&fixture.session, port).await;
    selected(&fixture.session, &mut receiver, &supervisor).await;
    let refused = first.await.unwrap().is_err();
    std::fs::set_permissions(&fixture.root, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(refused && fixture.bytes().is_none());
    assert!(fixture.session.lc.read().unwrap().config.port_forwards.is_empty());
    assert_eq!(fixture.session.listener_starts.load(Ordering::SeqCst), 0);
    drop(tcp::new_exclusive_listener(address).await.unwrap());
    let retry = request_add(&fixture.session, port).await;
    selected(&fixture.session, &mut receiver, &supervisor).await;
    retry.await.unwrap().unwrap();
    supervisor.close_and_join().await.unwrap();
    drop(tcp::new_exclusive_listener(address).await.unwrap());
    println!("PF_SETTINGS_WRITE=pass permission=refused cache=preserved listener=not-started retry=applied shutdown=joined");
}

#[cfg(pf_settings_results)]
#[tokio::test(flavor = "current_thread")]
async fn mapping_result_deadline_reports_uncertainty_without_cancelling_owned_work() {
    let (sender, mut receiver) = viewer_command_channel();
    let fixture = Fixture::new(Some(sender));
    let supervisor = PortForwardSupervisorOwner::start(fixture.session.clone()).unwrap();
    let port_owner = tcp::new_exclusive_listener("127.0.0.1:0").await.unwrap();
    let address = port_owner.local_addr().unwrap(); drop(port_owner);
    let operation = request_add(&fixture.session, i32::from(address.port())).await;
    let start = std::time::Instant::now();
    let error = tokio::time::timeout(Duration::from_secs(7), operation).await.unwrap()
        .unwrap().unwrap_err().to_string();
    assert!(error.contains("not yet known") && error.contains("may still finish"), "{error}");
    assert!(start.elapsed() >= Duration::from_millis(4500));
    assert!(fixture.bytes().is_none());
    assert!(!selected(&fixture.session, &mut receiver, &supervisor).await);
    assert!(fixture.bytes().is_some());
    assert!(tcp::new_exclusive_listener(address).await.is_err());
    supervisor.close_and_join().await.unwrap();
    drop(tcp::new_exclusive_listener(address).await.unwrap());
    println!("PF_SETTINGS_DEADLINE=pass result=uncertain wait=bounded saved-before-selection=false admitted-work=retained shutdown=joined");
}
impl Drop for Fixture { fn drop(&mut self) { std::fs::remove_dir_all(&self.root).unwrap(); } }

async fn add(session: &Session, port: i32) -> ResultType<()> {
    #[cfg(pf_settings_results)]
    { let session = session.clone(); tokio::task::spawn_blocking(move || session.add_port_forward(port, "localhost".into(), 22)).await? }
    #[cfg(not(pf_settings_results))]
    { session.add_port_forward(port, "localhost".into(), 22) }
}
async fn remove(session: &Session, port: i32) -> ResultType<()> {
    #[cfg(pf_settings_results)]
    { let session = session.clone(); tokio::task::spawn_blocking(move || session.remove_port_forward(port)).await? }
    #[cfg(not(pf_settings_results))]
    { session.remove_port_forward(port) }
}

#[tokio::test(flavor = "current_thread")]
async fn unavailable_mapping_round_refuses_before_persistence() {
    let mut correct = true;
    for action in ["add", "remove"] {
        for state in ["unpublished", "closed", "receiver-gone", "full"] {
            let (sender, receiver) = viewer_command_channel();
            let mut receiver = Some(receiver);
            match state {
                "closed" => { sender.send(Data::Close).unwrap(); }
                "receiver-gone" => { receiver.take(); }
                "full" => { for _ in 0..VIEWER_COMMAND_QUEUE_CAPACITY { sender.send(Data::CancelJob(1)).unwrap(); } }
                _ => {}
            }
            let fixture = Fixture::new((state != "unpublished").then_some(sender));
            if action == "remove" { fixture.seed(31001); }
            let before = fixture.bytes();
            let result = if action == "add" { add(&fixture.session, 31001).await }
                else { remove(&fixture.session, 31001).await };
            let preserved = fixture.bytes() == before;
            let case_correct = result.is_err() && preserved;
            println!("PF_SETTINGS_REFUSAL_CASE=observed action={action} state={state} refused={} preserved={preserved} correct={case_correct}", result.is_err());
            correct &= case_correct;
            drop(receiver);
        }
    }
    assert!(correct, "an unavailable mapping owner reported success or changed the saved mapping");
    println!("PF_SETTINGS_REFUSAL=pass cases=8 queues=production storage=preserved");
}

#[tokio::test(flavor = "current_thread")]
async fn identical_saved_mapping_still_requests_runtime_application() {
    let (sender, mut receiver) = viewer_command_channel();
    let fixture = Fixture::new(Some(sender));
    fixture.seed(31002);
    let before = fixture.bytes();
    let session = fixture.session.clone();
    let operation = tokio::spawn(async move { add(&session, 31002).await });
    let command = tokio::time::timeout(Duration::from_secs(2), receiver.recv()).await;
    let queued = match command {
        #[cfg(pf_settings_results)]
        Ok(Some(Ok(Data::SavedPortForward(request)))) => {
            request.completed.try_send(Ok(())).unwrap(); true
        }
        #[cfg(not(pf_settings_results))]
        Ok(Some(Ok(Data::AddPortForward(_)))) => true,
        _ => false,
    };
    if !queued { operation.abort(); }
    let succeeded = matches!(operation.await, Ok(Ok(())));
    let preserved = fixture.bytes() == before;
    println!("PF_SETTINGS_RETRY=observed queued={queued} succeeded={succeeded} file_unchanged={preserved}");
    assert!(queued && succeeded && preserved, "an identical durable mapping suppressed its runtime retry");
}

#[cfg(pf_settings_results)]
mod ffi {
    use crate::anyhow::Result;
    pub(super) type SessionID = uuid::Uuid;
    mod sessions {
        pub(super) fn get_session_by_session_id(_id: &super::SessionID) -> Option<super::super::Session> { None }
    }
    include!(env!("PF_SETTINGS_FFI"));
}
