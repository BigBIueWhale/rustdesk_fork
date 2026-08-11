use crate::ipc::{self, Data};
use hbb_common::{anyhow::anyhow, bail, ResultType};
use std::{
    io::{BufRead, BufReader, Write},
    process::{Child, Command, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};
use winapi::{
    shared::{
        minwindef::{FALSE, FILETIME},
        winerror::WAIT_TIMEOUT,
    },
    um::{
        handleapi::{CloseHandle, INVALID_HANDLE_VALUE},
        processthreadsapi::{GetProcessTimes, OpenProcess, TerminateProcess},
        synchapi::WaitForSingleObject,
        winbase::{WAIT_FAILED, WAIT_OBJECT_0},
        winnt::{HANDLE, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE, SYNCHRONIZE},
    },
};

const READY_PREFIX: &str = "RUSTDESK_WINDOWS_CM_READY";
const WORKER_START_TIMEOUT: Duration = Duration::from_secs(30);
const CM_PIPE_CONNECT_ATTEMPT_TIMEOUT_MS: u64 = 1_000;
const CM_PIPE_RETRY_DELAY: Duration = Duration::from_millis(50);
const CM_EXIT_TIMEOUT_MS: u32 = 10_000;

#[derive(Clone)]
struct NoopConnectionManager;

impl crate::ui_cm_interface::InvokeUiCM for NoopConnectionManager {
    fn add_connection(&self, _client: &crate::ui_cm_interface::Client) {}

    fn remove_connection(&self, _id: i32, _close: bool) {}

    fn new_message(&self, _id: i32, _text: String) {}

    fn change_theme(&self, _dark: String) {}

    fn change_language(&self) {}

    fn update_voice_call_state(&self, _client: &crate::ui_cm_interface::Client) {}

    fn file_transfer_log(&self, _action: &str, _log: &str) {}
}

struct OwnedProcessHandle(HANDLE);

impl OwnedProcessHandle {
    fn open(identity: ipc::WindowsProcessIdentityKey) -> ResultType<Self> {
        let handle = unsafe {
            OpenProcess(
                SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE,
                FALSE,
                identity.pid,
            )
        };
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            bail!(
                "could not open connection-manager process {}: {}",
                identity.pid,
                std::io::Error::last_os_error()
            );
        }
        let owned = Self(handle);
        let observed = owned.identity(identity.pid)?;
        if observed != identity {
            bail!(
                "connection-manager process generation changed: expected {}:{}, got {}:{}",
                identity.pid,
                identity.creation_time,
                observed.pid,
                observed.creation_time
            );
        }
        Ok(owned)
    }

    fn identity(&self, pid: u32) -> ResultType<ipc::WindowsProcessIdentityKey> {
        let mut creation = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        let mut exit = creation;
        let mut kernel = creation;
        let mut user = creation;
        if unsafe { GetProcessTimes(self.0, &mut creation, &mut exit, &mut kernel, &mut user) }
            == FALSE
        {
            bail!(
                "could not query connection-manager process {}: {}",
                pid,
                std::io::Error::last_os_error()
            );
        }
        let creation_time =
            ((creation.dwHighDateTime as u64) << 32) | creation.dwLowDateTime as u64;
        if creation_time == 0 {
            bail!("connection-manager process {pid} has a zero creation time");
        }
        Ok(ipc::WindowsProcessIdentityKey { pid, creation_time })
    }

    fn require_running(&self) -> ResultType<()> {
        match unsafe { WaitForSingleObject(self.0, 0) } {
            WAIT_TIMEOUT => Ok(()),
            WAIT_OBJECT_0 => bail!("connection-manager exited before its owner was terminated"),
            WAIT_FAILED => bail!(
                "could not query connection-manager liveness: {}",
                std::io::Error::last_os_error()
            ),
            status => bail!("unexpected connection-manager wait status {status:#x}"),
        }
    }

    fn wait_for_exit(&self) -> ResultType<()> {
        match unsafe { WaitForSingleObject(self.0, CM_EXIT_TIMEOUT_MS) } {
            WAIT_OBJECT_0 => Ok(()),
            WAIT_TIMEOUT => bail!(
                "connection-manager survived more than {} ms after its owner exited",
                CM_EXIT_TIMEOUT_MS
            ),
            WAIT_FAILED => bail!(
                "could not wait for connection-manager exit: {}",
                std::io::Error::last_os_error()
            ),
            status => bail!("unexpected connection-manager exit wait status {status:#x}"),
        }
    }

    fn force_terminate_and_wait(&self) -> ResultType<()> {
        if unsafe { TerminateProcess(self.0, 1) } == FALSE {
            let error = std::io::Error::last_os_error();
            if unsafe { WaitForSingleObject(self.0, 0) } != WAIT_OBJECT_0 {
                bail!("could not force-terminate stale connection-manager: {error}");
            }
        }
        match unsafe { WaitForSingleObject(self.0, CM_EXIT_TIMEOUT_MS) } {
            WAIT_OBJECT_0 => Ok(()),
            WAIT_TIMEOUT => bail!("force-terminated connection-manager did not exit"),
            WAIT_FAILED => bail!(
                "could not wait for force-terminated connection-manager: {}",
                std::io::Error::last_os_error()
            ),
            status => bail!("unexpected force-termination wait status {status:#x}"),
        }
    }
}

impl Drop for OwnedProcessHandle {
    fn drop(&mut self) {
        if unsafe { CloseHandle(self.0) } == FALSE {
            eprintln!(
                "windows_cm_lifecycle_probe: failed to close observation handle: {}",
                std::io::Error::last_os_error()
            );
        }
    }
}

struct Worker {
    child: Child,
    cm_identity: ipc::WindowsProcessIdentityKey,
    cm_process: OwnedProcessHandle,
}

async fn close_authenticated_cm(
    mut stream: ipc::ConnectionTmpl<parity_tokio_ipc::ConnectionClient>,
) -> ResultType<()> {
    stream.send(&Data::Close).await
}

fn connect_exact_cm_pipe_until_ready(
    runtime: &hbb_common::tokio::runtime::Runtime,
    expected_identity: ipc::WindowsProcessIdentityKey,
) -> ResultType<ipc::ConnectionTmpl<parity_tokio_ipc::ConnectionClient>> {
    let deadline = Instant::now() + WORKER_START_TIMEOUT;
    let mut last_error = "connection-manager pipe was not attempted".to_owned();
    loop {
        match runtime.block_on(ipc::connect(CM_PIPE_CONNECT_ATTEMPT_TIMEOUT_MS, "_cm")) {
            Ok(stream) => {
                ipc::authenticate_windows_cm_endpoint(&stream, "--cm", expected_identity).map_err(
                    |err| anyhow!("ready CM pipe had the wrong process identity: {err:#}"),
                )?;
                return Ok(stream);
            }
            Err(err) => last_error = format!("{err:#}"),
        }
        if Instant::now() >= deadline {
            bail!(
                "exact connection-manager pipe did not become ready within {} ms: {last_error}",
                WORKER_START_TIMEOUT.as_millis()
            );
        }
        thread::sleep(CM_PIPE_RETRY_DELAY);
    }
}

fn connect_authenticated_cm_until_ready(
    runtime: &hbb_common::tokio::runtime::Runtime,
    attempt: u8,
) -> ResultType<ipc::ConnectionTmpl<parity_tokio_ipc::ConnectionClient>> {
    let deadline = Instant::now() + WORKER_START_TIMEOUT;
    let mut last_error = "authenticated connection was not attempted".to_owned();
    loop {
        match runtime.block_on(crate::server::connect_authenticated_cm(
            CM_PIPE_CONNECT_ATTEMPT_TIMEOUT_MS,
            "--cm",
        )) {
            Ok(stream) => return Ok(stream),
            Err(err) => last_error = format!("{err:#}"),
        }
        if Instant::now() >= deadline {
            bail!(
                "authenticated CM connect {attempt} did not become ready within {} ms: {last_error}",
                WORKER_START_TIMEOUT.as_millis()
            );
        }
        thread::sleep(CM_PIPE_RETRY_DELAY);
    }
}

fn run_server_worker() -> ResultType<()> {
    let (first_identity, first_token) = crate::server::windows_cm_lifecycle_probe_lease()
        .map_err(|err| anyhow!("first production CM generation lease failed: {err:#}"))?;
    let (second_identity, second_token) = crate::server::windows_cm_lifecycle_probe_lease()
        .map_err(|err| anyhow!("second production CM generation lease failed: {err:#}"))?;
    if first_identity != second_identity || first_token != second_token {
        bail!("repeated launch selection did not lease one exact connection-manager generation");
    }

    let mut wrong_token = crate::encode64([0xA5; 32]);
    if wrong_token == first_token {
        wrong_token = crate::encode64([0x5A; 32]);
    }
    let runtime = hbb_common::tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|err| anyhow!("could not create CM lifecycle probe runtime: {err}"))?;
    let mut wrong_stream = connect_exact_cm_pipe_until_ready(&runtime, first_identity)?;
    let wrong = runtime.block_on(ipc::authenticate_cm_endpoint_launch_proof(
        &mut wrong_stream,
        &wrong_token,
        "--cm",
    ));
    if wrong.is_ok() {
        bail!("connection-manager accepted a wrong launch-generation token");
    }
    drop(wrong_stream);

    for attempt in 1..=2 {
        let stream = connect_authenticated_cm_until_ready(&runtime, attempt)?;
        runtime
            .block_on(close_authenticated_cm(stream))
            .map_err(|err| anyhow!("authenticated CM round trip {attempt} failed: {err}"))?;
    }

    println!(
        "{READY_PREFIX} {} {}",
        first_identity.pid, first_identity.creation_time
    );
    std::io::stdout()
        .flush()
        .map_err(|err| anyhow!("could not publish CM ready receipt: {err}"))?;
    loop {
        thread::park();
    }
}

fn run_cm_child() -> ResultType<()> {
    let cm = crate::ui_cm_interface::ConnectionManager {
        ui_handler: NoopConnectionManager,
    };
    crate::ui_cm_interface::start_ipc(cm);
    bail!("connection-manager listener returned unexpectedly")
}

fn parse_ready(line: &str) -> ResultType<ipc::WindowsProcessIdentityKey> {
    let mut fields = line.split_whitespace();
    if fields.next() != Some(READY_PREFIX) {
        bail!("invalid CM ready receipt prefix");
    }
    let pid = fields
        .next()
        .ok_or_else(|| anyhow!("CM ready receipt omitted pid"))?
        .parse::<u32>()
        .map_err(|err| anyhow!("CM ready receipt has invalid pid: {err}"))?;
    let creation_time = fields
        .next()
        .ok_or_else(|| anyhow!("CM ready receipt omitted creation time"))?
        .parse::<u64>()
        .map_err(|err| anyhow!("CM ready receipt has invalid creation time: {err}"))?;
    if fields.next().is_some() || pid == 0 || creation_time == 0 {
        bail!("CM ready receipt has an invalid field inventory");
    }
    Ok(ipc::WindowsProcessIdentityKey { pid, creation_time })
}

fn stop_worker(child: &mut Child) -> ResultType<()> {
    if child
        .try_wait()
        .map_err(|err| anyhow!("could not query CM owner worker state: {err}"))?
        .is_none()
    {
        child
            .kill()
            .map_err(|err| anyhow!("could not terminate CM owner worker: {err}"))?;
        child
            .wait()
            .map_err(|err| anyhow!("could not reap CM owner worker: {err}"))?;
    }
    Ok(())
}

fn stop_worker_after_error(child: &mut Child, error: impl std::fmt::Display) -> String {
    match stop_worker(child) {
        Ok(()) => error.to_string(),
        Err(cleanup) => format!("{error}; CM owner cleanup also failed: {cleanup}"),
    }
}

fn launch_worker() -> ResultType<Worker> {
    let exe = std::env::current_exe()
        .map_err(|err| anyhow!("could not resolve CM lifecycle probe executable: {err}"))?;
    let mut child = Command::new(exe)
        .arg("--server")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|err| anyhow!("could not launch CM owner worker: {err}"))?;
    let stdout = match child.stdout.take() {
        Some(stdout) => stdout,
        None => {
            let error =
                stop_worker_after_error(&mut child, "CM owner worker stdout was unavailable");
            bail!("{error}");
        }
    };
    let (sender, receiver) = mpsc::sync_channel::<Result<String, String>>(1);
    let reader = match thread::Builder::new()
        .name("windows-cm-lifecycle-receipt".to_owned())
        .spawn(move || {
            let mut receipt = None;
            for line in BufReader::new(stdout).lines() {
                match line {
                    Ok(line) if line.starts_with(READY_PREFIX) => {
                        receipt = Some(Ok(line));
                        break;
                    }
                    Ok(_) => {}
                    Err(err) => {
                        receipt = Some(Err(format!("could not read CM owner receipt: {err}")));
                        break;
                    }
                }
            }
            let receipt = match receipt {
                Some(receipt) => receipt,
                None => Err("CM owner exited without a ready receipt".to_owned()),
            };
            if sender.send(receipt).is_err() {
                eprintln!(
                    "windows_cm_lifecycle_probe: controller stopped waiting for the worker receipt"
                );
            }
        }) {
        Ok(reader) => reader,
        Err(err) => {
            let error = stop_worker_after_error(
                &mut child,
                format!("could not start CM owner receipt reader: {err}"),
            );
            bail!("{error}");
        }
    };

    let receipt = match receiver.recv_timeout(WORKER_START_TIMEOUT) {
        Ok(Ok(receipt)) => receipt,
        Ok(Err(err)) => {
            let mut error = stop_worker_after_error(&mut child, err);
            if reader.join().is_err() {
                error.push_str("; CM owner receipt reader panicked");
            }
            bail!("{error}");
        }
        Err(err) => {
            let mut error = stop_worker_after_error(
                &mut child,
                format!("CM owner did not become ready within its deadline: {err}"),
            );
            if reader.join().is_err() {
                error.push_str("; CM owner receipt reader panicked");
            }
            bail!("{error}");
        }
    };
    if reader.join().is_err() {
        let error = stop_worker_after_error(&mut child, "CM owner receipt reader panicked");
        bail!("{error}");
    }
    let cm_identity = match parse_ready(&receipt) {
        Ok(identity) => identity,
        Err(err) => {
            return Err(anyhow!("{}", stop_worker_after_error(&mut child, err)));
        }
    };
    let cm_process = match OwnedProcessHandle::open(cm_identity) {
        Ok(process) => process,
        Err(err) => {
            return Err(anyhow!("{}", stop_worker_after_error(&mut child, err)));
        }
    };
    if let Err(err) = cm_process.require_running() {
        return Err(anyhow!("{}", stop_worker_after_error(&mut child, err)));
    }
    Ok(Worker {
        child,
        cm_identity,
        cm_process,
    })
}

fn terminate_owner_and_require_cm_exit(worker: &mut Worker) -> ResultType<()> {
    let mut failures = Vec::new();
    if let Err(err) = worker.cm_process.require_running() {
        failures.push(err.to_string());
    }
    if let Err(err) = stop_worker(&mut worker.child) {
        failures.push(err.to_string());
    }
    if let Err(err) = worker.cm_process.wait_for_exit() {
        failures.push(err.to_string());
        if let Err(cleanup) = worker.cm_process.force_terminate_and_wait() {
            failures.push(format!(
                "stale connection-manager cleanup also failed: {cleanup}"
            ));
        }
    }
    if !failures.is_empty() {
        bail!("{}", failures.join("; "));
    }
    Ok(())
}

fn run_controller() -> ResultType<()> {
    let mut first = launch_worker()?;
    terminate_owner_and_require_cm_exit(&mut first)?;

    let mut replacement = launch_worker()?;
    if replacement.cm_identity == first.cm_identity {
        let error = match terminate_owner_and_require_cm_exit(&mut replacement) {
            Ok(()) => "replacement CM reused the retired process generation".to_owned(),
            Err(cleanup) => format!(
                "replacement CM reused the retired process generation; replacement cleanup failed: {cleanup}"
            ),
        };
        bail!("{error}");
    }
    terminate_owner_and_require_cm_exit(&mut replacement)?;

    println!(
        "windows_cm_lifecycle_probe: PASS first={}:{} replacement={}:{} wrong-token=refused reconnects=2 parent-death=closed",
        first.cm_identity.pid,
        first.cm_identity.creation_time,
        replacement.cm_identity.pid,
        replacement.cm_identity.creation_time
    );
    Ok(())
}

pub fn run() -> ResultType<()> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    match args.as_slice() {
        [] => run_controller(),
        [role] if role == "--server" => run_server_worker(),
        [role] if role == "--cm" => run_cm_child(),
        _ => bail!("invalid Windows CM lifecycle probe role"),
    }
}
