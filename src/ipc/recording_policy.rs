use super::{
    ipc_auth, Config, Connection, LinuxServiceAction, MainIpcRequest, MainIpcResponse,
    ServiceIpcRequest, ServiceIpcResponse, SERVICE_IPC_REQUEST_TIMEOUT_MS,
};
use crate::incoming_recording_status::{IncomingRecordingSetting, RecordingSettingChange, RecordingSettingOutcome};
use hbb_common::{anyhow::anyhow, bail, config, log, tokio, uuid::Uuid, ResultType};
use std::{
    collections::VecDeque,
    os::fd::{AsRawFd, BorrowedFd, OwnedFd},
    sync::{atomic::{AtomicU8, Ordering}, Arc, Mutex, OnceLock},
    time::{Duration, Instant},
};
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;

static WRITER: OnceLock<Arc<Semaphore>> = OnceLock::new();
static OPERATIONS: Mutex<VecDeque<Operation>> = Mutex::new(VecDeque::new());
static REFRESH: Semaphore = Semaphore::const_new(1);
// A service child must obtain the policy from its exact root parent before capture.
// Zero is unavailable, one is disabled, and two is enabled.
static RUNTIME_POLICY: AtomicU8 = AtomicU8::new(0);

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "outcome", deny_unknown_fields)]
pub(crate) enum RecordingPolicyOutcome {
    Applied { enabled: bool },
    Denied,
    Failed,
    Uncertain,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "state", content = "result", deny_unknown_fields)]
pub(crate) enum RecordingOperationStatus {
    Pending,
    Complete(RecordingPolicyOutcome),
    Unknown,
}

struct Operation {
    id: Uuid,
    requester: super::PeerProcessIdentity,
    enabled: bool,
    status: RecordingOperationStatus,
}

fn operation_id(value: &str) -> ResultType<Uuid> {
    if value.len() != 36 {
        bail!("Recording operation identity has the wrong length");
    }
    let id = Uuid::parse_str(value)?;
    if id.is_nil() || id.to_string() != value {
        bail!("Recording operation identity is not canonical");
    }
    Ok(id)
}

fn change_response(status: RecordingOperationStatus) -> ServiceIpcResponse {
    ServiceIpcResponse::IncomingRecordingPolicyChange { status }
}

fn complete_response(outcome: RecordingPolicyOutcome) -> ServiceIpcResponse {
    change_response(RecordingOperationStatus::Complete(outcome))
}

fn retain_peer(stream: &Connection) -> ResultType<OwnedFd> {
    // The accepted socket keeps its kernel peer identity through authorization.
    Ok(unsafe { BorrowedFd::borrow_raw(stream.inner.get_ref().as_raw_fd()) }
        .try_clone_to_owned()?)
}

fn authenticate_requester(peer: &OwnedFd) -> ResultType<super::PeerProcessIdentity> {
    require_supervisor()?;
    let shutdown = crate::server::shutdown_token();
    let cancelled = || shutdown.is_cancelled();
    let mut lookup = hbb_common::platform::linux::LoginctlLookup::new(
        Instant::now() + Duration::from_millis(SERVICE_IPC_REQUEST_TIMEOUT_MS), &cancelled,
    );
    lookup.check_pending()?;
    ipc_auth::authenticate_linux_recording_policy_requester(peer, &mut lookup)
}

fn status_for_requester(id: Uuid, requester: &super::PeerProcessIdentity) -> RecordingOperationStatus {
    OPERATIONS.lock().unwrap().iter()
        .find(|operation| operation.id == id && operation.requester == *requester)
        .map(|operation| operation.status.clone())
        .unwrap_or(RecordingOperationStatus::Unknown)
}

pub(super) async fn service_change_status(stream: &Connection, value: String) -> ServiceIpcResponse {
    let (id, peer) = match operation_id(&value).and_then(|id| Ok((id, retain_peer(stream)?))) {
        Ok(value) => value,
        Err(err) => {
            log::warn!("Rejected recording status request: {err}");
            return change_response(RecordingOperationStatus::Unknown);
        }
    };
    match tokio::task::spawn_blocking(move || authenticate_requester(&peer)).await {
        Ok(Ok(requester)) => change_response(status_for_requester(id, &requester)),
        result => {
            log::warn!("Recording status requester could not be proved: {result:?}");
            change_response(RecordingOperationStatus::Unknown)
        }
    }
}

pub(super) async fn read_service_setting() -> ServiceIpcResponse {
    if let Err(err) = require_supervisor() {
        log::warn!("Incoming recording setting requires its service owner: {err}");
        return ServiceIpcResponse::IncomingRecordingSetting(IncomingRecordingSetting::default());
    }
    let writer = WRITER.get_or_init(|| Arc::new(Semaphore::new(1))).clone();
    let Ok(permit) = writer.try_acquire_owned() else {
        return ServiceIpcResponse::IncomingRecordingSetting(IncomingRecordingSetting {
            enabled: None,
            pending: OPERATIONS.lock().unwrap().iter()
                .any(|operation| operation.status == RecordingOperationStatus::Pending),
        });
    };
    let enabled = match tokio::task::spawn_blocking(move || {
        let _permit = permit;
        require_supervisor()?;
        Config::read_incoming_recording_enabled()
    }).await {
        Ok(Ok(enabled)) => Some(enabled),
        result => {
            log::warn!("Incoming recording setting is unavailable: {result:?}");
            None
        }
    };
    ServiceIpcResponse::IncomingRecordingSetting(IncomingRecordingSetting { enabled, pending: false })
}

fn require_supervisor() -> ResultType<()> {
    if unsafe { hbb_common::libc::geteuid() } != 0
        || crate::common::current_service_supervisor_role()
            != crate::common::ServiceSupervisorRole::Exact
    {
        bail!("Incoming recording policy requires the root service supervisor");
    }
    Ok(())
}

pub(super) async fn read_service_policy() -> ServiceIpcResponse {
    let enabled = match tokio::task::spawn_blocking(|| {
        require_supervisor()?;
        Config::read_incoming_recording_enabled()
    }).await {
        Ok(Ok(enabled)) => Some(enabled),
        Ok(Err(err)) => {
            log::warn!("Incoming recording policy is unavailable: {err}");
            None
        }
        Err(err) => {
            log::error!("Incoming recording policy reader failed: {err}");
            None
        }
    };
    ServiceIpcResponse::IncomingRecordingPolicy { enabled }
}

fn commit_policy(
    peer: OwnedFd,
    identity: super::PeerProcessIdentity,
    enabled: bool,
) -> ResultType<RecordingPolicyOutcome> {
    require_supervisor()?;
    let shutdown = crate::server::shutdown_token();
    let cancelled = || shutdown.is_cancelled();
    if authenticate_requester(&peer)? != identity {
        return Ok(RecordingPolicyOutcome::Denied);
    }
    if !super::linux_pkcheck_authorizes_service_action(
        &identity, LinuxServiceAction::SetIncomingRecording, &cancelled,
    ) {
        return Ok(RecordingPolicyOutcome::Denied);
    }
    let mut lookup = hbb_common::platform::linux::LoginctlLookup::new(
        Instant::now() + Duration::from_millis(SERVICE_IPC_REQUEST_TIMEOUT_MS),
        &cancelled,
    );
    lookup.check_pending()?;
    if ipc_auth::authenticate_linux_recording_policy_requester(&peer, &mut lookup)? != identity {
        bail!("Incoming recording requester changed during authorization");
    }
    lookup.check_pending()?;
    // The service transaction retains this worker through persistence and its join.
    // Once admitted here, shutdown may drain it but cannot cancel the write.
    Config::set_option(
        config::keys::OPTION_ALLOW_AUTO_RECORD_INCOMING.to_owned(),
        if enabled { "Y" } else { "" }.to_owned(),
    )?;
    match Config::read_incoming_recording_enabled() {
        Ok(enabled) => Ok(RecordingPolicyOutcome::Applied { enabled }),
        Err(err) => {
            log::error!("Incoming recording was saved but readback failed: {err}");
            Ok(RecordingPolicyOutcome::Uncertain)
        }
    }
}

pub(super) async fn set_service_policy(
    stream: &Connection,
    value: String,
    enabled: bool,
) -> ServiceIpcResponse {
    let (id, peer) = match operation_id(&value).and_then(|id| Ok((id, retain_peer(stream)?))) {
        Ok(value) => value,
        Err(err) => {
            log::warn!("Rejected recording change request: {err}");
            return complete_response(RecordingPolicyOutcome::Denied);
        }
    };
    let (peer, requester) = match tokio::task::spawn_blocking(move || {
        authenticate_requester(&peer).map(|requester| (peer, requester))
    }).await {
        Ok(Ok(value)) => value,
        result => {
            log::warn!("Recording change requester could not be proved: {result:?}");
            return complete_response(RecordingPolicyOutcome::Denied);
        }
    };
    {
        let operations = OPERATIONS.lock().unwrap();
        if let Some(operation) = operations.iter().find(|operation| operation.id == id) {
            return if operation.requester == requester && operation.enabled == enabled {
                change_response(operation.status.clone())
            } else { complete_response(RecordingPolicyOutcome::Denied) };
        }
        if operations.iter().any(|operation| operation.status == RecordingOperationStatus::Pending) {
            return complete_response(RecordingPolicyOutcome::Denied);
        }
    }
    // A short read may own the slot. Waiting here precedes authorization and admission.
    let permit = match tokio::time::timeout(Duration::from_millis(SERVICE_IPC_REQUEST_TIMEOUT_MS),
        WRITER.get_or_init(|| Arc::new(Semaphore::new(1))).clone().acquire_owned(),
    ).await {
        Ok(Ok(permit)) => permit,
        _ => return complete_response(RecordingPolicyOutcome::Failed),
    };
    {
        let mut operations = OPERATIONS.lock().unwrap();
        if let Some(operation) = operations.iter().find(|operation| operation.id == id) {
            return if operation.requester == requester && operation.enabled == enabled {
                change_response(operation.status.clone())
            } else { complete_response(RecordingPolicyOutcome::Denied) };
        }
        if operations.len() == 16 { operations.pop_front(); }
        operations.push_back(Operation { id, requester: requester.clone(), enabled,
            status: RecordingOperationStatus::Pending });
    }
    // The transaction owns both persistence and child convergence. Other writers
    // remain excluded until both finish, including after the requester disconnects.
    let _permit = permit;
    let outcome = match tokio::task::spawn_blocking(move || commit_policy(peer, requester, enabled)).await {
        Ok(Ok(RecordingPolicyOutcome::Applied { enabled })) => {
            match converge_service_policy(enabled).await {
                Ok(()) => RecordingPolicyOutcome::Applied { enabled },
                Err(err) => {
                    log::error!("Incoming recording was saved but child convergence is uncertain: {err}");
                    RecordingPolicyOutcome::Uncertain
                }
            }
        }
        Ok(Ok(outcome)) => outcome,
        Ok(Err(err)) => {
            log::warn!("Incoming recording policy change failed: {err}");
            RecordingPolicyOutcome::Failed
        }
        Err(err) => {
            log::error!("Incoming recording policy writer failed: {err}");
            RecordingPolicyOutcome::Uncertain
        }
    };
    let status = RecordingOperationStatus::Complete(outcome);
    if let Some(operation) = OPERATIONS.lock().unwrap().iter_mut().find(|operation| operation.id == id) {
        operation.status = status.clone();
    } else {
        log::error!("Recording change lost its retained operation record");
        return complete_response(RecordingPolicyOutcome::Uncertain);
    }
    change_response(status)
}

pub(crate) async fn refresh_for_server() -> ResultType<()> {
    if !crate::common::is_service_owned_server_process() {
        bail!("Recording policy replication requires a service-owned server");
    }
    // Serialize the entire read/publication, so an older reply cannot replace a
    // newer policy. Waiting for the slot shares the same bounded read deadline.
    tokio::time::timeout(Duration::from_millis(SERVICE_IPC_REQUEST_TIMEOUT_MS), async {
        let _permit = REFRESH.acquire().await?;
        refresh_from_parent().await
    }).await?
}

async fn refresh_from_parent() -> ResultType<()> {
    let mut stream = super::connect_service(SERVICE_IPC_REQUEST_TIMEOUT_MS).await?;
    let parent = super::authenticate_linux_service_owned_password_parent(
        stream.inner.get_ref(), crate::POSTFIX_SERVICE,
    )?;
    stream.send_service_request_timeout(
        &ServiceIpcRequest::IncomingRecordingPolicy {}, SERVICE_IPC_REQUEST_TIMEOUT_MS,
    ).await?;
    let response = stream.next_service_response_timeout(SERVICE_IPC_REQUEST_TIMEOUT_MS).await?;
    let current_parent = super::authenticate_linux_service_owned_password_parent(
        stream.inner.get_ref(), crate::POSTFIX_SERVICE,
    )?;
    if parent != current_parent {
        bail!("Recording policy parent changed during replication");
    }
    let Some(ServiceIpcResponse::IncomingRecordingPolicy { enabled: Some(enabled) }) = response else {
        return Err(anyhow!("The service did not provide an incoming recording policy"));
    };
    RUNTIME_POLICY.store(if enabled { 2 } else { 1 }, Ordering::Release);
    Ok(())
}

async fn converge_service_policy(enabled: bool) -> ResultType<()> {
    require_supervisor()?;
    if crate::platform::linux::service_owned_children_are_absent()? {
        // Every later child must bootstrap the already committed service value.
        return Ok(());
    }
    let uid = tokio::task::spawn_blocking(super::user_main_ipc_server_uid).await??;
    let mut stream = super::connect_for_uid(SERVICE_IPC_REQUEST_TIMEOUT_MS, uid, "").await?;
    let child = super::authenticate_linux_service_owned_main_server(&stream)?;
    stream.send_main_request_timeout(
        &MainIpcRequest::StatusSnapshot, SERVICE_IPC_REQUEST_TIMEOUT_MS,
    ).await?;
    let response = stream.next_main_response_timeout(SERVICE_IPC_REQUEST_TIMEOUT_MS).await?;
    if super::authenticate_linux_service_owned_main_server(&stream)? != child {
        bail!("Recording policy child changed during convergence");
    }
    let Some(MainIpcResponse::StatusSnapshot(snapshot)) = response else {
        bail!("Recording policy child did not confirm its effective state");
    };
    let options = snapshot.options.into_map()?;
    let value = options.get(config::keys::OPTION_ALLOW_AUTO_RECORD_INCOMING)
        .ok_or_else(|| anyhow!("Recording policy is missing from child status"))?;
    if config::option2bool(config::keys::OPTION_ALLOW_AUTO_RECORD_INCOMING, value) != enabled {
        bail!("Recording policy child has not adopted the committed state");
    }
    Ok(())
}

pub(crate) fn enabled_for_server() -> ResultType<bool> {
    if !crate::common::is_service_owned_server_process() {
        return Ok(Config::get_bool_option(config::keys::OPTION_ALLOW_AUTO_RECORD_INCOMING));
    }
    match RUNTIME_POLICY.load(Ordering::Acquire) {
        1 => Ok(false),
        2 => Ok(true),
        _ => bail!("Incoming recording policy has not been authenticated"),
    }
}

pub(crate) async fn client_setting() -> ResultType<IncomingRecordingSetting> {
    let mut stream = super::connect_service(SERVICE_IPC_REQUEST_TIMEOUT_MS).await?;
    stream.send_service_request_timeout(&ServiceIpcRequest::IncomingRecordingSetting {}, SERVICE_IPC_REQUEST_TIMEOUT_MS).await?;
    match stream.next_service_response_timeout(SERVICE_IPC_REQUEST_TIMEOUT_MS).await? {
        Some(ServiceIpcResponse::IncomingRecordingSetting(setting)) => Ok(setting),
        _ => bail!("The service did not return the incoming recording setting"),
    }
}

pub(crate) async fn client_change(enabled: bool) -> RecordingSettingChange {
    client_change_with_connector(enabled, Duration::from_secs(150), ||
        super::connect_service(SERVICE_IPC_REQUEST_TIMEOUT_MS)).await
}

async fn client_change_with_connector<F, C, T>(enabled: bool, budget: Duration, mut connect: F) -> RecordingSettingChange
where
    F: FnMut() -> C,
    C: std::future::Future<Output = ResultType<super::ConnectionTmpl<T>>>,
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let deadline = tokio::time::Instant::now() + budget;
    let operation_id = Uuid::new_v4().to_string();
    let mut stream = match connect().await {
        Ok(stream) => stream,
        Err(err) => {
            log::warn!("Incoming recording service unavailable before submission: {err}");
            return RecordingSettingChange::without_confirmation(RecordingSettingOutcome::Failed);
        }
    };
    let request = ServiceIpcRequest::SetIncomingRecordingPolicy { operation_id: operation_id.clone(), enabled };
    // Submit exactly once. A broken write or missing reply can mean it was accepted.
    let mut response = match stream.send_service_request_timeout(&request, SERVICE_IPC_REQUEST_TIMEOUT_MS).await {
        Ok(()) => stream.next_service_response_timeout(SERVICE_IPC_REQUEST_TIMEOUT_MS).await,
        Err(err) => Err(err),
    };
    drop(stream);
    loop {
        if let Ok(Some(ServiceIpcResponse::IncomingRecordingPolicyChange {
            status: RecordingOperationStatus::Complete(outcome),
        })) = response {
            return match outcome {
                RecordingPolicyOutcome::Applied { enabled } => RecordingSettingChange {
                    outcome: RecordingSettingOutcome::Applied, enabled: Some(enabled),
                },
                RecordingPolicyOutcome::Denied => RecordingSettingChange::without_confirmation(RecordingSettingOutcome::Denied),
                RecordingPolicyOutcome::Failed => RecordingSettingChange::without_confirmation(RecordingSettingOutcome::Failed),
                RecordingPolicyOutcome::Uncertain => RecordingSettingChange::without_confirmation(RecordingSettingOutcome::Uncertain),
            };
        }
        let query = async {
            tokio::time::sleep(Duration::from_millis(250)).await;
            let mut stream = connect().await?;
            stream.send_service_request_timeout(&ServiceIpcRequest::IncomingRecordingPolicyChange {
                operation_id: operation_id.clone(),
            }, SERVICE_IPC_REQUEST_TIMEOUT_MS).await?;
            stream.next_service_response_timeout(SERVICE_IPC_REQUEST_TIMEOUT_MS).await
        };
        response = match tokio::time::timeout_at(deadline, query).await {
            Ok(response) => response,
            Err(_) => {
                log::warn!("Incoming recording operation {operation_id} remains unconfirmed");
                return RecordingSettingChange::without_confirmation(RecordingSettingOutcome::Uncertain);
            }
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::ConnectionTmpl;

    #[tokio::test]
    async fn policy_wire_accepts_only_the_closed_operation_and_outcome() {
        let (sender, receiver) = tokio::net::UnixStream::pair().unwrap();
        let mut sender = ConnectionTmpl::new_protected_service(sender);
        let mut receiver = ConnectionTmpl::new_protected_service(receiver);
        for enabled in [false, true] {
            let operation_id = Uuid::new_v4().to_string();
            sender.send_service_request_timeout(
                &ServiceIpcRequest::SetIncomingRecordingPolicy { operation_id: operation_id.clone(), enabled }, 1000,
            ).await.unwrap();
            assert!(matches!(receiver.next_service_request_timeout(1000).await.unwrap(),
                Some(ServiceIpcRequest::SetIncomingRecordingPolicy { operation_id: actual_id, enabled: actual })
                    if actual == enabled && actual_id == operation_id));
        }
        for invalid in [
            serde_json::json!({"t": "SetIncomingRecordingPolicy", "enabled": "Y"}),
            serde_json::json!({"t": "SetIncomingRecordingPolicy", "enabled": true, "key": "password"}),
            serde_json::json!({"t": "IncomingRecordingPolicy", "enabled": true}),
            serde_json::json!({"t": "SetOption", "key": "allow-auto-record-incoming", "value": "Y"}),
        ] {
            sender.send_json_timeout(&invalid, 1000).await.unwrap();
            assert!(receiver.next_service_request_timeout(1000).await.unwrap().is_none());
        }
        for outcome in [
            RecordingPolicyOutcome::Applied { enabled: true },
            RecordingPolicyOutcome::Applied { enabled: false },
            RecordingPolicyOutcome::Denied,
            RecordingPolicyOutcome::Failed,
            RecordingPolicyOutcome::Uncertain,
        ] {
            receiver.send_service_response_timeout(
                &complete_response(outcome.clone()), 1000,
            ).await.unwrap();
            assert!(matches!(sender.next_service_response_timeout(1000).await.unwrap(),
                Some(ServiceIpcResponse::IncomingRecordingPolicyChange {
                    status: RecordingOperationStatus::Complete(actual) }) if actual == outcome));
        }
        for status in [RecordingOperationStatus::Pending, RecordingOperationStatus::Unknown] {
            receiver.send_service_response_timeout(&change_response(status.clone()), 1000).await.unwrap();
            assert!(matches!(sender.next_service_response_timeout(1000).await.unwrap(),
                Some(ServiceIpcResponse::IncomingRecordingPolicyChange { status: actual }) if actual == status));
        }
        for invalid in ["", "00000000-0000-0000-0000-000000000000", "A0B00000-0000-0000-0000-000000000001"] {
            assert!(operation_id(invalid).is_err());
        }
    }

    #[tokio::test]
    async fn lost_change_reply_queries_same_operation_without_resubmitting() {
        for outcome in [RecordingPolicyOutcome::Applied { enabled: false },
            RecordingPolicyOutcome::Applied { enabled: true }, RecordingPolicyOutcome::Denied,
            RecordingPolicyOutcome::Failed, RecordingPolicyOutcome::Uncertain] {
            let id = Arc::new(Mutex::new(None));
            let mut jobs = Vec::new();
            let mut connections = 0;
            let result = client_change_with_connector(true, Duration::from_secs(5), || {
                let (client, peer) = tokio::net::UnixStream::pair().unwrap();
                let mut peer = ConnectionTmpl::new_protected_service(peer);
                let phase = connections;
                connections += 1;
                let id = id.clone();
                let outcome = outcome.clone();
                jobs.push(tokio::spawn(async move {
                    let request = peer.next_service_request_timeout(1000).await.unwrap().unwrap();
                    if phase == 0 {
                        let ServiceIpcRequest::SetIncomingRecordingPolicy { operation_id: value, enabled: true } = request else {
                            panic!("first connection must submit exactly one change");
                        };
                        assert!(operation_id(&value).is_ok());
                        *id.lock().unwrap() = Some(value);
                        // Model a lost acknowledgement after the receiver accepted the change.
                    } else {
                        let ServiceIpcRequest::IncomingRecordingPolicyChange { operation_id: value } = request else {
                            panic!("reply recovery must never resubmit the change");
                        };
                        assert_eq!(Some(value), *id.lock().unwrap());
                        let response = if phase == 1 { change_response(RecordingOperationStatus::Pending) }
                            else { complete_response(outcome) };
                        peer.send_service_response_timeout(&response, 1000).await.unwrap();
                    }
                }));
                std::future::ready(Ok(ConnectionTmpl::new_protected_service(client)))
            }).await;
            for job in jobs { job.await.unwrap(); }
            assert_eq!(connections, 3);
            let expected = match outcome {
                RecordingPolicyOutcome::Applied { enabled } => RecordingSettingChange { outcome: RecordingSettingOutcome::Applied, enabled: Some(enabled) },
                RecordingPolicyOutcome::Denied => RecordingSettingChange::without_confirmation(RecordingSettingOutcome::Denied),
                RecordingPolicyOutcome::Failed => RecordingSettingChange::without_confirmation(RecordingSettingOutcome::Failed),
                RecordingPolicyOutcome::Uncertain => RecordingSettingChange::without_confirmation(RecordingSettingOutcome::Uncertain),
            };
            assert_eq!(result, expected);
        }
    }

    #[tokio::test]
    async fn missing_change_history_remains_uncertain_and_unavailable_owner_fails_before_submit() {
        let mut jobs = Vec::new();
        let mut connections = 0;
        let result = client_change_with_connector(true, Duration::from_millis(600), || {
            let (client, peer) = tokio::net::UnixStream::pair().unwrap();
            let mut peer = ConnectionTmpl::new_protected_service(peer);
            let first = connections == 0;
            connections += 1;
            jobs.push(tokio::spawn(async move {
                let request = peer.next_service_request_timeout(1000).await.unwrap().unwrap();
                assert_eq!(matches!(request, ServiceIpcRequest::SetIncomingRecordingPolicy { .. }), first);
                if !first { assert!(matches!(request, ServiceIpcRequest::IncomingRecordingPolicyChange { .. })); }
                peer.send_service_response_timeout(&change_response(RecordingOperationStatus::Unknown), 1000).await.unwrap();
            }));
            std::future::ready(Ok(ConnectionTmpl::new_protected_service(client)))
        }).await;
        for job in jobs { job.await.unwrap(); }
        assert!(connections >= 2 && connections <= 3);
        assert_eq!(result, RecordingSettingChange::without_confirmation(RecordingSettingOutcome::Uncertain));
        let result = client_change_with_connector(true, Duration::from_secs(1), ||
            std::future::ready(Err::<ConnectionTmpl<super::super::ConnClient>, _>(anyhow!("owner is unavailable")))).await;
        assert_eq!(result, RecordingSettingChange::without_confirmation(RecordingSettingOutcome::Failed));
    }

    #[tokio::test]
    async fn ordinary_process_cannot_act_as_policy_supervisor_or_replica() {
        assert_ne!(unsafe { hbb_common::libc::geteuid() }, 0);
        assert!(require_supervisor().is_err());
        assert!(matches!(read_service_policy().await,
            ServiceIpcResponse::IncomingRecordingPolicy { enabled: None }));
        let (peer, _other) = std::os::unix::net::UnixStream::pair().unwrap();
        let peer = OwnedFd::from(peer);
        assert!(authenticate_requester(&peer).is_err());
        assert!(matches!(read_service_setting().await,
            ServiceIpcResponse::IncomingRecordingSetting(IncomingRecordingSetting { enabled: None, pending: false })));
        assert!(refresh_for_server().await.is_err());
    }

    #[test]
    fn policy_readback_observes_disk_changes_and_refuses_corruption() {
        const ROOT_ENV: &str = "RUSTDESK_RECORDING_POLICY_TEST_ROOT";
        let Some(root) = std::env::var_os(ROOT_ENV) else {
            let root = std::env::temp_dir().join(format!("recording-policy-{}", hbb_common::uuid::Uuid::new_v4()));
            std::fs::create_dir(&root).unwrap();
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["ipc::recording_policy::tests::policy_readback_observes_disk_changes_and_refuses_corruption",
                    "--exact", "--test-threads=1"])
                .env(ROOT_ENV, &root).env("XDG_CONFIG_HOME", &root)
                .output().unwrap();
            std::fs::remove_dir_all(&root).unwrap();
            assert!(output.status.success(), "{}{}",
                String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
            return;
        };
        let file = config::Config2::file();
        assert!(file.starts_with(std::path::PathBuf::from(root)));
        assert!(!Config::read_incoming_recording_enabled().unwrap());
        Config::set_option(config::keys::OPTION_ALLOW_AUTO_RECORD_INCOMING.into(), "Y".into()).unwrap();
        assert!(Config::read_incoming_recording_enabled().unwrap());
        assert!(Config::get_bool_option(config::keys::OPTION_ALLOW_AUTO_RECORD_INCOMING));
        let before = std::fs::read_to_string(&file).unwrap();
        let after = before.replace("allow-auto-record-incoming = \"Y\"", "allow-auto-record-incoming = \"\"");
        assert_ne!(after, before);
        std::fs::write(&file, &after).unwrap();
        assert!(!Config::read_incoming_recording_enabled().unwrap());
        assert!(Config::get_bool_option(config::keys::OPTION_ALLOW_AUTO_RECORD_INCOMING));
        std::fs::write(&file, b"[options\n").unwrap();
        assert!(Config::read_incoming_recording_enabled().is_err());
        assert_eq!(std::fs::read(&file).unwrap(), b"[options\n");
        std::fs::write(&file, before).unwrap();
        assert!(Config::read_incoming_recording_enabled().unwrap());
    }
}
