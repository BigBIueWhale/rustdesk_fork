use super::{
    ipc_auth, Config, Connection, LinuxServiceAction, MainIpcRequest, MainIpcResponse,
    ServiceIpcRequest, ServiceIpcResponse, SERVICE_IPC_REQUEST_TIMEOUT_MS,
};
use hbb_common::{anyhow::anyhow, bail, config, log, tokio, ResultType};
use std::{
    os::fd::{AsRawFd, BorrowedFd, OwnedFd},
    sync::{atomic::{AtomicU8, Ordering}, Arc, OnceLock},
    time::{Duration, Instant},
};
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;

static WRITER: OnceLock<Arc<Semaphore>> = OnceLock::new();
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
    enabled: bool,
) -> ResultType<RecordingPolicyOutcome> {
    require_supervisor()?;
    let shutdown = crate::server::shutdown_token();
    let cancelled = || shutdown.is_cancelled();
    let identity = {
        let mut lookup = hbb_common::platform::linux::LoginctlLookup::new(
            Instant::now() + Duration::from_millis(SERVICE_IPC_REQUEST_TIMEOUT_MS),
            &cancelled,
        );
        lookup.check_pending()?;
        ipc_auth::authenticate_linux_recording_policy_requester(&peer, &mut lookup)?
    };
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
    enabled: bool,
) -> ServiceIpcResponse {
    let response = |outcome| ServiceIpcResponse::IncomingRecordingPolicySet { outcome };
    let Ok(permit) = WRITER.get_or_init(|| Arc::new(Semaphore::new(1)))
        .clone().try_acquire_owned()
    else {
        return response(RecordingPolicyOutcome::Denied);
    };
    // Keep the accepted socket object while authorization runs off the async executor.
    let peer = match unsafe { BorrowedFd::borrow_raw(stream.inner.get_ref().as_raw_fd()) }
        .try_clone_to_owned()
    {
        Ok(peer) => peer,
        Err(err) => {
            log::error!("Failed to retain incoming recording requester socket: {err}");
            return response(RecordingPolicyOutcome::Failed);
        }
    };
    // The transaction owns both persistence and child convergence. Other writers
    // remain excluded until both finish, including after the requester disconnects.
    let _permit = permit;
    let outcome = match tokio::task::spawn_blocking(move || commit_policy(peer, enabled)).await {
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
    response(outcome)
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
            sender.send_service_request_timeout(
                &ServiceIpcRequest::SetIncomingRecordingPolicy { enabled }, 1000,
            ).await.unwrap();
            assert!(matches!(receiver.next_service_request_timeout(1000).await.unwrap(),
                Some(ServiceIpcRequest::SetIncomingRecordingPolicy { enabled: actual }) if actual == enabled));
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
                &ServiceIpcResponse::IncomingRecordingPolicySet { outcome: outcome.clone() }, 1000,
            ).await.unwrap();
            assert!(matches!(sender.next_service_response_timeout(1000).await.unwrap(),
                Some(ServiceIpcResponse::IncomingRecordingPolicySet { outcome: actual }) if actual == outcome));
        }
    }

    #[tokio::test]
    async fn ordinary_process_cannot_act_as_policy_supervisor_or_replica() {
        assert_ne!(unsafe { hbb_common::libc::geteuid() }, 0);
        assert!(require_supervisor().is_err());
        assert!(matches!(read_service_policy().await,
            ServiceIpcResponse::IncomingRecordingPolicy { enabled: None }));
        let (peer, _other) = std::os::unix::net::UnixStream::pair().unwrap();
        assert!(commit_policy(peer.into(), true).is_err());
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
