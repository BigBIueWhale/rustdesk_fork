use hbb_common::{bail, lazy_static, log, ResultType};
use std::sync::{
    mpsc::{self, Receiver, SyncSender, TrySendError},
    Arc, Mutex,
};
use winapi::{
    shared::{
        minwindef::{DWORD, FALSE, UINT, WPARAM},
        windef::POINT,
    },
    um::{processthreadsapi::GetCurrentThreadId, winuser::*},
};

const PRIVACY_ESCAPE_HOTKEY_ID: i32 = 0x5250;
const PRIVACY_ESCAPE_VK: UINT = b'P' as UINT;
const WM_USER_STOP_PRIVACY_ESCAPE: UINT = WM_USER + 1;

#[derive(Default)]
struct HotkeyWorkerResult {
    cleanup_error: Option<String>,
    unexpected_exit: Option<String>,
}

struct ActiveHotkey {
    thread_id: DWORD,
    worker: std::thread::JoinHandle<HotkeyWorkerResult>,
}

#[derive(Default)]
struct HotkeyRegistry {
    active: Option<ActiveHotkey>,
    poison: Option<String>,
}

struct PrivacyEscapeAuthority {
    conn_id: i32,
    cm_auth_token: String,
}

struct PrivacyOffDispatcher {
    sender: SyncSender<Arc<PrivacyEscapeAuthority>>,
    _worker: Mutex<Option<std::thread::JoinHandle<()>>>,
}

lazy_static::lazy_static! {
    static ref HOTKEY_REGISTRY: Mutex<HotkeyRegistry> = Mutex::new(HotkeyRegistry::default());

    static ref PRIVACY_OFF_DISPATCHER: Result<PrivacyOffDispatcher, String> = {
        let (sender, receiver) = mpsc::sync_channel::<Arc<PrivacyEscapeAuthority>>(1);
        std::thread::Builder::new()
            .name("rustdesk-privacy-hotkey-control".to_owned())
            .spawn(move || {
                while let Ok(authority) = receiver.recv() {
                    if let Some(Err(error)) = super::turn_off_privacy_for_owner(
                        authority.conn_id,
                        &authority.cm_auth_token,
                        Some(super::PrivacyModeState::OffByPeer),
                    ) {
                        log::error!("Failed to turn off privacy from the local escape hotkey: {error}");
                    }
                }
            })
            .map(|worker| PrivacyOffDispatcher {
                sender,
                _worker: Mutex::new(Some(worker)),
            })
            .map_err(|error| format!("failed to create privacy hotkey control worker: {error}"))
    };
}

fn privacy_off_sender() -> ResultType<SyncSender<Arc<PrivacyEscapeAuthority>>> {
    match &*PRIVACY_OFF_DISPATCHER {
        Ok(dispatcher) => Ok(dispatcher.sender.clone()),
        Err(error) => bail!(error.to_owned()),
    }
}

fn request_privacy_off(
    sender: &SyncSender<Arc<PrivacyEscapeAuthority>>,
    authority: &Arc<PrivacyEscapeAuthority>,
) {
    match sender.try_send(Arc::clone(authority)) {
        Ok(()) => {}
        Err(TrySendError::Full(_)) => {
            log::debug!("Privacy escape teardown is already requested");
        }
        Err(TrySendError::Disconnected(_)) => {
            log::error!("Privacy escape control worker stopped unexpectedly");
        }
    }
}

fn empty_message() -> MSG {
    MSG {
        hwnd: std::ptr::null_mut(),
        message: 0,
        wParam: 0,
        lParam: 0,
        time: 0,
        pt: POINT { x: 0, y: 0 },
    }
}

fn run_hotkey_worker(
    await_start: Receiver<()>,
    startup: mpsc::Sender<Result<DWORD, String>>,
    privacy_off: SyncSender<Arc<PrivacyEscapeAuthority>>,
    authority: Arc<PrivacyEscapeAuthority>,
) -> HotkeyWorkerResult {
    if await_start.recv().is_err() {
        return HotkeyWorkerResult::default();
    }

    let mut msg = empty_message();
    unsafe {
        // Create the queue before publishing the thread ID used by PostThreadMessage.
        PeekMessageA(
            &mut msg,
            std::ptr::null_mut(),
            WM_USER,
            WM_USER,
            PM_NOREMOVE,
        );
    }

    if unsafe {
        RegisterHotKey(
            std::ptr::null_mut(),
            PRIVACY_ESCAPE_HOTKEY_ID,
            (MOD_CONTROL | MOD_NOREPEAT) as UINT,
            PRIVACY_ESCAPE_VK,
        )
    } == FALSE
    {
        let error = format!(
            "failed to register the Ctrl+P privacy escape hotkey: {}",
            std::io::Error::last_os_error()
        );
        let _ = startup.send(Err(error));
        return HotkeyWorkerResult::default();
    }

    let thread_id = unsafe { GetCurrentThreadId() };
    if startup.send(Ok(thread_id)).is_err() {
        return HotkeyWorkerResult {
            cleanup_error: unregister_hotkey_native().err(),
            unexpected_exit: Some(
                "privacy escape owner retired before startup acknowledgement".to_owned(),
            ),
        };
    }

    let mut unexpected_exit = None;
    loop {
        let result = unsafe { GetMessageA(&mut msg, std::ptr::null_mut(), 0, 0) };
        if result == -1 {
            unexpected_exit = Some(format!(
                "privacy escape GetMessage failed: {}",
                std::io::Error::last_os_error()
            ));
            break;
        }
        if result == 0 {
            unexpected_exit = Some("privacy escape message loop received WM_QUIT".to_owned());
            break;
        }
        if msg.message == WM_USER_STOP_PRIVACY_ESCAPE {
            break;
        }
        if msg.message == WM_HOTKEY && msg.wParam == PRIVACY_ESCAPE_HOTKEY_ID as WPARAM {
            request_privacy_off(&privacy_off, &authority);
        }
    }

    let cleanup_error = unregister_hotkey_native().err();
    if unexpected_exit.is_some() {
        request_privacy_off(&privacy_off, &authority);
    }
    HotkeyWorkerResult {
        cleanup_error,
        unexpected_exit,
    }
}

fn unregister_hotkey_native() -> Result<(), String> {
    if unsafe { UnregisterHotKey(std::ptr::null_mut(), PRIVACY_ESCAPE_HOTKEY_ID) } == FALSE {
        return Err(format!(
            "failed to unregister the Ctrl+P privacy escape hotkey: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

pub fn register_escape_hotkey(owner: &super::PrivacyModeConnectionOwner) -> ResultType<()> {
    register_escape_hotkey_with_authority(Arc::new(PrivacyEscapeAuthority {
        conn_id: owner.conn_id(),
        cm_auth_token: owner.cm_auth_token().to_owned(),
    }))
}

fn register_escape_hotkey_with_authority(authority: Arc<PrivacyEscapeAuthority>) -> ResultType<()> {
    if authority.conn_id <= 0 || authority.cm_auth_token.is_empty() {
        bail!("privacy escape registration requires an exact connection owner");
    }
    let privacy_off = privacy_off_sender()?;
    let mut registry = HOTKEY_REGISTRY.lock().unwrap();
    if let Some(error) = registry.poison.as_ref() {
        bail!(error.to_owned());
    }
    if registry.active.is_some() {
        bail!("privacy escape hotkey is already registered");
    }

    let (start_worker, await_start) = mpsc::sync_channel(1);
    let (startup, startup_result) = mpsc::channel();
    let worker = std::thread::Builder::new()
        .name("rustdesk-privacy-hotkey".to_owned())
        .spawn(move || run_hotkey_worker(await_start, startup, privacy_off, authority))
        .map_err(|error| {
            hbb_common::anyhow::anyhow!("failed to create privacy escape worker: {error}")
        })?;

    if start_worker.try_send(()).is_err() {
        return join_failed_start(
            worker,
            "privacy escape worker rejected its owned start gate",
            &mut registry,
        );
    }

    match startup_result.recv() {
        Ok(Ok(thread_id)) => {
            if worker.is_finished() {
                return join_failed_start(
                    worker,
                    "privacy escape worker ended during startup",
                    &mut registry,
                );
            }
            registry.active = Some(ActiveHotkey { thread_id, worker });
            Ok(())
        }
        Ok(Err(error)) => join_failed_start(worker, &error, &mut registry),
        Err(error) => join_failed_start(
            worker,
            &format!("privacy escape worker closed its startup channel: {error}"),
            &mut registry,
        ),
    }
}

fn join_failed_start(
    worker: std::thread::JoinHandle<HotkeyWorkerResult>,
    reason: &str,
    registry: &mut HotkeyRegistry,
) -> ResultType<()> {
    match worker.join() {
        Ok(result) => {
            let detail = worker_result_detail(&result);
            if let Some(error) = result.cleanup_error {
                registry.poison = Some(format!("privacy escape startup cleanup failed: {error}"));
            }
            bail!("{reason}{detail}");
        }
        Err(_) => {
            registry.poison =
                Some("privacy escape worker panicked before registration finality".to_owned());
            bail!("{reason}; privacy escape worker panicked before exact join");
        }
    }
}

fn worker_result_detail(result: &HotkeyWorkerResult) -> String {
    let mut details = Vec::new();
    if let Some(error) = result.cleanup_error.as_ref() {
        details.push(format!("cleanup failed: {error}"));
    }
    if let Some(error) = result.unexpected_exit.as_ref() {
        details.push(error.to_owned());
    }
    if details.is_empty() {
        String::new()
    } else {
        format!("; {}", details.join("; "))
    }
}

pub fn unregister_escape_hotkey() -> ResultType<()> {
    let mut registry = HOTKEY_REGISTRY.lock().unwrap();
    if let Some(error) = registry.poison.as_ref() {
        bail!(error.to_owned());
    }
    let Some(active) = registry.active.as_ref() else {
        return Ok(());
    };

    if !active.worker.is_finished() {
        if unsafe { GetCurrentThreadId() } == active.thread_id {
            bail!("privacy escape hotkey cannot synchronously join its own worker");
        }
        if unsafe { PostThreadMessageA(active.thread_id, WM_USER_STOP_PRIVACY_ESCAPE, 0, 0) }
            == FALSE
        {
            let error = std::io::Error::last_os_error();
            if !active.worker.is_finished() {
                bail!("failed to request privacy escape worker teardown: {error}");
            }
        }
    }

    let Some(active) = registry.active.take() else {
        bail!("privacy escape owner disappeared before exact join");
    };
    match active.worker.join() {
        Ok(result) => {
            if let Some(error) = result.unexpected_exit.as_ref() {
                log::error!("Privacy escape worker ended unexpectedly: {error}");
            }
            if let Some(error) = result.cleanup_error {
                registry.poison = Some(format!(
                    "privacy escape hotkey cleanup is uncertain: {error}"
                ));
                bail!(error);
            }
            Ok(())
        }
        Err(_) => {
            let error = "privacy escape worker panicked before exact join".to_owned();
            registry.poison = Some(error.clone());
            bail!(error);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        register_escape_hotkey_with_authority, unregister_escape_hotkey, PrivacyEscapeAuthority,
        PRIVACY_ESCAPE_VK,
    };
    use std::sync::Arc;
    use winapi::{
        shared::minwindef::{FALSE, UINT},
        um::winuser::{RegisterHotKey, UnregisterHotKey, MOD_CONTROL, MOD_NOREPEAT},
    };

    const PROBE_HOTKEY_ID: i32 = 0x5251;

    fn assert_escape_chord_available() {
        let registered = unsafe {
            RegisterHotKey(
                std::ptr::null_mut(),
                PROBE_HOTKEY_ID,
                (MOD_CONTROL | MOD_NOREPEAT) as UINT,
                PRIVACY_ESCAPE_VK,
            )
        };
        assert_ne!(
            registered, FALSE,
            "Ctrl+P must be available before the production registration"
        );
        assert_ne!(
            unsafe { UnregisterHotKey(std::ptr::null_mut(), PROBE_HOTKEY_ID) },
            FALSE,
            "the native availability probe must clean up its exact registration"
        );
    }

    fn assert_escape_chord_reserved() {
        let registered = unsafe {
            RegisterHotKey(
                std::ptr::null_mut(),
                PROBE_HOTKEY_ID,
                (MOD_CONTROL | MOD_NOREPEAT) as UINT,
                PRIVACY_ESCAPE_VK,
            )
        };
        if registered != FALSE {
            let _ = unsafe { UnregisterHotKey(std::ptr::null_mut(), PROBE_HOTKEY_ID) };
            panic!("production registration did not reserve Ctrl+P in the native hotkey table");
        }
    }

    #[test]
    fn windows_privacy_escape_hotkey_reuses_only_after_joined_teardown() {
        let authority = || {
            Arc::new(PrivacyEscapeAuthority {
                conn_id: 91,
                cm_auth_token: "privacy-hotkey-test-token".to_owned(),
            })
        };
        assert_escape_chord_available();
        register_escape_hotkey_with_authority(authority()).unwrap();
        assert_escape_chord_reserved();
        assert!(register_escape_hotkey_with_authority(authority()).is_err());
        unregister_escape_hotkey().unwrap();
        assert_escape_chord_available();

        register_escape_hotkey_with_authority(authority()).unwrap();
        assert_escape_chord_reserved();
        unregister_escape_hotkey().unwrap();
        assert_escape_chord_available();
    }
}
