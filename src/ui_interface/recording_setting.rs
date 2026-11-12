use crate::incoming_recording_status::{IncomingRecordingSetting, RecordingSettingChange, RecordingSettingOutcome};
use std::sync::atomic::{AtomicBool, Ordering};

static CHANGING: AtomicBool = AtomicBool::new(false);

struct ChangePermit;

impl ChangePermit {
    fn acquire() -> Option<Self> {
        CHANGING.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).ok().map(|_| Self)
    }
}

impl Drop for ChangePermit {
    fn drop(&mut self) {
        CHANGING.store(false, Ordering::Release);
    }
}

pub(crate) fn get() -> IncomingRecordingSetting {
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    let mut setting = {
        super::start_main_status_sync();
        *desktop::SETTING.lock().unwrap()
    };
    #[cfg(target_os = "android")]
    let mut setting = IncomingRecordingSetting {
        enabled: Some(hbb_common::config::Config::get_bool_option(
            hbb_common::config::keys::OPTION_ALLOW_AUTO_RECORD_INCOMING)), pending: false,
    };
    #[cfg(target_os = "ios")]
    let mut setting = IncomingRecordingSetting::default();
    setting.pending |= CHANGING.load(Ordering::Acquire);
    setting
}

pub(crate) fn set(enabled: bool) -> RecordingSettingChange {
    let Some(permit) = ChangePermit::acquire() else {
        return RecordingSettingChange::without_confirmation(RecordingSettingOutcome::Denied);
    };
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    { desktop::submit(enabled, permit) }
    #[cfg(target_os = "android")]
    {
        use hbb_common::{config::{Config, keys::OPTION_ALLOW_AUTO_RECORD_INCOMING}, log};
        let _permit = permit;
        match Config::set_option(OPTION_ALLOW_AUTO_RECORD_INCOMING.to_owned(), if enabled { "Y" } else { "" }.to_owned()) {
            Ok(()) => RecordingSettingChange { outcome: RecordingSettingOutcome::Applied,
                enabled: Some(Config::get_bool_option(OPTION_ALLOW_AUTO_RECORD_INCOMING)) },
            Err(err) => {
                log::warn!("Incoming recording change failed: {err}");
                RecordingSettingChange::without_confirmation(RecordingSettingOutcome::Failed)
            }
        }
    }
    #[cfg(target_os = "ios")]
    {
        let _ = (enabled, permit);
        RecordingSettingChange::without_confirmation(RecordingSettingOutcome::Denied)
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub(super) mod desktop {
    use super::*;
    use crate::ipc;
    use hbb_common::{config, log, tokio, ResultType};
    use std::{sync::{mpsc, Mutex, OnceLock}, time::Duration};

    pub(super) static SETTING: Mutex<IncomingRecordingSetting> = Mutex::new(IncomingRecordingSetting {
        enabled: None, pending: false,
    });
    static COMMANDS: OnceLock<tokio::sync::mpsc::Sender<Command>> = OnceLock::new();

    pub(crate) struct Command {
        enabled: bool,
        reply: mpsc::SyncSender<RecordingSettingChange>,
        _permit: ChangePermit,
    }

    pub(crate) fn channel() -> tokio::sync::mpsc::Receiver<Command> {
        let (sender, receiver) = tokio::sync::mpsc::channel(1);
        if COMMANDS.set(sender).is_err() {
            log::error!("Incoming recording command owner was initialized twice");
        }
        receiver
    }

    pub(super) fn submit(enabled: bool, permit: ChangePermit) -> RecordingSettingChange {
        super::super::start_main_status_sync();
        let Some(sender) = COMMANDS.get() else {
            return RecordingSettingChange::without_confirmation(RecordingSettingOutcome::Failed);
        };
        let (reply, receiver) = mpsc::sync_channel(1);
        if let Err(err) = sender.try_send(Command { enabled, reply, _permit: permit }) {
            log::warn!("Incoming recording command was not admitted: {err}");
            return RecordingSettingChange::without_confirmation(RecordingSettingOutcome::Failed);
        }
        // FRB executes this synchronous export on its worker pool. The existing
        // status runtime owns the admitted command even if this wait expires.
        receiver.recv_timeout(Duration::from_secs(155)).unwrap_or_else(|err| {
            log::warn!("Incoming recording command confirmation is unavailable: {err}");
            RecordingSettingChange::without_confirmation(RecordingSettingOutcome::Uncertain)
        })
    }

    async fn read() -> ResultType<IncomingRecordingSetting> {
        if crate::platform::is_installed() {
            #[cfg(target_os = "linux")]
            { return ipc::recording_policy::client_setting().await; }
            #[cfg(not(target_os = "linux"))]
            { return Ok(IncomingRecordingSetting::default()); }
        }
        let snapshot = ipc::get_main_status_snapshot(1000).await?;
        let options = snapshot.options.into_map()?;
        let key = config::keys::OPTION_ALLOW_AUTO_RECORD_INCOMING;
        Ok(IncomingRecordingSetting { enabled: options.get(key).map(|value| config::option2bool(key, value)), pending: false })
    }

    async fn change(enabled: bool) -> RecordingSettingChange {
        // Select ownership before testing whether the owner is available.
        if crate::platform::is_installed() {
            #[cfg(target_os = "linux")]
            { return ipc::recording_policy::client_change(enabled).await; }
            #[cfg(not(target_os = "linux"))]
            { return RecordingSettingChange::without_confirmation(RecordingSettingOutcome::Denied); }
        }
        ipc::set_user_incoming_recording(enabled).await
    }

    pub(crate) async fn run(mut receiver: tokio::sync::mpsc::Receiver<Command>) {
        loop {
            // Reads and changes share one owner: an older poll can never publish
            // after a newer acknowledgement. No config I/O holds the cache lock.
            let setting = match read().await {
                Ok(setting) => setting,
                Err(err) => {
                    log::trace!("Incoming recording setting unavailable: {err}");
                    IncomingRecordingSetting::default()
                }
            };
            *SETTING.lock().unwrap() = setting;
            tokio::select! {
                command = receiver.recv() => {
                    let Some(command) = command else { return; };
                    let result = change(command.enabled).await;
                    *SETTING.lock().unwrap() = IncomingRecordingSetting { enabled: result.enabled, pending: false };
                    if let Err(err) = command.reply.try_send(result) {
                        log::debug!("Incoming recording confirmation could not reach its UI waiter: {err}");
                    }
                    drop(command);
                }
                _ = tokio::time::sleep(Duration::from_secs(1)) => {}
            }
        }
    }
}
