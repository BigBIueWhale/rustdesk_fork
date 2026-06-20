use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

// R-SV6(b): the heartbeat/sysinfo POST loop is excised, so the inherited imports it used
// (Connection, get_builtin_option, Config/LocalConfig/keys/config, log, serde_json,
// tokio::time::Instant) and the TIME_HEARTBEAT/UPLOAD_SYSINFO_TIMEOUT/TIME_CONN timers
// are gone with it — only the local broadcast channel + StrategyOptions + is_pro remain.
use hbb_common::tokio::sync::broadcast;
use serde::{Deserialize, Serialize};

#[cfg(not(any(target_os = "ios")))]
lazy_static::lazy_static! {
    static ref SENDER : Mutex<broadcast::Sender<Vec<i32>>> = Mutex::new(start_hbbs_sync());
    static ref PRO: Arc<Mutex<bool>> = Default::default();
}

// R-SV6(b): the vestigial `start()` (it kicked the now-excised heartbeat loop alive via
// the SENDER lazy_static) is removed — it had no callers once start_all went (R-D4
// Stage 2). SENDER now lazy-initializes on the first `signal_receiver()` access.
#[cfg(not(target_os = "ios"))]
pub fn signal_receiver() -> broadcast::Receiver<Vec<i32>> {
    SENDER.lock().unwrap().subscribe()
}

#[cfg(not(any(target_os = "ios")))]
fn start_hbbs_sync() -> broadcast::Sender<Vec<i32>> {
    let (tx, _rx) = broadcast::channel::<Vec<i32>>(16);
    // R-SV3 / R-SV6(b) / §18 (sovereignty — universal): no api-server heartbeat /
    // sysinfo phone-home. The HBBS sync loop POSTed a heartbeat and uploaded host
    // system info (get_sysinfo(): hostname, username, version, uuid, preset address-book
    // fields) to `<api-server>/api/{heartbeat,sysinfo}` every few seconds, and adopted
    // server `strategy`/`disconnect`/`modified_at` from the reply (the R-X3
    // handle_config_options re-home twin fired from here). It is now REMOVED from the
    // tree (start_hbbs_sync_async + heartbeat_url + InfoUploaded + handle_config_options),
    // so `crate::post_request` is unreachable from the sync path — structurally, not via
    // the empty-api-server pin (R-SV1). Only the local broadcast channel survives, so the
    // `signal_receiver`/`is_pro` consumers (connection.rs, ipc.rs) still resolve.
    return tx;
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StrategyOptions {
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub config_options: HashMap<String, String>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub extra: HashMap<String, String>,
}

// R-SV6(b) / R-SV3 / §18: start_hbbs_sync_async (the heartbeat/sysinfo POST loop) is
// EXCISED — it POSTed crate::get_sysinfo() (hostname, username, version, uuid, preset
// address-book fields) to <api-server>/api/{heartbeat,sysinfo_ver,sysinfo} every few
// seconds and adopted server strategy/disconnect/modified_at from the reply. Removed
// from the tree (with heartbeat_url / InfoUploaded / handle_config_options) so
// crate::post_request is unreachable from the sync path — structurally, not via the
// empty-api-server pin (R-SV1). It was already never spawned (start_hbbs_sync), so this
// is behaviour-neutral; the local broadcast channel + is_pro/signal_receiver remain.

#[allow(unused)]
#[cfg(not(any(target_os = "ios")))]
pub fn is_pro() -> bool {
    PRO.lock().unwrap().clone()
}
