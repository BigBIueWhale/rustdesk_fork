// R-G4 / R-SV6(b) / §18 (dial nobody): ACCOUNT LOGIN is REMOVED. A sovereign, direct-IP fork has
// NO account server, so the inherited OIDC flow was dead egress AND a leak: `account_auth` spawned
// a task that POSTed { op, id, uuid, deviceInfo: get_login_device_info() } to
// <api-server>/api/oidc/auth (a device-fingerprint leak), then polled /api/oidc/auth-query for an
// access_token (storing it + the user profile to LocalConfig), having warmed /api/login-options.
// All of it — `auth`/`query`/`ensure_client`/`auth_task` + the querying state machine + the
// session fields that drove it — is deleted. `account_auth` is now a refuse-stub that sets a
// "not available" result WITHOUT any network call (it is not behind the empty-`api-server` pin,
// R-SV1 structural absence). The public API the FFI/ui_interface call (`OidcSession::account_auth`
// / `auth_cancel` / `get_result`) and the `AuthResult`/`AuthBody` serialization shape the flutter
// side parses are preserved so callers compile; removing the GUI account button/dialog is the
// §19/R-G4 follow-on.
use serde_derive::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};
use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

lazy_static::lazy_static! {
    static ref OIDC_SESSION: Arc<RwLock<OidcSession>> = Arc::new(RwLock::new(OidcSession::new()));
}

const ACCOUNT_AUTH_UNAVAILABLE: &str =
    "Account login is unavailable: this is a serverless, direct-IP fork (it dials nobody).";

#[derive(Debug, Deserialize, Serialize, Default, Clone)]
pub struct DeviceInfo {
    /// Linux , Windows , Android ...
    #[serde(default)]
    pub os: String,

    /// `browser` or `client`
    #[serde(default)]
    pub r#type: String,

    /// device name from rustdesk client,
    /// browser info(name + version) from browser
    #[serde(default)]
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WhitelistItem {
    data: String, // ip / device uuid
    info: DeviceInfo,
    exp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UserInfo {
    #[serde(default, flatten)]
    pub settings: UserSettings,
    #[serde(default)]
    pub login_device_whitelist: Vec<WhitelistItem>,
    #[serde(default)]
    pub other: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UserSettings {
    #[serde(default)]
    pub email_verification: bool,
    #[serde(default)]
    pub email_alarm_notification: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize_repr, Deserialize_repr)]
#[repr(i64)]
pub enum UserStatus {
    Disabled = 0,
    Normal = 1,
    Unverified = -1,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserPayload {
    pub name: String,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub avatar: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub note: Option<String>,
    #[serde(default)]
    pub status: UserStatus,
    pub info: UserInfo,
    #[serde(default)]
    pub is_admin: bool,
    #[serde(default)]
    pub third_auth_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthBody {
    pub access_token: String,
    pub r#type: String,
    #[serde(default)]
    pub tfa_type: String,
    #[serde(default)]
    pub secret: String,
    pub user: UserPayload,
}

pub struct OidcSession {
    state_msg: &'static str,
    failed_msg: String,
}

#[derive(Serialize)]
pub struct AuthResult {
    pub state_msg: String,
    pub failed_msg: String,
    pub url: Option<String>,
    pub auth_body: Option<AuthBody>,
}

impl Default for UserStatus {
    fn default() -> Self {
        UserStatus::Normal
    }
}

impl OidcSession {
    fn new() -> Self {
        Self {
            state_msg: "",
            failed_msg: String::new(),
        }
    }

    /// R-G4/R-SV6(b): refuse-stub. There is no account server to authenticate against (dial
    /// nobody), so this performs NO network call — it sets a terminal "unavailable" result that
    /// the GUI surfaces as an error instead of starting the excised OIDC egress task.
    pub fn account_auth(
        _api_server: String,
        _op: String,
        _id: String,
        _uuid: String,
        _remember_me: bool,
    ) {
        let mut g = OIDC_SESSION.write().unwrap();
        g.state_msg = "";
        g.failed_msg = ACCOUNT_AUTH_UNAVAILABLE.to_owned();
    }

    pub fn auth_cancel() {
        // Nothing to cancel — there is no auth task (the OIDC querying loop is excised).
    }

    pub fn get_result() -> AuthResult {
        let g = OIDC_SESSION.read().unwrap();
        AuthResult {
            state_msg: g.state_msg.to_string(),
            failed_msg: g.failed_msg.clone(),
            url: None,
            auth_body: None,
        }
    }
}
