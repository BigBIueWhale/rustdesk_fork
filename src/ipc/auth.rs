use crate::ipc::{Connection, ConnectionTmpl};
#[cfg(target_os = "macos")]
use core_foundation::{base::TCFType, data::CFData, url::CFURL};
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
use hbb_common::{anyhow, bail, log, ResultType};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use hbb_common::{
    libc,
    tokio::io::{AsyncRead, AsyncWrite},
};
#[cfg(target_os = "macos")]
use security_framework::os::macos::code_signing::{
    Flags as MacosCodeSigningFlags, GuestAttributes as MacosGuestAttributes,
    SecCode as MacosSecCode, SecRequirement as MacosSecRequirement,
    SecStaticCode as MacosSecStaticCode,
};
#[cfg(target_os = "linux")]
use serde_derive::{Deserialize, Serialize};
#[cfg(target_os = "macos")]
use std::ffi::{c_void, CString};
#[cfg(target_os = "linux")]
use std::fmt;
#[cfg(target_os = "macos")]
use std::os::unix::ffi::OsStrExt;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::os::unix::fs::MetadataExt;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::os::unix::fs::PermissionsExt;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::os::unix::io::RawFd;
#[cfg(windows)]
use std::os::windows::io::AsRawHandle;
#[cfg(windows)]
use std::{collections::BTreeSet, ffi::c_void};
#[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
use std::{
    fs,
    path::{Path, PathBuf},
    sync::{Mutex, OnceLock},
};
#[cfg(windows)]
use windows::{
    core::PWSTR,
    Win32::{
        Foundation::{CloseHandle, LocalFree, HANDLE, HLOCAL},
        Security::{
            Authorization::ConvertSidToStringSidW, GetTokenInformation, RevertToSelf,
            TokenElevation, TokenGroups, TokenUser, PSID, TOKEN_ELEVATION, TOKEN_GROUPS,
            TOKEN_INFORMATION_CLASS, TOKEN_QUERY, TOKEN_USER,
        },
        System::{
            Pipes::{
                GetNamedPipeClientProcessId, GetNamedPipeServerProcessId,
                ImpersonateNamedPipeClient,
            },
            Threading::{GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken},
        },
    },
};

#[cfg(windows)]
const WINDOWS_URL_IPC_POSTFIX: &str = "_url";

#[cfg(windows)]
#[inline]
pub(crate) fn windows_privileged_ipc_uses_restricted_dacl(postfix: &str) -> bool {
    postfix.is_empty()
        || hbb_common::config::is_service_ipc_postfix(postfix)
        || postfix == WINDOWS_URL_IPC_POSTFIX
}

#[cfg(windows)]
pub(crate) const WINDOWS_NAMED_PIPE_CLIENT_ACCESS_MASK: u32 = 0x0012_019b;
#[cfg(windows)]
const SE_GROUP_LOGON_ID: u32 = 0xc000_0000;
#[cfg(windows)]
const LOCAL_SYSTEM_SID: &str = "S-1-5-18";

#[cfg(target_os = "macos")]
const MACOS_PRIVILEGED_HELPER_EXEC: &str =
    "/Library/PrivilegedHelperTools/com.carriez.rustdesk_service";
#[cfg(target_os = "macos")]
const MACOS_PRIVILEGED_HELPER_DIR: &str = "/Library/PrivilegedHelperTools";
#[cfg(target_os = "macos")]
const MACOS_PRIVILEGED_HELPER_REQUIREMENT: &str = r#"=anchor apple generic and certificate leaf[subject.OU] = "HZF9JMC8YN" and (identifier "service" or identifier "com.carriez.rustdesk_service")"#;
#[cfg(target_os = "macos")]
const MACOS_INSTALLED_APP_REQUIREMENT: &str = r#"=anchor apple generic and certificate leaf[subject.OU] = "HZF9JMC8YN" and identifier "com.carriez.rustdesk""#;
#[cfg(target_os = "macos")]
const MACOS_AUDIT_TOKEN_BYTES: usize = 32;
#[cfg(target_os = "macos")]
type MacosAcl = *mut c_void;
#[cfg(target_os = "macos")]
type MacosAclEntry = *mut c_void;
#[cfg(target_os = "macos")]
const MACOS_ACL_TYPE_EXTENDED: libc::c_int = 0x0000_0100;
#[cfg(target_os = "macos")]
const MACOS_ACL_FIRST_ENTRY: libc::c_int = 0;

#[cfg(target_os = "macos")]
extern "C" {
    fn acl_get_link_np(path_p: *const libc::c_char, acl_type: libc::c_int) -> MacosAcl;
    fn acl_get_entry(
        acl: MacosAcl,
        entry_id: libc::c_int,
        entry_p: *mut MacosAclEntry,
    ) -> libc::c_int;
    fn acl_valid(acl: MacosAcl) -> libc::c_int;
    fn acl_free(obj_p: *mut c_void) -> libc::c_int;
}

#[cfg(windows)]
struct WindowsIpcDaclSids {
    server_sids: Vec<String>,
    client_sids: Vec<String>,
}

#[cfg(target_os = "macos")]
struct MacosAclGuard(MacosAcl);

#[cfg(target_os = "macos")]
#[derive(Clone)]
pub(crate) struct MacosPeerProcessIdentity {
    uid: u32,
    pid: u32,
    audit_token: [u8; MACOS_AUDIT_TOKEN_BYTES],
}

#[cfg(target_os = "macos")]
impl MacosPeerProcessIdentity {
    #[inline]
    pub(crate) fn uid(&self) -> u32 {
        self.uid
    }

    #[inline]
    pub(crate) fn pid(&self) -> u32 {
        self.pid
    }
}

#[cfg(target_os = "macos")]
impl Drop for MacosAclGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = acl_free(self.0);
        }
    }
}

#[cfg(windows)]
struct WindowsHandle(HANDLE);

#[cfg(windows)]
impl Drop for WindowsHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

#[cfg(windows)]
struct LocalString(PWSTR);

#[cfg(windows)]
impl Drop for LocalString {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                let _ = LocalFree(Some(HLOCAL(self.0.as_ptr() as *mut c_void)));
            }
        }
    }
}

#[cfg(windows)]
struct ThreadImpersonationGuard {
    active: bool,
}

#[cfg(windows)]
#[derive(Clone, Copy)]
enum WindowsPipeClientTokenRequirement {
    Elevated,
    LocalSystem,
}

#[cfg(windows)]
impl WindowsPipeClientTokenRequirement {
    fn context(self) -> &'static str {
        match self {
            Self::Elevated => "Windows service-owned request caller",
            Self::LocalSystem => "Windows service-owned main IPC peer",
        }
    }

    fn is_satisfied(self, token: HANDLE) -> ResultType<bool> {
        match self {
            Self::Elevated => token_is_elevated(token),
            Self::LocalSystem => Ok(token_user_sid_string(token)? == LOCAL_SYSTEM_SID),
        }
    }
}

#[cfg(windows)]
impl ThreadImpersonationGuard {
    fn new() -> Self {
        Self { active: true }
    }

    fn restore(mut self) {
        revert_thread_impersonation_or_abort();
        self.active = false;
    }
}

#[cfg(windows)]
fn revert_thread_impersonation_or_abort() {
    unsafe {
        if RevertToSelf().is_err() {
            std::process::abort();
        }
    }
}

#[cfg(windows)]
impl Drop for ThreadImpersonationGuard {
    fn drop(&mut self) {
        if self.active {
            revert_thread_impersonation_or_abort();
        }
    }
}

#[cfg(windows)]
#[inline]
pub(crate) fn windows_named_pipe_client_access_mask() -> u32 {
    WINDOWS_NAMED_PIPE_CLIENT_ACCESS_MASK
}

#[cfg(windows)]
pub(crate) fn windows_ipc_listener_security_attributes(
    postfix: &str,
) -> ResultType<parity_tokio_ipc::SecurityAttributes> {
    if !windows_privileged_ipc_uses_restricted_dacl(postfix) {
        return Ok(parity_tokio_ipc::SecurityAttributes::empty());
    }
    let sids = windows_ipc_dacl_sids_for_postfix(postfix)?;
    let sddl = windows_restricted_ipc_sddl(&sids);
    parity_tokio_ipc::SecurityAttributes::from_sddl(&sddl).map_err(|err| {
        anyhow::anyhow!(
            "Failed to build Windows IPC security descriptor for '{}': {}",
            postfix,
            err
        )
        .into()
    })
}

#[cfg(windows)]
fn windows_ipc_dacl_sids_for_postfix(postfix: &str) -> ResultType<WindowsIpcDaclSids> {
    let mut server_sids = BTreeSet::new();
    let mut client_sids = BTreeSet::new();

    let current_token = current_process_token()?;
    if let Some(current_sid) = preferred_token_boundary_sid(current_token.0)? {
        if current_sid != LOCAL_SYSTEM_SID {
            server_sids.insert(current_sid);
        }
    }

    let session_id =
        crate::platform::windows::get_current_session_id(crate::platform::windows::is_share_rdp());
    if session_id != u32::MAX {
        match active_session_user_token(session_id) {
            Ok(token) => {
                if let Some(active_sid) = preferred_token_boundary_sid(token.0)? {
                    if active_sid != LOCAL_SYSTEM_SID {
                        client_sids.insert(active_sid);
                    }
                }
            }
            Err(err) => log::warn!(
                "Active-session IPC DACL sid unavailable for postfix '{}', session_id={}: {}",
                postfix,
                session_id,
                err
            ),
        }
    }

    for sid in &server_sids {
        client_sids.remove(sid);
    }
    Ok(WindowsIpcDaclSids {
        server_sids: server_sids.into_iter().collect(),
        client_sids: client_sids.into_iter().collect(),
    })
}

#[cfg(windows)]
fn current_process_token() -> ResultType<WindowsHandle> {
    let mut token = HANDLE::default();
    unsafe {
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)
            .map_err(|err| anyhow::anyhow!("OpenProcessToken(current) failed: {}", err))?;
    }
    Ok(WindowsHandle(token))
}

#[cfg(windows)]
fn active_session_user_token(session_id: u32) -> ResultType<WindowsHandle> {
    let token = crate::platform::windows::get_user_token(session_id, true);
    if token.is_null() {
        bail!("GetSessionUserTokenWin returned null");
    }
    Ok(WindowsHandle(HANDLE(token as *mut c_void)))
}

#[cfg(windows)]
fn preferred_token_boundary_sid(token: HANDLE) -> ResultType<Option<String>> {
    Ok(token_logon_sid_string(token)?.or(Some(token_user_sid_string(token)?)))
}

#[cfg(windows)]
fn token_information_buffer(
    token: HANDLE,
    token_information_class: TOKEN_INFORMATION_CLASS,
) -> ResultType<Vec<u8>> {
    let mut len = 0u32;
    let _ = unsafe { GetTokenInformation(token, token_information_class, None, 0, &mut len) };
    if len == 0 {
        bail!(
            "GetTokenInformation({:?}) did not return a buffer size: {}",
            token_information_class,
            std::io::Error::last_os_error()
        );
    }
    let mut buffer = vec![0u8; len as usize];
    unsafe {
        GetTokenInformation(
            token,
            token_information_class,
            Some(buffer.as_mut_ptr() as *mut c_void),
            len,
            &mut len,
        )
        .map_err(|err| {
            anyhow::anyhow!(
                "GetTokenInformation({:?}) failed: {}",
                token_information_class,
                err
            )
        })?;
    }
    Ok(buffer)
}

#[cfg(windows)]
fn token_user_sid_string(token: HANDLE) -> ResultType<String> {
    let buffer = token_information_buffer(token, TokenUser)?;
    let token_user = unsafe { &*(buffer.as_ptr() as *const TOKEN_USER) };
    sid_to_string(token_user.User.Sid)
}

#[cfg(windows)]
fn token_is_elevated(token: HANDLE) -> ResultType<bool> {
    let buffer = token_information_buffer(token, TokenElevation)?;
    if buffer.len() < std::mem::size_of::<TOKEN_ELEVATION>() {
        bail!(
            "GetTokenInformation(TokenElevation) returned a short buffer: {}",
            buffer.len()
        );
    }
    let elevation = unsafe { &*(buffer.as_ptr() as *const TOKEN_ELEVATION) };
    Ok(elevation.TokenIsElevated != 0)
}

#[cfg(windows)]
fn token_logon_sid_string(token: HANDLE) -> ResultType<Option<String>> {
    let buffer = token_information_buffer(token, TokenGroups)?;
    let token_groups = unsafe { &*(buffer.as_ptr() as *const TOKEN_GROUPS) };
    let groups = token_groups.Groups.as_ptr();
    for index in 0..token_groups.GroupCount as usize {
        let group = unsafe { *groups.add(index) };
        if (group.Attributes & SE_GROUP_LOGON_ID) == SE_GROUP_LOGON_ID {
            return sid_to_string(group.Sid).map(Some);
        }
    }
    Ok(None)
}

#[cfg(windows)]
fn sid_to_string(sid: PSID) -> ResultType<String> {
    if sid.is_invalid() {
        bail!("SID pointer is null");
    }
    let mut sid_string = PWSTR::null();
    unsafe {
        ConvertSidToStringSidW(sid, &mut sid_string)
            .map_err(|err| anyhow::anyhow!("ConvertSidToStringSidW failed: {}", err))?;
    }
    if sid_string.is_null() {
        bail!("ConvertSidToStringSidW returned null");
    }
    let _sid_guard = LocalString(sid_string);
    let sid = unsafe { sid_string.to_string() }
        .map_err(|err| anyhow::anyhow!("Converted SID was not valid UTF-16: {}", err))?;
    if !is_numeric_sid_string(&sid) {
        bail!("Converted SID has unexpected SDDL form: {}", sid);
    }
    Ok(sid)
}

#[cfg(windows)]
fn is_numeric_sid_string(sid: &str) -> bool {
    sid.strip_prefix("S-")
        .is_some_and(|rest| rest.bytes().all(|b| b.is_ascii_digit() || b == b'-'))
}

#[cfg(windows)]
fn windows_restricted_ipc_sddl(sids: &WindowsIpcDaclSids) -> String {
    let mut sddl = String::from("D:P(A;;GA;;;SY)");
    for sid in &sids.server_sids {
        sddl.push_str(&format!("(A;;GA;;;{})", sid));
    }
    for sid in &sids.client_sids {
        sddl.push_str(&format!(
            "(A;;0x{:08x};;;{})",
            WINDOWS_NAMED_PIPE_CLIENT_ACCESS_MASK, sid
        ));
    }
    sddl
}

#[cfg(windows)]
pub(crate) fn ensure_windows_ipc_server_matches_current(
    client: &parity_tokio_ipc::ConnectionClient,
    postfix: &str,
) -> ResultType<()> {
    let server_pid = windows_named_pipe_server_pid(client)?;
    ensure_peer_executable_matches_current_by_pid_opt(Some(server_pid), postfix)?;
    if postfix.is_empty() && !peer_process_is_current_exe_server(server_pid) {
        bail!("Windows main IPC server is not the current executable's --server process");
    }
    if hbb_common::config::is_service_ipc_postfix(postfix) {
        let is_system = crate::platform::windows::is_process_running_as_system(server_pid)
            .map_err(|err| {
                anyhow::anyhow!("Failed to determine _service server identity: {}", err)
            })?;
        if !is_system {
            bail!("Windows _service IPC server is not running as LocalSystem");
        }
    }
    Ok(())
}

#[cfg(target_os = "windows")]
pub(crate) fn authenticate_windows_service_owned_main_server(
    stream: &ConnectionTmpl<parity_tokio_ipc::ConnectionClient>,
) -> ResultType<u32> {
    let server_pid = windows_named_pipe_server_pid(stream.inner.get_ref())?;
    ensure_peer_executable_matches_fixed_windows_service_exe_by_pid(server_pid, "")?;
    let is_system =
        crate::platform::windows::is_process_running_as_system(server_pid).map_err(|err| {
            anyhow::anyhow!(
                "Failed to determine Windows service-owned main IPC server identity: {}",
                err
            )
        })?;
    if !is_system {
        bail!("Windows service-owned main IPC server is not running as LocalSystem");
    }
    if !peer_process_has_windows_service_owned_server_args(server_pid) {
        bail!("Windows service-owned main IPC server is not the exact --server --service-owned-server process");
    }
    Ok(server_pid)
}

#[cfg(windows)]
fn windows_named_pipe_server_pid(client: &parity_tokio_ipc::ConnectionClient) -> ResultType<u32> {
    let pipe_handle = client.as_raw_handle();
    if pipe_handle.is_null() {
        bail!("Windows IPC client handle is null");
    }
    let mut server_pid = 0u32;
    unsafe {
        GetNamedPipeServerProcessId(HANDLE(pipe_handle), &mut server_pid)
            .map_err(|err| anyhow::anyhow!("GetNamedPipeServerProcessId failed: {}", err))?;
    }
    if server_pid == 0 {
        bail!("GetNamedPipeServerProcessId returned pid 0");
    }
    Ok(server_pid)
}

#[cfg(target_os = "macos")]
#[inline]
fn macos_installed_app_executable_path() -> PathBuf {
    let app_name = crate::get_app_name();
    PathBuf::from(format!(
        "/Applications/{app_name}.app/Contents/MacOS/{app_name}"
    ))
}

#[cfg(target_os = "macos")]
#[inline]
fn macos_installed_app_bundle_path() -> PathBuf {
    PathBuf::from(format!("/Applications/{}.app", crate::get_app_name()))
}

#[cfg(target_os = "macos")]
#[inline]
fn macos_executable_matches_expected_path(actual: &Path, expected: &Path) -> bool {
    actual == expected || paths_refer_to_same_file(actual, expected)
}

#[cfg(target_os = "macos")]
#[inline]
fn macos_root_wheel_not_group_world_writable(metadata: &fs::Metadata) -> bool {
    metadata.uid() == 0 && metadata.gid() == 0 && metadata.permissions().mode() & 0o022 == 0
}

#[cfg(target_os = "macos")]
#[inline]
fn macos_root_owned_not_group_world_writable(metadata: &fs::Metadata) -> bool {
    metadata.uid() == 0 && metadata.permissions().mode() & 0o022 == 0
}

#[cfg(target_os = "macos")]
pub(crate) fn macos_path_has_no_extended_acl(path: &Path) -> bool {
    let path_c = match CString::new(path.as_os_str().as_bytes().to_vec()) {
        Ok(path_c) => path_c,
        Err(err) => {
            log::error!(
                "Rejected macOS ACL inspection for path containing NUL '{}': {}",
                path.display(),
                err
            );
            return false;
        }
    };
    let acl = unsafe { acl_get_link_np(path_c.as_ptr(), MACOS_ACL_TYPE_EXTENDED) };
    if acl.is_null() {
        log::error!(
            "Failed to retrieve macOS extended ACL for '{}': {}",
            path.display(),
            std::io::Error::last_os_error()
        );
        return false;
    }
    let _acl_guard = MacosAclGuard(acl);
    if unsafe { acl_valid(acl) } != 0 {
        log::error!(
            "Rejected invalid macOS extended ACL for '{}': {}",
            path.display(),
            std::io::Error::last_os_error()
        );
        return false;
    }
    let mut entry: MacosAclEntry = std::ptr::null_mut();
    (unsafe { acl_get_entry(acl, MACOS_ACL_FIRST_ENTRY, &mut entry) }) != 0
}

#[cfg(target_os = "macos")]
fn macos_path_has_expected_type_and_permissions(
    path: &Path,
    is_dir: bool,
    require_executable: bool,
    require_wheel: bool,
) -> bool {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return false;
    };
    if metadata.file_type().is_symlink() {
        return false;
    }
    if is_dir {
        if !metadata.is_dir() {
            return false;
        }
    } else if !metadata.is_file() {
        return false;
    }
    if require_wheel {
        if !macos_root_wheel_not_group_world_writable(&metadata) {
            return false;
        }
    } else if !macos_root_owned_not_group_world_writable(&metadata) {
        return false;
    }
    if require_executable && metadata.permissions().mode() & 0o111 == 0 {
        return false;
    }
    macos_path_has_no_extended_acl(path)
}

#[cfg(target_os = "macos")]
fn macos_code_requirement(requirement: &str, description: &str) -> ResultType<MacosSecRequirement> {
    let requirement = requirement.strip_prefix('=').unwrap_or(requirement);
    requirement.parse::<MacosSecRequirement>().map_err(|err| {
        anyhow::anyhow!("Failed to parse macOS {description} code requirement: {err:?}").into()
    })
}

#[cfg(target_os = "macos")]
fn macos_static_code_satisfies_requirement(
    path: &Path,
    is_dir: bool,
    requirement: &str,
    description: &str,
) -> bool {
    let Some(url) = CFURL::from_path(path, is_dir) else {
        log::error!(
            "Failed to build macOS {description} code-signing URL for '{}'",
            path.display()
        );
        return false;
    };
    let requirement = match macos_code_requirement(requirement, description) {
        Ok(requirement) => requirement,
        Err(err) => {
            log::error!("{err}");
            return false;
        }
    };
    let code = match MacosSecStaticCode::from_path(&url, MacosCodeSigningFlags::NONE) {
        Ok(code) => code,
        Err(err) => {
            log::error!(
                "Failed to resolve macOS {description} static code '{}': {err:?}",
                path.display()
            );
            return false;
        }
    };
    match code.check_validity(MacosCodeSigningFlags::STRICT_VALIDATE, &requirement) {
        Ok(()) => true,
        Err(err) => {
            log::error!("macOS {description} static code-signing check failed: {err:?}");
            false
        }
    }
}

#[cfg(target_os = "macos")]
fn macos_peer_code(
    identity: &MacosPeerProcessIdentity,
    description: &str,
) -> ResultType<MacosSecCode> {
    let audit_token = CFData::from_buffer(&identity.audit_token);
    let mut attributes = MacosGuestAttributes::new();
    attributes.set_audit_token(audit_token.as_concrete_TypeRef());
    MacosSecCode::copy_guest_with_attribues(None, &attributes, MacosCodeSigningFlags::NONE)
        .map_err(|err| {
            anyhow::anyhow!(
                "Failed to resolve macOS {description} peer code from audit token: pid={}, uid={}, err={err:?}",
                identity.pid,
                identity.uid
            )
            .into()
        })
}

#[cfg(target_os = "macos")]
fn macos_peer_code_path(code: &MacosSecCode, description: &str) -> ResultType<PathBuf> {
    let url = code.path(MacosCodeSigningFlags::NONE).map_err(|err| {
        anyhow::anyhow!("Failed to resolve macOS {description} peer code path: {err:?}")
    })?;
    let path = url.to_path().ok_or_else(|| {
        anyhow::anyhow!("macOS {description} peer code path is not a filesystem path")
    })?;
    fs::canonicalize(&path).map_err(|err| {
        anyhow::anyhow!(
            "Failed to canonicalize macOS {description} peer code path '{}': {}",
            path.display(),
            err
        )
        .into()
    })
}

#[cfg(target_os = "macos")]
fn macos_peer_code_satisfies_requirement(
    code: &MacosSecCode,
    requirement: &str,
    description: &str,
) -> bool {
    let requirement = match macos_code_requirement(requirement, description) {
        Ok(requirement) => requirement,
        Err(err) => {
            log::error!("{err}");
            return false;
        }
    };
    match code.check_validity(MacosCodeSigningFlags::STRICT_VALIDATE, &requirement) {
        Ok(()) => true,
        Err(err) => {
            log::error!("macOS {description} peer code-signing check failed: {err:?}");
            false
        }
    }
}

#[cfg(target_os = "macos")]
#[inline]
fn macos_privileged_helper_satisfies_code_requirement(path: &Path) -> bool {
    macos_static_code_satisfies_requirement(
        path,
        false,
        MACOS_PRIVILEGED_HELPER_REQUIREMENT,
        "privileged helper",
    )
}

#[cfg(target_os = "macos")]
#[inline]
fn macos_installed_app_satisfies_code_requirement(path: &Path) -> bool {
    macos_static_code_satisfies_requirement(
        path,
        true,
        MACOS_INSTALLED_APP_REQUIREMENT,
        "installed app",
    )
}

#[cfg(target_os = "macos")]
#[inline]
fn macos_privileged_helper_path_is_expected_and_trusted(current_exe: &Path) -> bool {
    let expected = Path::new(MACOS_PRIVILEGED_HELPER_EXEC);
    if !macos_executable_matches_expected_path(current_exe, expected) {
        return false;
    }
    if !macos_path_has_expected_type_and_permissions(
        Path::new(MACOS_PRIVILEGED_HELPER_DIR),
        true,
        false,
        true,
    ) {
        return false;
    }
    if !macos_path_has_expected_type_and_permissions(expected, false, true, true) {
        return false;
    };
    macos_privileged_helper_satisfies_code_requirement(expected)
}

#[cfg(target_os = "macos")]
#[inline]
fn macos_installed_app_path_is_expected_and_trusted(peer_exe: &Path) -> bool {
    let app_bundle = macos_installed_app_bundle_path();
    let app_contents = app_bundle.join("Contents");
    let app_macos = app_contents.join("MacOS");
    let app_executable = macos_installed_app_executable_path();
    if !macos_executable_matches_expected_path(peer_exe, &app_executable) {
        return false;
    }
    for app_dir in [&app_bundle, &app_contents, &app_macos] {
        if !macos_path_has_expected_type_and_permissions(app_dir, true, false, false) {
            return false;
        }
    }
    if !macos_path_has_expected_type_and_permissions(&app_executable, false, true, false) {
        return false;
    }
    macos_installed_app_satisfies_code_requirement(&app_bundle)
}

#[cfg(target_os = "macos")]
fn macos_peer_code_path_satisfies(
    identity: &MacosPeerProcessIdentity,
    requirement: &str,
    description: &str,
    path_is_trusted: impl FnOnce(&Path) -> bool,
) -> bool {
    let code = match macos_peer_code(identity, description) {
        Ok(code) => code,
        Err(err) => {
            log::error!("{err}");
            return false;
        }
    };
    if !macos_peer_code_satisfies_requirement(&code, requirement, description) {
        return false;
    }
    let path = match macos_peer_code_path(&code, description) {
        Ok(path) => path,
        Err(err) => {
            log::error!("{err}");
            return false;
        }
    };
    path_is_trusted(&path)
}

#[cfg(target_os = "macos")]
pub(crate) fn macos_peer_is_trusted_installed_app(identity: &MacosPeerProcessIdentity) -> bool {
    macos_peer_code_path_satisfies(
        identity,
        MACOS_INSTALLED_APP_REQUIREMENT,
        "installed app",
        macos_installed_app_path_is_expected_and_trusted,
    )
}

#[cfg(target_os = "macos")]
fn macos_peer_is_trusted_privileged_helper(identity: &MacosPeerProcessIdentity) -> bool {
    macos_peer_code_path_satisfies(
        identity,
        MACOS_PRIVILEGED_HELPER_REQUIREMENT,
        "privileged helper",
        macos_privileged_helper_path_is_expected_and_trusted,
    )
}

#[cfg(target_os = "macos")]
#[inline]
fn macos_service_ipc_allows_installed_app_and_privileged_helper(
    peer_identity: &MacosPeerProcessIdentity,
    current_exe: &Path,
    postfix: &str,
) -> bool {
    postfix == crate::POSTFIX_SERVICE
        && macos_peer_is_trusted_installed_app(peer_identity)
        && macos_privileged_helper_path_is_expected_and_trusted(current_exe)
}

#[cfg(target_os = "macos")]
pub(crate) fn ensure_macos_service_server_is_trusted<T>(
    stream: &ConnectionTmpl<T>,
) -> ResultType<()>
where
    T: AsyncRead + AsyncWrite + std::marker::Unpin + std::os::unix::io::AsRawFd,
{
    let identity = stream.macos_peer_process_identity("macOS _service server")?;
    if identity.uid != 0 {
        bail!(
            "macOS _service server is not root: peer_uid={}",
            identity.uid
        );
    }
    if !macos_peer_is_trusted_privileged_helper(&identity) {
        bail!(
            "macOS _service server is not the trusted privileged helper: peer_pid={}",
            identity.pid
        );
    }
    Ok(())
}

#[cfg(windows)]
#[inline]
pub(crate) fn is_allowed_windows_session_scoped_peer(
    client_is_system: bool,
    client_session_id: Option<u32>,
    expected_session_id: Option<u32>,
) -> bool {
    client_is_system
        || matches!(
            (client_session_id, expected_session_id),
            (Some(client), Some(expected)) if client == expected
        )
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[inline]
pub(crate) fn is_allowed_service_peer_uid(peer_uid: u32, active_uid: Option<u32>) -> bool {
    // Root is allowed at the UID gate because the service side may run as root.
    // Callers still enforce executable matching before accepting service-scoped peers.
    peer_uid == 0 || active_uid.is_some_and(|uid| uid == peer_uid)
}

#[cfg(target_os = "macos")]
#[inline]
fn console_owner_uid() -> Option<u32> {
    fs::metadata("/dev/console")
        .ok()
        .map(|metadata| metadata.uid())
}

#[cfg(target_os = "macos")]
#[inline]
fn active_uid_strict() -> Option<u32> {
    // Prefer the filesystem metadata over parsing external command output.
    console_owner_uid()
}

#[cfg(target_os = "linux")]
#[inline]
fn active_uid_strict() -> Option<u32> {
    let reported_uid_raw = crate::platform::linux::get_active_userid();
    let trimmed = reported_uid_raw.trim();
    if let Ok(uid) = trimmed.parse::<u32>() {
        return Some(uid);
    }
    if trimmed.is_empty() {
        log::debug!("Failed to resolve active user uid on linux: active uid is empty");
    } else {
        log::warn!("Failed to parse active user uid on linux: '{}'", trimmed);
    }
    None
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[inline]
pub(crate) fn active_uid() -> Option<u32> {
    active_uid_strict()
}

// R-S11a(a): a FRESH active-user lookup for AUTHORIZATION — bypassing the service-loop cache — so
// a just-switched-out user cannot pass the `_service` UID gate during the cache-lag window. This
// matches the fresh lookup the `_uinput_*` authorizer already does. The cached `active_uid()` is
// kept ONLY for stable config-sync ROUTING (ipc.rs `select_server_uid_for_user_main_ipc`, fs.rs) —
// which is not authorization. On macOS `/dev/console` ownership is already a live fs lookup.
#[cfg(target_os = "macos")]
#[inline]
fn active_uid_fresh() -> Option<u32> {
    console_owner_uid()
}

#[cfg(target_os = "linux")]
#[inline]
fn active_uid_fresh() -> Option<u32> {
    let reported_uid_raw = crate::platform::linux::get_active_userid_fresh();
    let trimmed = reported_uid_raw.trim();
    if let Ok(uid) = trimmed.parse::<u32>() {
        return Some(uid);
    }
    if trimmed.is_empty() {
        log::debug!("R-S11a(a): fresh active uid lookup is empty");
    } else {
        log::warn!("R-S11a(a): failed to parse fresh active uid: '{}'", trimmed);
    }
    None
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[inline]
pub(crate) fn peer_uid_from_fd(fd: RawFd) -> Option<u32> {
    #[cfg(target_os = "linux")]
    {
        return peer_cred_from_fd(fd).map(|cred| cred.uid as u32);
    }
    #[cfg(target_os = "macos")]
    {
        let mut uid = 0;
        let mut gid = 0;
        if unsafe { libc::getpeereid(fd, &mut uid, &mut gid) } == 0 {
            Some(uid as u32)
        } else {
            None
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[inline]
fn peer_pid_from_fd(fd: RawFd) -> Option<u32> {
    #[cfg(target_os = "linux")]
    {
        return peer_cred_from_fd(fd).and_then(|cred| (cred.pid > 0).then_some(cred.pid as u32));
    }
    #[cfg(target_os = "macos")]
    {
        // LOCAL_PEEREPID is preferred because it follows effective-identity
        // delegation, but some macOS Unix sockets only expose LOCAL_PEERPID.
        // Both values are kernel-authenticated and the caller still verifies
        // the peer UID, audit token, and executable identity.
        for option in [libc::LOCAL_PEEREPID, libc::LOCAL_PEERPID] {
            let mut pid = 0;
            let mut len = std::mem::size_of::<libc::pid_t>() as _;
            let rc = unsafe {
                libc::getsockopt(
                    fd,
                    libc::SOL_LOCAL,
                    option,
                    &mut pid as *mut _ as *mut libc::c_void,
                    &mut len,
                )
            };
            if rc == 0 && pid > 0 {
                return Some(pid as _);
            }
        }
        None
    }
}

#[cfg(target_os = "macos")]
#[inline]
fn peer_audit_token_from_fd(fd: RawFd) -> Option<[u8; MACOS_AUDIT_TOKEN_BYTES]> {
    let mut token = [0u8; MACOS_AUDIT_TOKEN_BYTES];
    let mut len = token.len() as _;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_LOCAL,
            libc::LOCAL_PEERTOKEN,
            token.as_mut_ptr() as *mut libc::c_void,
            &mut len,
        )
    };
    if rc == 0 && len as usize == token.len() {
        Some(token)
    } else {
        None
    }
}

#[cfg(target_os = "linux")]
#[inline]
fn peer_cred_from_fd(fd: RawFd) -> Option<libc::ucred> {
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as _;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if rc == 0 {
        Some(cred)
    } else {
        None
    }
}

#[cfg(target_os = "linux")]
#[derive(Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct PeerProcessIdentity {
    pid: u32,
    uid: u32,
    start_time: String,
    first_arg: String,
    cm_launch_token: String,
    cm_launch_parent: u32,
}

#[cfg(target_os = "linux")]
impl fmt::Debug for PeerProcessIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PeerProcessIdentity")
            .field("pid", &self.pid)
            .field("uid", &self.uid)
            .field("start_time", &self.start_time)
            .field("first_arg", &self.first_arg)
            .field("cm_launch_token", &"<redacted>")
            .field("cm_launch_parent", &self.cm_launch_parent)
            .finish()
    }
}

#[cfg(target_os = "linux")]
impl PeerProcessIdentity {
    pub(crate) fn pid(&self) -> u32 {
        self.pid
    }

    pub(crate) fn uid(&self) -> u32 {
        self.uid
    }

    pub(crate) fn start_time(&self) -> &str {
        &self.start_time
    }

    #[cfg(test)]
    pub(crate) fn for_test(pid: u32, uid: u32, start_time: String, first_arg: String) -> Self {
        Self {
            pid,
            uid,
            start_time,
            first_arg,
            cm_launch_token: String::new(),
            cm_launch_parent: 0,
        }
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn linux_proc_stat_start_time(pid: u32, stat: &str) -> ResultType<String> {
    let Some((_, after_comm)) = stat.rsplit_once(") ") else {
        bail!("Failed to parse /proc/{pid}/stat: missing command terminator");
    };
    let fields: Vec<_> = after_comm.split_whitespace().collect();
    let Some(start_time) = fields.get(19) else {
        bail!("Failed to parse /proc/{pid}/stat: missing start time");
    };
    Ok((*start_time).to_owned())
}

#[cfg(target_os = "linux")]
pub(crate) fn linux_proc_start_time(pid: u32) -> ResultType<String> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    linux_proc_stat_start_time(pid, &stat)
}

#[cfg(target_os = "linux")]
fn linux_proc_parent_pid(pid: u32) -> ResultType<u32> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let Some((_, after_comm)) = stat.rsplit_once(") ") else {
        bail!("Failed to parse /proc/{pid}/stat: missing command terminator");
    };
    let fields: Vec<_> = after_comm.split_whitespace().collect();
    let Some(ppid) = fields.get(1) else {
        bail!("Failed to parse /proc/{pid}/stat: missing parent pid");
    };
    ppid.parse::<u32>()
        .map_err(|err| anyhow::anyhow!("Failed to parse /proc/{pid}/stat parent pid: {err}"))
}

#[cfg(target_os = "linux")]
fn linux_process_has_ancestor(pid: u32, ancestor_pid: u32) -> bool {
    if pid == 0 || ancestor_pid == 0 {
        return false;
    }
    let mut current = pid;
    for _ in 0..128 {
        let Ok(parent) = linux_proc_parent_pid(current) else {
            return false;
        };
        if parent == ancestor_pid {
            return true;
        }
        if parent == 0 || parent == 1 || parent == current {
            return false;
        }
        current = parent;
    }
    false
}

#[cfg(target_os = "linux")]
fn linux_proc_cmdline_args(pid: u32) -> ResultType<Vec<String>> {
    let cmdline = fs::read(format!("/proc/{pid}/cmdline"))?;
    Ok(cmdline
        .split(|byte| *byte == 0)
        .filter(|part| !part.is_empty())
        .map(|part| String::from_utf8_lossy(part).into_owned())
        .collect())
}

#[cfg(target_os = "linux")]
fn linux_service_process_argv_is_expected(args: &[String]) -> bool {
    args.len() == 2 && args.get(1).map(String::as_str) == Some("--service")
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn user_owned_main_server_argv_is_expected(args: &[String]) -> bool {
    args.len() == 2 && args.get(1).map(String::as_str) == Some("--server")
}

#[cfg(target_os = "linux")]
fn linux_trusted_service_executable_file_metadata(is_file: bool, uid: u32, mode: u32) -> bool {
    is_file && uid == 0 && mode & 0o022 == 0 && mode & 0o111 != 0
}

#[cfg(target_os = "linux")]
fn linux_trusted_service_executable_parent_metadata(is_dir: bool, uid: u32, mode: u32) -> bool {
    is_dir && uid == 0 && mode & 0o022 == 0
}

#[cfg(target_os = "linux")]
fn linux_service_executable_is_trusted(path: &Path) -> bool {
    let Some(parent) = path.parent() else {
        return false;
    };
    let Ok(parent_metadata) = fs::metadata(parent) else {
        return false;
    };
    if !linux_trusted_service_executable_parent_metadata(
        parent_metadata.is_dir(),
        parent_metadata.uid(),
        parent_metadata.permissions().mode(),
    ) {
        return false;
    }
    let Ok(metadata) = fs::metadata(path) else {
        return false;
    };
    linux_trusted_service_executable_file_metadata(
        metadata.is_file(),
        metadata.uid(),
        metadata.permissions().mode(),
    )
}

#[cfg(target_os = "linux")]
pub(crate) fn ensure_linux_service_server_is_trusted<T>(
    stream: &ConnectionTmpl<T>,
) -> ResultType<PeerProcessIdentity>
where
    T: AsyncRead + AsyncWrite + std::marker::Unpin + std::os::unix::io::AsRawFd,
{
    let identity = peer_process_identity(stream, crate::POSTFIX_SERVICE)?;
    if identity.uid != 0 {
        bail!(
            "Linux _service server is not root: peer_uid={}",
            identity.uid
        );
    }
    let args = linux_proc_cmdline_args(identity.pid)?;
    if !linux_service_process_argv_is_expected(&args) {
        bail!(
            "Linux _service server argv mismatch: pid={}, args={:?}",
            identity.pid,
            args
        );
    }
    let peer_exe = peer_exe_canonical_path_by_pid(identity.pid)?;
    if !linux_service_executable_is_trusted(&peer_exe) {
        bail!(
            "Linux _service server executable is not trusted root-owned state: pid={}, peer_exe='{}'",
            identity.pid,
            peer_exe.display()
        );
    }
    Ok(identity)
}

#[cfg(target_os = "macos")]
fn macos_process_cmdline_args(pid: u32) -> ResultType<Vec<String>> {
    let mut sys = hbb_common::sysinfo::System::new_all();
    sys.refresh_processes();
    sys.processes()
        .values()
        .find(|process| process.pid().as_u32() == pid)
        .map(|process| process.cmd().to_vec())
        .ok_or_else(|| anyhow::anyhow!("Failed to resolve macOS process argv: pid={pid}"))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn main_server_cmdline_args(pid: u32) -> ResultType<Vec<String>> {
    #[cfg(target_os = "linux")]
    {
        linux_proc_cmdline_args(pid)
    }
    #[cfg(target_os = "macos")]
    {
        macos_process_cmdline_args(pid)
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn ensure_user_owned_main_server_is_trusted<T>(
    stream: &ConnectionTmpl<T>,
) -> ResultType<()>
where
    T: AsyncRead + AsyncWrite + std::marker::Unpin + std::os::unix::io::AsRawFd,
{
    let peer_uid = stream
        .peer_uid()
        .ok_or_else(|| anyhow::anyhow!("Failed to resolve user-owned main IPC server uid"))?;
    let current_uid = unsafe { libc::geteuid() as u32 };
    if peer_uid != current_uid {
        bail!(
            "user-owned main IPC server uid mismatch: peer_uid={}, current_uid={}",
            peer_uid,
            current_uid
        );
    }
    let peer_pid = stream
        .peer_pid()
        .ok_or_else(|| anyhow::anyhow!("Failed to resolve user-owned main IPC server pid"))?;
    ensure_peer_executable_matches_current_by_pid(peer_pid, "")?;
    let args = main_server_cmdline_args(peer_pid)?;
    if !user_owned_main_server_argv_is_expected(&args) {
        bail!(
            "user-owned main IPC server argv mismatch: pid={}, args={:?}",
            peer_pid,
            args
        );
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn linux_proc_environ_value(pid: u32, name: &str) -> ResultType<String> {
    if name.is_empty() || name.as_bytes().contains(&b'=') {
        bail!("invalid environment key");
    }
    let environ = fs::read(format!("/proc/{pid}/environ"))?;
    let prefix = format!("{name}=");
    for part in environ.split(|byte| *byte == 0) {
        if part.starts_with(prefix.as_bytes()) {
            return Ok(String::from_utf8_lossy(&part[prefix.len()..]).into_owned());
        }
    }
    Ok(String::new())
}

#[cfg(target_os = "linux")]
fn linux_proc_uid(pid: u32) -> ResultType<u32> {
    let metadata = fs::metadata(format!("/proc/{pid}"))?;
    Ok(metadata.uid())
}

#[cfg(target_os = "linux")]
fn linux_proc_u32_env(pid: u32, name: &str) -> ResultType<u32> {
    let value = linux_proc_environ_value(pid, name)?;
    if value.is_empty() {
        return Ok(0);
    }
    value
        .parse::<u32>()
        .map_err(|err| anyhow::anyhow!("Failed to parse environment key {name}: {err}"))
}

#[cfg(target_os = "linux")]
fn linux_process_identity_by_pid(pid: u32, postfix: &str) -> ResultType<PeerProcessIdentity> {
    if pid == 0 {
        bail!("invalid pid 0 on ipc channel '{}'", postfix);
    }
    ensure_peer_executable_matches_current_by_pid(pid, postfix)?;
    let args = linux_proc_cmdline_args(pid)?;
    Ok(PeerProcessIdentity {
        pid,
        uid: linux_proc_uid(pid)?,
        start_time: linux_proc_start_time(pid)?,
        first_arg: args.get(1).cloned().unwrap_or_default(),
        cm_launch_token: linux_proc_environ_value(pid, crate::common::CM_LAUNCH_TOKEN_ENV)?,
        cm_launch_parent: linux_proc_u32_env(pid, crate::common::CM_LAUNCH_PARENT_ENV)?,
    })
}

#[cfg(target_os = "linux")]
pub(crate) fn current_process_identity(postfix: &str) -> ResultType<PeerProcessIdentity> {
    linux_process_identity_by_pid(std::process::id(), postfix)
}

#[cfg(target_os = "linux")]
pub(crate) fn peer_process_identity<T>(
    stream: &ConnectionTmpl<T>,
    postfix: &str,
) -> ResultType<PeerProcessIdentity>
where
    T: AsyncRead + AsyncWrite + std::marker::Unpin + std::os::unix::io::AsRawFd,
{
    let peer_pid = stream.peer_pid().ok_or_else(|| {
        anyhow::anyhow!("Failed to resolve peer pid on ipc channel '{}'", postfix)
    })?;
    let peer_uid = stream.peer_uid().ok_or_else(|| {
        anyhow::anyhow!("Failed to resolve peer uid on ipc channel '{}'", postfix)
    })?;
    let identity = linux_process_identity_by_pid(peer_pid, postfix)?;
    if identity.uid != peer_uid {
        bail!(
            "Peer uid changed while authenticating ipc channel '{}': pid={}, socket_uid={}, proc_uid={}",
            postfix,
            peer_pid,
            peer_uid,
            identity.uid
        );
    }
    Ok(identity)
}

#[cfg(target_os = "linux")]
pub(crate) fn authenticate_cm_endpoint<T>(
    stream: &ConnectionTmpl<T>,
    expected_uid: u32,
    expected_arg: &str,
    expected_launch_token: &str,
    expected_launch_parent: u32,
) -> ResultType<PeerProcessIdentity>
where
    T: AsyncRead + AsyncWrite + std::marker::Unpin + std::os::unix::io::AsRawFd,
{
    let identity = peer_process_identity(stream, "_cm")?;
    if identity.uid != expected_uid {
        bail!(
            "_cm endpoint uid mismatch: expected {}, got {}",
            expected_uid,
            identity.uid
        );
    }
    if identity.first_arg != expected_arg {
        bail!(
            "_cm endpoint mode mismatch: expected {}, got {}",
            expected_arg,
            identity.first_arg
        );
    }
    if expected_launch_token.is_empty() {
        if !identity.cm_launch_token.is_empty() {
            bail!("_cm endpoint launch token mismatch");
        }
    } else if identity.cm_launch_token != expected_launch_token {
        bail!("_cm endpoint launch token mismatch");
    }
    if expected_launch_parent == 0 {
        if identity.cm_launch_parent != 0 {
            bail!("_cm endpoint launch parent mismatch");
        }
    } else if identity.cm_launch_parent != expected_launch_parent
        || !linux_process_has_ancestor(identity.pid, expected_launch_parent)
    {
        bail!("_cm endpoint launch parent mismatch");
    }
    Ok(identity)
}

#[cfg(target_os = "linux")]
fn linux_service_owned_server_argv_is_expected(args: &[String]) -> bool {
    args.len() == 3
        && args.get(1).map(String::as_str) == Some("--server")
        && args.get(2).map(String::as_str) == Some(crate::common::SERVICE_OWNED_SERVER_ARG)
}

#[cfg(target_os = "linux")]
pub(crate) fn authenticate_linux_service_owned_main_server<T>(
    stream: &ConnectionTmpl<T>,
) -> ResultType<PeerProcessIdentity>
where
    T: AsyncRead + AsyncWrite + std::marker::Unpin + std::os::unix::io::AsRawFd,
{
    let identity = peer_process_identity(stream, "")?;
    let args = linux_proc_cmdline_args(identity.pid)?;
    if !linux_service_owned_server_argv_is_expected(&args) {
        bail!(
            "service-owned main server argv mismatch: pid={}, args={:?}",
            identity.pid,
            args
        );
    }
    let expected_parent = std::process::id();
    let launch_parent = linux_proc_u32_env(
        identity.pid,
        crate::common::SERVICE_OWNED_SERVER_LAUNCH_PARENT_ENV,
    )?;
    if launch_parent != expected_parent
        || !linux_process_has_ancestor(identity.pid, expected_parent)
    {
        bail!(
            "service-owned main server launch parent mismatch: pid={}, expected_parent={}, launch_parent={}",
            identity.pid,
            expected_parent,
            launch_parent
        );
    }
    Ok(identity)
}

#[cfg(target_os = "linux")]
pub(crate) fn peer_process_identity_is_live(identity: &PeerProcessIdentity, postfix: &str) -> bool {
    linux_process_identity_by_pid(identity.pid, postfix)
        .map(|live| {
            live == *identity
                && (identity.cm_launch_parent == 0
                    || linux_process_has_ancestor(identity.pid, identity.cm_launch_parent))
        })
        .unwrap_or(false)
}

#[cfg(target_os = "linux")]
pub(crate) fn ensure_peer_process_identity_matches<T>(
    stream: &ConnectionTmpl<T>,
    expected: &PeerProcessIdentity,
    postfix: &str,
) -> ResultType<()>
where
    T: AsyncRead + AsyncWrite + std::marker::Unpin + std::os::unix::io::AsRawFd,
{
    let observed = peer_process_identity(stream, postfix)?;
    if &observed != expected {
        bail!(
            "IPC peer identity mismatch on '{}': expected {:?}, got {:?}",
            postfix,
            expected,
            observed
        );
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
#[inline]
fn current_exe_canonical_path() -> ResultType<PathBuf> {
    let current = std::env::current_exe()
        .map_err(|err| anyhow::anyhow!("Failed to resolve current executable path: {}", err))?;
    fs::canonicalize(&current).map_err(|err| {
        anyhow::anyhow!(
            "Failed to canonicalize current executable path '{}': {}",
            current.display(),
            err
        )
        .into()
    })
}

#[cfg(target_os = "linux")]
#[inline]
fn peer_exe_canonical_path_by_pid(peer_pid: u32) -> ResultType<PathBuf> {
    let proc_exe = PathBuf::from(format!("/proc/{peer_pid}/exe"));
    let peer_exe = fs::read_link(&proc_exe).map_err(|err| {
        anyhow::anyhow!(
            "Failed to read peer executable link '{}': {}",
            proc_exe.display(),
            err
        )
    })?;
    fs::canonicalize(&peer_exe).map_err(|err| {
        anyhow::anyhow!(
            "Failed to canonicalize peer executable path '{}': {}",
            peer_exe.display(),
            err
        )
        .into()
    })
}

#[cfg(target_os = "macos")]
#[inline]
fn peer_exe_canonical_path_by_pid(peer_pid: u32) -> ResultType<PathBuf> {
    const PROC_PIDPATH_BUF_SIZE: usize = libc::PROC_PIDPATHINFO_MAXSIZE as _;
    let mut buffer = vec![0u8; PROC_PIDPATH_BUF_SIZE];
    let length = unsafe {
        libc::proc_pidpath(
            peer_pid as _,
            buffer.as_mut_ptr() as _,
            PROC_PIDPATH_BUF_SIZE as _,
        )
    };
    if length <= 0 {
        bail!("Failed to query peer process path from pid {}", peer_pid);
    }
    buffer.truncate(length as _);
    let path = PathBuf::from(String::from_utf8_lossy(&buffer).to_string());
    fs::canonicalize(&path).map_err(|err| {
        anyhow::anyhow!(
            "Failed to canonicalize peer executable path '{}': {}",
            path.display(),
            err
        )
        .into()
    })
}

#[cfg(target_os = "windows")]
#[inline]
fn peer_exe_canonical_path_by_pid(peer_pid: u32) -> ResultType<PathBuf> {
    let path = crate::platform::windows::get_process_executable_path(peer_pid)?;
    fs::canonicalize(&path).map_err(|err| {
        anyhow::anyhow!(
            "Failed to canonicalize peer executable path '{}': {}",
            path.display(),
            err
        )
        .into()
    })
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
#[inline]
pub(crate) fn executable_paths_match(left: &Path, right: &Path) -> bool {
    #[cfg(target_os = "windows")]
    {
        // Callers pass paths resolved through fs::canonicalize() first, so NT
        // namespace paths and 8.3 short names are expected to be resolved before
        // this check. Keep this normalization limited to remaining Win32 spelling
        // differences.
        fn normalize(path: &Path) -> String {
            let mut normalized = path.to_string_lossy().replace('/', "\\");
            if let Some(stripped) = normalized.strip_prefix(r"\\?\") {
                normalized = stripped.to_owned();
            }
            normalized.to_ascii_lowercase()
        }
        return normalize(left) == normalize(right);
    }
    #[cfg(target_os = "macos")]
    {
        return paths_refer_to_same_file(left, right);
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        left == right
    }
}

#[cfg(target_os = "macos")]
#[inline]
fn paths_refer_to_same_file(left: &Path, right: &Path) -> bool {
    if left == right {
        return true;
    }
    let (Ok(left), Ok(right)) = (fs::metadata(left), fs::metadata(right)) else {
        return false;
    };
    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
#[inline]
fn ensure_peer_executable_matches_current_by_pid(peer_pid: u32, postfix: &str) -> ResultType<()> {
    let peer_exe = peer_exe_canonical_path_by_pid(peer_pid)?;
    let current_exe = current_exe_canonical_path()?;
    if executable_paths_match(&peer_exe, &current_exe) {
        return Ok(());
    }
    bail!(
        "Peer executable path mismatch on ipc channel '{}': peer_pid={}, peer_exe='{}', current_exe='{}'",
        postfix,
        peer_pid,
        peer_exe.display(),
        current_exe.display()
    );
}

#[cfg(target_os = "macos")]
#[inline]
fn ensure_peer_executable_matches_current_macos_identity(
    identity: &MacosPeerProcessIdentity,
    postfix: &str,
) -> ResultType<()> {
    let code = macos_peer_code(identity, "IPC peer")?;
    let peer_exe = macos_peer_code_path(&code, "IPC peer")?;
    let current_exe = current_exe_canonical_path()?;
    // SecCode returns the bundle root for an app process, whereas
    // std::env::current_exe() returns Contents/MacOS/<name>. Treat those as
    // the same identity only for this app's exact installed paths.
    let matches_current = executable_paths_match(&peer_exe, &current_exe)
        || (macos_executable_matches_expected_path(&peer_exe, &macos_installed_app_bundle_path())
            && macos_executable_matches_expected_path(
                &current_exe,
                &macos_installed_app_executable_path(),
            ));
    if matches_current {
        if postfix != crate::POSTFIX_SERVICE
            || (macos_peer_code_satisfies_requirement(
                &code,
                MACOS_PRIVILEGED_HELPER_REQUIREMENT,
                "privileged helper",
            ) && macos_privileged_helper_path_is_expected_and_trusted(&current_exe))
        {
            return Ok(());
        }
    }
    if macos_service_ipc_allows_installed_app_and_privileged_helper(identity, &current_exe, postfix)
    {
        return Ok(());
    }
    bail!(
        "Peer executable path mismatch on ipc channel '{}': peer_pid={}, peer_exe='{}', current_exe='{}'",
        postfix,
        identity.pid,
        peer_exe.display(),
        current_exe.display()
    );
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
#[inline]
pub(crate) fn ensure_peer_executable_matches_current_by_pid_opt(
    peer_pid: Option<u32>,
    postfix: &str,
) -> ResultType<()> {
    let peer_pid = peer_pid.ok_or_else(|| {
        anyhow::anyhow!("Failed to resolve peer pid on ipc channel '{}'", postfix)
    })?;
    ensure_peer_executable_matches_current_by_pid(peer_pid, postfix)
}

#[cfg(target_os = "windows")]
fn ensure_peer_executable_matches_fixed_windows_service_exe_by_pid(
    peer_pid: u32,
    postfix: &str,
) -> ResultType<()> {
    let peer_exe = peer_exe_canonical_path_by_pid(peer_pid)?;
    let expected_exe = crate::platform::windows::fixed_service_install_exe_path()?;
    let expected_exe = fs::canonicalize(&expected_exe).map_err(|err| {
        anyhow::anyhow!(
            "Failed to canonicalize fixed Windows service executable path '{}': {}",
            expected_exe.display(),
            err
        )
    })?;
    if executable_paths_match(&peer_exe, &expected_exe) {
        return Ok(());
    }
    bail!(
        "Peer executable path mismatch on service-owned ipc channel '{}': peer_pid={}, peer_exe='{}', expected_exe='{}'",
        postfix,
        peer_pid,
        peer_exe.display(),
        expected_exe.display()
    );
}

// R-X13 (§8): ensure_peer_executable_matches_current_by_fd (the FD-based exe-match used ONLY by the
// uinput peer authorizer) is removed with the uinput module. Linux _service and non-service
// helper channels still use the _by_pid variant; macOS _service uses the audit-token identity path.

#[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
const UNAUTHORIZED_IPC_LOG_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

#[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
#[derive(Default)]
struct UnauthorizedIpcLogThrottle {
    last_log_at: Option<std::time::Instant>,
    suppressed: u64,
}

#[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
impl UnauthorizedIpcLogThrottle {
    #[inline]
    fn on_reject(&mut self, now: std::time::Instant) -> Option<u64> {
        if let Some(last) = self.last_log_at {
            if now.saturating_duration_since(last) < UNAUTHORIZED_IPC_LOG_INTERVAL {
                self.suppressed += 1;
                return None;
            }
        }
        self.last_log_at = Some(now);
        Some(std::mem::take(&mut self.suppressed))
    }
}

#[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
#[inline]
fn throttled_unauthorized_ipc_log(
    throttle_cell: &OnceLock<Mutex<UnauthorizedIpcLogThrottle>>,
    emit: impl FnOnce(u64),
) {
    let throttle = throttle_cell.get_or_init(|| Mutex::new(UnauthorizedIpcLogThrottle::default()));
    let should_log = match throttle.lock() {
        Ok(mut throttle) => throttle.on_reject(std::time::Instant::now()),
        Err(_) => Some(0),
    };
    if let Some(suppressed) = should_log {
        emit(suppressed);
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[inline]
fn log_rejected_service_connection(postfix: &str, peer_uid: Option<u32>, active_uid: Option<u32>) {
    static LOG_THROTTLE: OnceLock<Mutex<UnauthorizedIpcLogThrottle>> = OnceLock::new();
    throttled_unauthorized_ipc_log(&LOG_THROTTLE, |suppressed| {
        if suppressed > 0 {
            log::warn!(
                "Rejected unauthorized connection on protected service-scoped IPC channel: postfix={}, peer_uid={:?}, active_uid={:?} (suppressed {} similar events)",
                postfix,
                peer_uid,
                active_uid,
                suppressed
            );
        } else {
            log::warn!(
                "Rejected unauthorized connection on protected service-scoped IPC channel: postfix={}, peer_uid={:?}, active_uid={:?}",
                postfix,
                peer_uid,
                active_uid
            );
        }
    });
}

// R-X13 (§8): log_rejected_uinput_connection (the throttled reject-log for the uinput IPC channel)
// is removed with the uinput module. log_rejected_service_connection remains for the _service channel.

#[cfg(windows)]
#[inline]
pub(crate) fn log_rejected_windows_ipc_connection(
    postfix: &str,
    peer_pid: Option<u32>,
    peer_session_id: Option<u32>,
    expected_session_id: Option<u32>,
    peer_is_system: Option<bool>,
    peer_is_elevated: Option<bool>,
) {
    static LOG_THROTTLE: OnceLock<Mutex<UnauthorizedIpcLogThrottle>> = OnceLock::new();
    throttled_unauthorized_ipc_log(&LOG_THROTTLE, |suppressed| {
        if suppressed > 0 {
            log::warn!(
                "Rejected unauthorized connection on ipc channel: postfix={}, peer_pid={:?}, peer_session_id={:?}, expected_session_id={:?}, peer_is_system={:?}, peer_is_elevated={:?} (suppressed {} similar events)",
                postfix,
                peer_pid,
                peer_session_id,
                expected_session_id,
                peer_is_system,
                peer_is_elevated,
                suppressed
            );
        } else {
            log::warn!(
                "Rejected unauthorized connection on ipc channel: postfix={}, peer_pid={:?}, peer_session_id={:?}, expected_session_id={:?}, peer_is_system={:?}, peer_is_elevated={:?}",
                postfix,
                peer_pid,
                peer_session_id,
                expected_session_id,
                peer_is_system,
                peer_is_elevated
            );
        }
    });
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) struct ServiceScopedIpcAuthorization {
    postfix: String,
    #[cfg(target_os = "linux")]
    peer_pid: Option<u32>,
    #[cfg(target_os = "macos")]
    macos_peer_identity: Option<MacosPeerProcessIdentity>,
    peer_uid: Option<u32>,
    active_uid: Option<u32>,
    uid_authorized: bool,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn service_scoped_ipc_authorization_snapshot(
    stream: &Connection,
    postfix: &str,
) -> ServiceScopedIpcAuthorization {
    #[cfg(target_os = "linux")]
    let peer_pid = stream.peer_pid();
    #[cfg(target_os = "macos")]
    let macos_peer_identity = match stream.macos_peer_process_identity("macOS _service peer") {
        Ok(identity) => Some(identity),
        Err(err) => {
            log::warn!("Rejected macOS _service IPC peer: {err}");
            None
        }
    };
    let (uid_authorized, peer_uid, active_uid) = stream.service_authorization_status();
    ServiceScopedIpcAuthorization {
        postfix: postfix.to_owned(),
        #[cfg(target_os = "linux")]
        peer_pid,
        #[cfg(target_os = "macos")]
        macos_peer_identity,
        peer_uid,
        active_uid,
        uid_authorized,
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn authorize_service_scoped_ipc_authorization_snapshot(
    authorization: ServiceScopedIpcAuthorization,
) -> bool {
    if !authorization.uid_authorized {
        log_rejected_service_connection(
            &authorization.postfix,
            authorization.peer_uid,
            authorization.active_uid,
        );
        return false;
    }
    #[cfg(target_os = "macos")]
    {
        let Some(identity) = authorization.macos_peer_identity else {
            log::warn!(
                "Rejected unauthorized connection on protected service-scoped IPC channel due to missing macOS peer identity: postfix={}",
                authorization.postfix
            );
            return false;
        };
        if let Err(err) =
            ensure_peer_executable_matches_current_macos_identity(&identity, &authorization.postfix)
        {
            log::warn!(
                "Rejected unauthorized connection on protected service-scoped IPC channel due to executable mismatch: postfix={}, peer_pid={}, err={}",
                authorization.postfix,
                identity.pid,
                err
            );
            return false;
        }
        return true;
    }
    #[cfg(target_os = "linux")]
    if let Err(err) = ensure_peer_executable_matches_current_by_pid_opt(
        authorization.peer_pid,
        &authorization.postfix,
    ) {
        log::warn!(
            "Rejected unauthorized connection on protected service-scoped IPC channel due to executable mismatch: postfix={}, peer_pid={:?}, err={}",
            authorization.postfix,
            authorization.peer_pid,
            err
        );
        return false;
    }
    true
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn authorize_service_scoped_ipc_connection(stream: &Connection, postfix: &str) -> bool {
    authorize_service_scoped_ipc_authorization_snapshot(service_scoped_ipc_authorization_snapshot(
        stream, postfix,
    ))
}

#[cfg(windows)]
fn authorize_windows_session_current_exe_ipc_connection(
    stream: &Connection,
    postfix: &str,
    channel: &str,
) -> bool {
    let (
        authorized,
        peer_pid,
        peer_session_id,
        server_session_id,
        peer_is_system,
        peer_is_elevated,
    ) = stream.server_authorization_status();
    if !authorized {
        log_rejected_windows_ipc_connection(
            postfix,
            peer_pid,
            peer_session_id,
            server_session_id,
            peer_is_system,
            peer_is_elevated,
        );
        return false;
    }
    if let Err(err) = ensure_peer_executable_matches_current_by_pid_opt(peer_pid, postfix) {
        log::warn!(
            "Rejected unauthorized connection on {} due to executable mismatch: postfix={}, peer_pid={:?}, err={}",
            channel,
            postfix,
            peer_pid,
            err
        );
        return false;
    }
    true
}

#[cfg(windows)]
pub(crate) fn authorize_windows_main_ipc_connection(stream: &Connection, postfix: &str) -> bool {
    authorize_windows_session_current_exe_ipc_connection(stream, postfix, "ipc channel")
}

#[cfg(windows)]
pub(crate) fn authorize_windows_url_ipc_connection(stream: &Connection, postfix: &str) -> bool {
    authorize_windows_session_current_exe_ipc_connection(
        stream,
        postfix,
        "protected _url IPC channel",
    )
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn peer_process_is_current_exe_with_first_arg(peer_pid: u32, expected_arg: &str) -> bool {
    let Some(exe_name) = std::env::current_exe()
        .ok()
        .and_then(|path| path.file_name().map(|name| name.to_owned()))
    else {
        return false;
    };
    let exe_name = exe_name.to_string_lossy();
    crate::platform::get_pids_of_process_with_first_arg(exe_name.as_ref(), expected_arg)
        .iter()
        .any(|pid| pid.as_u32() == peer_pid)
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn peer_process_is_current_exe_server(peer_pid: u32) -> bool {
    peer_process_is_current_exe_with_first_arg(peer_pid, "--server")
}

#[cfg(target_os = "windows")]
fn peer_process_has_windows_service_owned_server_args(peer_pid: u32) -> bool {
    let Some(exe_name) = crate::platform::windows::fixed_service_install_exe_path()
        .ok()
        .and_then(|path| path.file_name().map(|name| name.to_owned()))
    else {
        return false;
    };
    let exe_name = exe_name.to_string_lossy();
    crate::platform::get_pids_of_process_with_args(
        exe_name.as_ref(),
        &windows_service_owned_main_server_args(),
    )
    .iter()
    .any(|pid| pid.as_u32() == peer_pid)
}

#[cfg(target_os = "windows")]
fn windows_service_owned_main_server_args() -> [&'static str; 2] {
    ["--server", crate::common::SERVICE_OWNED_SERVER_ARG]
}

#[cfg(target_os = "macos")]
pub(crate) fn authenticate_macos_cm_endpoint<T>(
    stream: &ConnectionTmpl<T>,
    expected_arg: &str,
) -> ResultType<()>
where
    T: AsyncRead + AsyncWrite + std::marker::Unpin + std::os::unix::io::AsRawFd,
{
    let peer_pid = stream
        .peer_pid()
        .ok_or_else(|| anyhow::anyhow!("Failed to resolve peer pid on ipc channel '_cm'"))?;
    ensure_peer_executable_matches_current_by_pid(peer_pid, "_cm")?;
    if !peer_process_is_current_exe_with_first_arg(peer_pid, expected_arg) {
        bail!("_cm endpoint mode mismatch: expected {}", expected_arg);
    }
    Ok(())
}

#[cfg(target_os = "windows")]
pub(crate) fn authenticate_windows_cm_endpoint(
    stream: &ConnectionTmpl<parity_tokio_ipc::ConnectionClient>,
    expected_arg: &str,
) -> ResultType<()> {
    let peer_pid = windows_named_pipe_server_pid(stream.inner.get_ref())?;
    ensure_peer_executable_matches_current_by_pid(peer_pid, "_cm")?;
    if !peer_process_is_current_exe_with_first_arg(peer_pid, expected_arg) {
        bail!("_cm endpoint mode mismatch: expected {}", expected_arg);
    }
    Ok(())
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub(crate) fn authorize_cm_ipc_connection(stream: &Connection) -> bool {
    let peer_pid = stream.peer_pid();
    if let Err(err) = ensure_peer_executable_matches_current_by_pid_opt(peer_pid, "_cm") {
        log::warn!(
            "Rejected unauthorized connection on _cm IPC channel due to executable mismatch: peer_pid={:?}, err={}",
            peer_pid,
            err
        );
        return false;
    }
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    {
        let Some(peer_pid) = peer_pid else {
            log::warn!("Rejected unauthorized connection on _cm IPC channel: peer pid unavailable");
            return false;
        };
        if !peer_process_is_current_exe_server(peer_pid) {
            log::warn!(
                "Rejected unauthorized connection on _cm IPC channel: peer is not the current executable's --server process, peer_pid={}",
                peer_pid
            );
            return false;
        }
    }
    true
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub(crate) fn authorize_whiteboard_ipc_connection(
    stream: &Connection,
    expected_parent_pid: u32,
) -> bool {
    if expected_parent_pid == 0 {
        log::warn!("Rejected _whiteboard IPC peer: missing launch parent pid");
        return false;
    }
    let peer_pid = stream.peer_pid();
    if peer_pid != Some(expected_parent_pid) {
        log::warn!(
            "Rejected _whiteboard IPC peer: expected parent pid {}, got {:?}",
            expected_parent_pid,
            peer_pid
        );
        return false;
    }
    if let Err(err) = ensure_peer_executable_matches_current_by_pid_opt(peer_pid, "_whiteboard") {
        log::warn!(
            "Rejected _whiteboard IPC peer due to executable mismatch: peer_pid={:?}, err={}",
            peer_pid,
            err
        );
        return false;
    }
    if !peer_process_is_current_exe_server(expected_parent_pid) {
        log::warn!(
            "Rejected _whiteboard IPC peer: launch parent is not the current executable's --server process, peer_pid={}",
            expected_parent_pid
        );
        return false;
    }
    true
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl<T> ConnectionTmpl<T>
where
    T: AsyncRead + AsyncWrite + std::marker::Unpin + std::os::unix::io::AsRawFd,
{
    pub(super) fn peer_uid(&self) -> Option<u32> {
        peer_uid_from_fd(self.inner.get_ref().as_raw_fd())
    }

    fn service_authorization_status(&self) -> (bool, Option<u32>, Option<u32>) {
        let peer_uid = self.peer_uid();
        // R-S11a(a): authorize against a FRESH active-user lookup, NOT the service-loop cache —
        // otherwise a just-switched-out user could pass this `_service` UID gate in the cache-lag
        // window. Matches the `_uinput_*` authorizer's fresh lookup. (The cached active_uid() stays
        // for stable config-sync routing elsewhere; that is not authorization.) Fail-closed: if the
        // live lookup yields None, only root (uid 0) is admitted until it resolves.
        let active_uid = active_uid_fresh();
        let authorized = peer_uid.is_some_and(|uid| is_allowed_service_peer_uid(uid, active_uid));
        (authorized, peer_uid, active_uid)
    }

    pub(crate) fn peer_pid(&self) -> Option<u32> {
        peer_pid_from_fd(self.inner.get_ref().as_raw_fd())
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn macos_peer_process_identity(
        &self,
        description: &str,
    ) -> ResultType<MacosPeerProcessIdentity> {
        let fd = self.inner.get_ref().as_raw_fd();
        let uid = self
            .peer_uid()
            .ok_or_else(|| anyhow::anyhow!("Failed to resolve {description} uid"))?;
        let pid = self
            .peer_pid()
            .ok_or_else(|| anyhow::anyhow!("Failed to resolve {description} effective pid"))?;
        let audit_token = peer_audit_token_from_fd(fd)
            .ok_or_else(|| anyhow::anyhow!("Failed to resolve {description} audit token"))?;
        Ok(MacosPeerProcessIdentity {
            uid,
            pid,
            audit_token,
        })
    }
}

#[cfg(windows)]
impl ConnectionTmpl<parity_tokio_ipc::Connection> {
    fn peer_pid(&self) -> Option<u32> {
        let pipe_handle = self.inner.get_ref().as_raw_handle();
        if pipe_handle.is_null() {
            return None;
        }
        let mut pid = 0u32;
        let ok = unsafe { GetNamedPipeClientProcessId(HANDLE(pipe_handle), &mut pid as *mut u32) }
            .is_ok();
        if ok && pid != 0 {
            Some(pid)
        } else {
            None
        }
    }

    fn windows_pipe_client_token_satisfies(
        &self,
        requirement: WindowsPipeClientTokenRequirement,
    ) -> ResultType<bool> {
        let context = requirement.context();
        let pipe_handle = self.inner.get_ref().as_raw_handle();
        if pipe_handle.is_null() {
            bail!(
                "Failed to impersonate {}: named pipe handle is null",
                context
            );
        }
        unsafe {
            ImpersonateNamedPipeClient(HANDLE(pipe_handle))
                .map_err(|err| anyhow::anyhow!("Failed to impersonate {}: {}", context, err))?;
        }
        let revert = ThreadImpersonationGuard::new();
        let result = (|| -> ResultType<bool> {
            let mut token = HANDLE::default();
            unsafe {
                OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, true, &mut token).map_err(
                    |err| {
                        anyhow::anyhow!("Failed to open {} impersonation token: {}", context, err)
                    },
                )?;
            }
            let _token_guard = WindowsHandle(token);
            requirement.is_satisfied(token)
        })();
        revert.restore();
        result
    }

    pub(crate) fn windows_pipe_client_token_is_elevated(&self) -> ResultType<bool> {
        self.windows_pipe_client_token_satisfies(WindowsPipeClientTokenRequirement::Elevated)
    }

    pub(crate) fn windows_pipe_client_token_is_local_system(&self) -> ResultType<bool> {
        self.windows_pipe_client_token_satisfies(WindowsPipeClientTokenRequirement::LocalSystem)
    }

    fn server_authorization_status(
        &self,
    ) -> (
        bool,
        Option<u32>,
        Option<u32>,
        Option<u32>,
        Option<bool>,
        Option<bool>,
    ) {
        let peer_pid = self.peer_pid();
        let server_session_id = crate::platform::windows::get_current_process_session_id();
        let peer_session_id =
            peer_pid.and_then(crate::platform::windows::get_session_id_of_process);
        let peer_is_system_result =
            peer_pid.map(crate::platform::windows::is_process_running_as_system);
        let peer_is_system = peer_is_system_result
            .as_ref()
            .and_then(|r| r.as_ref().ok().copied());
        let session_authorized = is_allowed_windows_session_scoped_peer(
            peer_is_system.unwrap_or(false),
            peer_session_id,
            server_session_id,
        );
        let peer_is_elevated_result = if session_authorized {
            None
        } else {
            peer_pid.map(|pid| crate::platform::windows::is_elevated(Some(pid)))
        };
        let peer_is_elevated = peer_is_elevated_result
            .as_ref()
            .and_then(|r| r.as_ref().ok().copied());
        if server_session_id.is_none()
            && !peer_is_system.unwrap_or(false)
            && !peer_is_elevated.unwrap_or(false)
        {
            // When the server session id cannot be determined, the session-id allow-path is
            // disabled and only privileged peers can be authorized.
            log::debug!(
                "IPC authorization: server session id unavailable; rejecting non-privileged peer, peer_pid={:?}, peer_session_id={:?}",
                peer_pid,
                peer_session_id
            );
        }
        // Main IPC trusts same-session peers, LocalSystem, and elevated administrators.
        // Service-scoped IPC channels keep their own stricter authorization paths.
        let authorized = session_authorized || peer_is_elevated.unwrap_or(false);
        if !authorized {
            if let (Some(pid), Some(Err(err))) = (peer_pid, peer_is_system_result.as_ref()) {
                log::debug!(
                    "Failed to determine whether peer process is SYSTEM, pid={}, err={}",
                    pid,
                    err
                );
            }
            if let (Some(pid), Some(Err(err))) = (peer_pid, peer_is_elevated_result.as_ref()) {
                log::debug!(
                    "Failed to determine whether peer process is elevated, pid={}, err={}",
                    pid,
                    err
                );
            }
        }
        (
            authorized,
            peer_pid,
            peer_session_id,
            server_session_id,
            peer_is_system,
            peer_is_elevated,
        )
    }

    pub(crate) fn service_authorization_status_for_session(
        &self,
        expected_active_session_id: Option<u32>,
    ) -> (bool, Option<u32>, Option<u32>, Option<bool>) {
        let peer_pid = self.peer_pid();
        let peer_session_id =
            peer_pid.and_then(crate::platform::windows::get_session_id_of_process);
        let peer_is_system_result =
            peer_pid.map(crate::platform::windows::is_process_running_as_system);
        let peer_is_system = peer_is_system_result
            .as_ref()
            .and_then(|r| r.as_ref().ok().copied());
        let authorized = is_allowed_windows_session_scoped_peer(
            peer_is_system.unwrap_or(false),
            peer_session_id,
            expected_active_session_id,
        );
        if !authorized {
            if let (Some(pid), Some(Err(err))) = (peer_pid, peer_is_system_result.as_ref()) {
                log::debug!(
                    "Failed to determine whether peer process is SYSTEM, pid={}, err={}",
                    pid,
                    err
                );
            }
        }
        (authorized, peer_pid, peer_session_id, peer_is_system)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    fn test_service_peer_uid_policy() {
        assert!(super::is_allowed_service_peer_uid(0, None));
        assert!(super::is_allowed_service_peer_uid(501, Some(501)));
        assert!(!super::is_allowed_service_peer_uid(502, Some(501)));
        assert!(!super::is_allowed_service_peer_uid(501, None));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_linux_process_has_ancestor_requires_parent_chain() {
        let pid = std::process::id();
        let parent = super::linux_proc_parent_pid(pid).unwrap();
        assert!(!super::linux_process_has_ancestor(0, parent));
        assert!(!super::linux_process_has_ancestor(pid, 0));
        assert!(!super::linux_process_has_ancestor(pid, pid));
        if parent > 1 {
            assert!(super::linux_process_has_ancestor(pid, parent));
        }
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_linux_service_owned_server_argv_is_exact() {
        assert!(super::linux_service_owned_server_argv_is_expected(&[
            "/usr/bin/rustdesk".to_owned(),
            "--server".to_owned(),
            crate::common::SERVICE_OWNED_SERVER_ARG.to_owned(),
        ]));
        assert!(!super::linux_service_owned_server_argv_is_expected(&[
            "/usr/bin/rustdesk".to_owned(),
            "--server".to_owned(),
        ]));
        assert!(!super::linux_service_owned_server_argv_is_expected(&[
            "/usr/bin/rustdesk".to_owned(),
            "--server".to_owned(),
            crate::common::SERVICE_OWNED_SERVER_ARG.to_owned(),
            "--extra".to_owned(),
        ]));
        assert!(!super::linux_service_owned_server_argv_is_expected(&[
            "/usr/bin/rustdesk".to_owned(),
            "--cm".to_owned(),
            crate::common::SERVICE_OWNED_SERVER_ARG.to_owned(),
        ]));
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn test_windows_service_owned_server_args_are_exact() {
        let args = super::windows_service_owned_main_server_args();
        assert_eq!(args.len(), 2);
        assert_eq!(
            args,
            ["--server", crate::common::SERVICE_OWNED_SERVER_ARG],
            "R-S11e-11: the Windows service-owned main-server authenticator must require the exact service-owned server argv shape"
        );
    }

    #[test]
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn test_user_owned_main_server_argv_is_exact() {
        assert!(super::user_owned_main_server_argv_is_expected(&[
            "/usr/bin/rustdesk".to_owned(),
            "--server".to_owned(),
        ]));
        assert!(!super::user_owned_main_server_argv_is_expected(&[
            "/usr/bin/rustdesk".to_owned(),
        ]));
        assert!(!super::user_owned_main_server_argv_is_expected(&[
            "/usr/bin/rustdesk".to_owned(),
            "--server".to_owned(),
            crate::common::SERVICE_OWNED_SERVER_ARG.to_owned(),
        ]));
        assert!(!super::user_owned_main_server_argv_is_expected(&[
            "/usr/bin/rustdesk".to_owned(),
            "--server".to_owned(),
            "--tray".to_owned(),
        ]));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_linux_service_process_argv_is_exact() {
        assert!(super::linux_service_process_argv_is_expected(&[
            "/usr/bin/rustdesk".to_owned(),
            "--service".to_owned(),
        ]));
        assert!(!super::linux_service_process_argv_is_expected(&[
            "/usr/bin/rustdesk".to_owned(),
        ]));
        assert!(!super::linux_service_process_argv_is_expected(&[
            "/usr/bin/rustdesk".to_owned(),
            "--server".to_owned(),
        ]));
        assert!(!super::linux_service_process_argv_is_expected(&[
            "/usr/bin/rustdesk".to_owned(),
            "--service".to_owned(),
            "--extra".to_owned(),
        ]));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn linux_trusted_service_executable_metadata_requires_root_unwritable_executable_file() {
        assert!(super::linux_trusted_service_executable_file_metadata(
            true, 0, 0o755
        ));
        assert!(!super::linux_trusted_service_executable_file_metadata(
            false, 0, 0o755
        ));
        assert!(!super::linux_trusted_service_executable_file_metadata(
            true, 1000, 0o755
        ));
        assert!(!super::linux_trusted_service_executable_file_metadata(
            true, 0, 0o775
        ));
        assert!(!super::linux_trusted_service_executable_file_metadata(
            true, 0, 0o777
        ));
        assert!(!super::linux_trusted_service_executable_file_metadata(
            true, 0, 0o644
        ));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn linux_trusted_service_executable_parent_requires_root_unwritable_directory() {
        assert!(super::linux_trusted_service_executable_parent_metadata(
            true, 0, 0o755
        ));
        assert!(!super::linux_trusted_service_executable_parent_metadata(
            false, 0, 0o755
        ));
        assert!(!super::linux_trusted_service_executable_parent_metadata(
            true, 1000, 0o755
        ));
        assert!(!super::linux_trusted_service_executable_parent_metadata(
            true, 0, 0o775
        ));
        assert!(!super::linux_trusted_service_executable_parent_metadata(
            true, 0, 0o777
        ));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_peer_process_identity_debug_redacts_launch_token() {
        let mut identity =
            super::PeerProcessIdentity::for_test(10, 20, "30".to_owned(), "--cm".to_owned());
        identity.cm_launch_token = "secret-token".to_owned();
        identity.cm_launch_parent = 40;

        let formatted = format!("{identity:?}");
        assert!(!formatted.contains("secret-token"));
        assert!(formatted.contains("<redacted>"));
        assert!(formatted.contains("cm_launch_parent"));
    }

    #[test]
    #[cfg(windows)]
    fn test_windows_server_peer_policy() {
        assert!(super::is_allowed_windows_session_scoped_peer(
            true, None, None
        ));
        assert!(super::is_allowed_windows_session_scoped_peer(
            false,
            Some(1),
            Some(1)
        ));
        assert!(!super::is_allowed_windows_session_scoped_peer(
            false,
            Some(1),
            Some(2)
        ));
        assert!(!super::is_allowed_windows_session_scoped_peer(
            false,
            None,
            Some(1)
        ));
    }

    #[test]
    #[cfg(windows)]
    fn test_windows_privileged_ipc_uses_restricted_dacl_policy() {
        assert!(super::windows_privileged_ipc_uses_restricted_dacl(""));
        assert!(super::windows_privileged_ipc_uses_restricted_dacl(
            "_service"
        ));
        assert!(super::windows_privileged_ipc_uses_restricted_dacl("_url"));
        assert!(!super::windows_privileged_ipc_uses_restricted_dacl(
            "_portable_service"
        ));
    }

    #[test]
    #[cfg(windows)]
    fn test_windows_restricted_ipc_sddl_omits_world_and_administrators() {
        let sddl = super::windows_restricted_ipc_sddl(&super::WindowsIpcDaclSids {
            server_sids: vec!["S-1-5-5-100-200".to_owned()],
            client_sids: vec!["S-1-5-21-1-2-3-1001".to_owned()],
        });
        assert!(sddl.starts_with("D:P(A;;GA;;;SY)"));
        assert!(sddl.contains("(A;;GA;;;S-1-5-5-100-200)"));
        assert!(sddl.contains("(A;;0x0012019b;;;S-1-5-21-1-2-3-1001)"));
        assert!(!sddl.contains(";;;BA"));
        assert!(!sddl.contains(";;;WD"));
    }

    #[test]
    #[cfg(windows)]
    fn test_windows_client_pipe_access_does_not_grant_create_instance() {
        const FILE_CREATE_PIPE_INSTANCE: u32 = 0x0000_0004;
        assert_eq!(
            super::WINDOWS_NAMED_PIPE_CLIENT_ACCESS_MASK & FILE_CREATE_PIPE_INSTANCE,
            0
        );
    }

    #[test]
    #[cfg(windows)]
    fn test_executable_paths_match_windows_normalization() {
        let left = std::path::PathBuf::from(r"\\?\C:\Program Files\RustDesk\RustDesk.exe");
        let right = std::path::PathBuf::from(r"c:\program files\rustdesk\rustdesk.exe");
        assert!(super::executable_paths_match(&left, &right));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_console_owner_uid_matches_get_active_userid() {
        let console_uid =
            super::console_owner_uid().expect("/dev/console must have a resolvable uid");
        let raw_uid = crate::platform::macos::get_active_userid();
        let parsed_uid: u32 = raw_uid
            .trim()
            .parse()
            .unwrap_or_else(|_| panic!("failed to parse get_active_userid() output: '{raw_uid}'"));
        assert_eq!(parsed_uid, console_uid);
    }
}
