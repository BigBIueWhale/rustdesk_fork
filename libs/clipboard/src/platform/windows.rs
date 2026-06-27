//! windows implementation
#![allow(dead_code)]
#![allow(non_camel_case_types)]
#![allow(unused_variables)]
#![allow(non_snake_case)]
#![allow(deref_nullptr)]

use crate::{
    send_data, send_data_exclude, ClipboardFile, CliprdrError, CliprdrServiceContext,
    ProgressPercent, ResultType, ERR_CODE_INVALID_PARAMETER, ERR_CODE_SEND_MSG,
    ERR_CODE_SERVER_FUNCTION_NONE,
};
use hbb_common::{allow_err, log};
use std::{
    boxed::Box,
    collections::{HashMap, VecDeque},
    ffi::CString,
    result::Result,
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};

// only used error code will be recorded here
/// success
const CHANNEL_RC_OK: u32 = 0;
/// error code from WinError.h
/// success
const ERROR_SUCCESS: u32 = 0;
/// allocation failure
const CHANNEL_RC_NO_MEMORY: u32 = 12;
/// error code from WinError.h
/// used by FreeRDP to represent errors.
const ERROR_INTERNAL_ERROR: u32 = 0x54F;
const MAX_NATIVE_CLIPRDR_FORMATS: usize = 32;
const MAX_NATIVE_CLIPRDR_FORMAT_NAME_BYTES: usize = 256;
const MAX_NATIVE_CLIPRDR_FORMAT_DATA_BYTES: usize = 16 * 1024 * 1024;
const MAX_NATIVE_CLIPRDR_FILE_CONTENTS_BYTES: usize = 8 * 1024 * 1024;
const MAX_NATIVE_CLIPRDR_LOCAL_FILES: usize = 4096;
const MAX_NATIVE_CLIPRDR_FILE_NAME_WCHARS: usize = 32767;
const MAX_NATIVE_CLIPRDR_NOTIFICATION_BYTES: usize = 4096;
const MAX_PENDING_CLIPRDR_REQUESTS_PER_CONN: usize = 64;
const MAX_PENDING_CLIPRDR_REQUESTS_TOTAL: usize = 8192;
const PENDING_CLIPRDR_REQUEST_TTL_SECS: u64 = 60;

#[derive(Clone, Copy)]
struct PendingFileContentsRequest {
    requested: usize,
    created: Instant,
}

#[derive(Default)]
struct PendingCliprdrRequests {
    format_data: HashMap<i32, VecDeque<Instant>>,
    file_contents: HashMap<(i32, i32), PendingFileContentsRequest>,
}

impl PendingCliprdrRequests {
    fn prune_expired(&mut self) {
        let now = Instant::now();
        let ttl = Duration::from_secs(PENDING_CLIPRDR_REQUEST_TTL_SECS);
        self.format_data.retain(|_, requests| {
            requests.retain(|created| now.duration_since(*created) <= ttl);
            !requests.is_empty()
        });
        self.file_contents
            .retain(|_, request| now.duration_since(request.created) <= ttl);
    }

    fn pending_count_for_conn(&self, conn_id: i32) -> usize {
        let format_count = self
            .format_data
            .get(&conn_id)
            .map(|requests| requests.len())
            .unwrap_or_default();
        let file_count = self
            .file_contents
            .keys()
            .filter(|(pending_conn_id, _)| *pending_conn_id == conn_id)
            .count();
        format_count.saturating_add(file_count)
    }

    fn total_count(&self) -> usize {
        let format_count = self
            .format_data
            .values()
            .map(VecDeque::len)
            .fold(0usize, usize::saturating_add);
        format_count.saturating_add(self.file_contents.len())
    }
}

fn pending_cliprdr_requests() -> &'static Mutex<PendingCliprdrRequests> {
    static PENDING: OnceLock<Mutex<PendingCliprdrRequests>> = OnceLock::new();
    PENDING.get_or_init(|| Mutex::new(PendingCliprdrRequests::default()))
}

fn clear_pending_cliprdr_conn_local(conn_id: i32) {
    let Ok(mut pending) = pending_cliprdr_requests().lock() else {
        log::warn!("failed to clear Windows CLIPRDR pending requests: lock poisoned");
        return;
    };
    pending.format_data.remove(&conn_id);
    pending
        .file_contents
        .retain(|(pending_conn_id, _), _| *pending_conn_id != conn_id);
}

pub(crate) fn clear_pending_cliprdr_conn(conn_id: i32) {
    clear_pending_cliprdr_conn_local(conn_id);
    cliprdr_worker::clear_pending_conn(conn_id);
}

fn mark_pending_cliprdr_format_data_request(conn_id: i32) -> bool {
    let Ok(mut pending) = pending_cliprdr_requests().lock() else {
        log::warn!("dropping Windows CLIPRDR format-data request: pending lock poisoned");
        return false;
    };
    pending.prune_expired();
    if pending.pending_count_for_conn(conn_id) >= MAX_PENDING_CLIPRDR_REQUESTS_PER_CONN {
        log::warn!(
            "dropping Windows CLIPRDR format-data request: too many pending requests for conn {}",
            conn_id
        );
        return false;
    }
    if pending.total_count() >= MAX_PENDING_CLIPRDR_REQUESTS_TOTAL {
        log::warn!("dropping Windows CLIPRDR format-data request: too many total pending requests");
        return false;
    }
    pending
        .format_data
        .entry(conn_id)
        .or_default()
        .push_back(Instant::now());
    true
}

fn unmark_pending_cliprdr_format_data_request(conn_id: i32) {
    let Ok(mut pending) = pending_cliprdr_requests().lock() else {
        return;
    };
    if let Some(requests) = pending.format_data.get_mut(&conn_id) {
        requests.pop_back();
        if requests.is_empty() {
            pending.format_data.remove(&conn_id);
        }
    }
}

fn take_pending_cliprdr_format_data_response(conn_id: i32) -> bool {
    let Ok(mut pending) = pending_cliprdr_requests().lock() else {
        log::warn!("dropping Windows CLIPRDR format-data response: pending lock poisoned");
        return false;
    };
    pending.prune_expired();
    let Some(requests) = pending.format_data.get_mut(&conn_id) else {
        return false;
    };
    let matched = requests.pop_front().is_some();
    if requests.is_empty() {
        pending.format_data.remove(&conn_id);
    }
    matched
}

fn mark_pending_cliprdr_file_contents_request(
    conn_id: i32,
    stream_id: i32,
    requested: usize,
) -> bool {
    if requested > MAX_NATIVE_CLIPRDR_FILE_CONTENTS_BYTES {
        return false;
    }
    let Ok(mut pending) = pending_cliprdr_requests().lock() else {
        log::warn!("dropping Windows CLIPRDR file-content request: pending lock poisoned");
        return false;
    };
    pending.prune_expired();
    if pending.pending_count_for_conn(conn_id) >= MAX_PENDING_CLIPRDR_REQUESTS_PER_CONN {
        log::warn!(
            "dropping Windows CLIPRDR file-content request: too many pending requests for conn {}",
            conn_id
        );
        return false;
    }
    if pending.total_count() >= MAX_PENDING_CLIPRDR_REQUESTS_TOTAL {
        log::warn!(
            "dropping Windows CLIPRDR file-content request: too many total pending requests"
        );
        return false;
    }
    if pending.file_contents.contains_key(&(conn_id, stream_id)) {
        log::warn!(
            "dropping duplicate pending Windows CLIPRDR file-content request: conn_id={}, stream_id={}",
            conn_id,
            stream_id
        );
        return false;
    }
    pending.file_contents.insert(
        (conn_id, stream_id),
        PendingFileContentsRequest {
            requested,
            created: Instant::now(),
        },
    );
    true
}

fn unmark_pending_cliprdr_file_contents_request(conn_id: i32, stream_id: i32) {
    let Ok(mut pending) = pending_cliprdr_requests().lock() else {
        return;
    };
    pending.file_contents.remove(&(conn_id, stream_id));
}

fn take_pending_cliprdr_file_contents_response(
    conn_id: i32,
    stream_id: i32,
    actual: usize,
) -> bool {
    let Ok(mut pending) = pending_cliprdr_requests().lock() else {
        log::warn!("dropping Windows CLIPRDR file-content response: pending lock poisoned");
        return false;
    };
    pending.prune_expired();
    let Some(request) = pending.file_contents.remove(&(conn_id, stream_id)) else {
        return false;
    };
    actual <= request.requested
}

pub type size_t = ::std::os::raw::c_ulonglong;
pub type __vcrt_bool = bool;
pub type wchar_t = ::std::os::raw::c_ushort;

pub type POINTER_64_INT = ::std::os::raw::c_ulonglong;
pub type INT8 = ::std::os::raw::c_schar;
pub type PINT8 = *mut ::std::os::raw::c_schar;
pub type INT16 = ::std::os::raw::c_short;
pub type PINT16 = *mut ::std::os::raw::c_short;
pub type INT32 = ::std::os::raw::c_int;
pub type PINT32 = *mut ::std::os::raw::c_int;
pub type INT64 = ::std::os::raw::c_longlong;
pub type PINT64 = *mut ::std::os::raw::c_longlong;
pub type UINT8 = ::std::os::raw::c_uchar;
pub type PUINT8 = *mut ::std::os::raw::c_uchar;
pub type UINT16 = ::std::os::raw::c_ushort;
pub type PUINT16 = *mut ::std::os::raw::c_ushort;
pub type UINT32 = ::std::os::raw::c_uint;
pub type PUINT32 = *mut ::std::os::raw::c_uint;
pub type UINT64 = ::std::os::raw::c_ulonglong;
pub type PUINT64 = *mut ::std::os::raw::c_ulonglong;
pub type LONG32 = ::std::os::raw::c_int;
pub type PLONG32 = *mut ::std::os::raw::c_int;
pub type ULONG32 = ::std::os::raw::c_uint;
pub type PULONG32 = *mut ::std::os::raw::c_uint;
pub type DWORD32 = ::std::os::raw::c_uint;
pub type PDWORD32 = *mut ::std::os::raw::c_uint;
pub type INT_PTR = ::std::os::raw::c_longlong;
pub type PINT_PTR = *mut ::std::os::raw::c_longlong;
pub type UINT_PTR = ::std::os::raw::c_ulonglong;
pub type PUINT_PTR = *mut ::std::os::raw::c_ulonglong;
pub type LONG_PTR = ::std::os::raw::c_longlong;
pub type PLONG_PTR = *mut ::std::os::raw::c_longlong;
pub type ULONG_PTR = ::std::os::raw::c_ulonglong;
pub type PULONG_PTR = *mut ::std::os::raw::c_ulonglong;
pub type SHANDLE_PTR = ::std::os::raw::c_longlong;
pub type HANDLE_PTR = ::std::os::raw::c_ulonglong;
pub type UHALF_PTR = ::std::os::raw::c_uint;
pub type PUHALF_PTR = *mut ::std::os::raw::c_uint;
pub type HALF_PTR = ::std::os::raw::c_int;
pub type PHALF_PTR = *mut ::std::os::raw::c_int;
pub type SIZE_T = ULONG_PTR;
pub type PSIZE_T = *mut ULONG_PTR;
pub type SSIZE_T = LONG_PTR;
pub type PSSIZE_T = *mut LONG_PTR;
pub type DWORD_PTR = ULONG_PTR;
pub type PDWORD_PTR = *mut ULONG_PTR;
pub type LONG64 = ::std::os::raw::c_longlong;
pub type PLONG64 = *mut ::std::os::raw::c_longlong;
pub type ULONG64 = ::std::os::raw::c_ulonglong;
pub type PULONG64 = *mut ::std::os::raw::c_ulonglong;
pub type DWORD64 = ::std::os::raw::c_ulonglong;
pub type PDWORD64 = *mut ::std::os::raw::c_ulonglong;
pub type KAFFINITY = ULONG_PTR;
pub type PKAFFINITY = *mut KAFFINITY;
pub type PVOID = *mut ::std::os::raw::c_void;
pub type CHAR = ::std::os::raw::c_char;
pub type SHORT = ::std::os::raw::c_short;
pub type LONG = ::std::os::raw::c_long;
pub type WCHAR = wchar_t;
pub type PWCHAR = *mut WCHAR;
pub type LPWCH = *mut WCHAR;
pub type PWCH = *mut WCHAR;
pub type LPCWCH = *const WCHAR;
pub type PCWCH = *const WCHAR;
pub type NWPSTR = *mut WCHAR;
pub type LPWSTR = *mut WCHAR;
pub type PWSTR = *mut WCHAR;
pub type PZPWSTR = *mut PWSTR;
pub type PCZPWSTR = *const PWSTR;
pub type LPUWSTR = *mut WCHAR;
pub type PUWSTR = *mut WCHAR;
pub type LPCWSTR = *const WCHAR;
pub type PCWSTR = *const WCHAR;
pub type PZPCWSTR = *mut PCWSTR;
pub type PCZPCWSTR = *const PCWSTR;
pub type LPCUWSTR = *const WCHAR;
pub type PCUWSTR = *const WCHAR;
pub type PZZWSTR = *mut WCHAR;
pub type PCZZWSTR = *const WCHAR;
pub type PUZZWSTR = *mut WCHAR;
pub type PCUZZWSTR = *const WCHAR;
pub type PNZWCH = *mut WCHAR;
pub type PCNZWCH = *const WCHAR;
pub type PUNZWCH = *mut WCHAR;
pub type PCUNZWCH = *const WCHAR;
pub type PCHAR = *mut CHAR;
pub type LPCH = *mut CHAR;
pub type PCH = *mut CHAR;
pub type LPCCH = *const CHAR;
pub type PCCH = *const CHAR;
pub type NPSTR = *mut CHAR;
pub type LPSTR = *mut CHAR;
pub type PSTR = *mut CHAR;
pub type PZPSTR = *mut PSTR;
pub type PCZPSTR = *const PSTR;
pub type LPCSTR = *const CHAR;
pub type PCSTR = *const CHAR;
pub type PZPCSTR = *mut PCSTR;
pub type PCZPCSTR = *const PCSTR;
pub type PZZSTR = *mut CHAR;
pub type PCZZSTR = *const CHAR;
pub type PNZCH = *mut CHAR;
pub type PCNZCH = *const CHAR;
pub type TCHAR = ::std::os::raw::c_char;
pub type PTCHAR = *mut ::std::os::raw::c_char;
pub type TBYTE = ::std::os::raw::c_uchar;
pub type PTBYTE = *mut ::std::os::raw::c_uchar;
pub type LPTCH = LPCH;
pub type PTCH = LPCH;
pub type LPCTCH = LPCCH;
pub type PCTCH = LPCCH;
pub type PTSTR = LPSTR;
pub type LPTSTR = LPSTR;
pub type PUTSTR = LPSTR;
pub type LPUTSTR = LPSTR;
pub type PCTSTR = LPCSTR;
pub type LPCTSTR = LPCSTR;
pub type PCUTSTR = LPCSTR;
pub type LPCUTSTR = LPCSTR;
pub type PZZTSTR = PZZSTR;
pub type PUZZTSTR = PZZSTR;
pub type PCZZTSTR = PCZZSTR;
pub type PCUZZTSTR = PCZZSTR;
pub type PZPTSTR = PZPSTR;
pub type PNZTCH = PNZCH;
pub type PUNZTCH = PNZCH;
pub type PCNZTCH = PCNZCH;
pub type PCUNZTCH = PCNZCH;
pub type PSHORT = *mut SHORT;
pub type PLONG = *mut LONG;
pub type ULONG = ::std::os::raw::c_ulong;
pub type PULONG = *mut ULONG;
pub type USHORT = ::std::os::raw::c_ushort;
pub type PUSHORT = *mut USHORT;
pub type UCHAR = ::std::os::raw::c_uchar;
pub type PUCHAR = *mut UCHAR;
pub type PSZ = *mut ::std::os::raw::c_char;
pub type DWORD = ::std::os::raw::c_ulong;
pub type BOOL = ::std::os::raw::c_int;
pub type BYTE = ::std::os::raw::c_uchar;
pub type WORD = ::std::os::raw::c_ushort;
pub type FLOAT = f32;
pub type PFLOAT = *mut FLOAT;
pub type PBOOL = *mut BOOL;
pub type LPBOOL = *mut BOOL;
pub type PBYTE = *mut BYTE;
pub type LPBYTE = *mut BYTE;
pub type PINT = *mut ::std::os::raw::c_int;
pub type LPINT = *mut ::std::os::raw::c_int;
pub type PWORD = *mut WORD;
pub type LPWORD = *mut WORD;
pub type LPLONG = *mut ::std::os::raw::c_long;
pub type PDWORD = *mut DWORD;
pub type LPDWORD = *mut DWORD;
pub type LPVOID = *mut ::std::os::raw::c_void;
pub type LPCVOID = *const ::std::os::raw::c_void;
pub type INT = ::std::os::raw::c_int;
pub type UINT = ::std::os::raw::c_uint;
pub type PUINT = *mut ::std::os::raw::c_uint;
pub type va_list = *mut ::std::os::raw::c_char;

pub const TRUE: ::std::os::raw::c_int = 1;
pub const FALSE: ::std::os::raw::c_int = 0;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct _CLIPRDR_HEADER {
    pub connID: UINT32,
    pub msgType: UINT16,
    pub msgFlags: UINT16,
    pub dataLen: UINT32,
}
pub type CLIPRDR_HEADER = _CLIPRDR_HEADER;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct _CLIPRDR_CAPABILITY_SET {
    pub capabilitySetType: UINT16,
    pub capabilitySetLength: UINT16,
}
pub type CLIPRDR_CAPABILITY_SET = _CLIPRDR_CAPABILITY_SET;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct _CLIPRDR_GENERAL_CAPABILITY_SET {
    pub capabilitySetType: UINT16,
    pub capabilitySetLength: UINT16,
    pub version: UINT32,
    pub generalFlags: UINT32,
}
pub type CLIPRDR_GENERAL_CAPABILITY_SET = _CLIPRDR_GENERAL_CAPABILITY_SET;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct _CLIPRDR_CAPABILITIES {
    pub connID: UINT32,
    pub msgType: UINT16,
    pub msgFlags: UINT16,
    pub dataLen: UINT32,
    pub cCapabilitiesSets: UINT32,
    pub capabilitySets: *mut CLIPRDR_CAPABILITY_SET,
}
pub type CLIPRDR_CAPABILITIES = _CLIPRDR_CAPABILITIES;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct _CLIPRDR_MONITOR_READY {
    pub connID: UINT32,
    pub msgType: UINT16,
    pub msgFlags: UINT16,
    pub dataLen: UINT32,
}
pub type CLIPRDR_MONITOR_READY = _CLIPRDR_MONITOR_READY;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct _CLIPRDR_TEMP_DIRECTORY {
    pub connID: UINT32,
    pub msgType: UINT16,
    pub msgFlags: UINT16,
    pub dataLen: UINT32,
    pub szTempDir: [::std::os::raw::c_char; 520usize],
}
pub type CLIPRDR_TEMP_DIRECTORY = _CLIPRDR_TEMP_DIRECTORY;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct _CLIPRDR_FORMAT {
    pub formatId: UINT32,
    pub formatName: *mut ::std::os::raw::c_char,
}
pub type CLIPRDR_FORMAT = _CLIPRDR_FORMAT;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct _CLIPRDR_FORMAT_LIST {
    pub connID: UINT32,
    pub msgType: UINT16,
    pub msgFlags: UINT16,
    pub dataLen: UINT32,
    pub numFormats: UINT32,
    pub formats: *mut CLIPRDR_FORMAT,
}
pub type CLIPRDR_FORMAT_LIST = _CLIPRDR_FORMAT_LIST;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct _CLIPRDR_FORMAT_LIST_RESPONSE {
    pub connID: UINT32,
    pub msgType: UINT16,
    pub msgFlags: UINT16,
    pub dataLen: UINT32,
}
pub type CLIPRDR_FORMAT_LIST_RESPONSE = _CLIPRDR_FORMAT_LIST_RESPONSE;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct _CLIPRDR_LOCK_CLIPBOARD_DATA {
    pub connID: UINT32,
    pub msgType: UINT16,
    pub msgFlags: UINT16,
    pub dataLen: UINT32,
    pub clipDataId: UINT32,
}
pub type CLIPRDR_LOCK_CLIPBOARD_DATA = _CLIPRDR_LOCK_CLIPBOARD_DATA;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct _CLIPRDR_UNLOCK_CLIPBOARD_DATA {
    pub connID: UINT32,
    pub msgType: UINT16,
    pub msgFlags: UINT16,
    pub dataLen: UINT32,
    pub clipDataId: UINT32,
}
pub type CLIPRDR_UNLOCK_CLIPBOARD_DATA = _CLIPRDR_UNLOCK_CLIPBOARD_DATA;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct _CLIPRDR_FORMAT_DATA_REQUEST {
    pub connID: UINT32,
    pub msgType: UINT16,
    pub msgFlags: UINT16,
    pub dataLen: UINT32,
    pub requestedFormatId: UINT32,
}
pub type CLIPRDR_FORMAT_DATA_REQUEST = _CLIPRDR_FORMAT_DATA_REQUEST;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct _CLIPRDR_FORMAT_DATA_RESPONSE {
    pub connID: UINT32,
    pub msgType: UINT16,
    pub msgFlags: UINT16,
    pub dataLen: UINT32,
    pub requestedFormatData: *const BYTE,
}
pub type CLIPRDR_FORMAT_DATA_RESPONSE = _CLIPRDR_FORMAT_DATA_RESPONSE;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct _CLIPRDR_FILE_CONTENTS_REQUEST {
    pub connID: UINT32,
    pub msgType: UINT16,
    pub msgFlags: UINT16,
    pub dataLen: UINT32,
    pub streamId: UINT32,
    pub listIndex: UINT32,
    pub dwFlags: UINT32,
    pub nPositionLow: UINT32,
    pub nPositionHigh: UINT32,
    pub cbRequested: UINT32,
    pub haveClipDataId: BOOL,
    pub clipDataId: UINT32,
}
pub type CLIPRDR_FILE_CONTENTS_REQUEST = _CLIPRDR_FILE_CONTENTS_REQUEST;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct _CLIPRDR_FILE_CONTENTS_RESPONSE {
    pub connID: UINT32,
    pub msgType: UINT16,
    pub msgFlags: UINT16,
    pub dataLen: UINT32,
    pub streamId: UINT32,
    pub cbRequested: UINT32,
    pub requestedData: *const BYTE,
}
pub type CLIPRDR_FILE_CONTENTS_RESPONSE = _CLIPRDR_FILE_CONTENTS_RESPONSE;
pub type CliprdrClientContext = _cliprdr_client_context;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct _NOTIFICATION_MESSAGE {
    pub r#type: UINT32, // 0 - info, 1 - warning, 2 - error
    pub msg: *const BYTE,
    pub details: *const BYTE,
}
pub type NOTIFICATION_MESSAGE = _NOTIFICATION_MESSAGE;
pub type pcCliprdrServerCapabilities = ::std::option::Option<
    unsafe extern "C" fn(
        context: *mut CliprdrClientContext,
        capabilities: *const CLIPRDR_CAPABILITIES,
    ) -> UINT,
>;
pub type pcCliprdrClientCapabilities = ::std::option::Option<
    unsafe extern "C" fn(
        context: *mut CliprdrClientContext,
        capabilities: *const CLIPRDR_CAPABILITIES,
    ) -> UINT,
>;
pub type pcCliprdrMonitorReady = ::std::option::Option<
    unsafe extern "C" fn(
        context: *mut CliprdrClientContext,
        monitorReady: *const CLIPRDR_MONITOR_READY,
    ) -> UINT,
>;
pub type pcCliprdrTempDirectory = ::std::option::Option<
    unsafe extern "C" fn(
        context: *mut CliprdrClientContext,
        tempDirectory: *const CLIPRDR_TEMP_DIRECTORY,
    ) -> UINT,
>;
pub type pcNotifyClipboardMsg = ::std::option::Option<
    unsafe extern "C" fn(connID: UINT32, msg: *const NOTIFICATION_MESSAGE) -> UINT,
>;
pub type pcHandleClipboardFiles = ::std::option::Option<
    unsafe extern "C" fn(connID: UINT32, nFiles: size_t, fileNames: *mut *mut WCHAR) -> UINT,
>;
pub type pcCliprdrClientFormatList = ::std::option::Option<
    unsafe extern "C" fn(
        context: *mut CliprdrClientContext,
        formatList: *const CLIPRDR_FORMAT_LIST,
    ) -> UINT,
>;
pub type pcCliprdrServerFormatList = ::std::option::Option<
    unsafe extern "C" fn(
        context: *mut CliprdrClientContext,
        formatList: *const CLIPRDR_FORMAT_LIST,
    ) -> UINT,
>;
pub type pcCliprdrClientFormatListResponse = ::std::option::Option<
    unsafe extern "C" fn(
        context: *mut CliprdrClientContext,
        formatListResponse: *const CLIPRDR_FORMAT_LIST_RESPONSE,
    ) -> UINT,
>;
pub type pcCliprdrServerFormatListResponse = ::std::option::Option<
    unsafe extern "C" fn(
        context: *mut CliprdrClientContext,
        formatListResponse: *const CLIPRDR_FORMAT_LIST_RESPONSE,
    ) -> UINT,
>;
pub type pcCliprdrClientLockClipboardData = ::std::option::Option<
    unsafe extern "C" fn(
        context: *mut CliprdrClientContext,
        lockClipboardData: *const CLIPRDR_LOCK_CLIPBOARD_DATA,
    ) -> UINT,
>;
pub type pcCliprdrServerLockClipboardData = ::std::option::Option<
    unsafe extern "C" fn(
        context: *mut CliprdrClientContext,
        lockClipboardData: *const CLIPRDR_LOCK_CLIPBOARD_DATA,
    ) -> UINT,
>;
pub type pcCliprdrClientUnlockClipboardData = ::std::option::Option<
    unsafe extern "C" fn(
        context: *mut CliprdrClientContext,
        unlockClipboardData: *const CLIPRDR_UNLOCK_CLIPBOARD_DATA,
    ) -> UINT,
>;
pub type pcCliprdrServerUnlockClipboardData = ::std::option::Option<
    unsafe extern "C" fn(
        context: *mut CliprdrClientContext,
        unlockClipboardData: *const CLIPRDR_UNLOCK_CLIPBOARD_DATA,
    ) -> UINT,
>;
pub type pcCliprdrClientFormatDataRequest = ::std::option::Option<
    unsafe extern "C" fn(
        context: *mut CliprdrClientContext,
        formatDataRequest: *const CLIPRDR_FORMAT_DATA_REQUEST,
    ) -> UINT,
>;
pub type pcCliprdrServerFormatDataRequest = ::std::option::Option<
    unsafe extern "C" fn(
        context: *mut CliprdrClientContext,
        formatDataRequest: *const CLIPRDR_FORMAT_DATA_REQUEST,
    ) -> UINT,
>;
pub type pcCliprdrClientFormatDataResponse = ::std::option::Option<
    unsafe extern "C" fn(
        context: *mut CliprdrClientContext,
        formatDataResponse: *const CLIPRDR_FORMAT_DATA_RESPONSE,
    ) -> UINT,
>;
pub type pcCliprdrServerFormatDataResponse = ::std::option::Option<
    unsafe extern "C" fn(
        context: *mut CliprdrClientContext,
        formatDataResponse: *const CLIPRDR_FORMAT_DATA_RESPONSE,
    ) -> UINT,
>;
pub type pcCliprdrClientFileContentsRequest = ::std::option::Option<
    unsafe extern "C" fn(
        context: *mut CliprdrClientContext,
        fileContentsRequest: *const CLIPRDR_FILE_CONTENTS_REQUEST,
    ) -> UINT,
>;
pub type pcCliprdrServerFileContentsRequest = ::std::option::Option<
    unsafe extern "C" fn(
        context: *mut CliprdrClientContext,
        fileContentsRequest: *const CLIPRDR_FILE_CONTENTS_REQUEST,
    ) -> UINT,
>;
pub type pcCliprdrClientFileContentsResponse = ::std::option::Option<
    unsafe extern "C" fn(
        context: *mut CliprdrClientContext,
        fileContentsResponse: *const CLIPRDR_FILE_CONTENTS_RESPONSE,
    ) -> UINT,
>;
pub type pcCliprdrServerFileContentsResponse = ::std::option::Option<
    unsafe extern "C" fn(
        context: *mut CliprdrClientContext,
        fileContentsResponse: *const CLIPRDR_FILE_CONTENTS_RESPONSE,
    ) -> UINT,
>;

// TODO: hide more members of clipboard context
#[repr(C)]
#[derive(Debug, Clone)]
pub struct _cliprdr_client_context {
    pub Custom: *mut ::std::os::raw::c_void,
    pub EnableFiles: BOOL,
    pub EnableOthers: BOOL,
    pub IsStopped: BOOL,
    pub ResponseWaitTimeoutSecs: UINT32,
    pub ServerCapabilities: pcCliprdrServerCapabilities,
    pub ClientCapabilities: pcCliprdrClientCapabilities,
    pub MonitorReady: pcCliprdrMonitorReady,
    pub TempDirectory: pcCliprdrTempDirectory,
    pub NotifyClipboardMsg: pcNotifyClipboardMsg,
    pub HandleClipboardFiles: pcHandleClipboardFiles,
    pub ClientFormatList: pcCliprdrClientFormatList,
    pub ServerFormatList: pcCliprdrServerFormatList,
    pub ClientFormatListResponse: pcCliprdrClientFormatListResponse,
    pub ServerFormatListResponse: pcCliprdrServerFormatListResponse,
    pub ClientLockClipboardData: pcCliprdrClientLockClipboardData,
    pub ServerLockClipboardData: pcCliprdrServerLockClipboardData,
    pub ClientUnlockClipboardData: pcCliprdrClientUnlockClipboardData,
    pub ServerUnlockClipboardData: pcCliprdrServerUnlockClipboardData,
    pub ClientFormatDataRequest: pcCliprdrClientFormatDataRequest,
    pub ServerFormatDataRequest: pcCliprdrServerFormatDataRequest,
    pub ClientFormatDataResponse: pcCliprdrClientFormatDataResponse,
    pub ServerFormatDataResponse: pcCliprdrServerFormatDataResponse,
    pub ClientFileContentsRequest: pcCliprdrClientFileContentsRequest,
    pub ServerFileContentsRequest: pcCliprdrServerFileContentsRequest,
    pub ClientFileContentsResponse: pcCliprdrClientFileContentsResponse,
    pub ServerFileContentsResponse: pcCliprdrServerFileContentsResponse,
    pub LastRequestedFormatId: UINT32,
}

// #[link(name = "user32")]
// #[link(name = "ole32")]
extern "C" {
    fn init_cliprdr(context: *mut CliprdrClientContext) -> BOOL;
    fn uninit_cliprdr(context: *mut CliprdrClientContext) -> BOOL;
    fn empty_cliprdr(context: *mut CliprdrClientContext, connID: UINT32) -> BOOL;
}

unsafe impl Send for CliprdrClientContext {}

unsafe impl Sync for CliprdrClientContext {}

impl CliprdrClientContext {
    fn create(
        enable_files: bool,
        enable_others: bool,
        response_wait_timeout_secs: u32,
        notify_callback: pcNotifyClipboardMsg,
        handle_clipboard_files: pcHandleClipboardFiles,
        client_format_list: pcCliprdrClientFormatList,
        client_format_list_response: pcCliprdrClientFormatListResponse,
        client_format_data_request: pcCliprdrClientFormatDataRequest,
        client_format_data_response: pcCliprdrClientFormatDataResponse,
        client_file_contents_request: pcCliprdrClientFileContentsRequest,
        client_file_contents_response: pcCliprdrClientFileContentsResponse,
    ) -> Result<Box<Self>, CliprdrError> {
        let context = CliprdrClientContext {
            Custom: 0 as *mut _,
            EnableFiles: if enable_files { TRUE } else { FALSE },
            EnableOthers: if enable_others { TRUE } else { FALSE },
            IsStopped: FALSE,
            ResponseWaitTimeoutSecs: response_wait_timeout_secs,
            ServerCapabilities: None,
            ClientCapabilities: None,
            MonitorReady: None,
            TempDirectory: None,
            NotifyClipboardMsg: notify_callback,
            HandleClipboardFiles: handle_clipboard_files,
            ClientFormatList: client_format_list,
            ServerFormatList: None,
            ClientFormatListResponse: client_format_list_response,
            ServerFormatListResponse: None,
            ClientLockClipboardData: None,
            ServerLockClipboardData: None,
            ClientUnlockClipboardData: None,
            ServerUnlockClipboardData: None,
            ClientFormatDataRequest: client_format_data_request,
            ServerFormatDataRequest: None,
            ClientFormatDataResponse: client_format_data_response,
            ServerFormatDataResponse: None,
            ClientFileContentsRequest: client_file_contents_request,
            ServerFileContentsRequest: None,
            ClientFileContentsResponse: client_file_contents_response,
            ServerFileContentsResponse: None,
            LastRequestedFormatId: 0,
        };
        let mut context = Box::new(context);
        unsafe {
            if FALSE == init_cliprdr(&mut (*context)) {
                println!("Failed to init cliprdr");
                Err(CliprdrError::CliprdrInit)
            } else {
                Ok(context)
            }
        }
    }
}

impl Drop for CliprdrClientContext {
    fn drop(&mut self) {
        unsafe {
            if FALSE == uninit_cliprdr(&mut *self) {
                println!("Failed to uninit cliprdr");
            } else {
                println!("Succeeded to uninit cliprdr");
            }
        }
    }
}

impl CliprdrServiceContext for CliprdrClientContext {
    fn set_is_stopped(&mut self) -> Result<(), CliprdrError> {
        self.IsStopped = TRUE;
        Ok(())
    }

    fn empty_clipboard(&mut self, conn_id: i32) -> Result<bool, CliprdrError> {
        Ok(empty_clipboard(self, conn_id))
    }

    fn server_clip_file(&mut self, conn_id: i32, msg: ClipboardFile) -> Result<(), CliprdrError> {
        let ret = server_clip_file(self, conn_id, msg);
        ret_to_result(ret)
    }

    fn get_progress_percent(&self) -> Option<ProgressPercent> {
        None
    }

    fn cancel(&mut self) {}
}

fn ret_to_result(ret: u32) -> Result<(), CliprdrError> {
    match ret {
        #[allow(unreachable_patterns)]
        // CHANNEL_RC_OK is unreachable, but ignore it
        ERROR_SUCCESS | CHANNEL_RC_OK => Ok(()),
        CHANNEL_RC_NO_MEMORY => Err(CliprdrError::CliprdrOutOfMemory),
        ERROR_INTERNAL_ERROR => Err(CliprdrError::ClipboardInternalError),
        e => Err(CliprdrError::Unknown(e)),
    }
}

fn dispatch_send_data(conn_id: i32, data: ClipboardFile) -> Result<(), CliprdrError> {
    if let Some(result) = cliprdr_worker::emit_send_data(conn_id, data.clone()) {
        result
    } else {
        send_data(conn_id, data)
    }
}

fn dispatch_send_data_exclude(conn_id: i32, data: ClipboardFile) {
    if !cliprdr_worker::emit_send_data_exclude(conn_id, data.clone()) {
        send_data_exclude(conn_id, data);
    }
}

fn cliprdr_format_list_within_native_limit(format_list: &[(i32, String)]) -> bool {
    format_list.len() <= MAX_NATIVE_CLIPRDR_FORMATS
        && format_list
            .iter()
            .all(|(_, name)| name.len() <= MAX_NATIVE_CLIPRDR_FORMAT_NAME_BYTES)
}

unsafe fn bounded_c_string_to_string(
    ptr: *const ::std::os::raw::c_char,
    max_len: usize,
) -> Result<String, ()> {
    if ptr.is_null() {
        return Err(());
    }

    let mut len = 0usize;
    while len <= max_len {
        if *ptr.add(len) == 0 {
            let bytes = std::slice::from_raw_parts(ptr as *const u8, len);
            return std::str::from_utf8(bytes)
                .map(|value| value.to_owned())
                .map_err(|_| ());
        }
        len += 1;
    }

    Err(())
}

#[inline]
fn cliprdr_payload_within_native_limit(label: &str, len: usize, max: usize) -> bool {
    if len > max {
        log::warn!("dropping oversized Windows CLIPRDR {label} at FFI bridge: {len} > {max}");
        return false;
    }
    true
}

#[inline]
fn cliprdr_file_request_within_native_limit(cb_requested: i32) -> bool {
    cb_requested >= 0 && (cb_requested as usize) <= MAX_NATIVE_CLIPRDR_FILE_CONTENTS_BYTES
}

fn empty_clipboard(context: &mut CliprdrClientContext, conn_id: i32) -> bool {
    unsafe { TRUE == empty_cliprdr(context, conn_id as u32) }
}

fn server_clip_file(context: &mut CliprdrClientContext, conn_id: i32, msg: ClipboardFile) -> u32 {
    let mut ret = 0;
    match msg {
        ClipboardFile::NotifyCallback { .. } => {
            // unreachable
        }
        ClipboardFile::MonitorReady => {
            clear_pending_cliprdr_conn(conn_id);
            log::debug!("server_monitor_ready called");
            ret = server_monitor_ready(context, conn_id);
            log::debug!(
                "server_monitor_ready called, conn_id {}, return {}",
                conn_id,
                ret
            );
        }
        ClipboardFile::FormatList { format_list } => {
            clear_pending_cliprdr_conn(conn_id);
            if !cliprdr_format_list_within_native_limit(&format_list) {
                log::warn!("dropping oversized Windows CLIPRDR format list at FFI bridge");
                return ERR_CODE_INVALID_PARAMETER;
            }
            log::debug!(
                "server_format_list called, conn_id {}, format_list: {:?}",
                conn_id,
                &format_list
            );
            dispatch_send_data_exclude(conn_id as _, ClipboardFile::TryEmpty);
            ret = server_format_list(context, conn_id, format_list);
            log::debug!(
                "server_format_list called, conn_id {}, return {}",
                conn_id,
                ret
            );
        }
        ClipboardFile::FormatListResponse { msg_flags } => {
            log::debug!("server_format_list_response called");
            ret = server_format_list_response(context, conn_id, msg_flags);
            log::debug!(
                "server_format_list_response called, conn_id {}, msg_flags {}, return {}",
                conn_id,
                msg_flags,
                ret
            );
        }
        ClipboardFile::FormatDataRequest {
            requested_format_id,
        } => {
            log::debug!("server_format_data_request called");
            ret = server_format_data_request(context, conn_id, requested_format_id);
            log::debug!(
                "server_format_data_request called, conn_id {}, requested_format_id {}, return {}",
                conn_id,
                requested_format_id,
                ret
            );
        }
        ClipboardFile::FormatDataResponse {
            msg_flags,
            format_data,
        } => {
            if !take_pending_cliprdr_format_data_response(conn_id) {
                log::warn!(
                    "dropping unsolicited Windows CLIPRDR format-data response at FFI bridge: conn_id={}",
                    conn_id
                );
                return ERR_CODE_INVALID_PARAMETER;
            }
            if !cliprdr_payload_within_native_limit(
                "format data response",
                format_data.len(),
                MAX_NATIVE_CLIPRDR_FORMAT_DATA_BYTES,
            ) {
                return ERR_CODE_INVALID_PARAMETER;
            }
            log::debug!("server_format_data_response called");
            ret = server_format_data_response(context, conn_id, msg_flags, format_data);
            log::debug!(
                "server_format_data_response called, conn_id {}, msg_flags: {}, return {}",
                conn_id,
                msg_flags,
                ret
            );
        }
        ClipboardFile::FileContentsRequest {
            stream_id,
            list_index,
            dw_flags,
            n_position_low,
            n_position_high,
            cb_requested,
            have_clip_data_id,
            clip_data_id,
        } => {
            if !cliprdr_file_request_within_native_limit(cb_requested) {
                log::warn!(
                    "dropping oversized Windows CLIPRDR file-content request at FFI bridge: {} > {}",
                    cb_requested,
                    MAX_NATIVE_CLIPRDR_FILE_CONTENTS_BYTES
                );
                return ERR_CODE_INVALID_PARAMETER;
            }
            log::debug!("server_file_contents_request called");
            ret = server_file_contents_request(
                context,
                conn_id,
                stream_id,
                list_index,
                dw_flags,
                n_position_low,
                n_position_high,
                cb_requested,
                have_clip_data_id,
                clip_data_id,
            );
            log::debug!("server_file_contents_request called, conn_id {}, stream_id: {}, list_index {}, dw_flags {}, n_position_low {}, n_position_high {}, cb_requested {}, have_clip_data_id {}, clip_data_id {}, return {}",                 conn_id,
                stream_id,
                list_index,
                dw_flags,
                n_position_low,
                n_position_high,
                cb_requested,
                have_clip_data_id,
                clip_data_id,
                ret
            );
        }
        ClipboardFile::FileContentsResponse {
            msg_flags,
            stream_id,
            requested_data,
        } => {
            if !take_pending_cliprdr_file_contents_response(
                conn_id,
                stream_id,
                requested_data.len(),
            ) {
                log::warn!(
                    "dropping unsolicited or overlong Windows CLIPRDR file-content response at FFI bridge: conn_id={}, stream_id={}, bytes={}",
                    conn_id,
                    stream_id,
                    requested_data.len()
                );
                return ERR_CODE_INVALID_PARAMETER;
            }
            if !cliprdr_payload_within_native_limit(
                "file contents response",
                requested_data.len(),
                MAX_NATIVE_CLIPRDR_FILE_CONTENTS_BYTES,
            ) {
                return ERR_CODE_INVALID_PARAMETER;
            }
            log::debug!("server_file_contents_response called");
            ret = server_file_contents_response(
                context,
                conn_id,
                msg_flags,
                stream_id,
                requested_data,
            );
            log::debug!("server_file_contents_response called, conn_id {}, msg_flags {}, stream_id {}, return {}",
                conn_id,
                msg_flags,
                stream_id,
                ret
            );
        }
        ClipboardFile::TryEmpty => {
            clear_pending_cliprdr_conn(conn_id);
            log::debug!("empty_clipboard called");
            let ret = empty_clipboard(context, conn_id);
            log::debug!(
                "empty_clipboard called, conn_id {}, return {}",
                conn_id,
                ret
            );
        }
        ClipboardFile::Files { .. } => {
            // unreachable
        }
    }
    ret
}

fn server_monitor_ready(context: &mut CliprdrClientContext, conn_id: i32) -> u32 {
    unsafe {
        let monitor_ready = CLIPRDR_MONITOR_READY {
            connID: conn_id as UINT32,
            msgType: 0 as UINT16,
            msgFlags: 0 as UINT16,
            dataLen: 0 as UINT32,
        };
        if let Some(f) = context.MonitorReady {
            let ret = f(context, &monitor_ready);
            ret as u32
        } else {
            ERR_CODE_SERVER_FUNCTION_NONE
        }
    }
}

fn server_format_list(
    context: &mut CliprdrClientContext,
    conn_id: i32,
    format_list: Vec<(i32, String)>,
) -> u32 {
    if !cliprdr_format_list_within_native_limit(&format_list) {
        log::warn!("dropping oversized Windows CLIPRDR format list at FFI bridge");
        return ERR_CODE_INVALID_PARAMETER;
    }
    unsafe {
        let num_formats = format_list.len() as UINT32;
        let mut formats = format_list
            .into_iter()
            .map(|format| {
                if format.1.is_empty() {
                    CLIPRDR_FORMAT {
                        formatId: format.0 as UINT32,
                        formatName: 0 as *mut _,
                    }
                } else {
                    let n = match CString::new(format.1) {
                        Ok(n) => n,
                        Err(_) => CString::new("").unwrap_or_default(),
                    };
                    CLIPRDR_FORMAT {
                        formatId: format.0 as UINT32,
                        formatName: n.into_raw(),
                    }
                }
            })
            .collect::<Vec<CLIPRDR_FORMAT>>();

        let format_list = CLIPRDR_FORMAT_LIST {
            connID: conn_id as UINT32,
            msgType: 0 as UINT16,
            msgFlags: 0 as UINT16,
            dataLen: 0 as UINT32,
            numFormats: num_formats,
            formats: formats.as_mut_ptr(),
        };

        let ret = if let Some(f) = context.ServerFormatList {
            f(context, &format_list)
        } else {
            ERR_CODE_SERVER_FUNCTION_NONE
        };

        for f in formats {
            if !f.formatName.is_null() {
                // retake pointer to free memory
                let _ = CString::from_raw(f.formatName);
            }
        }

        ret as u32
    }
}

fn server_format_list_response(
    context: &mut CliprdrClientContext,
    conn_id: i32,
    msg_flags: i32,
) -> u32 {
    unsafe {
        let format_list_response = CLIPRDR_FORMAT_LIST_RESPONSE {
            connID: conn_id as UINT32,
            msgType: 0 as UINT16,
            msgFlags: msg_flags as UINT16,
            dataLen: 0 as UINT32,
        };

        if let Some(f) = context.ServerFormatListResponse {
            f(context, &format_list_response)
        } else {
            ERR_CODE_SERVER_FUNCTION_NONE
        }
    }
}

fn server_format_data_request(
    context: &mut CliprdrClientContext,
    conn_id: i32,
    requested_format_id: i32,
) -> u32 {
    unsafe {
        let format_data_request = CLIPRDR_FORMAT_DATA_REQUEST {
            connID: conn_id as UINT32,
            msgType: 0 as UINT16,
            msgFlags: 0 as UINT16,
            dataLen: 0 as UINT32,
            requestedFormatId: requested_format_id as UINT32,
        };
        if let Some(f) = context.ServerFormatDataRequest {
            f(context, &format_data_request)
        } else {
            ERR_CODE_SERVER_FUNCTION_NONE
        }
    }
}

fn server_format_data_response(
    context: &mut CliprdrClientContext,
    conn_id: i32,
    msg_flags: i32,
    mut format_data: Vec<u8>,
) -> u32 {
    if !cliprdr_payload_within_native_limit(
        "format data response",
        format_data.len(),
        MAX_NATIVE_CLIPRDR_FORMAT_DATA_BYTES,
    ) {
        return ERR_CODE_INVALID_PARAMETER;
    }
    unsafe {
        let format_data_response = CLIPRDR_FORMAT_DATA_RESPONSE {
            connID: conn_id as UINT32,
            msgType: 0 as UINT16,
            msgFlags: msg_flags as UINT16,
            dataLen: format_data.len() as UINT32,
            requestedFormatData: format_data.as_mut_ptr(),
        };
        if let Some(f) = context.ServerFormatDataResponse {
            f(context, &format_data_response)
        } else {
            ERR_CODE_SERVER_FUNCTION_NONE
        }
    }
}

fn server_file_contents_request(
    context: &mut CliprdrClientContext,
    conn_id: i32,
    stream_id: i32,
    list_index: i32,
    dw_flags: i32,
    n_position_low: i32,
    n_position_high: i32,
    cb_requested: i32,
    have_clip_data_id: bool,
    clip_data_id: i32,
) -> u32 {
    if !cliprdr_file_request_within_native_limit(cb_requested) {
        log::warn!(
            "dropping oversized Windows CLIPRDR file-content request at FFI bridge: {} > {}",
            cb_requested,
            MAX_NATIVE_CLIPRDR_FILE_CONTENTS_BYTES
        );
        return ERR_CODE_INVALID_PARAMETER;
    }
    unsafe {
        let file_contents_request = CLIPRDR_FILE_CONTENTS_REQUEST {
            connID: conn_id as UINT32,
            msgType: 0 as UINT16,
            msgFlags: 0 as UINT16,
            dataLen: 0 as UINT32,
            streamId: stream_id as UINT32,
            listIndex: list_index as UINT32,
            dwFlags: dw_flags as UINT32,
            nPositionLow: n_position_low as UINT32,
            nPositionHigh: n_position_high as UINT32,
            cbRequested: cb_requested as UINT32,
            haveClipDataId: if have_clip_data_id { TRUE } else { FALSE },
            clipDataId: clip_data_id as UINT32,
        };
        if let Some(f) = context.ServerFileContentsRequest {
            f(context, &file_contents_request)
        } else {
            ERR_CODE_SERVER_FUNCTION_NONE
        }
    }
}

fn server_file_contents_response(
    context: &mut CliprdrClientContext,
    conn_id: i32,
    msg_flags: i32,
    stream_id: i32,
    mut requested_data: Vec<u8>,
) -> u32 {
    if !cliprdr_payload_within_native_limit(
        "file contents response",
        requested_data.len(),
        MAX_NATIVE_CLIPRDR_FILE_CONTENTS_BYTES,
    ) {
        return ERR_CODE_INVALID_PARAMETER;
    }
    unsafe {
        let file_contents_response = CLIPRDR_FILE_CONTENTS_RESPONSE {
            connID: conn_id as UINT32,
            msgType: 0 as UINT16,
            msgFlags: msg_flags as UINT16,
            dataLen: 4 + requested_data.len() as UINT32,
            streamId: stream_id as UINT32,
            cbRequested: requested_data.len() as UINT32,
            requestedData: requested_data.as_mut_ptr(),
        };
        if let Some(f) = context.ServerFileContentsResponse {
            f(context, &file_contents_response)
        } else {
            ERR_CODE_SERVER_FUNCTION_NONE
        }
    }
}

fn create_in_process_cliprdr_context(
    enable_files: bool,
    enable_others: bool,
    response_wait_timeout_secs: u32,
) -> ResultType<Box<CliprdrClientContext>> {
    Ok(CliprdrClientContext::create(
        enable_files,
        enable_others,
        response_wait_timeout_secs,
        Some(notify_callback),
        Some(handle_clipboard_files),
        Some(client_format_list),
        Some(client_format_list_response),
        Some(client_format_data_request),
        Some(client_format_data_response),
        Some(client_file_contents_request),
        Some(client_file_contents_response),
    )?)
}

pub fn create_cliprdr_context(
    enable_files: bool,
    enable_others: bool,
    response_wait_timeout_secs: u32,
) -> ResultType<Box<dyn CliprdrServiceContext>> {
    cliprdr_worker::create_proxy_context(enable_files, enable_others, response_wait_timeout_secs)
}

pub fn cliprdr_worker_arg() -> &'static str {
    cliprdr_worker::worker_arg()
}

pub fn run_cliprdr_worker() -> ResultType<()> {
    cliprdr_worker::run_worker()
}

mod cliprdr_worker {
    use super::{
        create_in_process_cliprdr_context, dispatch_send_data, dispatch_send_data_exclude,
        ClipboardFile, CliprdrError, CliprdrServiceContext, ProgressPercent,
        MAX_NATIVE_CLIPRDR_FILE_CONTENTS_BYTES, MAX_NATIVE_CLIPRDR_FILE_NAME_WCHARS,
        MAX_NATIVE_CLIPRDR_FORMATS, MAX_NATIVE_CLIPRDR_FORMAT_DATA_BYTES,
        MAX_NATIVE_CLIPRDR_FORMAT_NAME_BYTES, MAX_NATIVE_CLIPRDR_LOCAL_FILES,
        MAX_NATIVE_CLIPRDR_NOTIFICATION_BYTES,
    };
    use hbb_common::{
        anyhow::{anyhow, bail},
        ResultType,
    };
    use std::{
        collections::HashMap,
        convert::TryFrom,
        io::{self, Cursor, Read, Write},
        process::{Child, ChildStdin, ChildStdout, Command, Stdio},
        sync::{
            mpsc::{self, SyncSender, TrySendError},
            Arc, Mutex, MutexGuard, OnceLock,
        },
        time::Duration,
    };

    const WORKER_ARG: &str = "--native-cliprdr-worker";
    const PROTOCOL_VERSION: u8 = 1;
    const COMMAND_MAGIC: [u8; 4] = *b"RDCI";
    const OUTPUT_MAGIC: [u8; 4] = *b"RDCO";
    const MAX_WORKER_FRAME_BYTES: usize = 64 * 1024 * 1024;
    const MAX_WORKER_ERROR_BYTES: usize = 64 * 1024;
    const CHILD_OUTPUT_QUEUE: usize = 256;
    const MAX_CHILD_RESPONSE_WAIT_TIMEOUT_SECS: u32 = 30;
    const WORKER_RESPONSE_GRACE_SECS: u64 = 3;
    const OP_INIT: u8 = 1;
    const OP_SET_STOPPED: u8 = 2;
    const OP_EMPTY_CLIPBOARD: u8 = 3;
    const OP_SERVER_CLIP_FILE: u8 = 4;
    const OP_CANCEL: u8 = 5;
    const OP_CLEAR_PENDING_CONN: u8 = 6;
    const OUT_RESPONSE: u8 = 1;
    const OUT_SEND_DATA: u8 = 2;
    const OUT_SEND_DATA_EXCLUDE: u8 = 3;
    const RESPONSE_UNIT: u8 = 0;
    const RESPONSE_BOOL: u8 = 1;
    const STATUS_OK: u8 = 0;
    const STATUS_ERROR: u8 = 1;
    const CLIP_NOTIFY_CALLBACK: u8 = 1;
    const CLIP_MONITOR_READY: u8 = 2;
    const CLIP_FORMAT_LIST: u8 = 3;
    const CLIP_FORMAT_LIST_RESPONSE: u8 = 4;
    const CLIP_FORMAT_DATA_REQUEST: u8 = 5;
    const CLIP_FORMAT_DATA_RESPONSE: u8 = 6;
    const CLIP_FILE_CONTENTS_REQUEST: u8 = 7;
    const CLIP_FILE_CONTENTS_RESPONSE: u8 = 8;
    const CLIP_TRY_EMPTY: u8 = 9;
    const CLIP_FILES: u8 = 10;

    pub(super) fn worker_arg() -> &'static str {
        WORKER_ARG
    }

    pub(super) fn create_proxy_context(
        enable_files: bool,
        enable_others: bool,
        response_wait_timeout_secs: u32,
    ) -> ResultType<Box<dyn CliprdrServiceContext>> {
        let response_wait_timeout_secs =
            response_wait_timeout_secs.min(MAX_CHILD_RESPONSE_WAIT_TIMEOUT_SECS);
        let mut proxy = CliprdrWorkerProxy::spawn(response_wait_timeout_secs)?;
        proxy.init(enable_files, enable_others, response_wait_timeout_secs)?;
        Ok(Box::new(proxy))
    }

    pub(super) fn run_worker() -> ResultType<()> {
        hbb_common::native_worker_sandbox::enter_worker_process()?;
        let (output_tx, output_rx) = mpsc::sync_channel::<WorkerOutput>(CHILD_OUTPUT_QUEUE);
        install_event_sender(output_tx.clone());

        let writer = std::thread::Builder::new()
            .name("rd-cliprdr-worker-out".to_owned())
            .spawn(move || child_output_loop(std::io::stdout(), output_rx))
            .map_err(|e| anyhow!("failed to spawn CLIPRDR worker output thread: {e}"))?;

        let run_result = child_command_loop(std::io::stdin(), output_tx);
        clear_event_sender();
        let writer_result = match writer.join() {
            Ok(result) => result,
            Err(_) => Err(anyhow!("CLIPRDR worker output thread panicked")),
        };
        run_result.and(writer_result)
    }

    pub(super) fn emit_send_data(
        conn_id: i32,
        data: ClipboardFile,
    ) -> Option<Result<(), CliprdrError>> {
        let sender = worker_event_sender()?.clone();
        Some(
            sender
                .try_send(WorkerOutput::SendData { conn_id, data })
                .map_err(worker_send_error),
        )
    }

    pub(super) fn emit_send_data_exclude(conn_id: i32, data: ClipboardFile) -> bool {
        let Some(sender) = worker_event_sender() else {
            return false;
        };
        match sender.try_send(WorkerOutput::SendDataExclude { conn_id, data }) {
            Ok(()) => true,
            Err(err) => {
                hbb_common::log::warn!("failed to forward CLIPRDR worker broadcast event: {err}");
                true
            }
        }
    }

    fn worker_send_error(err: TrySendError<WorkerOutput>) -> CliprdrError {
        CliprdrError::CommonError {
            description: format!("failed to forward CLIPRDR worker event: {err}"),
        }
    }

    fn worker_event_sender() -> Option<SyncSender<WorkerOutput>> {
        worker_event_sender_lock().lock().ok()?.clone()
    }

    fn install_event_sender(sender: SyncSender<WorkerOutput>) {
        if let Ok(mut guard) = worker_event_sender_lock().lock() {
            *guard = Some(sender);
        }
    }

    fn clear_event_sender() {
        if let Ok(mut guard) = worker_event_sender_lock().lock() {
            *guard = None;
        }
    }

    fn worker_event_sender_lock() -> &'static Mutex<Option<SyncSender<WorkerOutput>>> {
        static WORKER_EVENT_SENDER: OnceLock<Mutex<Option<SyncSender<WorkerOutput>>>> =
            OnceLock::new();
        WORKER_EVENT_SENDER.get_or_init(|| Mutex::new(None))
    }

    pub(super) fn clear_pending_conn(conn_id: i32) {
        let Some(sender) = parent_command_sender() else {
            return;
        };
        match sender.try_send(ParentCommand {
            seq: 0,
            command: WorkerCommand::ClearPendingConn { conn_id },
        }) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                hbb_common::log::warn!(
                    "CLIPRDR worker command queue full; pending cleanup deferred to TTL for conn {}",
                    conn_id
                );
            }
            Err(TrySendError::Disconnected(_)) => {
                hbb_common::log::warn!(
                    "CLIPRDR worker command queue closed; pending cleanup unavailable for conn {}",
                    conn_id
                );
                clear_parent_command_sender();
            }
        }
    }

    fn parent_command_sender() -> Option<mpsc::SyncSender<ParentCommand>> {
        parent_command_sender_lock().lock().ok()?.clone()
    }

    fn install_parent_command_sender(sender: mpsc::SyncSender<ParentCommand>) {
        if let Ok(mut guard) = parent_command_sender_lock().lock() {
            *guard = Some(sender);
        }
    }

    fn clear_parent_command_sender() {
        if let Ok(mut guard) = parent_command_sender_lock().lock() {
            *guard = None;
        }
    }

    fn parent_command_sender_lock() -> &'static Mutex<Option<mpsc::SyncSender<ParentCommand>>> {
        static PARENT_COMMAND_SENDER: OnceLock<Mutex<Option<mpsc::SyncSender<ParentCommand>>>> =
            OnceLock::new();
        PARENT_COMMAND_SENDER.get_or_init(|| Mutex::new(None))
    }

    struct CliprdrWorkerProxy {
        process: Mutex<CliprdrWorkerProcess>,
    }

    impl CliprdrWorkerProxy {
        fn spawn(response_wait_timeout_secs: u32) -> ResultType<Self> {
            Ok(Self {
                process: Mutex::new(CliprdrWorkerProcess::spawn(response_wait_timeout_secs)?),
            })
        }

        fn init(
            &mut self,
            enable_files: bool,
            enable_others: bool,
            response_wait_timeout_secs: u32,
        ) -> ResultType<()> {
            self.process
                .get_mut()
                .map_err(|_| anyhow!("CLIPRDR worker process lock poisoned"))?
                .request(WorkerCommand::Init {
                    enable_files,
                    enable_others,
                    response_wait_timeout_secs,
                })?;
            Ok(())
        }

        fn process(&self) -> Result<MutexGuard<'_, CliprdrWorkerProcess>, CliprdrError> {
            self.process.lock().map_err(|_| CliprdrError::CommonError {
                description: "CLIPRDR worker process lock poisoned".to_owned(),
            })
        }
    }

    impl Drop for CliprdrWorkerProxy {
        fn drop(&mut self) {
            if let Ok(process) = self.process.get_mut() {
                process.kill_child();
            }
        }
    }

    impl CliprdrServiceContext for CliprdrWorkerProxy {
        fn set_is_stopped(&mut self) -> Result<(), CliprdrError> {
            self.process()?
                .request(WorkerCommand::SetStopped)
                .map(|_| ())
                .map_err(cliprdr_worker_error)
        }

        fn empty_clipboard(&mut self, conn_id: i32) -> Result<bool, CliprdrError> {
            let response = self
                .process()?
                .request(WorkerCommand::EmptyClipboard { conn_id })
                .map_err(cliprdr_worker_error)?;
            response
                .bool_value
                .ok_or_else(|| CliprdrError::CommonError {
                    description: "CLIPRDR worker returned no bool for empty_clipboard".to_owned(),
                })
        }

        fn server_clip_file(
            &mut self,
            conn_id: i32,
            msg: ClipboardFile,
        ) -> Result<(), CliprdrError> {
            self.process()?
                .request(WorkerCommand::ServerClipFile { conn_id, msg })
                .map(|_| ())
                .map_err(cliprdr_worker_error)
        }

        fn get_progress_percent(&self) -> Option<ProgressPercent> {
            None
        }

        fn cancel(&mut self) {
            if let Ok(mut process) = self.process() {
                let _ = process.request(WorkerCommand::Cancel);
            }
        }
    }

    fn cliprdr_worker_error(err: hbb_common::anyhow::Error) -> CliprdrError {
        CliprdrError::CommonError {
            description: format!("CLIPRDR worker failed: {err}"),
        }
    }

    struct CliprdrWorkerProcess {
        child: Child,
        _process_guard: hbb_common::native_worker_sandbox::WorkerProcessGuard,
        command_tx: mpsc::SyncSender<ParentCommand>,
        pending: PendingResponses,
        next_seq: u64,
        response_timeout: Duration,
    }

    impl Drop for CliprdrWorkerProcess {
        fn drop(&mut self) {
            clear_parent_command_sender();
            self.kill_child();
        }
    }

    impl CliprdrWorkerProcess {
        fn spawn(response_wait_timeout_secs: u32) -> ResultType<Self> {
            let exe = std::env::current_exe().map_err(|e| {
                anyhow!("failed to resolve current executable for CLIPRDR worker: {e}")
            })?;
            let mut command = Command::new(exe);
            command
                .arg(WORKER_ARG)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null());
            hbb_common::native_worker_sandbox::apply_to_command(&mut command);
            let mut child = command
                .spawn()
                .map_err(|e| anyhow!("failed to spawn CLIPRDR worker: {e}"))?;
            let process_guard =
                match hbb_common::native_worker_sandbox::apply_to_spawned_child(&mut child) {
                    Ok(process_guard) => process_guard,
                    Err(err) => {
                        let _ = child.kill();
                        let _ = child.wait();
                        return Err(anyhow!("failed to constrain CLIPRDR worker: {err}"));
                    }
                };
            let stdin = child
                .stdin
                .take()
                .ok_or_else(|| anyhow!("CLIPRDR worker stdin unavailable"))?;
            let stdout = child
                .stdout
                .take()
                .ok_or_else(|| anyhow!("CLIPRDR worker stdout unavailable"))?;
            let pending = Arc::new(Mutex::new(HashMap::new()));
            let command_tx = spawn_parent_writer(stdin, pending.clone())?;
            spawn_parent_reader(stdout, pending.clone())?;
            install_parent_command_sender(command_tx.clone());
            Ok(Self {
                child,
                _process_guard: process_guard,
                command_tx,
                pending,
                next_seq: 0,
                response_timeout: Duration::from_secs(
                    u64::from(response_wait_timeout_secs)
                        .saturating_add(WORKER_RESPONSE_GRACE_SECS),
                ),
            })
        }

        fn request(&mut self, command: WorkerCommand) -> ResultType<WorkerResponse> {
            self.next_seq = self
                .next_seq
                .checked_add(1)
                .ok_or_else(|| anyhow!("CLIPRDR worker request sequence exhausted"))?;
            let seq = self.next_seq;
            let (reply_tx, reply_rx) = mpsc::channel();
            {
                let mut pending = self
                    .pending
                    .lock()
                    .map_err(|_| anyhow!("CLIPRDR worker pending map lock poisoned"))?;
                pending.insert(seq, reply_tx);
            }
            if let Err(err) = self.command_tx.send(ParentCommand { seq, command }) {
                remove_pending(&self.pending, seq);
                return Err(anyhow!("CLIPRDR worker command thread unavailable: {err}"));
            }
            match reply_rx.recv_timeout(self.response_timeout) {
                Ok(Ok(response)) => Ok(response),
                Ok(Err(err)) => Err(anyhow!("{err}")),
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    remove_pending(&self.pending, seq);
                    self.kill_child();
                    Err(anyhow!(
                        "CLIPRDR worker timed out after {:?}; killed child",
                        self.response_timeout
                    ))
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    remove_pending(&self.pending, seq);
                    self.kill_child();
                    Err(anyhow!("CLIPRDR worker reader exited without a response"))
                }
            }
        }

        fn kill_child(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    type PendingResponses = Arc<Mutex<HashMap<u64, mpsc::Sender<Result<WorkerResponse, String>>>>>;

    struct ParentCommand {
        seq: u64,
        command: WorkerCommand,
    }

    fn spawn_parent_writer(
        mut stdin: ChildStdin,
        pending: PendingResponses,
    ) -> ResultType<mpsc::SyncSender<ParentCommand>> {
        let (tx, rx) = mpsc::sync_channel::<ParentCommand>(1);
        std::thread::Builder::new()
            .name("rd-cliprdr-worker-in".to_owned())
            .spawn(move || {
                while let Ok(command) = rx.recv() {
                    if let Err(err) = write_command_frame(&mut stdin, command.seq, &command.command)
                    {
                        complete_pending(
                            &pending,
                            command.seq,
                            Err(format!("failed to write CLIPRDR worker command: {err}")),
                        );
                        fail_all_pending(
                            &pending,
                            "CLIPRDR worker command writer exited".to_owned(),
                        );
                        break;
                    }
                    if let Err(err) = stdin.flush() {
                        complete_pending(
                            &pending,
                            command.seq,
                            Err(format!("failed to flush CLIPRDR worker command: {err}")),
                        );
                        fail_all_pending(
                            &pending,
                            "CLIPRDR worker command writer exited".to_owned(),
                        );
                        break;
                    }
                }
            })
            .map_err(|e| anyhow!("failed to spawn CLIPRDR worker command thread: {e}"))?;
        Ok(tx)
    }

    fn spawn_parent_reader(mut stdout: ChildStdout, pending: PendingResponses) -> ResultType<()> {
        std::thread::Builder::new()
            .name("rd-cliprdr-worker-events".to_owned())
            .spawn(move || loop {
                match read_output_frame(&mut stdout) {
                    Ok(Some(WorkerOutput::Response { seq, response })) => {
                        complete_pending(&pending, seq, response);
                    }
                    Ok(Some(WorkerOutput::SendData { conn_id, data })) => {
                        if let Err(err) = dispatch_send_data(conn_id, data) {
                            hbb_common::log::warn!(
                                "failed to dispatch CLIPRDR worker send_data event: {err}"
                            );
                        }
                    }
                    Ok(Some(WorkerOutput::SendDataExclude { conn_id, data })) => {
                        dispatch_send_data_exclude(conn_id, data);
                    }
                    Ok(None) => {
                        fail_all_pending(&pending, "CLIPRDR worker stdout closed".to_owned());
                        break;
                    }
                    Err(err) => {
                        fail_all_pending(
                            &pending,
                            format!("failed to read CLIPRDR worker output: {err}"),
                        );
                        break;
                    }
                }
            })
            .map_err(|e| anyhow!("failed to spawn CLIPRDR worker reader thread: {e}"))?;
        Ok(())
    }

    fn complete_pending(
        pending: &PendingResponses,
        seq: u64,
        response: Result<WorkerResponse, String>,
    ) {
        let Some(tx) = remove_pending(pending, seq) else {
            return;
        };
        let _ = tx.send(response);
    }

    fn remove_pending(
        pending: &PendingResponses,
        seq: u64,
    ) -> Option<mpsc::Sender<Result<WorkerResponse, String>>> {
        pending.lock().ok()?.remove(&seq)
    }

    fn fail_all_pending(pending: &PendingResponses, reason: String) {
        let responses = match pending.lock() {
            Ok(mut pending) => pending.drain().map(|(_, tx)| tx).collect::<Vec<_>>(),
            Err(_) => return,
        };
        for tx in responses {
            let _ = tx.send(Err(reason.clone()));
        }
    }

    fn child_command_loop<R: Read>(
        mut input: R,
        output_tx: SyncSender<WorkerOutput>,
    ) -> ResultType<()> {
        let mut context = None;
        loop {
            let Some((seq, command)) = read_command_frame(&mut input)? else {
                return Ok(());
            };
            let response = match command {
                WorkerCommand::Init {
                    enable_files,
                    enable_others,
                    response_wait_timeout_secs,
                } => match create_in_process_cliprdr_context(
                    enable_files,
                    enable_others,
                    response_wait_timeout_secs,
                ) {
                    Ok(created) => {
                        context = Some(created);
                        Ok(WorkerResponse::unit())
                    }
                    Err(err) => Err(err.to_string()),
                },
                WorkerCommand::SetStopped => with_context(&mut context, |context| {
                    context.set_is_stopped().map(|_| WorkerResponse::unit())
                }),
                WorkerCommand::EmptyClipboard { conn_id } => {
                    super::clear_pending_cliprdr_conn_local(conn_id);
                    with_context(&mut context, |context| {
                        context
                            .empty_clipboard(conn_id)
                            .map(WorkerResponse::bool_value)
                    })
                }
                WorkerCommand::ServerClipFile { conn_id, msg } => {
                    with_context(&mut context, |context| {
                        context
                            .server_clip_file(conn_id, msg)
                            .map(|_| WorkerResponse::unit())
                    })
                }
                WorkerCommand::Cancel => with_context(&mut context, |context| {
                    context.cancel();
                    Ok(WorkerResponse::unit())
                }),
                WorkerCommand::ClearPendingConn { conn_id } => {
                    super::clear_pending_cliprdr_conn_local(conn_id);
                    Ok(WorkerResponse::unit())
                }
            };
            output_tx
                .send(WorkerOutput::Response { seq, response })
                .map_err(|e| anyhow!("CLIPRDR worker output channel unavailable: {e}"))?;
        }
    }

    fn with_context<F>(
        context: &mut Option<Box<super::CliprdrClientContext>>,
        f: F,
    ) -> Result<WorkerResponse, String>
    where
        F: FnOnce(&mut Box<super::CliprdrClientContext>) -> Result<WorkerResponse, CliprdrError>,
    {
        let Some(context) = context.as_mut() else {
            return Err("CLIPRDR worker context is not initialized".to_owned());
        };
        f(context).map_err(|err| err.to_string())
    }

    fn child_output_loop<W: Write>(
        mut output: W,
        output_rx: mpsc::Receiver<WorkerOutput>,
    ) -> ResultType<()> {
        while let Ok(output_frame) = output_rx.recv() {
            write_output_frame(&mut output, &output_frame)?;
            output
                .flush()
                .map_err(|e| anyhow!("failed to flush CLIPRDR worker output: {e}"))?;
        }
        Ok(())
    }

    enum WorkerCommand {
        Init {
            enable_files: bool,
            enable_others: bool,
            response_wait_timeout_secs: u32,
        },
        SetStopped,
        EmptyClipboard {
            conn_id: i32,
        },
        ServerClipFile {
            conn_id: i32,
            msg: ClipboardFile,
        },
        Cancel,
        ClearPendingConn {
            conn_id: i32,
        },
    }

    #[derive(Clone)]
    struct WorkerResponse {
        bool_value: Option<bool>,
    }

    impl WorkerResponse {
        fn unit() -> Self {
            Self { bool_value: None }
        }

        fn bool_value(value: bool) -> Self {
            Self {
                bool_value: Some(value),
            }
        }
    }

    enum WorkerOutput {
        Response {
            seq: u64,
            response: Result<WorkerResponse, String>,
        },
        SendData {
            conn_id: i32,
            data: ClipboardFile,
        },
        SendDataExclude {
            conn_id: i32,
            data: ClipboardFile,
        },
    }

    fn write_command_frame<W: Write>(
        writer: &mut W,
        seq: u64,
        command: &WorkerCommand,
    ) -> ResultType<()> {
        let mut payload = Vec::new();
        let op = encode_command(&mut payload, command)?;
        write_frame(writer, COMMAND_MAGIC, op, seq, &payload)
    }

    fn read_command_frame<R: Read>(reader: &mut R) -> io::Result<Option<(u64, WorkerCommand)>> {
        let Some((op, seq, payload)) = read_frame(reader, COMMAND_MAGIC)? else {
            return Ok(None);
        };
        let mut cursor = Cursor::new(payload);
        let command = decode_command(op, &mut cursor)?;
        ensure_consumed(&cursor)?;
        Ok(Some((seq, command)))
    }

    fn write_output_frame<W: Write>(writer: &mut W, output: &WorkerOutput) -> ResultType<()> {
        let mut payload = Vec::new();
        let (op, seq) = encode_output(&mut payload, output)?;
        write_frame(writer, OUTPUT_MAGIC, op, seq, &payload)
    }

    fn read_output_frame<R: Read>(reader: &mut R) -> io::Result<Option<WorkerOutput>> {
        let Some((op, seq, payload)) = read_frame(reader, OUTPUT_MAGIC)? else {
            return Ok(None);
        };
        let mut cursor = Cursor::new(payload);
        let output = decode_output(op, seq, &mut cursor)?;
        ensure_consumed(&cursor)?;
        Ok(Some(output))
    }

    fn write_frame<W: Write>(
        writer: &mut W,
        magic: [u8; 4],
        op: u8,
        seq: u64,
        payload: &[u8],
    ) -> ResultType<()> {
        if payload.len() > MAX_WORKER_FRAME_BYTES {
            bail!(
                "CLIPRDR worker frame too large: {} > {}",
                payload.len(),
                MAX_WORKER_FRAME_BYTES
            );
        }
        writer.write_all(&magic)?;
        writer.write_all(&[PROTOCOL_VERSION, op])?;
        writer.write_all(&seq.to_le_bytes())?;
        writer.write_all(
            &u32::try_from(payload.len())
                .map_err(|_| anyhow!("CLIPRDR worker payload length overflow"))?
                .to_le_bytes(),
        )?;
        writer.write_all(payload)?;
        Ok(())
    }

    fn read_frame<R: Read>(
        reader: &mut R,
        expected_magic: [u8; 4],
    ) -> io::Result<Option<(u8, u64, Vec<u8>)>> {
        let mut magic = [0u8; 4];
        if !read_exact_or_eof(reader, &mut magic)? {
            return Ok(None);
        }
        if magic != expected_magic {
            return invalid_data("bad CLIPRDR worker frame magic");
        }
        let version = read_u8(reader)?;
        if version != PROTOCOL_VERSION {
            return invalid_data("unsupported CLIPRDR worker protocol version");
        }
        let op = read_u8(reader)?;
        let seq = read_u64(reader)?;
        let len = read_u32(reader)? as usize;
        if len > MAX_WORKER_FRAME_BYTES {
            return invalid_data("oversized CLIPRDR worker frame");
        }
        let mut payload = vec![0u8; len];
        reader.read_exact(&mut payload)?;
        Ok(Some((op, seq, payload)))
    }

    fn encode_command(buf: &mut Vec<u8>, command: &WorkerCommand) -> ResultType<u8> {
        match command {
            WorkerCommand::Init {
                enable_files,
                enable_others,
                response_wait_timeout_secs,
            } => {
                put_bool(buf, *enable_files);
                put_bool(buf, *enable_others);
                put_u32(buf, *response_wait_timeout_secs);
                Ok(OP_INIT)
            }
            WorkerCommand::SetStopped => Ok(OP_SET_STOPPED),
            WorkerCommand::EmptyClipboard { conn_id } => {
                put_i32(buf, *conn_id);
                Ok(OP_EMPTY_CLIPBOARD)
            }
            WorkerCommand::ServerClipFile { conn_id, msg } => {
                put_i32(buf, *conn_id);
                encode_clipboard_file(buf, msg)?;
                Ok(OP_SERVER_CLIP_FILE)
            }
            WorkerCommand::Cancel => Ok(OP_CANCEL),
            WorkerCommand::ClearPendingConn { conn_id } => {
                put_i32(buf, *conn_id);
                Ok(OP_CLEAR_PENDING_CONN)
            }
        }
    }

    fn decode_command(op: u8, cursor: &mut Cursor<Vec<u8>>) -> io::Result<WorkerCommand> {
        match op {
            OP_INIT => Ok(WorkerCommand::Init {
                enable_files: get_bool(cursor)?,
                enable_others: get_bool(cursor)?,
                response_wait_timeout_secs: get_u32(cursor)?,
            }),
            OP_SET_STOPPED => Ok(WorkerCommand::SetStopped),
            OP_EMPTY_CLIPBOARD => Ok(WorkerCommand::EmptyClipboard {
                conn_id: get_i32(cursor)?,
            }),
            OP_SERVER_CLIP_FILE => Ok(WorkerCommand::ServerClipFile {
                conn_id: get_i32(cursor)?,
                msg: decode_clipboard_file(cursor)?,
            }),
            OP_CANCEL => Ok(WorkerCommand::Cancel),
            OP_CLEAR_PENDING_CONN => Ok(WorkerCommand::ClearPendingConn {
                conn_id: get_i32(cursor)?,
            }),
            _ => invalid_data("unsupported CLIPRDR worker command"),
        }
    }

    fn encode_output(buf: &mut Vec<u8>, output: &WorkerOutput) -> ResultType<(u8, u64)> {
        match output {
            WorkerOutput::Response { seq, response } => {
                encode_response(buf, response)?;
                Ok((OUT_RESPONSE, *seq))
            }
            WorkerOutput::SendData { conn_id, data } => {
                put_i32(buf, *conn_id);
                encode_clipboard_file(buf, data)?;
                Ok((OUT_SEND_DATA, 0))
            }
            WorkerOutput::SendDataExclude { conn_id, data } => {
                put_i32(buf, *conn_id);
                encode_clipboard_file(buf, data)?;
                Ok((OUT_SEND_DATA_EXCLUDE, 0))
            }
        }
    }

    fn decode_output(op: u8, seq: u64, cursor: &mut Cursor<Vec<u8>>) -> io::Result<WorkerOutput> {
        match op {
            OUT_RESPONSE => Ok(WorkerOutput::Response {
                seq,
                response: decode_response(cursor)?,
            }),
            OUT_SEND_DATA => Ok(WorkerOutput::SendData {
                conn_id: get_i32(cursor)?,
                data: decode_clipboard_file(cursor)?,
            }),
            OUT_SEND_DATA_EXCLUDE => Ok(WorkerOutput::SendDataExclude {
                conn_id: get_i32(cursor)?,
                data: decode_clipboard_file(cursor)?,
            }),
            _ => invalid_data("unsupported CLIPRDR worker output"),
        }
    }

    fn encode_response(
        buf: &mut Vec<u8>,
        response: &Result<WorkerResponse, String>,
    ) -> ResultType<()> {
        match response {
            Ok(response) => {
                put_u8(buf, STATUS_OK);
                match response.bool_value {
                    Some(value) => {
                        put_u8(buf, RESPONSE_BOOL);
                        put_bool(buf, value);
                    }
                    None => put_u8(buf, RESPONSE_UNIT),
                }
            }
            Err(err) => {
                put_u8(buf, STATUS_ERROR);
                put_string(buf, err, MAX_WORKER_ERROR_BYTES)?;
            }
        }
        Ok(())
    }

    fn decode_response(cursor: &mut Cursor<Vec<u8>>) -> io::Result<Result<WorkerResponse, String>> {
        match get_u8(cursor)? {
            STATUS_OK => match get_u8(cursor)? {
                RESPONSE_UNIT => Ok(Ok(WorkerResponse::unit())),
                RESPONSE_BOOL => Ok(Ok(WorkerResponse::bool_value(get_bool(cursor)?))),
                _ => invalid_data("unsupported CLIPRDR worker response kind"),
            },
            STATUS_ERROR => Ok(Err(get_string(cursor, MAX_WORKER_ERROR_BYTES)?)),
            _ => invalid_data("unsupported CLIPRDR worker response status"),
        }
    }

    fn encode_clipboard_file(buf: &mut Vec<u8>, msg: &ClipboardFile) -> ResultType<()> {
        match msg {
            ClipboardFile::NotifyCallback {
                r#type,
                title,
                text,
            } => {
                put_u8(buf, CLIP_NOTIFY_CALLBACK);
                put_string(buf, r#type, MAX_NATIVE_CLIPRDR_NOTIFICATION_BYTES)?;
                put_string(buf, title, MAX_NATIVE_CLIPRDR_NOTIFICATION_BYTES)?;
                put_string(buf, text, MAX_NATIVE_CLIPRDR_NOTIFICATION_BYTES)?;
            }
            ClipboardFile::MonitorReady => put_u8(buf, CLIP_MONITOR_READY),
            ClipboardFile::FormatList { format_list } => {
                if format_list.len() > MAX_NATIVE_CLIPRDR_FORMATS {
                    bail!("oversized CLIPRDR worker format list");
                }
                put_u8(buf, CLIP_FORMAT_LIST);
                put_u32_len(buf, format_list.len())?;
                for (id, name) in format_list {
                    put_i32(buf, *id);
                    put_string(buf, name, MAX_NATIVE_CLIPRDR_FORMAT_NAME_BYTES)?;
                }
            }
            ClipboardFile::FormatListResponse { msg_flags } => {
                put_u8(buf, CLIP_FORMAT_LIST_RESPONSE);
                put_i32(buf, *msg_flags);
            }
            ClipboardFile::FormatDataRequest {
                requested_format_id,
            } => {
                put_u8(buf, CLIP_FORMAT_DATA_REQUEST);
                put_i32(buf, *requested_format_id);
            }
            ClipboardFile::FormatDataResponse {
                msg_flags,
                format_data,
            } => {
                put_u8(buf, CLIP_FORMAT_DATA_RESPONSE);
                put_i32(buf, *msg_flags);
                put_bytes(buf, format_data, MAX_NATIVE_CLIPRDR_FORMAT_DATA_BYTES)?;
            }
            ClipboardFile::FileContentsRequest {
                stream_id,
                list_index,
                dw_flags,
                n_position_low,
                n_position_high,
                cb_requested,
                have_clip_data_id,
                clip_data_id,
            } => {
                put_u8(buf, CLIP_FILE_CONTENTS_REQUEST);
                put_i32(buf, *stream_id);
                put_i32(buf, *list_index);
                put_i32(buf, *dw_flags);
                put_i32(buf, *n_position_low);
                put_i32(buf, *n_position_high);
                put_i32(buf, *cb_requested);
                put_bool(buf, *have_clip_data_id);
                put_i32(buf, *clip_data_id);
            }
            ClipboardFile::FileContentsResponse {
                msg_flags,
                stream_id,
                requested_data,
            } => {
                put_u8(buf, CLIP_FILE_CONTENTS_RESPONSE);
                put_i32(buf, *msg_flags);
                put_i32(buf, *stream_id);
                put_bytes(buf, requested_data, MAX_NATIVE_CLIPRDR_FILE_CONTENTS_BYTES)?;
            }
            ClipboardFile::TryEmpty => put_u8(buf, CLIP_TRY_EMPTY),
            ClipboardFile::Files { files } => {
                if files.len() > MAX_NATIVE_CLIPRDR_LOCAL_FILES {
                    bail!("oversized CLIPRDR worker local-file list");
                }
                put_u8(buf, CLIP_FILES);
                put_u32_len(buf, files.len())?;
                for (name, size) in files {
                    put_string(buf, name, max_file_name_bytes())?;
                    put_u64(buf, *size);
                }
            }
        }
        Ok(())
    }

    fn decode_clipboard_file(cursor: &mut Cursor<Vec<u8>>) -> io::Result<ClipboardFile> {
        match get_u8(cursor)? {
            CLIP_NOTIFY_CALLBACK => Ok(ClipboardFile::NotifyCallback {
                r#type: get_string(cursor, MAX_NATIVE_CLIPRDR_NOTIFICATION_BYTES)?,
                title: get_string(cursor, MAX_NATIVE_CLIPRDR_NOTIFICATION_BYTES)?,
                text: get_string(cursor, MAX_NATIVE_CLIPRDR_NOTIFICATION_BYTES)?,
            }),
            CLIP_MONITOR_READY => Ok(ClipboardFile::MonitorReady),
            CLIP_FORMAT_LIST => {
                let count = get_count(cursor, MAX_NATIVE_CLIPRDR_FORMATS)?;
                let mut format_list = Vec::with_capacity(count);
                for _ in 0..count {
                    format_list.push((
                        get_i32(cursor)?,
                        get_string(cursor, MAX_NATIVE_CLIPRDR_FORMAT_NAME_BYTES)?,
                    ));
                }
                Ok(ClipboardFile::FormatList { format_list })
            }
            CLIP_FORMAT_LIST_RESPONSE => Ok(ClipboardFile::FormatListResponse {
                msg_flags: get_i32(cursor)?,
            }),
            CLIP_FORMAT_DATA_REQUEST => Ok(ClipboardFile::FormatDataRequest {
                requested_format_id: get_i32(cursor)?,
            }),
            CLIP_FORMAT_DATA_RESPONSE => Ok(ClipboardFile::FormatDataResponse {
                msg_flags: get_i32(cursor)?,
                format_data: get_bytes(cursor, MAX_NATIVE_CLIPRDR_FORMAT_DATA_BYTES)?,
            }),
            CLIP_FILE_CONTENTS_REQUEST => Ok(ClipboardFile::FileContentsRequest {
                stream_id: get_i32(cursor)?,
                list_index: get_i32(cursor)?,
                dw_flags: get_i32(cursor)?,
                n_position_low: get_i32(cursor)?,
                n_position_high: get_i32(cursor)?,
                cb_requested: get_i32(cursor)?,
                have_clip_data_id: get_bool(cursor)?,
                clip_data_id: get_i32(cursor)?,
            }),
            CLIP_FILE_CONTENTS_RESPONSE => Ok(ClipboardFile::FileContentsResponse {
                msg_flags: get_i32(cursor)?,
                stream_id: get_i32(cursor)?,
                requested_data: get_bytes(cursor, MAX_NATIVE_CLIPRDR_FILE_CONTENTS_BYTES)?,
            }),
            CLIP_TRY_EMPTY => Ok(ClipboardFile::TryEmpty),
            CLIP_FILES => {
                let count = get_count(cursor, MAX_NATIVE_CLIPRDR_LOCAL_FILES)?;
                let mut files = Vec::with_capacity(count);
                for _ in 0..count {
                    files.push((get_string(cursor, max_file_name_bytes())?, get_u64(cursor)?));
                }
                Ok(ClipboardFile::Files { files })
            }
            _ => invalid_data("unsupported CLIPRDR worker ClipboardFile tag"),
        }
    }

    fn max_file_name_bytes() -> usize {
        MAX_NATIVE_CLIPRDR_FILE_NAME_WCHARS.saturating_mul(4)
    }

    fn put_u8(buf: &mut Vec<u8>, value: u8) {
        buf.push(value);
    }

    fn put_bool(buf: &mut Vec<u8>, value: bool) {
        put_u8(buf, u8::from(value));
    }

    fn put_i32(buf: &mut Vec<u8>, value: i32) {
        buf.extend_from_slice(&value.to_le_bytes());
    }

    fn put_u32(buf: &mut Vec<u8>, value: u32) {
        buf.extend_from_slice(&value.to_le_bytes());
    }

    fn put_u64(buf: &mut Vec<u8>, value: u64) {
        buf.extend_from_slice(&value.to_le_bytes());
    }

    fn put_u32_len(buf: &mut Vec<u8>, len: usize) -> ResultType<()> {
        put_u32(
            buf,
            u32::try_from(len).map_err(|_| anyhow!("CLIPRDR worker length overflow"))?,
        );
        Ok(())
    }

    fn put_bytes(buf: &mut Vec<u8>, bytes: &[u8], max: usize) -> ResultType<()> {
        if bytes.len() > max {
            bail!(
                "oversized CLIPRDR worker byte field: {} > {}",
                bytes.len(),
                max
            );
        }
        put_u32_len(buf, bytes.len())?;
        buf.extend_from_slice(bytes);
        Ok(())
    }

    fn put_string(buf: &mut Vec<u8>, value: &str, max: usize) -> ResultType<()> {
        put_bytes(buf, value.as_bytes(), max)
    }

    fn get_u8(cursor: &mut Cursor<Vec<u8>>) -> io::Result<u8> {
        let mut buf = [0u8; 1];
        cursor.read_exact(&mut buf)?;
        Ok(buf[0])
    }

    fn get_bool(cursor: &mut Cursor<Vec<u8>>) -> io::Result<bool> {
        match get_u8(cursor)? {
            0 => Ok(false),
            1 => Ok(true),
            _ => invalid_data("invalid CLIPRDR worker bool"),
        }
    }

    fn get_i32(cursor: &mut Cursor<Vec<u8>>) -> io::Result<i32> {
        Ok(i32::from_le_bytes(get_array::<4>(cursor)?))
    }

    fn get_u32(cursor: &mut Cursor<Vec<u8>>) -> io::Result<u32> {
        Ok(u32::from_le_bytes(get_array::<4>(cursor)?))
    }

    fn get_u64(cursor: &mut Cursor<Vec<u8>>) -> io::Result<u64> {
        Ok(u64::from_le_bytes(get_array::<8>(cursor)?))
    }

    fn get_count(cursor: &mut Cursor<Vec<u8>>, max: usize) -> io::Result<usize> {
        let count = get_u32(cursor)? as usize;
        if count > max {
            return invalid_data("oversized CLIPRDR worker count");
        }
        Ok(count)
    }

    fn get_bytes(cursor: &mut Cursor<Vec<u8>>, max: usize) -> io::Result<Vec<u8>> {
        let len = get_u32(cursor)? as usize;
        if len > max {
            return invalid_data("oversized CLIPRDR worker byte field");
        }
        let mut out = vec![0u8; len];
        cursor.read_exact(&mut out)?;
        Ok(out)
    }

    fn get_string(cursor: &mut Cursor<Vec<u8>>, max: usize) -> io::Result<String> {
        let bytes = get_bytes(cursor, max)?;
        String::from_utf8(bytes)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid UTF-8 string"))
    }

    fn get_array<const N: usize>(cursor: &mut Cursor<Vec<u8>>) -> io::Result<[u8; N]> {
        let mut out = [0u8; N];
        cursor.read_exact(&mut out)?;
        Ok(out)
    }

    fn read_u8<R: Read>(reader: &mut R) -> io::Result<u8> {
        let mut buf = [0u8; 1];
        reader.read_exact(&mut buf)?;
        Ok(buf[0])
    }

    fn read_u32<R: Read>(reader: &mut R) -> io::Result<u32> {
        let mut buf = [0u8; 4];
        reader.read_exact(&mut buf)?;
        Ok(u32::from_le_bytes(buf))
    }

    fn read_u64<R: Read>(reader: &mut R) -> io::Result<u64> {
        let mut buf = [0u8; 8];
        reader.read_exact(&mut buf)?;
        Ok(u64::from_le_bytes(buf))
    }

    fn read_exact_or_eof<R: Read>(reader: &mut R, buf: &mut [u8]) -> io::Result<bool> {
        let mut read = 0usize;
        while read < buf.len() {
            match reader.read(&mut buf[read..])? {
                0 if read == 0 => return Ok(false),
                0 => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "partial CLIPRDR worker frame",
                    ))
                }
                n => read += n,
            }
        }
        Ok(true)
    }

    fn ensure_consumed(cursor: &Cursor<Vec<u8>>) -> io::Result<()> {
        if cursor.position() == cursor.get_ref().len() as u64 {
            Ok(())
        } else {
            invalid_data("trailing CLIPRDR worker frame bytes")
        }
    }

    fn invalid_data<T>(message: &'static str) -> io::Result<T> {
        Err(io::Error::new(io::ErrorKind::InvalidData, message))
    }
}

extern "C" fn notify_callback(conn_id: UINT32, msg: *const NOTIFICATION_MESSAGE) -> UINT {
    log::debug!("notify_callback called");
    if msg.is_null() {
        log::warn!("dropping null Windows CLIPRDR notification callback at FFI bridge");
        return ERR_CODE_INVALID_PARAMETER;
    }

    let data = unsafe {
        let msg = &*msg;
        let details = if msg.details.is_null() {
            Ok(String::new())
        } else {
            bounded_c_string_to_string(msg.details as _, MAX_NATIVE_CLIPRDR_NOTIFICATION_BYTES)
        };
        match (
            bounded_c_string_to_string(msg.msg as _, MAX_NATIVE_CLIPRDR_NOTIFICATION_BYTES),
            details,
        ) {
            (Ok(m), Ok(d)) => {
                let msgtype = format!(
                    "custom-{}-nocancel-nook-hasclose",
                    if msg.r#type == 0 {
                        "info"
                    } else if msg.r#type == 1 {
                        "warn"
                    } else {
                        "error"
                    }
                );
                let title = "Clipboard";
                let text = if d.is_empty() {
                    m.to_string()
                } else {
                    format!("{} {}", m, d)
                };
                ClipboardFile::NotifyCallback {
                    r#type: msgtype,
                    title: title.to_string(),
                    text,
                }
            }
            _ => {
                log::error!("notify_callback: failed to convert bounded msg");
                return ERR_CODE_INVALID_PARAMETER;
            }
        }
    };
    // no need to handle result here
    allow_err!(dispatch_send_data(conn_id as _, data));

    0
}

extern "C" fn handle_clipboard_files(
    conn_id: UINT32,
    n_files: size_t,
    file_names: *mut *mut WCHAR,
) -> UINT {
    if n_files == 0 {
        return 0;
    }
    if file_names.is_null() {
        log::warn!("dropping null Windows CLIPRDR local-file callback at FFI bridge");
        return ERR_CODE_INVALID_PARAMETER;
    }
    if n_files as usize > MAX_NATIVE_CLIPRDR_LOCAL_FILES {
        log::warn!(
            "dropping oversized Windows CLIPRDR local-file callback at FFI bridge: {} > {}",
            n_files,
            MAX_NATIVE_CLIPRDR_LOCAL_FILES
        );
        return ERR_CODE_INVALID_PARAMETER;
    }

    let data = unsafe {
        let mut files = Vec::new();
        use std::ffi::OsString;
        use std::os::windows::ffi::OsStringExt;
        for i in 0..n_files as usize {
            let file_name_ptr = *file_names.offset(i as isize);
            if !file_name_ptr.is_null() {
                let mut len = 0usize;
                while len <= MAX_NATIVE_CLIPRDR_FILE_NAME_WCHARS && *file_name_ptr.add(len) != 0 {
                    len += 1;
                }
                if len > MAX_NATIVE_CLIPRDR_FILE_NAME_WCHARS {
                    log::warn!(
                        "dropping unterminated Windows CLIPRDR local-file path at FFI bridge"
                    );
                    return ERR_CODE_INVALID_PARAMETER;
                }
                let slice = std::slice::from_raw_parts(file_name_ptr, len);
                let os_string = OsString::from_wide(slice);
                match os_string.to_str() {
                    Some(n) => match std::fs::metadata(n) {
                        Ok(meta) => {
                            if meta.is_file() {
                                files.push((n.to_owned(), meta.len()));
                            }
                        }
                        Err(e) => {
                            log::warn!(
                                "handle_clipboard_files: Failed to get metadata for file '{}': {}",
                                n,
                                e
                            );
                        }
                    },
                    None => {
                        log::warn!("handle_clipboard_files: Failed to convert file name to UTF-8");
                    }
                };
            }
        }
        if files.is_empty() {
            return 0;
        }

        ClipboardFile::Files { files }
    };
    // no need to handle result here
    allow_err!(dispatch_send_data(conn_id as _, data));

    0
}

extern "C" fn client_format_list(
    _context: *mut CliprdrClientContext,
    clip_format_list: *const CLIPRDR_FORMAT_LIST,
) -> UINT {
    if clip_format_list.is_null() {
        log::warn!("dropping null Windows CLIPRDR callback format list at FFI bridge");
        return ERR_CODE_INVALID_PARAMETER;
    }

    let conn_id;
    let mut format_list: Vec<(i32, String)> = Vec::new();
    unsafe {
        let num_formats = (*clip_format_list).numFormats as usize;
        if num_formats > MAX_NATIVE_CLIPRDR_FORMATS {
            log::warn!(
                "dropping oversized Windows CLIPRDR callback format list at FFI bridge: {} > {}",
                (*clip_format_list).numFormats,
                MAX_NATIVE_CLIPRDR_FORMATS
            );
            return ERR_CODE_INVALID_PARAMETER;
        }
        if num_formats > 0 && (*clip_format_list).formats.is_null() {
            log::warn!("dropping null Windows CLIPRDR callback format-array at FFI bridge");
            return ERR_CODE_INVALID_PARAMETER;
        }
        let mut i = 0usize;
        while i < num_formats {
            let format_data = &(*(*clip_format_list).formats.offset(i as isize));
            if format_data.formatName.is_null() {
                format_list.push((format_data.formatId as i32, "".to_owned()));
            } else {
                let format_name = match bounded_c_string_to_string(
                    format_data.formatName,
                    MAX_NATIVE_CLIPRDR_FORMAT_NAME_BYTES,
                ) {
                    Ok(n) => n,
                    Err(_) => {
                        log::warn!(
                            "dropping invalid Windows CLIPRDR callback format name at FFI bridge"
                        );
                        return ERR_CODE_INVALID_PARAMETER;
                    }
                };
                format_list.push((format_data.formatId as i32, format_name));
            }
            // log::debug!("format list item {}: format id: {}, format name: {}", i, format_data.formatId, &format_name);
            i += 1;
        }
        conn_id = (*clip_format_list).connID as i32;
    }
    log::debug!(
        "client_format_list called, client id: {}, format_list: {:?}",
        conn_id,
        &format_list
    );
    let data = ClipboardFile::FormatList { format_list };
    // no need to handle result here
    if conn_id == 0 {
        dispatch_send_data_exclude(conn_id, data);
    } else {
        match dispatch_send_data(conn_id, data) {
            Ok(_) => {}
            Err(e) => {
                log::error!("failed to send format list: {:?}", e);
                return ERR_CODE_SEND_MSG;
            }
        }
    }

    0
}

extern "C" fn client_format_list_response(
    _context: *mut CliprdrClientContext,
    format_list_response: *const CLIPRDR_FORMAT_LIST_RESPONSE,
) -> UINT {
    if format_list_response.is_null() {
        log::warn!("dropping null Windows CLIPRDR callback format-list response at FFI bridge");
        return ERR_CODE_INVALID_PARAMETER;
    }

    let conn_id;
    let msg_flags;
    unsafe {
        conn_id = (*format_list_response).connID as i32;
        msg_flags = (*format_list_response).msgFlags as i32;
    }
    log::debug!(
        "client_format_list_response called, client id: {}, msg_flags: {}",
        conn_id,
        msg_flags
    );
    let data = ClipboardFile::FormatListResponse { msg_flags };
    match dispatch_send_data(conn_id, data) {
        Ok(_) => 0,
        Err(e) => {
            log::error!("failed to send format list response: {:?}", e);
            ERR_CODE_SEND_MSG
        }
    }
}

extern "C" fn client_format_data_request(
    _context: *mut CliprdrClientContext,
    format_data_request: *const CLIPRDR_FORMAT_DATA_REQUEST,
) -> UINT {
    if format_data_request.is_null() {
        log::warn!("dropping null Windows CLIPRDR callback format-data request at FFI bridge");
        return ERR_CODE_INVALID_PARAMETER;
    }

    let conn_id;
    let requested_format_id;
    unsafe {
        conn_id = (*format_data_request).connID as i32;
        requested_format_id = (*format_data_request).requestedFormatId as i32;
    }
    let data = ClipboardFile::FormatDataRequest {
        requested_format_id,
    };
    log::debug!(
        "client_format_data_request called, conn_id: {}, requested_format_id: {}",
        conn_id,
        requested_format_id
    );
    if !mark_pending_cliprdr_format_data_request(conn_id) {
        return ERR_CODE_INVALID_PARAMETER;
    }
    match dispatch_send_data(conn_id, data) {
        Ok(_) => 0,
        Err(e) => {
            unmark_pending_cliprdr_format_data_request(conn_id);
            log::error!("failed to send format data request: {:?}", e);
            ERR_CODE_SEND_MSG
        }
    }
}

extern "C" fn client_format_data_response(
    _context: *mut CliprdrClientContext,
    format_data_response: *const CLIPRDR_FORMAT_DATA_RESPONSE,
) -> UINT {
    if format_data_response.is_null() {
        log::warn!("dropping null Windows CLIPRDR callback format-data response at FFI bridge");
        return ERR_CODE_INVALID_PARAMETER;
    }

    let conn_id;
    let msg_flags;
    let format_data;
    unsafe {
        conn_id = (*format_data_response).connID as i32;
        msg_flags = (*format_data_response).msgFlags as i32;
        let data_len = (*format_data_response).dataLen as usize;
        if data_len > MAX_NATIVE_CLIPRDR_FORMAT_DATA_BYTES {
            log::warn!(
                "dropping oversized Windows CLIPRDR callback format data at FFI bridge: {} > {}",
                (*format_data_response).dataLen,
                MAX_NATIVE_CLIPRDR_FORMAT_DATA_BYTES
            );
            return ERR_CODE_INVALID_PARAMETER;
        }
        if data_len > 0 && (*format_data_response).requestedFormatData.is_null() {
            log::warn!("dropping null Windows CLIPRDR callback format-data payload at FFI bridge");
            return ERR_CODE_INVALID_PARAMETER;
        }
        if data_len == 0 {
            format_data = Vec::new();
        } else {
            format_data =
                std::slice::from_raw_parts((*format_data_response).requestedFormatData, data_len)
                    .to_vec();
        }
    }
    log::debug!(
        "client_format_data_response called, client id: {}, msg_flags: {}",
        conn_id,
        msg_flags
    );
    let data = ClipboardFile::FormatDataResponse {
        msg_flags,
        format_data,
    };
    match dispatch_send_data(conn_id, data) {
        Ok(_) => 0,
        Err(e) => {
            log::error!("failed to send format data response: {:?}", e);
            ERR_CODE_SEND_MSG
        }
    }
}

extern "C" fn client_file_contents_request(
    _context: *mut CliprdrClientContext,
    file_contents_request: *const CLIPRDR_FILE_CONTENTS_REQUEST,
) -> UINT {
    if file_contents_request.is_null() {
        log::warn!("dropping null Windows CLIPRDR callback file-content request at FFI bridge");
        return ERR_CODE_INVALID_PARAMETER;
    }

    // TODO: support huge file?
    // if (!cliprdr->hasHugeFileSupport)
    // {
    // 	if (((UINT64)fileContentsRequest->cbRequested + fileContentsRequest->nPositionLow) >
    // 	    UINT32_MAX)
    // 		return ERROR_INVALID_PARAMETER;
    // 	if (fileContentsRequest->nPositionHigh != 0)
    // 		return ERROR_INVALID_PARAMETER;
    // }

    let conn_id;
    let stream_id;
    let list_index;
    let dw_flags;
    let n_position_low;
    let n_position_high;
    let cb_requested_raw;
    let have_clip_data_id;
    let clip_data_id;
    unsafe {
        conn_id = (*file_contents_request).connID as i32;
        stream_id = (*file_contents_request).streamId as i32;
        list_index = (*file_contents_request).listIndex as i32;
        dw_flags = (*file_contents_request).dwFlags as i32;
        n_position_low = (*file_contents_request).nPositionLow as i32;
        n_position_high = (*file_contents_request).nPositionHigh as i32;
        cb_requested_raw = (*file_contents_request).cbRequested as usize;
        have_clip_data_id = (*file_contents_request).haveClipDataId == TRUE;
        clip_data_id = (*file_contents_request).clipDataId as i32;
    }
    if cb_requested_raw > MAX_NATIVE_CLIPRDR_FILE_CONTENTS_BYTES {
        log::warn!(
            "dropping oversized Windows CLIPRDR callback file-content request at FFI bridge: {} > {}",
            cb_requested_raw,
            MAX_NATIVE_CLIPRDR_FILE_CONTENTS_BYTES
        );
        return ERR_CODE_INVALID_PARAMETER;
    }
    let cb_requested = cb_requested_raw as i32;
    if !mark_pending_cliprdr_file_contents_request(conn_id, stream_id, cb_requested_raw) {
        return ERR_CODE_INVALID_PARAMETER;
    }
    let data = ClipboardFile::FileContentsRequest {
        stream_id,
        list_index,
        dw_flags,
        n_position_low,
        n_position_high,
        cb_requested,
        have_clip_data_id,
        clip_data_id,
    };
    log::debug!("client_file_contents_request called, data: {:?}", &data);
    match dispatch_send_data(conn_id, data) {
        Ok(_) => 0,
        Err(e) => {
            unmark_pending_cliprdr_file_contents_request(conn_id, stream_id);
            log::error!("failed to send file contents request: {:?}", e);
            ERR_CODE_SEND_MSG
        }
    }
}

extern "C" fn client_file_contents_response(
    _context: *mut CliprdrClientContext,
    file_contents_response: *const CLIPRDR_FILE_CONTENTS_RESPONSE,
) -> UINT {
    if file_contents_response.is_null() {
        log::warn!("dropping null Windows CLIPRDR callback file-content response at FFI bridge");
        return ERR_CODE_INVALID_PARAMETER;
    }

    let conn_id;
    let msg_flags;
    let stream_id;
    let requested_data;
    unsafe {
        conn_id = (*file_contents_response).connID as i32;
        msg_flags = (*file_contents_response).msgFlags as i32;
        stream_id = (*file_contents_response).streamId as i32;
        let data_len = (*file_contents_response).cbRequested as usize;
        if data_len > MAX_NATIVE_CLIPRDR_FILE_CONTENTS_BYTES {
            log::warn!(
                "dropping oversized Windows CLIPRDR callback file contents at FFI bridge: {} > {}",
                (*file_contents_response).cbRequested,
                MAX_NATIVE_CLIPRDR_FILE_CONTENTS_BYTES
            );
            return ERR_CODE_INVALID_PARAMETER;
        }
        if data_len > 0 && (*file_contents_response).requestedData.is_null() {
            log::warn!("dropping null Windows CLIPRDR callback file-content payload at FFI bridge");
            return ERR_CODE_INVALID_PARAMETER;
        }
        if data_len == 0 {
            requested_data = Vec::new();
        } else {
            requested_data =
                std::slice::from_raw_parts((*file_contents_response).requestedData, data_len)
                    .to_vec();
        }
    }
    let data = ClipboardFile::FileContentsResponse {
        msg_flags,
        stream_id,
        requested_data,
    };
    log::debug!(
        "client_file_contents_response called, conn_id: {}, msg_flags: {}, stream_id: {}",
        conn_id,
        msg_flags,
        stream_id
    );
    match dispatch_send_data(conn_id, data) {
        Ok(_) => 0,
        Err(e) => {
            log::error!("failed to send file contents response: {:?}", e);
            ERR_CODE_SEND_MSG
        }
    }
}
