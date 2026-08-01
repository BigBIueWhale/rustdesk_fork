use super::{PrivacyMode, INVALID_PRIVACY_MODE_CONN_ID};
use crate::{
    platform::windows::{get_current_process_session_id, get_user_token},
    privacy_mode::PrivacyModeState,
};
use hbb_common::{allow_err, bail, log, ResultType};
use std::{
    ffi::CString,
    io::Error,
    mem,
    os::windows::ffi::OsStrExt,
    ptr::null_mut,
    time::{Duration, Instant},
};
use winapi::{
    ctypes::c_void,
    shared::{
        minwindef::FALSE,
        ntdef::{HANDLE, NULL},
        winerror::WAIT_TIMEOUT,
        windef::HWND,
    },
    um::{
        handleapi::CloseHandle,
        jobapi2::{AssignProcessToJobObject, CreateJobObjectW, SetInformationJobObject},
        libloaderapi::{GetModuleHandleA, GetProcAddress},
        memoryapi::{VirtualAllocEx, WriteProcessMemory},
        processthreadsapi::{
            CreateProcessAsUserW, QueueUserAPC, ResumeThread, TerminateProcess,
            PROCESS_INFORMATION, STARTUPINFOW,
        },
        synchapi::WaitForSingleObject,
        userenv::{CreateEnvironmentBlock, DestroyEnvironmentBlock},
        winbase::{
            CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, DETACHED_PROCESS, WAIT_OBJECT_0,
        },
        winnt::{
            JobObjectExtendedLimitInformation, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, MEM_COMMIT, PAGE_READWRITE,
        },
        winuser::*,
    },
};

pub(super) const PRIVACY_MODE_IMPL: &str = "privacy_mode_impl_mag";

pub const INJECTED_PROCESS_EXE: &'static str = "RuntimeBroker_rustdesk.exe";
pub(super) const PRIVACY_WINDOW_NAME: &'static str = "RustDeskPrivacyWindow";

struct PrivacyBrokerLaunchToken(HANDLE);

impl PrivacyBrokerLaunchToken {
    fn as_raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for PrivacyBrokerLaunchToken {
    fn drop(&mut self) {
        unsafe {
            if CloseHandle(self.0) == FALSE {
                log::warn!(
                    "Failed to close privacy broker launch token: {}",
                    Error::last_os_error()
                );
            }
        }
    }
}

struct PrivacyBrokerEnvironment(*mut c_void);

impl PrivacyBrokerEnvironment {
    fn for_token(token: HANDLE, session_id: u32) -> ResultType<Self> {
        let mut environment = null_mut();
        if unsafe { CreateEnvironmentBlock(&mut environment, token, FALSE) } == FALSE {
            bail!(
                "Failed to create environment for privacy broker session {session_id}: {}",
                Error::last_os_error()
            );
        }
        if environment.is_null() {
            bail!("Created null environment for privacy broker session {session_id}");
        }
        Ok(Self(environment))
    }

    fn as_ptr(&self) -> *mut c_void {
        self.0
    }
}

impl Drop for PrivacyBrokerEnvironment {
    fn drop(&mut self) {
        unsafe {
            if DestroyEnvironmentBlock(self.0) == FALSE {
                log::warn!(
                    "Failed to destroy privacy broker environment: {}",
                    Error::last_os_error()
                );
            }
        }
    }
}

struct WindowHandlers {
    hjob: u64,
    hthread: u64,
    hprocess: u64,
    process_id: u32,
    job_assigned: bool,
}

impl Drop for WindowHandlers {
    fn drop(&mut self) {
        self.reset();
    }
}

impl WindowHandlers {
    fn reset(&mut self) {
        unsafe {
            let mut job_closed = false;
            if self.hjob != 0 {
                if CloseHandle(self.hjob as _) == 0 {
                    log::error!(
                        "Failed to close privacy broker job: {}",
                        Error::last_os_error()
                    );
                } else {
                    job_closed = true;
                }
            }
            if self.hprocess != 0 && (!self.job_assigned || !job_closed) {
                if TerminateProcess(self.hprocess as _, 0) == FALSE {
                    log::warn!(
                        "Failed to terminate exact privacy broker process: {}",
                        Error::last_os_error()
                    );
                }
            }
            self.hjob = 0;
            self.job_assigned = false;
            if self.hthread != 0 {
                if CloseHandle(self.hthread as _) == FALSE {
                    log::warn!(
                        "Failed to close privacy broker thread handle: {}",
                        Error::last_os_error()
                    );
                }
            }
            self.hthread = 0;
            if self.hprocess != 0 {
                if CloseHandle(self.hprocess as _) == FALSE {
                    log::warn!(
                        "Failed to close privacy broker process handle: {}",
                        Error::last_os_error()
                    );
                }
            }
            self.hprocess = 0;
            self.process_id = 0;
        }
    }

    fn is_default(&self) -> bool {
        self.hjob == 0 && self.hthread == 0 && self.hprocess == 0
    }

    fn owned_live_process_id(&self) -> ResultType<u32> {
        if self.hjob == 0
            || self.hthread == 0
            || self.hprocess == 0
            || self.process_id == 0
            || !self.job_assigned
        {
            bail!("Privacy broker process is not fully owned");
        }
        match unsafe { WaitForSingleObject(self.hprocess as _, 0) } {
            WAIT_TIMEOUT => Ok(self.process_id),
            WAIT_OBJECT_0 => bail!("Owned privacy broker process has exited"),
            _ => bail!(
                "Failed to query owned privacy broker liveness: {}",
                Error::last_os_error()
            ),
        }
    }
}

unsafe fn create_privacy_broker_job() -> ResultType<HANDLE> {
    let job = CreateJobObjectW(null_mut(), null_mut());
    if job.is_null() {
        bail!("Failed to create privacy broker job: {}", Error::last_os_error());
    }
    let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = mem::zeroed();
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if SetInformationJobObject(
        job,
        JobObjectExtendedLimitInformation,
        &mut limits as *mut _ as *mut c_void,
        mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
    ) == FALSE
    {
        let err = Error::last_os_error();
        if CloseHandle(job) == FALSE {
            log::warn!(
                "Failed to close unconfigured privacy broker job: {}",
                Error::last_os_error()
            );
        }
        bail!("Failed to configure privacy broker job: {err}");
    }
    Ok(job)
}

pub struct PrivacyModeImpl {
    impl_key: String,
    conn_id: i32,
    handlers: WindowHandlers,
}

impl PrivacyMode for PrivacyModeImpl {
    fn is_async_privacy_mode(&self) -> bool {
        false
    }

    fn init(&self) -> ResultType<()> {
        Ok(())
    }

    fn clear(&mut self) {
        allow_err!(self.turn_off_privacy(self.conn_id, None));
    }

    fn turn_on_privacy(&mut self, conn_id: i32) -> ResultType<bool> {
        if self.check_on_conn_id(conn_id)? {
            log::debug!("Privacy mode of conn {} is already on", conn_id);
            return Ok(true);
        }

        let exe_file = std::env::current_exe()?;
        if let Some(cur_dir) = exe_file.parent() {
            if !cur_dir.join("WindowInjection.dll").exists() {
                return Ok(false);
            }
        } else {
            bail!(
                "Invalid exe parent for {}",
                exe_file.to_string_lossy().as_ref()
            );
        }

        self.start()?;

        let hwnd = wait_find_privacy_hwnd(&self.handlers, 0)?;
        if hwnd.is_null() {
            bail!("No privacy window created");
        }
        super::win_input::hook()?;
        unsafe {
            ShowWindow(hwnd as _, SW_SHOW);
        }
        self.conn_id = conn_id;
        Ok(true)
    }

    fn turn_off_privacy(
        &mut self,
        conn_id: i32,
        state: Option<PrivacyModeState>,
    ) -> ResultType<()> {
        self.check_off_conn_id(conn_id)?;
        super::win_input::unhook()?;

        match wait_find_privacy_hwnd(&self.handlers, 0) {
            Ok(hwnd) => unsafe {
                if !hwnd.is_null() {
                    ShowWindow(hwnd, SW_HIDE);
                }
            },
            Err(err) => {
                log::warn!("Privacy broker was not live during privacy teardown: {err}");
                self.handlers.reset();
            }
        }

        if self.conn_id != INVALID_PRIVACY_MODE_CONN_ID {
            if let Some(state) = state {
                allow_err!(super::set_privacy_mode_state(
                    conn_id,
                    state,
                    PRIVACY_MODE_IMPL.to_string(),
                    1_000
                ));
            }
            self.conn_id = INVALID_PRIVACY_MODE_CONN_ID.to_owned();
        }

        Ok(())
    }

    #[inline]
    fn pre_conn_id(&self) -> i32 {
        self.conn_id
    }

    #[inline]
    fn get_impl_key(&self) -> &str {
        &self.impl_key
    }
}

impl PrivacyModeImpl {
    pub fn new(impl_key: &str) -> Self {
        Self {
            impl_key: impl_key.to_owned(),
            conn_id: INVALID_PRIVACY_MODE_CONN_ID,
            handlers: WindowHandlers {
                hjob: 0,
                hthread: 0,
                hprocess: 0,
                process_id: 0,
                job_assigned: false,
            },
        }
    }

    pub fn start(&mut self) -> ResultType<()> {
        if !self.handlers.is_default() {
            match self.handlers.owned_live_process_id() {
                Ok(_) => return Ok(()),
                Err(err) => {
                    log::warn!("Replacing exited or incomplete privacy broker: {err}");
                    self.handlers.reset();
                }
            }
        }

        let broker_file = crate::platform::windows::check_update_broker_process()?;
        let Some(cur_dir) = broker_file.parent() else {
            bail!("Privacy broker has no parent directory");
        };

        let dll_file = cur_dir.join("WindowInjection.dll");
        crate::platform::windows::require_existing_file_no_reparse(
            &dll_file,
            "privacy injection DLL",
        )?;

        unsafe {
            let broker_path_utf16: Vec<u16> = broker_file
                .as_os_str()
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();
            let current_dir_utf16: Vec<u16> = cur_dir
                .as_os_str()
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();

            let mut start_info = STARTUPINFOW {
                cb: mem::size_of::<STARTUPINFOW>() as u32,
                lpReserved: NULL as _,
                lpDesktop: NULL as _,
                lpTitle: NULL as _,
                dwX: 0,
                dwY: 0,
                dwXSize: 0,
                dwYSize: 0,
                dwXCountChars: 0,
                dwYCountChars: 0,
                dwFillAttribute: 0,
                dwFlags: 0,
                wShowWindow: 0,
                cbReserved2: 0,
                lpReserved2: NULL as _,
                hStdInput: NULL as _,
                hStdOutput: NULL as _,
                hStdError: NULL as _,
            };
            let mut proc_info = PROCESS_INFORMATION {
                hProcess: NULL as _,
                hThread: NULL as _,
                dwProcessId: 0,
                dwThreadId: 0,
            };

            let mut pending = WindowHandlers {
                hjob: create_privacy_broker_job()? as _,
                hthread: 0,
                hprocess: 0,
                process_id: 0,
                job_assigned: false,
            };

            let session_id = privacy_broker_session_id()?;
            let create_error = {
                let token = get_user_token(session_id, true);
                if token.is_null() {
                    bail!("Failed to get token of privacy broker session {session_id}");
                }
                let token = PrivacyBrokerLaunchToken(token);
                let environment =
                    PrivacyBrokerEnvironment::for_token(token.as_raw(), session_id)?;
                let create_res = CreateProcessAsUserW(
                    token.as_raw(),
                    broker_path_utf16.as_ptr() as _,
                    NULL as _,
                    NULL as _,
                    NULL as _,
                    FALSE,
                    CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | DETACHED_PROCESS,
                    environment.as_ptr(),
                    current_dir_utf16.as_ptr() as _,
                    &mut start_info,
                    &mut proc_info,
                );
                (create_res == FALSE).then(Error::last_os_error)
            };
            if let Some(err) = create_error {
                bail!(
                    "Failed to create privacy window process {}, error {}",
                    broker_file.to_string_lossy().as_ref(),
                    err
                );
            };

            pending.hthread = proc_info.hThread as _;
            pending.hprocess = proc_info.hProcess as _;
            pending.process_id = proc_info.dwProcessId;
            if pending.hthread == 0 || pending.hprocess == 0 || pending.process_id == 0 {
                bail!("Privacy broker launch returned incomplete process identity");
            }
            if AssignProcessToJobObject(pending.hjob as _, proc_info.hProcess) == FALSE {
                bail!(
                    "Failed to assign privacy broker to its owned job: {}",
                    Error::last_os_error()
                );
            }
            pending.job_assigned = true;

            inject_dll(
                proc_info.hProcess,
                proc_info.hThread,
                dll_file.to_string_lossy().as_ref(),
            )?;

            let previous_suspend_count = ResumeThread(proc_info.hThread);
            if previous_suspend_count == u32::MAX {
                bail!(
                    "Failed to create privacy window process, error {}",
                    Error::last_os_error()
                );
            }
            if previous_suspend_count != 1 {
                bail!(
                    "Privacy broker primary thread had unexpected suspend count {previous_suspend_count}"
                );
            }

            let hwnd = wait_find_privacy_hwnd(&pending, 1_000)?;
            if hwnd.is_null() {
                bail!("Failed to get hwnd after started");
            }
            self.handlers = pending;
        }

        Ok(())
    }

    #[inline]
    pub fn stop(&mut self) {
        self.handlers.reset();
    }
}

impl Drop for PrivacyModeImpl {
    fn drop(&mut self) {
        if self.conn_id != INVALID_PRIVACY_MODE_CONN_ID {
            allow_err!(self.turn_off_privacy(self.conn_id, None));
        }
    }
}

fn privacy_broker_session_id() -> ResultType<u32> {
    let Some(session_id) = get_current_process_session_id() else {
        bail!("Failed to get current process session id for privacy broker");
    };
    if session_id == u32::MAX {
        bail!("Invalid current process session id for privacy broker");
    }
    Ok(session_id)
}

unsafe fn inject_dll<'a>(hproc: HANDLE, hthread: HANDLE, dll_file: &'a str) -> ResultType<()> {
    let dll_file_utf16: Vec<u16> = dll_file.encode_utf16().chain(Some(0).into_iter()).collect();

    let buf = VirtualAllocEx(
        hproc,
        NULL as _,
        dll_file_utf16.len() * 2,
        MEM_COMMIT,
        PAGE_READWRITE,
    );
    if buf.is_null() {
        bail!("Failed VirtualAllocEx");
    }

    let mut written: usize = 0;
    if 0 == WriteProcessMemory(
        hproc,
        buf,
        dll_file_utf16.as_ptr() as _,
        dll_file_utf16.len() * 2,
        &mut written,
    ) {
        bail!("Failed WriteProcessMemory");
    }

    let kernel32_modulename = CString::new("kernel32")?;
    let hmodule = GetModuleHandleA(kernel32_modulename.as_ptr() as _);
    if hmodule.is_null() {
        bail!("Failed GetModuleHandleA");
    }

    let load_librarya_name = CString::new("LoadLibraryW")?;
    let load_librarya = GetProcAddress(hmodule, load_librarya_name.as_ptr() as _);
    if load_librarya.is_null() {
        bail!("Failed GetProcAddress of LoadLibraryW");
    }

    if 0 == QueueUserAPC(Some(std::mem::transmute(load_librarya)), hthread, buf as _) {
        bail!("Failed QueueUserAPC");
    }

    Ok(())
}

fn privacy_hwnd_for_process(window_name: &CString, process_id: u32) -> HWND {
    let mut after = NULL as HWND;
    loop {
        let hwnd = unsafe {
            FindWindowExA(
                NULL as _,
                after,
                NULL as _,
                window_name.as_ptr() as _,
            )
        };
        if hwnd.is_null() {
            return NULL as _;
        }
        let mut owner_process_id = 0;
        unsafe {
            GetWindowThreadProcessId(hwnd, &mut owner_process_id);
        }
        if owner_process_id == process_id {
            return hwnd;
        }
        after = hwnd;
    }
}

fn wait_find_privacy_hwnd(handlers: &WindowHandlers, msecs: u128) -> ResultType<HWND> {
    let process_id = handlers.owned_live_process_id()?;
    let tm_begin = Instant::now();
    let wndname = CString::new(PRIVACY_WINDOW_NAME)?;
    loop {
        let hwnd = privacy_hwnd_for_process(&wndname, process_id);
        if !hwnd.is_null() {
            handlers.owned_live_process_id()?;
            return Ok(hwnd);
        }

        if msecs == 0 || tm_begin.elapsed().as_millis() > msecs {
            return Ok(NULL as _);
        }

        std::thread::sleep(Duration::from_millis(100));
    }
}
