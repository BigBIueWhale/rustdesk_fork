use std::process::{Child, Command};

#[cfg(unix)]
pub const WORKER_NOFILE_LIMIT: u64 = 64;
#[cfg(unix)]
pub const WORKER_ADDRESS_SPACE_LIMIT: u64 = 1536 * 1024 * 1024;
#[cfg(unix)]
pub const WORKER_DATA_LIMIT: u64 = 1024 * 1024 * 1024;
#[cfg(unix)]
pub const WORKER_STACK_LIMIT: u64 = 16 * 1024 * 1024;

/// Apply OS-level confinement to hostile-peer native parser workers.
///
/// The worker still runs from the same signed artifact, but Linux children do
/// not need privilege transitions, core dumps, fd fan-out, or unbounded address
/// space. Keep this helper allocation-free inside `pre_exec`.
pub fn apply_to_command(command: &mut Command) {
    apply_to_command_platform(command);
}

/// Keeps post-spawn worker confinement alive for the child lifetime.
///
/// On Windows this owns the Job Object handle. Dropping it closes the handle and,
/// with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, terminates the assigned worker if it
/// is still alive. Other platforms currently carry no post-spawn handle.
#[must_use = "dropping this guard immediately releases the worker process confinement handle"]
pub struct WorkerProcessGuard {
    #[cfg(target_os = "windows")]
    job: winapi::um::winnt::HANDLE,
}

#[cfg(target_os = "windows")]
unsafe impl Send for WorkerProcessGuard {}

impl WorkerProcessGuard {
    #[cfg(not(target_os = "windows"))]
    fn new() -> Self {
        Self {}
    }

    #[cfg(target_os = "windows")]
    fn from_windows_job(job: winapi::um::winnt::HANDLE) -> Self {
        Self { job }
    }
}

#[cfg(target_os = "windows")]
impl Drop for WorkerProcessGuard {
    fn drop(&mut self) {
        unsafe {
            winapi::um::handleapi::CloseHandle(self.job);
        }
    }
}

/// Apply post-spawn confinement to a hostile-peer native parser worker child.
///
/// Linux does all currently-supported child confinement in `pre_exec` and at
/// worker entry. Windows needs the child process handle before it can assign a
/// Job Object, so worker parents must call this immediately after `spawn()`,
/// store the returned guard for the child lifetime, and do both before the child
/// receives hostile-peer bytes.
pub fn apply_to_spawned_child(child: &mut Child) -> std::io::Result<WorkerProcessGuard> {
    apply_to_spawned_child_platform(child)
}

/// Enter the post-exec worker sandbox before hostile-peer bytes are parsed.
///
/// This must run after the worker process has entered its hidden same-artifact
/// role: the filter blocks future exec/process creation, so installing it from
/// `pre_exec` would prevent `Command` from starting the worker binary at all.
pub fn enter_worker_process() -> std::io::Result<()> {
    enter_worker_process_platform()
}

#[cfg(target_os = "linux")]
fn apply_to_command_platform(command: &mut Command) {
    use std::os::unix::process::CommandExt;

    unsafe {
        command.pre_exec(apply_linux_worker_sandbox);
    }
}

#[cfg(all(
    unix,
    not(any(target_os = "linux", target_os = "android", target_os = "ios"))
))]
fn apply_to_command_platform(command: &mut Command) {
    use std::os::unix::process::CommandExt;

    unsafe {
        command.pre_exec(apply_unix_worker_resource_sandbox);
    }
}

#[cfg(target_os = "windows")]
fn apply_to_command_platform(command: &mut Command) {
    use std::os::windows::process::CommandExt;

    command.creation_flags(winapi::um::winbase::CREATE_NO_WINDOW);
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "windows",
    all(
        unix,
        not(any(target_os = "linux", target_os = "android", target_os = "ios"))
    )
)))]
fn apply_to_command_platform(_command: &mut Command) {}

#[cfg(target_os = "linux")]
fn apply_to_spawned_child_platform(_child: &mut Child) -> std::io::Result<WorkerProcessGuard> {
    Ok(WorkerProcessGuard::new())
}

#[cfg(target_os = "windows")]
fn apply_to_spawned_child_platform(child: &mut Child) -> std::io::Result<WorkerProcessGuard> {
    apply_windows_worker_job_limits(child)
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
fn apply_to_spawned_child_platform(_child: &mut Child) -> std::io::Result<WorkerProcessGuard> {
    Ok(WorkerProcessGuard::new())
}

#[cfg(target_os = "linux")]
fn enter_worker_process_platform() -> std::io::Result<()> {
    close_inherited_worker_fds()?;
    apply_linux_worker_syscall_filter()
}

#[cfg(target_os = "macos")]
fn enter_worker_process_platform() -> std::io::Result<()> {
    close_inherited_worker_fds()?;
    apply_macos_worker_no_network_sandbox()
}

#[cfg(target_os = "windows")]
fn enter_worker_process_platform() -> std::io::Result<()> {
    apply_windows_worker_process_mitigations()
}

#[cfg(all(
    unix,
    not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "android",
        target_os = "ios"
    ))
))]
fn enter_worker_process_platform() -> std::io::Result<()> {
    close_inherited_worker_fds()
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "windows",
    all(
        unix,
        not(any(
            target_os = "linux",
            target_os = "macos",
            target_os = "android",
            target_os = "ios"
        ))
    )
)))]
fn enter_worker_process_platform() -> std::io::Result<()> {
    Ok(())
}

#[cfg(target_os = "windows")]
const WINDOWS_WORKER_PROCESS_MEMORY_LIMIT: usize = 1536 * 1024 * 1024;

#[cfg(target_os = "windows")]
fn apply_windows_worker_job_limits(child: &mut Child) -> std::io::Result<WorkerProcessGuard> {
    use std::{mem, os::windows::io::AsRawHandle, ptr};
    use winapi::um::{
        handleapi::{CloseHandle, INVALID_HANDLE_VALUE},
        jobapi2::{AssignProcessToJobObject, CreateJobObjectW, SetInformationJobObject},
        winnt::{
            JobObjectExtendedLimitInformation, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
            JOB_OBJECT_LIMIT_ACTIVE_PROCESS, JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION,
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOB_OBJECT_LIMIT_PROCESS_MEMORY,
        },
    };

    let job = unsafe { CreateJobObjectW(ptr::null_mut(), ptr::null()) };
    if job.is_null() || job == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error());
    }

    let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { mem::zeroed() };
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_ACTIVE_PROCESS
        | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION
        | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        | JOB_OBJECT_LIMIT_PROCESS_MEMORY;
    limits.BasicLimitInformation.ActiveProcessLimit = 1;
    limits.ProcessMemoryLimit = WINDOWS_WORKER_PROCESS_MEMORY_LIMIT;

    let set_ok = unsafe {
        SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            &mut limits as *mut _ as *mut _,
            mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
    };
    if set_ok == 0 {
        let err = std::io::Error::last_os_error();
        unsafe {
            CloseHandle(job);
        }
        return Err(err);
    }

    if unsafe { AssignProcessToJobObject(job, child.as_raw_handle() as _) } == 0 {
        let err = std::io::Error::last_os_error();
        unsafe {
            CloseHandle(job);
        }
        Err(err)
    } else {
        Ok(WorkerProcessGuard::from_windows_job(job))
    }
}

#[cfg(target_os = "windows")]
fn apply_windows_worker_process_mitigations() -> std::io::Result<()> {
    use std::mem;
    use winapi::um::winnt::{
        ProcessDynamicCodePolicy, ProcessExtensionPointDisablePolicy, ProcessImageLoadPolicy,
        ProcessStrictHandleCheckPolicy, PROCESS_MITIGATION_DYNAMIC_CODE_POLICY,
        PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY, PROCESS_MITIGATION_IMAGE_LOAD_POLICY,
        PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY,
    };

    let mut dynamic_code: PROCESS_MITIGATION_DYNAMIC_CODE_POLICY = unsafe { mem::zeroed() };
    dynamic_code.set_ProhibitDynamicCode(1);
    dynamic_code.set_AllowThreadOptOut(0);
    dynamic_code.set_AllowRemoteDowngrade(0);
    set_windows_process_mitigation(ProcessDynamicCodePolicy, &mut dynamic_code)?;

    let mut extension_points: PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY =
        unsafe { mem::zeroed() };
    extension_points.set_DisableExtensionPoints(1);
    set_windows_process_mitigation(ProcessExtensionPointDisablePolicy, &mut extension_points)?;

    let mut strict_handles: PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY =
        unsafe { mem::zeroed() };
    strict_handles.set_RaiseExceptionOnInvalidHandleReference(1);
    strict_handles.set_HandleExceptionsPermanentlyEnabled(1);
    set_windows_process_mitigation(ProcessStrictHandleCheckPolicy, &mut strict_handles)?;

    let mut image_load: PROCESS_MITIGATION_IMAGE_LOAD_POLICY = unsafe { mem::zeroed() };
    image_load.set_NoRemoteImages(1);
    image_load.set_NoLowMandatoryLabelImages(1);
    image_load.set_PreferSystem32Images(1);
    set_windows_process_mitigation(ProcessImageLoadPolicy, &mut image_load)
}

#[cfg(target_os = "windows")]
fn set_windows_process_mitigation<T>(
    policy: winapi::um::winnt::PROCESS_MITIGATION_POLICY,
    mitigation: &mut T,
) -> std::io::Result<()> {
    let ok = unsafe {
        winapi::um::processthreadsapi::SetProcessMitigationPolicy(
            policy,
            mitigation as *mut _ as *mut _,
            std::mem::size_of::<T>(),
        )
    };
    if ok == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn apply_linux_worker_sandbox() -> std::io::Result<()> {
    set_prctl_no_new_privs()?;
    set_prctl_parent_death_signal()?;
    set_prctl_not_dumpable()?;
    apply_unix_worker_resource_sandbox()
}

#[cfg(all(unix, not(any(target_os = "android", target_os = "ios"))))]
fn apply_unix_worker_resource_sandbox() -> std::io::Result<()> {
    set_limit(crate::libc::RLIMIT_NOFILE, WORKER_NOFILE_LIMIT)?;
    set_limit(crate::libc::RLIMIT_AS, WORKER_ADDRESS_SPACE_LIMIT)?;
    set_limit(crate::libc::RLIMIT_DATA, WORKER_DATA_LIMIT)?;
    set_limit(crate::libc::RLIMIT_STACK, WORKER_STACK_LIMIT)?;
    set_limit(crate::libc::RLIMIT_MEMLOCK, 0)?;
    set_limit(crate::libc::RLIMIT_CORE, 0)?;
    set_limit(crate::libc::RLIMIT_FSIZE, 0)?;
    Ok(())
}

#[cfg(target_os = "macos")]
const MACOS_WORKER_SANDBOX_NAMED: u64 = 0x0001;

#[cfg(target_os = "macos")]
fn apply_macos_worker_no_network_sandbox() -> std::io::Result<()> {
    use std::{ffi::CStr, ptr};

    extern "C" {
        static kSBXProfileNoNetwork: crate::libc::c_char;

        fn sandbox_init(
            profile: *const crate::libc::c_char,
            flags: u64,
            errorbuf: *mut *mut crate::libc::c_char,
        ) -> crate::libc::c_int;

        fn sandbox_free_error(errorbuf: *mut crate::libc::c_char);
    }

    let mut errorbuf: *mut crate::libc::c_char = ptr::null_mut();
    let rc = unsafe {
        sandbox_init(
            &kSBXProfileNoNetwork as *const crate::libc::c_char,
            MACOS_WORKER_SANDBOX_NAMED,
            &mut errorbuf,
        )
    };
    if rc == 0 {
        return Ok(());
    }

    let os_error = std::io::Error::last_os_error();
    let detail = if errorbuf.is_null() {
        os_error.to_string()
    } else {
        let detail = unsafe { CStr::from_ptr(errorbuf) }
            .to_string_lossy()
            .into_owned();
        unsafe {
            sandbox_free_error(errorbuf);
        }
        detail
    };
    Err(std::io::Error::new(
        os_error.kind(),
        format!("failed to apply macOS NoNetwork worker sandbox: {detail}"),
    ))
}

#[cfg(target_os = "linux")]
fn set_prctl_no_new_privs() -> std::io::Result<()> {
    cvt_prctl(unsafe { crate::libc::prctl(crate::libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) })
}

#[cfg(target_os = "linux")]
fn set_prctl_parent_death_signal() -> std::io::Result<()> {
    cvt_prctl(unsafe {
        crate::libc::prctl(crate::libc::PR_SET_PDEATHSIG, crate::libc::SIGKILL, 0, 0, 0)
    })
}

#[cfg(target_os = "linux")]
fn set_prctl_not_dumpable() -> std::io::Result<()> {
    cvt_prctl(unsafe { crate::libc::prctl(crate::libc::PR_SET_DUMPABLE, 0, 0, 0, 0) })
}

#[cfg(target_os = "linux")]
fn cvt_prctl(rc: crate::libc::c_int) -> std::io::Result<()> {
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(target_os = "linux")]
fn set_limit(resource: crate::libc::__rlimit_resource_t, value: u64) -> std::io::Result<()> {
    let rlim = crate::libc::rlimit {
        rlim_cur: value as crate::libc::rlim_t,
        rlim_max: value as crate::libc::rlim_t,
    };
    let rc = unsafe { crate::libc::setrlimit(resource, &rlim) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(all(
    unix,
    not(any(target_os = "linux", target_os = "android", target_os = "ios"))
))]
fn set_limit(resource: crate::libc::c_int, value: u64) -> std::io::Result<()> {
    let rlim = crate::libc::rlimit {
        rlim_cur: value as crate::libc::rlim_t,
        rlim_max: value as crate::libc::rlim_t,
    };
    let rc = unsafe { crate::libc::setrlimit(resource, &rlim) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(all(unix, not(any(target_os = "android", target_os = "ios"))))]
fn close_inherited_worker_fds() -> std::io::Result<()> {
    close_inherited_worker_fds_platform()
}

#[cfg(target_os = "linux")]
fn close_inherited_worker_fds_platform() -> std::io::Result<()> {
    match close_range_from(3) {
        Ok(()) => Ok(()),
        Err(close_range_err) => close_inherited_worker_fds_from_dir("/proc/self/fd").map_err(
            |dir_err| {
                std::io::Error::new(
                    dir_err.kind(),
                    format!(
                        "close_range failed ({close_range_err}); /proc/self/fd fallback failed ({dir_err})"
                    ),
                )
            },
        ),
    }
}

#[cfg(all(
    unix,
    not(any(target_os = "linux", target_os = "android", target_os = "ios"))
))]
fn close_inherited_worker_fds_platform() -> std::io::Result<()> {
    close_inherited_worker_fds_from_dir("/dev/fd")
}

#[cfg(target_os = "linux")]
fn close_range_from(first_fd: crate::libc::c_int) -> std::io::Result<()> {
    let rc = unsafe {
        crate::libc::syscall(
            crate::libc::SYS_close_range,
            first_fd as crate::libc::c_uint,
            !0u32,
            0u32,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(all(unix, not(any(target_os = "android", target_os = "ios"))))]
fn close_inherited_worker_fds_from_dir(path: &str) -> std::io::Result<()> {
    let mut fds = Vec::new();
    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        if let Some(fd) = parse_worker_fd_name(&entry.file_name()) {
            fds.push(fd);
        }
    }
    close_worker_fd_list(fds)
}

#[cfg(all(unix, not(any(target_os = "android", target_os = "ios"))))]
fn parse_worker_fd_name(name: &std::ffi::OsStr) -> Option<crate::libc::c_int> {
    let fd = name.to_str()?.parse::<crate::libc::c_int>().ok()?;
    if fd > crate::libc::STDERR_FILENO {
        Some(fd)
    } else {
        None
    }
}

#[cfg(all(unix, not(any(target_os = "android", target_os = "ios"))))]
fn close_worker_fd_list(mut fds: Vec<crate::libc::c_int>) -> std::io::Result<()> {
    fds.sort_unstable();
    fds.dedup();
    for fd in fds {
        close_worker_fd(fd)?;
    }
    Ok(())
}

#[cfg(all(unix, not(any(target_os = "android", target_os = "ios"))))]
fn close_worker_fd(fd: crate::libc::c_int) -> std::io::Result<()> {
    loop {
        let rc = unsafe { crate::libc::close(fd) };
        if rc == 0 {
            return Ok(());
        }
        let err = std::io::Error::last_os_error();
        match err.raw_os_error() {
            Some(code) if code == crate::libc::EBADF => return Ok(()),
            Some(code) if code == crate::libc::EINTR => continue,
            _ => return Err(err),
        }
    }
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
const SECCOMP_MODE_FILTER: crate::libc::c_ulong = 2;
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
const SECCOMP_RET_KILL: u32 = 0x0000_0000;
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
const AUDIT_ARCH_AARCH64: u32 = 0xc000_00b7;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const AUDIT_ARCH_NATIVE: u32 = AUDIT_ARCH_X86_64;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
const AUDIT_ARCH_NATIVE: u32 = AUDIT_ARCH_AARCH64;
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
const SECCOMP_DATA_NR_OFFSET: u32 = 0;
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
const SECCOMP_DATA_ARCH_OFFSET: u32 = 4;
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
const SECCOMP_DATA_ARG0_OFFSET: u32 = 16;
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
const CLONE_THREAD_FLAG: u32 = 0x0001_0000;

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
const BPF_LD: u16 = 0x00;
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
const BPF_W: u16 = 0x00;
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
const BPF_ABS: u16 = 0x20;
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
const BPF_JMP: u16 = 0x05;
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
const BPF_JEQ: u16 = 0x10;
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
const BPF_JSET: u16 = 0x40;
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
const BPF_K: u16 = 0x00;
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
const BPF_RET: u16 = 0x06;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const SYS_SOCKET: u32 = 41;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const SYS_BIND: u32 = 49;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const SYS_LISTEN: u32 = 50;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const SYS_ACCEPT: u32 = 43;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const SYS_ACCEPT4: u32 = 288;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const SYS_CLONE: u32 = 56;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const SYS_FORK: u32 = 57;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const SYS_VFORK: u32 = 58;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const SYS_EXECVE: u32 = 59;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const SYS_CLONE3: u32 = 435;

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
const SYS_SOCKET: u32 = 198;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
const SYS_BIND: u32 = 200;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
const SYS_LISTEN: u32 = 201;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
const SYS_ACCEPT: u32 = 202;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
const SYS_ACCEPT4: u32 = 242;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
const SYS_CLONE: u32 = 220;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
const SYS_EXECVE: u32 = 221;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
const SYS_CLONE3: u32 = 435;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const WORKER_DENIED_SYSCALLS: &[u32] = &[
    SYS_BIND,
    SYS_LISTEN,
    SYS_ACCEPT,
    SYS_ACCEPT4,
    SYS_FORK,
    SYS_VFORK,
    SYS_EXECVE,
    62,  // kill
    101, // ptrace
    133, // mknod
    155, // pivot_root
    161, // chroot
    163, // acct
    165, // mount
    166, // umount2
    167, // swapon
    168, // swapoff
    169, // reboot
    170, // sethostname
    171, // setdomainname
    175, // init_module
    176, // delete_module
    179, // quotactl
    200, // tkill
    234, // tgkill
    246, // kexec_load
    248, // add_key
    249, // request_key
    250, // keyctl
    259, // mknodat
    272, // unshare
    298, // perf_event_open
    304, // open_by_handle_at
    308, // setns
    310, // process_vm_readv
    311, // process_vm_writev
    313, // finit_module
    317, // seccomp
    321, // bpf
    322, // execveat
    323, // userfaultfd
    424, // pidfd_send_signal
    425, // io_uring_setup
    426, // io_uring_enter
    427, // io_uring_register
    428, // open_tree
    429, // move_mount
    430, // fsopen
    431, // fsconfig
    432, // fsmount
    433, // fspick
    438, // pidfd_getfd
];

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
const WORKER_DENIED_SYSCALLS: &[u32] = &[
    SYS_BIND,
    SYS_LISTEN,
    SYS_ACCEPT,
    SYS_ACCEPT4,
    SYS_EXECVE,
    33,  // mknodat
    39,  // umount2
    40,  // mount
    41,  // pivot_root
    51,  // chroot
    60,  // quotactl
    89,  // acct
    97,  // unshare
    104, // kexec_load
    105, // init_module
    106, // delete_module
    117, // ptrace
    129, // kill
    130, // tkill
    131, // tgkill
    142, // reboot
    161, // sethostname
    162, // setdomainname
    217, // add_key
    218, // request_key
    219, // keyctl
    224, // swapon
    225, // swapoff
    241, // perf_event_open
    265, // open_by_handle_at
    268, // setns
    270, // process_vm_readv
    271, // process_vm_writev
    273, // finit_module
    277, // seccomp
    280, // bpf
    281, // execveat
    282, // userfaultfd
    424, // pidfd_send_signal
    425, // io_uring_setup
    426, // io_uring_enter
    427, // io_uring_register
    428, // open_tree
    429, // move_mount
    430, // fsopen
    431, // fsconfig
    432, // fsmount
    433, // fspick
    438, // pidfd_getfd
];

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const WORKER_DENIED_SOCKET_DOMAINS: &[u32] = &[
    crate::libc::AF_INET as u32,
    crate::libc::AF_INET6 as u32,
    crate::libc::AF_PACKET as u32,
    crate::libc::AF_NETLINK as u32,
    crate::libc::AF_BLUETOOTH as u32,
    crate::libc::AF_VSOCK as u32,
];

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
const WORKER_DENIED_SOCKET_DOMAINS: &[u32] = &[
    crate::libc::AF_INET as u32,
    crate::libc::AF_INET6 as u32,
    crate::libc::AF_PACKET as u32,
    crate::libc::AF_NETLINK as u32,
    crate::libc::AF_BLUETOOTH as u32,
    crate::libc::AF_VSOCK as u32,
];

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn apply_linux_worker_syscall_filter() -> std::io::Result<()> {
    let mut filter = build_worker_seccomp_filter();
    let program = crate::libc::sock_fprog {
        len: filter.len() as crate::libc::c_ushort,
        filter: filter.as_mut_ptr(),
    };
    let rc = unsafe {
        crate::libc::prctl(
            crate::libc::PR_SET_SECCOMP,
            SECCOMP_MODE_FILTER,
            &program as *const crate::libc::sock_fprog,
        )
    };
    cvt_prctl(rc)
}

#[cfg(all(
    target_os = "linux",
    not(any(target_arch = "x86_64", target_arch = "aarch64"))
))]
fn apply_linux_worker_syscall_filter() -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "native worker Linux seccomp filter is not implemented for this architecture; refusing parser worker entry",
    ))
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn build_worker_seccomp_filter() -> Vec<crate::libc::sock_filter> {
    let mut filter = Vec::with_capacity(worker_seccomp_filter_instruction_count());
    filter.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_ARCH_OFFSET));
    filter.push(bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_NATIVE, 1, 0));
    filter.push(bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL));
    filter.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_NR_OFFSET));
    push_clone_rule(&mut filter);
    push_socket_rule(&mut filter);
    push_deny_syscall(&mut filter, SYS_CLONE3, crate::libc::ENOSYS);
    for &syscall in WORKER_DENIED_SYSCALLS {
        push_deny_syscall(&mut filter, syscall, crate::libc::EPERM);
    }
    filter.push(bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
    filter
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn push_clone_rule(filter: &mut Vec<crate::libc::sock_filter>) {
    filter.push(bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, SYS_CLONE, 0, 4));
    filter.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_ARG0_OFFSET));
    filter.push(bpf_jump(
        BPF_JMP | BPF_JSET | BPF_K,
        CLONE_THREAD_FLAG,
        1,
        0,
    ));
    filter.push(bpf_stmt(
        BPF_RET | BPF_K,
        SECCOMP_RET_ERRNO | crate::libc::EPERM as u32,
    ));
    filter.push(bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn push_socket_rule(filter: &mut Vec<crate::libc::sock_filter>) {
    let handler_len = (2 + WORKER_DENIED_SOCKET_DOMAINS.len() * 2) as u8;
    filter.push(bpf_jump(
        BPF_JMP | BPF_JEQ | BPF_K,
        SYS_SOCKET,
        0,
        handler_len,
    ));
    filter.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_ARG0_OFFSET));
    for &domain in WORKER_DENIED_SOCKET_DOMAINS {
        filter.push(bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, domain, 0, 1));
        filter.push(bpf_stmt(
            BPF_RET | BPF_K,
            SECCOMP_RET_ERRNO | crate::libc::EPERM as u32,
        ));
    }
    filter.push(bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn push_deny_syscall(
    filter: &mut Vec<crate::libc::sock_filter>,
    syscall: u32,
    errno: crate::libc::c_int,
) {
    filter.push(bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, syscall, 0, 1));
    filter.push(bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | errno as u32));
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn worker_seccomp_filter_instruction_count() -> usize {
    4 + 5 + (3 + WORKER_DENIED_SOCKET_DOMAINS.len() * 2) + 2 + WORKER_DENIED_SYSCALLS.len() * 2 + 1
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn bpf_stmt(code: u16, k: u32) -> crate::libc::sock_filter {
    crate::libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn bpf_jump(code: u16, k: u32, jt: u8, jf: u8) -> crate::libc::sock_filter {
    crate::libc::sock_filter { code, jt, jf, k }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::os::unix::io::AsRawFd;

    #[test]
    fn linux_worker_limits_are_tight_but_usable() {
        assert!(super::WORKER_NOFILE_LIMIT >= 16);
        assert!(super::WORKER_NOFILE_LIMIT <= 128);
        assert!(super::WORKER_STACK_LIMIT >= 8 * 1024 * 1024);
        assert!(super::WORKER_DATA_LIMIT < super::WORKER_ADDRESS_SPACE_LIMIT);
    }

    #[test]
    fn worker_fd_name_parser_skips_stdio_and_non_numeric_names() {
        assert_eq!(super::parse_worker_fd_name(std::ffi::OsStr::new("0")), None);
        assert_eq!(super::parse_worker_fd_name(std::ffi::OsStr::new("2")), None);
        assert_eq!(
            super::parse_worker_fd_name(std::ffi::OsStr::new("3")),
            Some(3)
        );
        assert_eq!(
            super::parse_worker_fd_name(std::ffi::OsStr::new("128")),
            Some(128)
        );
        assert_eq!(
            super::parse_worker_fd_name(std::ffi::OsStr::new("not-a-fd")),
            None
        );
    }

    #[test]
    fn linux_worker_fd_cleanup_closes_high_inherited_fd() {
        let mut files = Vec::new();
        let mut probe_fd = None;
        for _ in 0..(super::WORKER_NOFILE_LIMIT + 256) {
            let file = std::fs::File::open("/dev/null").expect("open /dev/null");
            let fd = file.as_raw_fd();
            files.push(file);
            if fd > super::WORKER_NOFILE_LIMIT as crate::libc::c_int {
                probe_fd = Some(fd);
                break;
            }
        }
        let probe_fd = probe_fd.expect("obtain an inherited fd above the worker rlimit");

        let flags = unsafe { crate::libc::fcntl(probe_fd, crate::libc::F_GETFD) };
        assert_ne!(flags, -1, "probe fd is not open before child spawn");
        let rc = unsafe {
            crate::libc::fcntl(
                probe_fd,
                crate::libc::F_SETFD,
                flags & !crate::libc::FD_CLOEXEC,
            )
        };
        assert_eq!(rc, 0, "clear FD_CLOEXEC on probe fd");

        let exe = std::env::current_exe().expect("current test executable");
        let output = std::process::Command::new(exe)
            .env("RD_NATIVE_WORKER_FD_CLEANUP_PROBE", probe_fd.to_string())
            .arg("--exact")
            .arg("native_worker_sandbox::tests::linux_worker_fd_cleanup_probe_child")
            .output()
            .expect("spawn fd-cleanup probe child");
        assert!(
            output.status.success(),
            "fd-cleanup probe child failed: status={:?}\nstdout={}\nstderr={}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn linux_worker_fd_cleanup_probe_child() {
        let Some(fd) = std::env::var_os("RD_NATIVE_WORKER_FD_CLEANUP_PROBE") else {
            return;
        };
        let fd = fd
            .to_string_lossy()
            .parse::<crate::libc::c_int>()
            .expect("numeric fd probe");

        let before = unsafe { crate::libc::fcntl(fd, crate::libc::F_GETFD) };
        assert_ne!(before, -1, "probe fd was not inherited by child");

        super::close_inherited_worker_fds().expect("close inherited worker fds");

        let after = unsafe { crate::libc::fcntl(fd, crate::libc::F_GETFD) };
        assert_eq!(after, -1, "high inherited fd survived worker cleanup");
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(crate::libc::EBADF)
        );
    }

    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn linux_worker_seccomp_arch_is_known_64bit() {
        #[cfg(target_arch = "x86_64")]
        assert_eq!(super::AUDIT_ARCH_NATIVE, super::AUDIT_ARCH_X86_64);
        #[cfg(target_arch = "aarch64")]
        assert_eq!(super::AUDIT_ARCH_NATIVE, super::AUDIT_ARCH_AARCH64);
    }

    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn linux_worker_seccomp_filter_blocks_expected_syscalls() {
        assert!(super::WORKER_DENIED_SYSCALLS.contains(&super::SYS_EXECVE));
        assert!(super::WORKER_DENIED_SYSCALLS.contains(&super::SYS_BIND));
        assert!(super::WORKER_DENIED_SYSCALLS.len() >= 30);
        assert!(super::WORKER_DENIED_SOCKET_DOMAINS.contains(&(crate::libc::AF_INET as u32)));
        assert_eq!(
            super::build_worker_seccomp_filter().len(),
            super::worker_seccomp_filter_instruction_count()
        );
    }

    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn linux_worker_seccomp_blocks_inet_socket_at_runtime() {
        let exe = std::env::current_exe().expect("current test executable");
        let output = std::process::Command::new(exe)
            .env("RD_NATIVE_WORKER_SANDBOX_PROBE", "1")
            .arg("--exact")
            .arg("native_worker_sandbox::tests::linux_worker_seccomp_probe_child")
            .output()
            .expect("spawn seccomp probe child");
        assert!(
            output.status.success(),
            "seccomp probe child failed: status={:?}\nstdout={}\nstderr={}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn linux_worker_seccomp_probe_child() {
        if std::env::var_os("RD_NATIVE_WORKER_SANDBOX_PROBE").is_none() {
            return;
        }

        super::set_prctl_no_new_privs().expect("enable no-new-privs for seccomp probe");
        super::apply_linux_worker_syscall_filter().expect("install seccomp probe filter");
        let fd = unsafe {
            crate::libc::socket(
                crate::libc::AF_INET,
                crate::libc::SOCK_STREAM | crate::libc::SOCK_CLOEXEC,
                0,
            )
        };
        assert_eq!(fd, -1, "AF_INET socket unexpectedly escaped worker seccomp");
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(crate::libc::EPERM)
        );
    }
}
