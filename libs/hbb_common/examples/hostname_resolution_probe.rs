//! Linux connector diagnostic; never linked into the application.
//! A seccomp trap counts and refuses IP datagram socket attempts. An interposed
//! getaddrinfo calls the real libc function, with an optional cancellation gate.

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod probe {
    use anyhow::{bail, ensure, Context, Result};
    use hbb_common::tcp::FramedStream;
    use std::{
        io,
        net::SocketAddr,
        sync::atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst},
        time::{Duration, Instant},
    };

    static UDP_ATTEMPTS: AtomicUsize = AtomicUsize::new(0);
    static GAI_CALLS: AtomicUsize = AtomicUsize::new(0);
    static GAI_ACTIVE: AtomicUsize = AtomicUsize::new(0);
    static HOLD_GAI: AtomicBool = AtomicBool::new(false);
    static FORCED_RELEASE: AtomicBool = AtomicBool::new(false);

    // This symbol observes the real std/Tokio call, rather than replacing its result.
    #[no_mangle]
    unsafe extern "C" fn getaddrinfo(
        node: *const libc::c_char,
        service: *const libc::c_char,
        hints: *const libc::addrinfo,
        result: *mut *mut libc::addrinfo,
    ) -> libc::c_int {
        type Lookup = unsafe extern "C" fn(
            *const libc::c_char,
            *const libc::c_char,
            *const libc::addrinfo,
            *mut *mut libc::addrinfo,
        ) -> libc::c_int;
        let symbol = libc::dlsym(libc::RTLD_NEXT, b"getaddrinfo\0".as_ptr().cast());
        if symbol.is_null() {
            *libc::__errno_location() = libc::ENOSYS;
            return libc::EAI_SYSTEM;
        }
        let real: Lookup = std::mem::transmute(symbol);
        GAI_CALLS.fetch_add(1, SeqCst);
        GAI_ACTIVE.fetch_add(1, SeqCst);
        let began = Instant::now();
        while HOLD_GAI.load(SeqCst) {
            if began.elapsed() >= Duration::from_secs(2) {
                FORCED_RELEASE.store(true, SeqCst);
                break;
            }
            // This hook executes on Tokio's blocking resolver thread.
            std::thread::sleep(Duration::from_millis(1));
        }
        let status = real(node, service, hints, result);
        GAI_ACTIVE.fetch_sub(1, SeqCst);
        status
    }

    extern "C" fn socket_trap(
        signal: libc::c_int,
        info: *mut libc::siginfo_t,
        context: *mut libc::c_void,
    ) {
        // Linux's SIGSYS/seccomp ABI supplies this thread's ucontext. Only
        // socket(AF_INET/AF_INET6, SOCK_DGRAM, ...) reaches this handler.
        unsafe {
            if signal != libc::SIGSYS || info.is_null() || context.is_null()
                || (*info).si_code != 1 // SYS_SECCOMP
            {
                libc::_exit(192);
            }
            UDP_ATTEMPTS.fetch_add(1, SeqCst);
            let context = &mut *context.cast::<libc::ucontext_t>();
            context.uc_mcontext.gregs[libc::REG_RAX as usize] = -(libc::EPERM as libc::greg_t);
        }
    }

    fn observe_datagram_attempts() -> Result<()> {
        fn instruction(code: u16, jt: u8, jf: u8, k: u32) -> libc::sock_filter {
            libc::sock_filter { code, jt, jf, k }
        }
        // seccomp_data: nr=0, arch=4, args[0]=16, args[1]=24 (Linux UAPI).
        // Check the ABI before interpreting the syscall number or registers.
        let mut filter = [
            instruction(0x20, 0, 0, 4),
            instruction(0x15, 1, 0, 0xc000003e), // AUDIT_ARCH_X86_64
            instruction(0x06, 0, 0, 0x80000000), // KILL_PROCESS
            instruction(0x20, 0, 0, 0),
            instruction(0x15, 0, 6, libc::SYS_socket as u32),
            instruction(0x20, 0, 0, 16),
            instruction(0x15, 1, 0, libc::AF_INET as u32),
            instruction(0x15, 0, 3, libc::AF_INET6 as u32),
            instruction(0x20, 0, 0, 24),
            instruction(0x54, 0, 0, 0xf), // strip SOCK_CLOEXEC/SOCK_NONBLOCK
            instruction(0x15, 1, 0, libc::SOCK_DGRAM as u32),
            instruction(0x06, 0, 0, 0x7fff0000), // ALLOW
            instruction(0x06, 0, 0, 0x00030000), // TRAP
        ];
        let program = libc::sock_fprog {
            len: filter.len() as u16,
            filter: filter.as_mut_ptr(),
        };
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = socket_trap as usize;
            action.sa_flags = libc::SA_SIGINFO;
            if libc::sigemptyset(&mut action.sa_mask) != 0
                || libc::sigaction(libc::SIGSYS, &action, std::ptr::null_mut()) != 0
                || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
            {
                return Err(io::Error::last_os_error().into());
            }
            // TSYNC covers any existing runtime thread; future blocking threads inherit it.
            if libc::syscall(libc::SYS_seccomp, 1, 1, &program as *const libc::sock_fprog) != 0 {
                bail!("seccomp TSYNC failed: {}", io::Error::last_os_error());
            }
        }
        Ok(())
    }

    struct ReleaseGate;
    impl Drop for ReleaseGate {
        fn drop(&mut self) {
            HOLD_GAI.store(false, SeqCst);
        }
    }

    fn observer_controls() -> Result<()> {
        for family in [libc::AF_INET, libc::AF_INET6] {
            let socket = unsafe { libc::socket(family, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
            if socket >= 0 {
                unsafe { libc::close(socket) };
                bail!("observer allowed its IP datagram control");
            }
            ensure!(io::Error::last_os_error().raw_os_error() == Some(libc::EPERM), "trap errno differs");
        }
        ensure!(UDP_ATTEMPTS.swap(0, SeqCst) == 2, "trap controls were not observed");
        unsafe {
            let mut hints: libc::addrinfo = std::mem::zeroed();
            hints.ai_family = libc::AF_INET;
            hints.ai_socktype = libc::SOCK_STREAM;
            hints.ai_flags = libc::AI_NUMERICHOST | libc::AI_NUMERICSERV;
            let mut result = std::ptr::null_mut();
            let status = libc::getaddrinfo(
                b"127.0.0.1\0".as_ptr().cast(), b"0\0".as_ptr().cast(), &hints, &mut result,
            );
            let valid = !result.is_null() && (*result).ai_family == libc::AF_INET;
            if !result.is_null() {
                libc::freeaddrinfo(result);
            }
            ensure!(status == 0 && valid, "real getaddrinfo forwarding failed");
        }
        ensure!(GAI_CALLS.swap(0, SeqCst) == 1 && GAI_ACTIVE.load(SeqCst) == 0,
                "getaddrinfo interposition was not observed");
        ensure!(UDP_ATTEMPTS.load(SeqCst) == 0, "numeric forwarding control attempted UDP");
        Ok(())
    }

    pub async fn run() -> Result<()> {
        let case = std::env::args().nth(1).context("missing diagnostic case")?;
        let host = match case.as_str() {
            "literal" => "127.0.0.1",
            "hosts-single" | "cancel" => "single.resolver-audit.invalid",
            "hosts-multi" | "hosts-multi-tcp" => "multi.resolver-audit.invalid",
            "dns-udp" | "dns-tcp" => "missing.resolver-audit.invalid",
            _ => bail!("unknown diagnostic case"),
        };
        std::env::set_var("LOCALDOMAIN", "");
        std::env::set_var(
            "RES_OPTIONS",
            if case.ends_with("tcp") {
                "attempts:1 timeout:1 use-vc"
            } else {
                "attempts:1 timeout:1"
            },
        );
        let listener = tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let target = format!("{host}:{}", listener.local_addr()?.port());
        observe_datagram_attempts()?;
        tokio::task::spawn_blocking(observer_controls).await??;
        let mut pending_after_budget = false;
        let mut active_after_cancel = false;
        let mut gate_reached = false;
        let mut gate_elapsed_ms = 0;
        let connected;
        if case == "cancel" {
            HOLD_GAI.store(true, SeqCst);
            let release = ReleaseGate;
            let task = tokio::spawn(async move { FramedStream::new(target, None, 5).await });
            let began = Instant::now();
            while GAI_ACTIVE.load(SeqCst) == 0 && !task.is_finished() {
                ensure!(began.elapsed() < Duration::from_secs(1), "resolver entry was not observable");
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            gate_reached = GAI_ACTIVE.load(SeqCst) != 0;
            if gate_reached {
                let held = Instant::now();
                tokio::time::sleep(Duration::from_millis(50)).await;
                gate_elapsed_ms = held.elapsed().as_millis() as u64;
                pending_after_budget = !task.is_finished();
                task.abort();
                let outcome = tokio::time::timeout(Duration::from_millis(100), task).await?;
                ensure!(matches!(outcome, Err(ref e) if e.is_cancelled()), "task did not cancel");
                active_after_cancel = GAI_ACTIVE.load(SeqCst) != 0;
                connected = false;
                drop(release);
                let began = Instant::now();
                while GAI_ACTIVE.load(SeqCst) != 0 {
                    ensure!(began.elapsed() < Duration::from_secs(1), "resolver did not drain");
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            } else {
                drop(release);
                connected = task.await?.is_ok();
            }
        } else {
            let stream = FramedStream::new(target, None, 100).await;
            connected = stream.is_ok();
            if connected {
                let accepted = tokio::time::timeout(Duration::from_secs(1), listener.accept()).await??;
                ensure!(accepted.1.ip().is_loopback(), "connection escaped loopback");
                drop(accepted);
            }
            drop(stream);
        }
        ensure!(!FORCED_RELEASE.load(SeqCst), "observer gate expired instead of being released");
        ensure!(GAI_ACTIVE.load(SeqCst) == 0, "native lookup remains active");
        println!("HOSTNAME_RESOLUTION_OBSERVATION={}", serde_json::json!({
            "case": case,
            "connected": connected,
            "ip_datagram_socket_attempts": UDP_ATTEMPTS.load(SeqCst),
            "getaddrinfo_calls": GAI_CALLS.load(SeqCst),
            "gate_reached": gate_reached,
            "pending_after_connect_budget": pending_after_budget,
            "native_active_after_future_cancel": active_after_cancel,
            "native_hook_drained": true,
            "datagram_action": "kernel-trap-denied",
            "cancellation_gate": "controlled-before-real-getaddrinfo",
            "trap_self_controls": 2,
            "getaddrinfo_self_control": true,
            "connect_timeout_ms": if case == "cancel" { 5 } else { 100 },
            "gate_observed_elapsed_ms": gate_elapsed_ms
        }));
        Ok(())
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    probe::run().await
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
fn main() {
    eprintln!("hostname resolution observation requires Linux x86_64");
    std::process::exit(2);
}
