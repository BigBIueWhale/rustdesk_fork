extern crate self as hbb_common;
pub extern crate libc;

#[path = "../src/direct_service/resource_limits.rs"]
mod resource_limits;
include!("fixtures/linux-resource-limits-before.rs");

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::BTreeMap, io, process::Command};

    const CASES: [&str; 8] = [
        "above", "at", "below", "zero", "hard_below", "query_denied",
        "set_denied", "noop_set_denied",
    ];

    fn limits() -> io::Result<libc::rlimit> {
        let mut value = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        // SAFETY: valid fixed resource and writable output.
        if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut value) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(value)
    }

    fn deny_limit_calls(query: bool) {
        assert_eq!(std::env::consts::ARCH, "x86_64");
        let stmt = |code, k| libc::sock_filter { code, jt: 0, jf: 0, k };
        let jump = |k, jt, jf| libc::sock_filter { code: 0x15, jt, jf, k };
        let deny = 0x0005_0000u32 | libc::EPERM as u32;
        let allow = 0x7fff_0000u32;
        // seccomp_data.arch, then nr; only the native ABI is admitted.
        let mut filter = vec![
            stmt(0x20, 4), jump(0xc000_003e, 1, 0), stmt(0x06, 0x8000_0000),
            stmt(0x20, 0),
        ];
        if query {
            filter.extend([
                jump(libc::SYS_getrlimit as u32, 0, 1), stmt(0x06, deny),
                jump(libc::SYS_prlimit64 as u32, 0, 1), stmt(0x06, deny),
                stmt(0x06, allow),
            ]);
        } else {
            filter.extend([
                jump(libc::SYS_setrlimit as u32, 0, 1), stmt(0x06, deny),
                jump(libc::SYS_prlimit64 as u32, 1, 0), stmt(0x06, allow),
                // prlimit64's third argument is the new-limit pointer.
                stmt(0x20, 32), jump(0, 0, 3), stmt(0x20, 36), jump(0, 0, 1),
                stmt(0x06, allow), stmt(0x06, deny),
            ]);
        }
        let program = libc::sock_fprog { len: filter.len().try_into().unwrap(), filter: filter.as_mut_ptr() };
        // SAFETY: read-only query of this fixture process's no-new-privileges state.
        assert_eq!(unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0 as libc::c_ulong, 0 as libc::c_ulong, 0 as libc::c_ulong, 0 as libc::c_ulong) }, 1);
        // SAFETY: the live BPF slice is valid for installation; this only restricts this fixture.
        assert_eq!(unsafe { libc::prctl(libc::PR_SET_SECCOMP, 2 as libc::c_ulong, &program, 0 as libc::c_ulong, 0 as libc::c_ulong) }, 0, "{}", io::Error::last_os_error());
    }

    fn prove_child_can_raise(expected: &libc::rlimit) {
        // SAFETY: the child below calls only libc operations and _exit after fork.
        let parent = unsafe { libc::getpid() };
        let child = unsafe { libc::fork() };
        assert!(child >= 0, "{}", io::Error::last_os_error());
        if child == 0 {
            unsafe {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL as libc::c_ulong, 0 as libc::c_ulong, 0 as libc::c_ulong, 0 as libc::c_ulong) != 0 || libc::getppid() != parent {
                    libc::_exit(20);
                }
                let mut inherited = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
                if libc::getrlimit(libc::RLIMIT_NOFILE, &mut inherited) != 0 || inherited.rlim_cur != expected.rlim_cur || inherited.rlim_max != expected.rlim_max {
                    libc::_exit(21);
                }
                inherited.rlim_cur = inherited.rlim_max;
                if libc::setrlimit(libc::RLIMIT_NOFILE, &inherited) != 0 {
                    libc::_exit(22);
                }
                let mut observed = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
                if libc::getrlimit(libc::RLIMIT_NOFILE, &mut observed) != 0 || observed.rlim_cur != expected.rlim_max || observed.rlim_max != expected.rlim_max {
                    libc::_exit(23);
                }
                libc::_exit(0);
            }
        }
        let mut status = 0;
        loop {
            // SAFETY: this process owns this exact unreaped child and status output.
            let observed = unsafe { libc::waitpid(child, &mut status, 0) };
            if observed == child { break; }
            assert!(observed < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::EINTR));
        }
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0);
        let unchanged = limits().unwrap();
        assert_eq!((unchanged.rlim_cur, unchanged.rlim_max), (expected.rlim_cur, expected.rlim_max));
    }

    // Process-isolated actor: native_matrix invokes this exact test with a closed case.
    #[test]
    fn native_actor() {
        let mode = std::env::var("RD_RESOURCE_MODE").unwrap();
        let case = std::env::var("RD_RESOURCE_CASE").unwrap();
        assert!(mode == "before" || mode == "after");
        assert!(CASES.contains(&case.as_str()));
        assert_eq!(unsafe { libc::getuid() }, 1000);
        assert_eq!(unsafe { libc::geteuid() }, 1000);
        assert_eq!(unsafe { libc::getgid() }, 1000);
        assert_eq!(unsafe { libc::getegid() }, 1000);
        let status = std::fs::read_to_string("/proc/self/status").unwrap();
        for key in ["CapInh:", "CapPrm:", "CapEff:", "CapBnd:", "CapAmb:"] {
            let value = status.lines().find_map(|line| line.strip_prefix(key)).unwrap().trim();
            assert_eq!(u64::from_str_radix(value, 16).unwrap(), 0);
        }
        assert_eq!(unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0 as libc::c_ulong, 0 as libc::c_ulong, 0 as libc::c_ulong, 0 as libc::c_ulong) }, 1);
        assert!(limits().unwrap().rlim_max >= 32768, "fixture needs its declared initial hard limit");
        let (soft, hard) = match case.as_str() {
            "below" | "noop_set_denied" => (64, 32768),
            "zero" => (0, 32768), "at" => (8192, 32768),
            "hard_below" => (128, 256), _ => (16384, 32768),
        };
        let initial = libc::rlimit { rlim_cur: soft, rlim_max: hard };
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &initial) }, 0);
        let before = limits().unwrap();
        assert_eq!((before.rlim_cur, before.rlim_max), (soft, hard));
        if case == "query_denied" { deny_limit_calls(true); }
        if case == "set_denied" || case == "noop_set_denied" { deny_limit_calls(false); }
        let result = if mode == "before" {
            self_enforce_resource_limits();
            Ok(None)
        } else {
            resource_limits::enforce_fd_ceiling().map(Some)
        };
        let result_errno = result.as_ref().err().and_then(io::Error::raw_os_error).unwrap_or(0);
        let result_name = if result.is_ok() { "ok" } else { "refused" };
        let after = limits();
        if let (Ok(Some(reported)), Ok(observed)) = (&result, &after) {
            assert_eq!((reported.rlim_cur, reported.rlim_max), (observed.rlim_cur, observed.rlim_max));
        }
        let child_joined = if !case.ends_with("denied") {
            prove_child_can_raise(after.as_ref().unwrap()); true
        } else { false };
        let (after_soft, after_hard, after_errno) = match after {
            Ok(value) => (value.rlim_cur, value.rlim_max, 0),
            Err(error) => (0, 0, error.raw_os_error().unwrap()),
        };
        println!("RESOURCE_LIMIT_CASE mode={mode} case={case} result={result_name} errno={result_errno} before_soft={soft} before_hard={hard} after_soft={after_soft} after_hard={after_hard} after_errno={after_errno} child_joined={} uid=1000 gid=1000 caps=0 nnp=1", u8::from(child_joined));
    }

    #[test]
    fn native_matrix() {
        let executable = std::env::current_exe().unwrap();
        let mut baseline_failures = 0;
        let mut child_raises = 0;
        for mode in ["before", "after"] {
            for case in CASES {
                let output = Command::new(&executable)
                    .args(["--exact", "tests::native_actor", "--nocapture", "--test-threads=1"])
                    .env("RD_RESOURCE_MODE", mode).env("RD_RESOURCE_CASE", case)
                    .output().unwrap();
                assert!(output.status.success(), "actor {mode}/{case}: {} {}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
                assert!(output.stdout.len() < 16384 && output.stderr.len() < 16384);
                let stdout = String::from_utf8(output.stdout).unwrap();
                let records: Vec<_> = stdout.lines().filter_map(|line| line.find("RESOURCE_LIMIT_CASE ").map(|i| &line[i..])).collect();
                assert_eq!(records.len(), 1);
                let mut fields = BTreeMap::new();
                for field in records[0].split_whitespace().skip(1) {
                    let (key, value) = field.split_once('=').unwrap();
                    assert!(fields.insert(key, value).is_none());
                }
                assert_eq!(fields.len(), 14);
                assert_eq!(fields["mode"], mode); assert_eq!(fields["case"], case);
                for (key, expected) in [("uid", "1000"), ("gid", "1000"), ("caps", "0"), ("nnp", "1")] { assert_eq!(fields[key], expected); }
                let number = |name| fields[name].parse::<u64>().unwrap();
                let expected_refusal = case == "query_denied" || case == "set_denied";
                let conforms = if expected_refusal {
                    fields["result"] == "refused" && number("errno") == libc::EPERM as u64
                } else {
                    fields["result"] == "ok" && number("errno") == 0 && number("after_errno") == 0
                        && number("after_soft") == number("before_soft").min(8192)
                        && number("after_hard") == number("before_hard")
                };
                let expected_baseline_failure = ["below", "zero", "hard_below", "query_denied", "set_denied"].contains(&case);
                if mode == "before" { assert_eq!(conforms, !expected_baseline_failure); baseline_failures += usize::from(!conforms); }
                else { assert!(conforms, "corrected {case}: {}", records[0]); }
                if !case.ends_with("denied") { assert_eq!(fields["child_joined"], "1"); child_raises += 1; }
                else { assert_eq!(fields["child_joined"], "0"); }
                println!("{}", records[0]);
            }
        }
        assert_eq!(baseline_failures, 5); assert_eq!(child_raises, 10);
        println!("LINUX_RESOURCE_LIMITS_NATIVE=pass cases=16 before_failed=5 before_controls=3 after_passed=8 child_raises=10 children=joined");
    }
}
