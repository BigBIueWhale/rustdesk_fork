// Compiled with the exact production authority reader by the isolated fixture.
use std::{
    fs::{self, DirBuilder, File},
    os::unix::fs::{symlink, DirBuilderExt, PermissionsExt},
    path::Path,
    process::{Command, Stdio},
    sync::{Arc, Barrier},
};

fn observe(root: &Path, mode: &str, report: bool) -> bool {
    let mut good = true;
    for name in ["regular", "link", "unreadable"] {
        std::env::set_var("XAUTHORITY", root.join(name));
        let result = native_authority(xauth::Family::WILD, b"", 94,
                                     Instant::now() + Duration::from_secs(1));
        let expected = if name == "unreadable" {
            matches!(&result, Err(error) if error.kind() == io::ErrorKind::PermissionDenied)
        } else {
            matches!(&result, Ok((name, data)) if name == b"MIT-MAGIC-COOKIE-1"
                     && data == b"test-cookie-1234")
        };
        if report {
            println!("CLIPBOARD_AUTHORITY_LIFETIME=case mode={mode} kind={name} ok={expected} error={:?}",
                     result.as_ref().err().map(io::Error::kind));
        }
        good &= expected;
    }
    good
}

fn worker(root: PathBuf, mode: String, ready: Arc<Barrier>) -> ! {
    assert_ne!(unsafe { libc::syscall(libc::SYS_gettid) } as u32, std::process::id());
    let probe = File::open(root.join("regular")).unwrap();
    let metadata = probe.metadata().unwrap();
    let leader = format!("/proc/self/fd/{}", probe.as_raw_fd());
    ready.wait();
    if mode == "exited" {
        let deadline = Instant::now() + Duration::from_secs(2);
        while fs::metadata(&leader).is_ok() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    let available = fs::metadata(&leader).is_ok();
    let alias = fs::metadata(format!("/proc/thread-self/fd/{}", probe.as_raw_fd()))
        .map(|value| (value.dev(), value.ino()) == (metadata.dev(), metadata.ino())).unwrap_or(false);
    let path_read = fs::read(root.join("regular")).is_ok();
    let mut good = available == (mode == "alive") && alias && path_read;
    println!("CLIPBOARD_AUTHORITY_LIFETIME=kernel mode={mode} leader_available={available} thread_alias={alias} path_read={path_read}");
    good &= observe(&root, &mode, false);
    let descriptors = || fs::read_dir("/proc/thread-self/fd").unwrap().count();
    let before = descriptors();
    for round in 0..8 { good &= observe(&root, &mode, round == 7); }
    let after = descriptors();
    println!("CLIPBOARD_AUTHORITY_LIFETIME=resources mode={mode} rounds=8 before={before} after={after}");
    drop(probe);
    std::process::exit(if good && before == after { 0 } else { 73 });
}

fn main() {
    assert_eq!((unsafe { libc::getuid() }, unsafe { libc::geteuid() }), (4000, 4000));
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.len() == 3 && args[0] == "--worker" && matches!(args[1].as_str(), "alive" | "exited") {
        let mode = args[1].clone();
        let exited = mode == "exited";
        let root = PathBuf::from(&args[2]);
        let ready = Arc::new(Barrier::new(2));
        let child_ready = Arc::clone(&ready);
        let thread = std::thread::spawn(move || worker(root, mode, child_ready));
        ready.wait();
        if exited {
            // No application/library lock is held at this controlled leader-only exit.
            unsafe { libc::syscall(libc::SYS_exit, 0); }
            unreachable!("leader exit returned");
        }
        thread.join().unwrap();
        unreachable!("the worker owns the process result");
    }
    assert!(args.is_empty());
    let root = std::env::temp_dir().join(format!("clipboard-authority-lifetime-{}", std::process::id()));
    DirBuilder::new().mode(0o700).create(&root).unwrap();
    let mut record = 65535u16.to_be_bytes().to_vec();
    for field in [b"".as_slice(), b"94", b"MIT-MAGIC-COOKIE-1", b"test-cookie-1234"] {
        record.extend_from_slice(&(field.len() as u16).to_be_bytes());
        record.extend_from_slice(field);
    }
    for (name, mode) in [("regular", 0o600), ("unreadable", 0o000)] {
        fs::write(root.join(name), &record).unwrap();
        fs::set_permissions(root.join(name), fs::Permissions::from_mode(mode)).unwrap();
    }
    symlink(root.join("regular"), root.join("link")).unwrap();
    let mut good = true;
    for mode in ["alive", "exited"] {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .arg("--worker").arg(mode).arg(&root).env_clear().env("LC_ALL", "C")
            .stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let timed_out = loop {
            if child.try_wait().unwrap().is_some() { break false; }
            if Instant::now() >= deadline { child.kill().unwrap(); break true; }
            std::thread::sleep(Duration::from_millis(5));
        };
        let output = child.wait_with_output().unwrap();
        assert!(output.stdout.len() + output.stderr.len() < 16384);
        let stdout = String::from_utf8(output.stdout).unwrap();
        print!("{stdout}");
        eprint!("{}", String::from_utf8_lossy(&output.stderr));
        println!("CLIPBOARD_AUTHORITY_LIFETIME=child mode={mode} success={} timed_out={timed_out} joined=true", output.status.success());
        good &= output.status.success() && !timed_out
            && stdout.lines().filter(|line| line.starts_with("CLIPBOARD_AUTHORITY_LIFETIME=case ")).count() == 3;
    }
    for name in ["regular", "link", "unreadable"] { fs::remove_file(root.join(name)).unwrap(); }
    fs::remove_dir(&root).unwrap();
    assert!(!root.exists());
    if !good { std::process::exit(1); }
    println!("CLIPBOARD_AUTHORITY_LIFETIME=pass modes=2 cases=6 children=joined fixture=retired");
}
