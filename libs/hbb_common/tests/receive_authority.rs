#[cfg(target_os = "linux")]
mod linux {
    use hbb_common::{
        anyhow::{anyhow, ensure},
        fs::{DigestCheckResult, JobType, TransferJob},
        message_proto::{FileEntry, FileTransferBlock, FileTransferDigest},
        serde_json::{json, Value},
        tokio::{self, io::AsyncReadExt},
        ResultType,
    };
    use std::{
        fs::{self, OpenOptions},
        io::{self, Write},
        os::unix::{
            fs::{symlink, MetadataExt, OpenOptionsExt, PermissionsExt},
            process::CommandExt,
        },
        path::{Path, PathBuf},
        process::Stdio,
        time::Duration,
    };

    const ACTOR_UID: u32 = 4001;
    const DIGEST: &[u8] = br#"{"size":6,"modified":31}"#;

    fn identity(expected: u32) -> ResultType<Value> {
        let status = fs::read_to_string("/proc/self/status")?;
        let field = |key: &str| -> ResultType<String> {
            status.lines().find_map(|line| line.strip_prefix(key))
                .map(|v| v.trim().to_owned()).ok_or_else(|| anyhow!("missing process field"))
        };
        let uids = field("Uid:")?;
        let gids = field("Gid:")?;
        let expected_ids = vec![expected.to_string(); 4];
        ensure!(uids.split_whitespace().eq(expected_ids.iter().map(String::as_str)));
        ensure!(gids.split_whitespace().eq(expected_ids.iter().map(String::as_str)));
        ensure!(field("NoNewPrivs:")? == "1");
        let capabilities = field("CapEff:")?;
        let mut inherited_fixture_descriptors = 0;
        if expected == ACTOR_UID {
            ensure!(field("Groups:")?.is_empty());
            for key in ["CapEff:", "CapPrm:", "CapInh:", "CapAmb:"] {
                ensure!(u64::from_str_radix(&field(key)?, 16)? == 0);
            }
            let executable = std::env::current_exe()?;
            let fixtures = executable.parent().ok_or_else(|| anyhow!("actor parent absent"))?.join("data");
            for descriptor in fs::read_dir("/proc/self/fd")? {
                match fs::read_link(descriptor?.path()) {
                    Ok(path) if path.starts_with(&fixtures) => inherited_fixture_descriptors += 1,
                    Ok(_) => {}
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                    Err(e) => return Err(e.into()),
                }
            }
            ensure!(inherited_fixture_descriptors == 0, "actor inherited a fixture descriptor");
        }
        Ok(json!({"pid": std::process::id(), "uids": uids, "gids": gids,
            "effective_capabilities": capabilities, "no_new_privileges": true,
            "inherited_fixture_descriptors":inherited_fixture_descriptors}))
    }

    fn create(path: &Path, bytes: &[u8], mode: u32) -> ResultType<()> {
        let mut file = OpenOptions::new().write(true).create_new(true).mode(mode).open(path)?;
        file.write_all(bytes)?;
        file.set_permissions(fs::Permissions::from_mode(mode))?;
        ensure!(file.metadata()?.mode() & 0o7777 == mode, "fixture mode differs");
        Ok(())
    }

    fn snapshot(path: &Path) -> ResultType<Value> {
        let m = match fs::symlink_metadata(path) {
            Ok(m) => m,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Value::Null),
            Err(e) => return Err(e.into()),
        };
        ensure!(m.is_file() && m.len() <= 4096, "unexpected fixture object");
        Ok(json!({"device":m.dev(), "inode":m.ino(), "uid":m.uid(), "gid":m.gid(),
            "mode":m.mode() & 0o7777, "links":m.nlink(), "length":m.len(),
            "mtime":m.mtime(), "mtime_ns":m.mtime_nsec(), "bytes":fs::read(path)?}))
    }

    fn staging(base: &Path) -> ResultType<PathBuf> {
        use hbb_common::sha2::{Digest, Sha256};
        let mut directories = Vec::new();
        for entry in fs::read_dir(base)? {
            let entry = entry?;
            if entry.file_name().as_encoded_bytes().starts_with(b".rustdesk-receive-") {
                let metadata = fs::symlink_metadata(entry.path())?;
                ensure!(metadata.is_dir() && metadata.uid() == 0 && metadata.mode() & 0o7777 == 0o700);
                directories.push(entry.path());
            }
        }
        ensure!(directories.len() == 1, "expected one production receive namespace");
        let mut hash = Sha256::new();
        hash.update(b"rustdesk.receive.file.v1\0");
        hash.update(b"incoming.bin");
        Ok(directories.remove(0).join(format!("{:x}", hash.finalize())))
    }

    async fn prepare_staging(base: &Path) -> ResultType<PathBuf> {
        // Production inspection establishes the namespace, then releases its lease.
        // Only the test fixtures below inject malformed artifacts into that private directory.
        let mut receiver = job(base)?;
        receiver.inspect_receive_digest(&incoming(), false).await?;
        receiver.retire_current_file_state()?;
        let path = staging(base)?;
        fs::create_dir(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
        Ok(path)
    }

    fn state(base: &Path) -> ResultType<Vec<Value>> {
        let artifacts = staging(base)?;
        [base.join("incoming.bin"), artifacts.join("payload.download"),
            artifacts.join("resume.digest"), artifacts.join("claim.download.lock")]
            .iter().map(|path| snapshot(path)).collect()
    }

    fn denied<T>(result: io::Result<T>) -> bool {
        matches!(result, Err(e) if e.kind() == io::ErrorKind::PermissionDenied)
    }

    fn actor_main(base: &Path, operation: &str) -> ResultType<()> {
        let who = identity(ACTOR_UID)?;
        let data = base.join("incoming.bin.download");
        let digest = base.join("incoming.bin.digest");
        let details = match operation {
            "probe-data" | "probe-final" => {
                let path = if operation == "probe-final" { base.join("incoming.bin") } else { base.to_owned() };
                let bytes = fs::read(&path);
                let read_denied = matches!(&bytes, Err(e) if e.kind() == io::ErrorKind::PermissionDenied);
                json!({"read_denied":read_denied, "bytes":bytes.ok(),
                    "write_denied":denied(OpenOptions::new().write(true).open(path))})
            }
            "foreign-lease" | "foreign-data" | "foreign-digest" | "foreign-final" => {
                let (path, bytes): (PathBuf, &[u8]) = match operation {
                    "foreign-lease" => (base.join("incoming.bin.download.lock"), b"foreign-lock"),
                    "foreign-data" => (data, b"abc"),
                    "foreign-digest" => (digest, DIGEST),
                    _ => (base.join("incoming.bin"), b"original"),
                };
                create(&path, bytes, 0o600)?;
                json!({"created":snapshot(&path)?})
            }
            "mutate-digest" => {
                fs::write(&digest, b"actor changed this digest")?;
                json!({"mutated":snapshot(&digest)?})
            }
            "replace-data" | "replace-digest" => {
                let held = base.with_file_name("held");
                ensure!(denied(fs::rename(base, &held)), "actor replaced a private receive artifact");
                ensure!(denied(fs::read(base)), "actor read a private receive artifact");
                json!({"replacement_denied":true, "read_denied":true})
            }
            "swap-parent" => {
                fs::rename(base.join("selected"), base.join("held-parent"))?;
                symlink(base.join("outside"), base.join("selected"))?;
                json!({"parent_replaced":true})
            }
            "swap-namespace" => {
                let held = base.with_file_name("held-namespace");
                fs::rename(base, &held)?;
                fs::create_dir(base)?;
                fs::set_permissions(base, fs::Permissions::from_mode(0o700))?;
                create(&base.join("foreign"), b"preserve this replacement", 0o600)?;
                ensure!(denied(fs::read_dir(&held)));
                json!({"namespace_replaced":true, "old_namespace_access_denied":true})
            }
            "replace-window" => {
                let held = base.with_file_name("window-held");
                match fs::rename(base, &held) {
                    Ok(()) => {
                        create(base, b"replacement", 0o600)?;
                        ensure!(denied(fs::read(&held)));
                        json!({"renamed":true, "denied":false, "held_read_denied":true,
                            "replacement":snapshot(base)?})
                    }
                    Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                        ensure!(denied(fs::read(base)));
                        json!({"renamed":false, "denied":true})
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            _ => return Err(anyhow!("unknown actor operation")),
        };
        println!("{}", json!({"operation":operation, "identity":who, "details":details}));
        Ok(())
    }

    fn actor_command(base: &Path, operation: &str) -> ResultType<std::process::Command> {
        let mut command = std::process::Command::new(std::env::current_exe()?);
        command.args(["actor", operation]).arg(base)
            .stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
        // Only async-signal-safe credential syscalls run between fork and exec.
        unsafe {
            command.pre_exec(|| {
                if libc::setgroups(0, std::ptr::null()) != 0
                    || libc::setresgid(ACTOR_UID, ACTOR_UID, ACTOR_UID) != 0
                    || libc::setresuid(ACTOR_UID, ACTOR_UID, ACTOR_UID) != 0
                    || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        Ok(command)
    }

    fn report_actor(operation: &str, count: &mut usize, status: std::process::ExitStatus,
        out: &[u8], err: &[u8]) -> ResultType<Value> {
        ensure!(out.len() <= 16384 && err.len() <= 16384, "actor output bound exceeded");
        ensure!(status.success(), "actor failed: {}", String::from_utf8_lossy(err));
        let value: Value = hbb_common::serde_json::from_slice(out)?;
        ensure!(value["operation"] == operation);
        *count += 1;
        println!("RECEIVE_NATIVE_ACTOR={value}");
        Ok(value["details"].clone())
    }

    async fn actor(base: &Path, operation: &str, count: &mut usize) -> ResultType<Value> {
        let mut command = tokio::process::Command::from(actor_command(base, operation)?);
        let mut child = command.spawn()?;
        let mut stdout = child.stdout.take().ok_or_else(|| anyhow!("actor stdout absent"))?;
        let mut stderr = child.stderr.take().ok_or_else(|| anyhow!("actor stderr absent"))?;
        let status = match tokio::time::timeout(Duration::from_secs(5), child.wait()).await {
            Ok(result) => result?,
            Err(_) => {
                let killed = child.start_kill();
                let joined = child.wait().await?;
                return Err(anyhow!("actor deadline expired; child joined: {joined}; kill: {killed:?}"));
            }
        };
        let mut out = Vec::new();
        let mut err = Vec::new();
        (&mut stdout).take(16385).read_to_end(&mut out).await?;
        (&mut stderr).take(16385).read_to_end(&mut err).await?;
        report_actor(operation, count, status, &out, &err)
    }

    fn incoming() -> FileTransferDigest {
        FileTransferDigest { id: 807, file_num: 0, file_size: 6,
            last_modified: 31, ..Default::default() }
    }

    fn job(base: &Path) -> ResultType<TransferJob> {
        TransferJob::new_write(807, JobType::Generic, String::new(), base.to_owned(),
            0, false, false, true).with_files(vec![FileEntry {
                name:"incoming.bin".into(), size:6, modified_time:31, ..Default::default()
            }])
    }

    async fn write(job: &mut TransferJob, bytes: &[u8]) -> ResultType<()> {
        job.write(FileTransferBlock { id:807, file_num:0,
            data:bytes.to_vec().into(), ..Default::default() }).await
    }

    async fn admit(job: &mut TransferJob, resume: bool, offset: u64) -> ResultType<()> {
        let (result, _) = job.inspect_receive_digest(&incoming(), resume).await?;
        if resume {
            ensure!(matches!(result, DigestCheckResult::NeedConfirm(v) if v.transferred_size == offset));
        }
        job.confirm_with_offset(0, offset).await?;
        Ok(())
    }

    fn private_final(base: &Path) -> ResultType<Value> {
        let path = base.join("incoming.bin");
        let m = fs::metadata(&path)?;
        ensure!(m.uid() == 0 && m.mode() & 0o7777 == 0o600 && m.nlink() == 1);
        ensure!(m.mtime() == 31 && fs::read(&path)? == b"abcdef");
        ensure!(!staging(base)?.exists(), "completed receive retained its per-file namespace");
        snapshot(&path)
    }

    async fn window_receiver(base: &Path) -> ResultType<()> {
        let who = identity(0)?;
        create(&base.join("incoming.bin"), b"original", 0o600)?;
        let mut receiver = job(base)?;
        admit(&mut receiver, false, 0).await?;
        write(&mut receiver, b"abcdef").await?;
        io::stdout().write_all(syscall_window::ARMED)?;
        let finish = receiver.finalize_write(1).await;
        let retire = receiver.retire_current_file_state();
        println!("RECEIVE_NATIVE_WINDOW_RECEIVER={}", json!({"identity":who,
            "finish_ok":finish.is_ok(), "finish_error":finish.err().map(|e| e.to_string()),
            "retire_ok":retire.is_ok(), "retire_error":retire.err().map(|e| e.to_string())}));
        Ok(())
    }

    fn coordinator() -> ResultType<PathBuf> {
        Ok(hbb_common::platform::linux::get_effective_home_dir_trusted()
            .ok_or_else(|| anyhow!("native receiver home absent"))?.join(".rustdesk-receive"))
    }

    fn temporary_records() -> ResultType<std::collections::BTreeSet<PathBuf>> {
        let mut paths = std::collections::BTreeSet::new();
        for entry in fs::read_dir(coordinator()?)? {
            let entry = entry?;
            if entry.file_name().as_encoded_bytes().ends_with(b".tmp") {
                ensure!(paths.len() < 64, "native temporary-record inventory exceeds bound");
                paths.insert(entry.path());
            }
        }
        Ok(paths)
    }

    fn coordination_inventory() -> ResultType<std::collections::BTreeMap<PathBuf, u64>> {
        let mut records = std::collections::BTreeMap::new();
        for entry in fs::read_dir(coordinator()?)? {
            let entry = entry?;
            let metadata = fs::symlink_metadata(entry.path())?;
            ensure!(records.len() < 1024 && metadata.is_file() && metadata.len() <= 4096,
                "native coordination inventory exceeds fixture bounds");
            records.insert(entry.path(), metadata.blocks() * 512);
        }
        Ok(records)
    }

    async fn complete_transfer(base: &Path) -> ResultType<()> {
        let mut receiver = job(base)?;
        admit(&mut receiver, false, 0).await?;
        write(&mut receiver, b"abcdef").await?;
        receiver.finalize_write(1).await?;
        receiver.retire_current_file_state()?;
        let final_state = snapshot(&base.join("incoming.bin"))?;
        ensure!(final_state["bytes"] == json!(b"abcdef".to_vec())
            && final_state["uid"] == 0 && final_state["mode"] == 0o600
            && final_state["links"] == 1 && final_state["mtime"] == 31);
        Ok(())
    }

    async fn crash_receiver(base: &Path) -> ResultType<()> {
        identity(0)?;
        io::stdout().write_all(syscall_window::ARMED)?;
        let mut receiver = job(base)?;
        admit(&mut receiver, false, 0).await?;
        Err(anyhow!("required enrollment crash point was not reached"))
    }

    mod syscall_window {
        use super::{actor_command, coordinator, private_final, report_actor, snapshot, ACTOR_UID};
        use hbb_common::{anyhow::{anyhow, ensure}, serde_json::{json, Value}, ResultType};
        use std::{
            collections::BTreeSet,
            convert::TryFrom,
            fs,
            io::{self, Read},
            os::unix::{ffi::OsStringExt, process::{CommandExt, ExitStatusExt}},
            path::{Path, PathBuf},
            process::{Child, Command, Stdio},
            time::{Duration, Instant},
        };

        pub const ARMED: &[u8] = b"RECEIVE_NATIVE_WINDOW_ARMED\n";

        // Linux UAPI ptrace_syscall_info, including its largest (64-byte) union member.
        #[repr(C)]
        #[derive(Default)]
        struct SyscallInfo {
            op: u8,
            reserved: [u8; 3],
            arch: u32,
            instruction_pointer: u64,
            stack_pointer: u64,
            data: [u64; 8],
        }

        fn trace(request: u32, pid: i32, address: usize, data: usize) -> io::Result<libc::c_long> {
            let result = unsafe {
                libc::ptrace(request, pid, address as *mut libc::c_void, data as *mut libc::c_void)
            };
            if result == -1 { Err(io::Error::last_os_error()) } else { Ok(result) }
        }

        struct TraceOwner {
            child: Child,
            tasks: BTreeSet<i32>,
        }

        struct ActorOwner(Child);

        impl Drop for ActorOwner {
            fn drop(&mut self) {
                if matches!(self.0.try_wait(), Ok(Some(_))) { return; }
                let killed = self.0.kill();
                let joined = self.0.wait();
                eprintln!("window actor cancellation: kill={killed:?} join={joined:?}");
            }
        }

        impl Drop for TraceOwner {
            fn drop(&mut self) {
                if self.tasks.is_empty() { return; }
                // Cancellation initiates termination, then joins every owned tracee. Never detach.
                for pid in &self.tasks { unsafe { libc::kill(*pid, libc::SIGKILL); } }
                loop {
                    let mut status = 0;
                    let pid = unsafe { libc::waitpid(-1, &mut status, libc::__WALL | libc::__WNOTHREAD) };
                    if pid < 0 {
                        if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted { continue; }
                        break;
                    }
                    if libc::WIFSTOPPED(status) {
                        let event = status >> 16;
                        if [libc::PTRACE_EVENT_CLONE, libc::PTRACE_EVENT_FORK,
                            libc::PTRACE_EVENT_VFORK].contains(&event) {
                            let mut spawned = 0usize;
                            if trace(libc::PTRACE_GETEVENTMSG, pid, 0, &mut spawned as *mut _ as usize).is_ok() {
                                unsafe { libc::kill(spawned as i32, libc::SIGKILL); }
                            }
                        }
                        unsafe { libc::kill(pid, libc::SIGKILL); }
                        let _ = trace(libc::PTRACE_CONT, pid, 0, libc::SIGKILL as usize);
                    }
                }
            }
        }

        fn read_memory(pid: i32, address: usize, length: usize) -> ResultType<Vec<u8>> {
            ensure!(length <= 4096 && address != 0);
            let mut bytes = vec![0u8; length];
            let mut done = 0;
            while done < length {
                let at = address.checked_add(done).ok_or_else(|| anyhow!("trace address overflow"))?;
                // Do not cross a page in one remote iovec: an inaccessible next page is unrelated.
                let count = (length - done).min(4096 - at % 4096);
                let local = libc::iovec { iov_base: bytes[done..].as_mut_ptr().cast(), iov_len: count };
                let remote = libc::iovec { iov_base: at as *mut libc::c_void, iov_len: count };
                let read = unsafe { libc::process_vm_readv(pid, &local, 1, &remote, 1, 0) };
                if read < 0 { return Err(io::Error::last_os_error().into()); }
                ensure!(read > 0, "empty trace memory read");
                done += read as usize;
            }
            Ok(bytes)
        }

        fn source_path(pid: i32, info: &SyscallInfo) -> ResultType<PathBuf> {
            let address = usize::try_from(info.data[2])?;
            let mut name = Vec::new();
            // Native filenames have at most NAME_MAX bytes in this VM's local fixture filesystem.
            for offset in 0..=255 {
                let byte = read_memory(pid, address.checked_add(offset)
                    .ok_or_else(|| anyhow!("trace filename address overflow"))?, 1)?[0];
                if byte == 0 { break; }
                name.push(byte);
            }
            ensure!(!name.is_empty() && name.len() <= 255 && !name.contains(&b'/')
                && name != b"." && name != b"..", "unexpected syscall source name");
            let fd = info.data[1] as i32;
            ensure!(fd >= 0, "retained source directory descriptor required");
            let parent = fs::read_link(format!("/proc/{pid}/fd/{fd}"))?;
            ensure!(parent.is_absolute());
            Ok(parent.join(std::ffi::OsString::from_vec(name)))
        }

        fn bounded_output<R: Read>(pipe: R) -> ResultType<Vec<u8>> {
            let mut bytes = Vec::new();
            pipe.take(16385).read_to_end(&mut bytes)?;
            ensure!(bytes.len() <= 16384, "child output bound exceeded");
            Ok(bytes)
        }

        fn actor(path: &Path) -> ResultType<Value> {
            let mut owned = ActorOwner(actor_command(path, "replace-window")?.spawn()?);
            let child = &mut owned.0;
            let deadline = Instant::now() + Duration::from_secs(5);
            let status = loop {
                if let Some(status) = child.try_wait()? { break status; }
                if Instant::now() >= deadline {
                    let killed = child.kill();
                    let joined = child.wait()?;
                    return Err(anyhow!("window actor deadline; joined: {joined}; kill: {killed:?}"));
                }
                std::thread::sleep(Duration::from_millis(1));
            };
            let out = bounded_output(child.stdout.take().ok_or_else(|| anyhow!("actor stdout absent"))?)?;
            let err = bounded_output(child.stderr.take().ok_or_else(|| anyhow!("actor stderr absent"))?)?;
            let mut count = 0;
            let observed = report_actor("replace-window", &mut count, status, &out, &err)?;
            ensure!(count == 1);
            Ok(observed)
        }

        pub fn run(base: PathBuf, operation: String) -> ResultType<Value> {
            // This whole controller runs on one blocking thread: ptrace ownership is per thread.
            ensure!(cfg!(target_arch = "x86_64"), "canonical x86_64 verifier required");
            let (number, suffix) = match operation.as_str() {
                "payload-rename" => (libc::SYS_renameat, ".download"),
                "digest-unlink" => (libc::SYS_unlinkat, ".digest"),
                "lease-unlink" => (libc::SYS_unlinkat, ".download.lock"),
                "crash-directory" => (libc::SYS_mkdirat, ""),
                "crash-identity" => (libc::SYS_fsync, "identity"),
                "crash-record" => (libc::SYS_renameat, ".tmp"),
                _ => return Err(anyhow!("unknown syscall window")),
            };
            let crash = operation.starts_with("crash-");
            let mut killed = false;
            let mut command = Command::new(std::env::current_exe()?);
            command.arg(if crash { "crash-receiver" } else { "window-receiver" }).arg(&base)
                .stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
            unsafe {
                command.pre_exec(|| {
                    if libc::ptrace(libc::PTRACE_TRACEME, 0, std::ptr::null_mut::<libc::c_void>(),
                        std::ptr::null_mut::<libc::c_void>()) == -1 {
                        return Err(io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
            let child = command.spawn()?;
            let root = i32::try_from(child.id())?;
            let mut owner = TraceOwner { child, tasks: BTreeSet::from([root]) };
            let deadline = Instant::now() + Duration::from_secs(15);
            let mut initial = true;
            let mut newborn_stops = BTreeSet::new();
            let mut armed = false;
            let mut observation = None;
            let mut syscall_result = None;
            let mut selected_task = None;
            let mut main_status = None;
            let mut events = 0usize;
            while !owner.tasks.is_empty() {
                ensure!(Instant::now() < deadline, "receiver trace deadline exceeded");
                let mut status = 0;
                let pid = unsafe {
                    libc::waitpid(-1, &mut status, libc::WNOHANG | libc::__WALL | libc::__WNOTHREAD)
                };
                if pid < 0 {
                    let error = io::Error::last_os_error();
                    if error.kind() == io::ErrorKind::Interrupted { continue; }
                    return Err(error.into());
                }
                if pid == 0 { std::thread::sleep(Duration::from_millis(1)); continue; }
                events += 1;
                ensure!(events <= 100000, "trace event bound exceeded");
                if !owner.tasks.contains(&pid) {
                    // A child's initial stop can be reported before its parent's clone event.
                    ensure!(libc::WIFSTOPPED(status) && libc::WSTOPSIG(status) == libc::SIGSTOP
                        && newborn_stops.len() < 32 && newborn_stops.insert(pid),
                        "unexpected trace ownership");
                    continue;
                }
                if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
                    owner.tasks.remove(&pid);
                    if pid == root { main_status = Some(std::process::ExitStatus::from_raw(status)); }
                    continue;
                }
                ensure!(libc::WIFSTOPPED(status));
                if killed {
                    match trace(libc::PTRACE_CONT, pid, 0, libc::SIGKILL as usize) {
                        Ok(_) => {}
                        Err(error) if error.raw_os_error() == Some(libc::ESRCH) => {}
                        Err(error) => return Err(error.into()),
                    }
                    continue;
                }
                let signal = libc::WSTOPSIG(status);
                let event = status >> 16;
                let mut deliver = 0;
                if initial {
                    ensure!(pid == root && signal == libc::SIGTRAP && event == 0);
                    let options = libc::PTRACE_O_TRACESYSGOOD | libc::PTRACE_O_TRACECLONE
                        | libc::PTRACE_O_TRACEFORK | libc::PTRACE_O_TRACEVFORK | libc::PTRACE_O_EXITKILL;
                    trace(libc::PTRACE_SETOPTIONS, pid, 0, options as usize)?;
                    initial = false;
                } else if [libc::PTRACE_EVENT_CLONE, libc::PTRACE_EVENT_FORK,
                    libc::PTRACE_EVENT_VFORK].contains(&event) {
                    let mut spawned = 0usize;
                    trace(libc::PTRACE_GETEVENTMSG, pid, 0, &mut spawned as *mut _ as usize)?;
                    let spawned = i32::try_from(spawned)?;
                    ensure!(owner.tasks.len() < 32 && owner.tasks.insert(spawned));
                    if newborn_stops.remove(&spawned) { trace(libc::PTRACE_SYSCALL, spawned, 0, 0)?; }
                } else if signal == (libc::SIGTRAP | 0x80) {
                    let mut info = SyscallInfo::default();
                    let size = trace(0x420e, pid, std::mem::size_of::<SyscallInfo>(),
                        &mut info as *mut _ as usize)?;
                    ensure!(info.arch == 0xc000003e, "unexpected syscall architecture");
                    if info.op == 1 {
                        ensure!(size >= 80, "incomplete syscall entry");
                        if info.data[0] as i64 == libc::SYS_write && info.data[1] == 1
                            && info.data[3] == ARMED.len() as u64
                            && read_memory(pid, usize::try_from(info.data[2])?, ARMED.len())? == ARMED {
                            ensure!(!armed);
                            armed = true;
                        }
                        if armed && observation.is_none() && info.data[0] as i64 == number {
                            let path = if number == libc::SYS_fsync {
                                fs::read_link(format!("/proc/{pid}/fd/{}", info.data[1]))?
                            } else { source_path(pid, &info)? };
                            let selected = if operation == "crash-directory" {
                                path.parent() == Some(base.as_path()) && path.file_name()
                                    .is_some_and(|n| n.as_encoded_bytes().starts_with(b".rustdesk-receive-"))
                            } else if operation == "crash-record" {
                                path.parent() == Some(coordinator()?.as_path())
                                    && path.extension().is_some_and(|s| s == "tmp")
                                    && fs::metadata(&path)?.len() <= 256
                                    && hbb_common::serde_json::from_slice::<Value>(&fs::read(&path)?)?
                                        ["inode"].as_u64().is_some()
                            } else {
                                path.file_name().is_some_and(|n| n.as_encoded_bytes().ends_with(suffix.as_bytes()))
                            };
                            if selected && crash {
                                ensure!(path.starts_with(&base) || operation == "crash-record");
                                observation = Some(json!({"source":path,"tid":pid,"syscall":number}));
                                selected_task = Some(pid);
                                if operation == "crash-record" {
                                    owner.child.kill()?;
                                    killed = true;
                                    continue;
                                }
                            } else if selected {
                                ensure!(path.starts_with(&base));
                                let before = snapshot(&path)?;
                                ensure!(before["uid"] == 0 && before["mode"] == 0o600 && before["links"] == 1);
                                let changed = actor(&path)?;
                                let after = snapshot(&path)?;
                                observation = Some(json!({"source":path, "tid":pid,
                                    "directory_fd":info.data[1], "syscall":number,
                                    "before":before, "actor":changed, "after_actor":after}));
                                selected_task = Some(pid);
                            }
                        }
                    } else if info.op == 2 && selected_task == Some(pid) && syscall_result.is_none() {
                        ensure!(size >= 33, "incomplete syscall exit");
                        syscall_result = Some(json!({"return":info.data[0] as i64,
                            "is_error":info.data[1] & 255 != 0}));
                        if crash {
                            ensure!(info.data[0] == 0 && info.data[1] & 255 == 0,
                                "selected enrollment syscall did not succeed");
                            owner.child.kill()?;
                            killed = true;
                            continue;
                        }
                    }
                } else if signal != libc::SIGSTOP {
                    ensure!(event == 0, "unexpected ptrace event");
                    deliver = signal;
                }
                trace(libc::PTRACE_SYSCALL, pid, 0, deliver as usize)?;
            }
            ensure!(newborn_stops.is_empty(), "unclaimed tracee stop");
            let out = bounded_output(owner.child.stdout.take().ok_or_else(|| anyhow!("receiver stdout absent"))?)?;
            let err = bounded_output(owner.child.stderr.take().ok_or_else(|| anyhow!("receiver stderr absent"))?)?;
            if crash {
                ensure!(killed && main_status.is_some_and(|s| s.signal() == Some(libc::SIGKILL)));
                ensure!(out == ARMED && err.is_empty(), "unexpected killed-receiver output");
                let observation = observation.ok_or_else(|| anyhow!("required crash point not observed"))?;
                return Ok(json!({"operation":operation,"selected":observation,
                    "syscall_exit":syscall_result,"signal":"SIGKILL","children_joined":true,
                    "trace_events":events}));
            }
            ensure!(main_status.is_some_and(|s| s.success()), "receiver failed: {}", String::from_utf8_lossy(&err));
            let text = std::str::from_utf8(&out)?;
            let reports: Vec<_> = text.lines().filter_map(|l| l.strip_prefix("RECEIVE_NATIVE_WINDOW_RECEIVER=")).collect();
            ensure!(reports.len() == 1 && text.lines().filter(|l| l.as_bytes() == &ARMED[..ARMED.len()-1]).count() == 1);
            let receiver: Value = hbb_common::serde_json::from_str(reports[0])?;
            let observation = observation.ok_or_else(|| anyhow!("required syscall window never reached"))?;
            let path = Path::new(observation["source"].as_str().ok_or_else(|| anyhow!("source absent"))?);
            let held = snapshot(&path.with_file_name("window-held"))?;
            let final_state = snapshot(&base.join("incoming.bin"))?;
            let source_after = snapshot(path)?;
            let actor_denied = observation["actor"]["denied"] == true;
            let safe = if actor_denied {
                receiver["finish_ok"] == true && receiver["retire_ok"] == true
                    && private_final(&base).is_ok() && held.is_null()
            } else {
                // A refusal must preserve both the unrelated replacement and the prior final target.
                receiver["finish_ok"] == false && source_after == observation["after_actor"]
                    && final_state["bytes"] == json!(b"original".to_vec())
                    && held == observation["before"]
            };
            ensure!(actor_denied || (observation["actor"]["renamed"] == true
                && observation["after_actor"]["uid"] == ACTOR_UID));
            ensure!(syscall_result.is_some(), "selected syscall exit missing");
            Ok(json!({"operation":operation, "safe":safe, "selected":observation,
                "syscall_exit":syscall_result, "receiver":receiver, "source_after":source_after,
                "held":held, "final":final_state, "trace_events":events, "children_joined":true}))
        }
    }

    async fn parent(root: &Path) -> ResultType<()> {
        let who = identity(0)?;
        ensure!(fs::metadata(root)?.uid() == 0);
        let cases = ["fresh", "resume", "foreign-final", "foreign-lease", "foreign-data",
            "foreign-digest", "read-shared-data", "writable-digest", "replace-data-finalize",
            "replace-data-cancel", "replace-digest-finalize", "replace-parent", "replace-namespace"];
        let mut actors = 0;
        println!("RECEIVE_NATIVE_RECEIVER={who}");
        for case in cases {
            let base = root.join(case);
            fs::create_dir(&base)?;
            fs::set_permissions(&base, fs::Permissions::from_mode(0o777))?;
            let mut receiver = job(&base)?;
            let observation = match case {
                "fresh" | "resume" | "foreign-final" => {
                    if case == "resume" {
                        let artifacts = prepare_staging(&base).await?;
                        create(&artifacts.join("payload.download"), b"abc", 0o600)?;
                        create(&artifacts.join("resume.digest"), DIGEST, 0o600)?;
                    }
                    if case == "foreign-final" {
                        actor(&base, "foreign-final", &mut actors).await?;
                        ensure!(fs::read(base.join("incoming.bin"))? == b"original",
                            "privileged read calibration failed");
                    }
                    admit(&mut receiver, case == "resume", if case == "resume" {3} else {0}).await?;
                    if case != "resume" { write(&mut receiver, b"abc").await?; }
                    let probe = actor(&staging(&base)?.join("payload.download"), "probe-data", &mut actors).await?;
                    ensure!(probe["read_denied"] == true && probe["write_denied"] == true);
                    write(&mut receiver, b"def").await?;
                    receiver.finalize_write(1).await?;
                    receiver.retire_current_file_state()?;
                    let final_state = private_final(&base)?;
                    let probe = actor(&base, "probe-final", &mut actors).await?;
                    ensure!(probe["read_denied"] == true && probe["write_denied"] == true);
                    json!({"final":final_state, "actor_access_denied":true})
                }
                "foreign-lease" | "foreign-data" | "foreign-digest"
                    | "read-shared-data" | "writable-digest" => {
                    create(&base.join("incoming.bin"), b"original", 0o600)?;
                    let artifacts = prepare_staging(&base).await?;
                    if case == "foreign-lease" {
                        actor(&base, case, &mut actors).await?;
                        OpenOptions::new().write(true).open(base.join("incoming.bin.download.lock"))?;
                    } else {
                        if case != "foreign-data" {
                            create(&base.join("incoming.bin.download"), b"abc",
                                if case == "read-shared-data" {0o644} else {0o600})?;
                        }
                        if case != "foreign-digest" {
                            create(&base.join("incoming.bin.digest"), DIGEST,
                                if case == "writable-digest" {0o666} else {0o600})?;
                        }
                        match case {
                            "foreign-data" | "foreign-digest" => {
                                let result = actor(&base, case, &mut actors).await?;
                                ensure!(result["created"]["uid"] == ACTOR_UID);
                                let path = if case == "foreign-data" {"incoming.bin.download"}
                                    else {"incoming.bin.digest"};
                                fs::read(base.join(path))?;
                            }
                            "read-shared-data" => {
                                let probe = actor(&base.join("incoming.bin.download"), "probe-data", &mut actors).await?;
                                ensure!(probe["bytes"] == json!(b"abc".to_vec())
                                    && probe["write_denied"] == true);
                            }
                            _ => { actor(&base, "mutate-digest", &mut actors).await?; }
                        }
                    }
                    // Root places the calibrated malformed objects inside its namespace.
                    // Their foreign ownership/unsafe metadata must still be refused.
                    for (old, new) in [("incoming.bin.download", "payload.download"),
                        ("incoming.bin.digest", "resume.digest"),
                        ("incoming.bin.download.lock", "claim.download.lock")] {
                        if base.join(old).exists() { fs::rename(base.join(old), artifacts.join(new))?; }
                    }
                    let before = state(&base)?;
                    let result = receiver.inspect_receive_digest(&incoming(), case != "foreign-lease").await;
                    let error = result.err().ok_or_else(|| anyhow!("unsafe resume inspection succeeded"))?;
                    ensure!(error.downcast_ref::<io::Error>()
                        .is_some_and(|e| e.kind() == io::ErrorKind::PermissionDenied));
                    ensure!(!receiver.file_confirmed() && receiver.finished_size() == 0
                        && receiver.transferred() == 0);
                    receiver.retire_current_file_state()?;
                    let after = state(&base)?;
                    ensure!(before == after, "refused artifact state changed");
                    json!({"refused":true, "before":before, "after":after})
                }
                "replace-data-finalize" | "replace-data-cancel" | "replace-digest-finalize" => {
                    create(&base.join("incoming.bin"), b"original", 0o600)?;
                    admit(&mut receiver, false, 0).await?;
                    write(&mut receiver, b"abcdef").await?;
                    let op = if case == "replace-digest-finalize" {"replace-digest"} else {"replace-data"};
                    let artifacts = staging(&base)?;
                    let selected = artifacts.join(if op == "replace-data" {"payload.download"} else {"resume.digest"});
                    let before = snapshot(&selected)?;
                    let changed = actor(&selected, op, &mut actors).await?;
                    ensure!(changed["replacement_denied"] == true && snapshot(&selected)? == before);
                    if case == "replace-data-cancel" {
                        receiver.retire_current_file_state()?;
                        ensure!(fs::read(base.join("incoming.bin"))? == b"original");
                    } else {
                        receiver.finalize_write(1).await?;
                        receiver.retire_current_file_state()?;
                        private_final(&base)?;
                    }
                    ensure!(!artifacts.exists());
                    json!({"actor_replacement_denied":true, "artifact_before":before,
                        "authorized_operation_completed":true, "artifacts_retired":true})
                }
                "replace-namespace" => {
                    admit(&mut receiver, false, 0).await?;
                    write(&mut receiver, b"abc").await?;
                    let artifacts = staging(&base)?;
                    let container = artifacts.parent().ok_or_else(|| anyhow!("namespace parent absent"))?;
                    actor(container, "swap-namespace", &mut actors).await?;
                    let replacement = snapshot(&container.join("foreign"))?;
                    let mut contender = job(&base)?;
                    let error = contender.inspect_receive_digest(&incoming(), false).await
                        .err().ok_or_else(|| anyhow!("parallel receive generation admitted"))?;
                    ensure!(error.downcast_ref::<io::Error>()
                        .is_some_and(|e| e.kind() == io::ErrorKind::WouldBlock));
                    contender.retire_current_file_state()?;
                    write(&mut receiver, b"def").await?;
                    receiver.finalize_write(1).await?;
                    receiver.retire_current_file_state()?;
                    let final_state = snapshot(&base.join("incoming.bin"))?;
                    ensure!(final_state["bytes"] == json!(b"abcdef".to_vec())
                        && final_state["uid"] == 0 && final_state["mode"] == 0o600
                        && final_state["mtime"] == 31);
                    ensure!(snapshot(&container.join("foreign"))? == replacement);
                    ensure!(fs::read_dir(base.join("held-namespace"))?.count() == 1);
                    json!({"parallel_generation_refused":true, "retained_namespace_completed":true,
                        "replacement_preserved":true, "final":final_state})
                }
                "replace-parent" => {
                    fs::create_dir(base.join("selected"))?;
                    fs::create_dir(base.join("outside"))?;
                    create(&base.join("outside/incoming.bin"), b"outside", 0o600)?;
                    receiver = job(&base.join("selected"))?;
                    admit(&mut receiver, false, 0).await?;
                    write(&mut receiver, b"abc").await?;
                    actor(&base, "swap-parent", &mut actors).await?;
                    write(&mut receiver, b"def").await?;
                    receiver.finalize_write(1).await?;
                    receiver.retire_current_file_state()?;
                    let final_state = private_final(&base.join("held-parent"))?;
                    ensure!(fs::read(base.join("outside/incoming.bin"))? == b"outside");
                    ensure!(fs::symlink_metadata(base.join("selected"))?.file_type().is_symlink());
                    json!({"retained_parent_final":final_state, "outside_preserved":true})
                }
                _ => return Err(anyhow!("unknown case")),
            };
            println!("RECEIVE_NATIVE_CASE={}", json!({"case":case,"observed":observation}));
            fs::remove_dir_all(&base)?;
        }
        let mut safe_windows = 0;
        for operation in ["payload-rename", "digest-unlink", "lease-unlink"] {
            let case = format!("window-{operation}");
            let base = root.join(&case);
            fs::create_dir(&base)?;
            fs::set_permissions(&base, fs::Permissions::from_mode(0o777))?;
            let selected = base.clone();
            let operation = operation.to_owned();
            let observed = tokio::task::spawn_blocking(move || syscall_window::run(selected, operation)).await??;
            actors += 1;
            if observed["safe"] == true { safe_windows += 1; }
            println!("RECEIVE_NATIVE_CASE={}", json!({"case":case,"observed":observed}));
            fs::remove_dir_all(&base)?;
        }
        ensure!(actors == 20, "unexpected joined actor total: {actors}");
        println!("RECEIVE_NATIVE_WINDOW_SUMMARY=observed cases=3 safe={safe_windows} children=joined fixture=retired");
        ensure!(safe_windows == 3, "receive namespace syscall-window cases failed: {safe_windows}/3 safe");
        let mut recovered = 0;
        for operation in ["crash-directory", "crash-identity", "crash-record"] {
            let base = root.join(operation);
            fs::create_dir(&base)?;
            let before = temporary_records()?;
            let selected = base.clone();
            let phase = operation.to_owned();
            let crash = tokio::task::spawn_blocking(move || syscall_window::run(selected, phase)).await??;
            let recovery = async {
                let mut receiver = job(&base)?;
                admit(&mut receiver, false, 0).await?;
                write(&mut receiver, b"abcdef").await?;
                receiver.finalize_write(1).await?;
                receiver.retire_current_file_state()?;
                Ok::<_, hbb_common::anyhow::Error>(())
            }.await;
            let containers = fs::read_dir(&base)?.collect::<Result<Vec<_>, _>>()?.into_iter()
                .filter(|e| e.file_name().as_encoded_bytes().starts_with(b".rustdesk-receive-")).count();
            let temporary = temporary_records()?.difference(&before).cloned().collect::<Vec<_>>();
            let safe = recovery.is_ok() && containers == 1 && temporary.is_empty()
                && private_final(&base).is_ok();
            recovered += usize::from(safe);
            println!("RECEIVE_NATIVE_CASE={}", json!({"case":operation,"observed":{
                "crash":crash,"recovery_ok":recovery.is_ok(),"recovery_error":recovery.err().map(|e|e.to_string()),
                "containers":containers,"temporary_records_added":temporary.len(),"safe":safe}}));
            fs::remove_dir_all(&base)?;
        }
        println!("RECEIVE_NATIVE_ENROLLMENT_SUMMARY=observed cases=3 recovered={recovered} children=joined fixture=retired");
        ensure!(recovered == 3, "receive enrollment crash cases failed: {recovered}/3 recovered");
        let mut retired = 0;
        let base = root.join("completed-listing");
        fs::create_dir(&base)?;
        complete_transfer(&base).await?;
        let mut listings = Vec::new();
        let mut listing_ok = true;
        for hidden in [false, true] {
            let listing = hbb_common::fs::read_dir(&base, hidden)?;
            let mut names: Vec<_> = listing.entries.iter().map(|e| e.name.clone()).collect();
            names.sort();
            listing_ok &= names == ["incoming.bin"];
            listings.push(json!({"include_hidden":hidden,"names":names}));
        }
        retired += usize::from(listing_ok);
        println!("RECEIVE_NATIVE_CASE={}", json!({"case":"completed-listing",
            "observed":{"listings":listings,"safe":listing_ok}}));
        fs::remove_dir_all(&base)?;

        let mut removals = Vec::new();
        let mut removal_ok = true;
        for recursive in [false, true] {
            let base = root.join(format!("completed-removal-{recursive}"));
            fs::create_dir(&base)?;
            complete_transfer(&base).await?;
            hbb_common::fs::remove_file(base.join("incoming.bin").to_str()
                .ok_or_else(|| anyhow!("native removal path is not UTF-8"))?)?;
            let result = if recursive { hbb_common::fs::remove_empty_directory_tree(&base) }
                else { hbb_common::fs::remove_directory(&base) };
            let absent = !base.try_exists()?;
            removal_ok &= result.is_ok() && absent;
            removals.push(json!({"recursive":recursive,"removed":absent,
                "success":result.is_ok(),"error":result.err().map(|e| e.to_string())}));
            if !absent { fs::remove_dir_all(&base)?; }
        }
        retired += usize::from(removal_ok);
        println!("RECEIVE_NATIVE_CASE={}", json!({"case":"completed-removal",
            "observed":{"removals":removals,"safe":removal_ok}}));

        let base = root.join("completed-destinations");
        fs::create_dir(&base)?;
        let before = coordination_inventory()?;
        for index in 0..32 {
            let destination = base.join(index.to_string());
            fs::create_dir(&destination)?;
            complete_transfer(&destination).await?;
        }
        // Retain all destinations until after measurement, excluding inode reuse.
        let after = coordination_inventory()?;
        let added: Vec<_> = after.iter().filter(|(path, _)| !before.contains_key(*path)).collect();
        let retained_bytes: u64 = added.iter().map(|(_, bytes)| **bytes).sum();
        let retention_ok = added.is_empty();
        retired += usize::from(retention_ok);
        println!("RECEIVE_NATIVE_CASE={}", json!({"case":"completed-destinations",
            "observed":{"destinations":32,"coordination_records_added":added.len(),
                "coordination_allocated_bytes_added":retained_bytes,"safe":retention_ok}}));
        fs::remove_dir_all(&base)?;
        println!("RECEIVE_NATIVE_RETIREMENT_SUMMARY=observed cases=3 retired={retired} children=joined fixture=retired");
        ensure!(retired == 3, "receive completed-destination cases failed: {retired}/3 retired");
        println!("RECEIVE_NATIVE_AUTHORITY=pass cases=22 actors={actors} receiver_uid=0 actor_uid=4001 children=joined fixture=retired");
        Ok(())
    }

    pub async fn entry() -> ResultType<()> {
        ensure!(fs::read_to_string("/proc/cmdline")?.split_whitespace()
            .any(|s| s == "rustdesk.verifier_vm=1"), "owned verifier VM required");
        let args: Vec<_> = std::env::args().collect();
        let executable = std::env::current_exe()?;
        let owned = executable.parent().ok_or_else(|| anyhow!("executable parent absent"))?.join("data");
        if args.len() == 4 && args[1] == "actor" {
            let base = Path::new(&args[3]);
            ensure!(base.starts_with(&owned) && base != owned);
            actor_main(base, &args[2])
        } else if args.len() == 3 && args[1] == "window-receiver" {
            let base = Path::new(&args[2]);
            ensure!(base.starts_with(&owned) && base != owned);
            window_receiver(base).await
        } else if args.len() == 3 && args[1] == "crash-receiver" {
            let base = Path::new(&args[2]);
            ensure!(base.starts_with(&owned) && base != owned);
            crash_receiver(base).await
        } else {
            ensure!(args.len() == 3 && args[1] == "run" && Path::new(&args[2]) == owned);
            parent(&owned).await
        }
    }
}

#[cfg(target_os = "linux")]
#[tokio::main(flavor = "current_thread")]
async fn main() -> hbb_common::ResultType<()> {
    linux::entry().await
}

#[cfg(not(target_os = "linux"))]
fn main() -> Result<(), &'static str> {
    Err("this native authority target requires the owned Linux verifier VM")
}
