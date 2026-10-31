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
        // Establish a retained namespace in a shared fixture parent, then restore
        // its intended test permissions before injecting saved/malformed artifacts.
        let permissions = fs::metadata(base)?.permissions();
        fs::set_permissions(base, fs::Permissions::from_mode(0o777))?;
        let mut receiver = job(base)?;
        let prepared = async {
            receiver.inspect_receive_digest(&incoming(), false).await?;
            receiver.confirm_with_offset(0, 0).await?;
            receiver.retire_current_file_state()
        }.await;
        fs::set_permissions(base, permissions)?;
        prepared?;
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
        let mut namespace_present = false;
        for entry in fs::read_dir(base)? {
            namespace_present |= entry?.file_name().as_encoded_bytes().starts_with(b".rustdesk-receive-");
        }
        if namespace_present {
            ensure!(!staging(base)?.exists(), "completed receive retained its per-file namespace");
        }
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

    async fn full_filesystem(base: &Path, phase: &str, free_pages: u64) -> ResultType<Value> {
        use std::{ffi::CString, os::unix::{ffi::OsStrExt, io::AsRawFd}};
        const PAGE: usize = 4096;
        ensure!(free_pages <= 1 && unsafe { libc::sysconf(libc::_SC_PAGESIZE) } == PAGE as i64);
        ensure!(matches!(phase, "block" | "identity" | "digest")
            && (phase == "block" || free_pages == 0));
        fs::create_dir(base)?;
        let target = CString::new(base.as_os_str().as_bytes())?;
        if unsafe { libc::mount(b"tmpfs\0".as_ptr().cast(), target.as_ptr(),
            b"tmpfs\0".as_ptr().cast(), libc::MS_NODEV | libc::MS_NOSUID | libc::MS_NOEXEC,
            b"size=65536,nr_inodes=128,mode=0700,huge=never\0".as_ptr().cast()) } != 0 {
            let error = io::Error::last_os_error();
            fs::remove_dir(base)?;
            return Err(error.into());
        }
        // The result-bearing scope drops every receive/filler handle before unmount.
        let result = async {
            let final_path = base.join("incoming.bin");
            create(&final_path, b"original", 0o600)?;
            let original = snapshot(&final_path)?;
            let expected_size = (3 * PAGE) as u64;
            let new_receiver = || TransferJob::new_write(807, JobType::Generic,
                String::new(), base.to_owned(), 0, false, false, true)
                .with_files(vec![FileEntry { name:"incoming.bin".into(),
                    size:expected_size, modified_time:31, ..Default::default() }]);
            let mut receiver = new_receiver()?;
            let mut digest = incoming();
            digest.file_size = expected_size;
            if phase == "digest" {
                // Retain the enrolled identity so exhaustion reaches digest setup.
                // Restore the protected parent before admitting the write.
                fs::set_permissions(base, fs::Permissions::from_mode(0o777))?;
            }
            receiver.inspect_receive_digest(&digest, false).await?;
            if phase == "identity" {
                ensure!(fs::read_dir(base)?.count() == 1, "inspection created staging before exhaustion");
            }
            let prepared_artifacts = if phase == "digest" {
                receiver.confirm_with_offset(0, 0).await?;
                receiver.retire_current_file_state()?;
                receiver = new_receiver()?;
                receiver.inspect_receive_digest(&digest, false).await?;
                fs::set_permissions(base, fs::Permissions::from_mode(0o700))?;
                Some(staging(base)?)
            } else { None };
            if phase == "block" {
                receiver.confirm_with_offset(0, 0).await?;
                write(&mut receiver, &vec![b'a'; PAGE]).await?;
            }
            let counters = (receiver.finished_size(), receiver.transferred());
            let filler_path = base.join("space-filler");
            let mut filler = OpenOptions::new().write(true).create_new(true)
                .mode(0o600).open(&filler_path)?;
            let mut exhausted = false;
            for _ in 0..=16 {
                match filler.write_all(&[0; PAGE]) {
                    Ok(()) => {}
                    Err(error) if error.raw_os_error() == Some(libc::ENOSPC) => {
                        exhausted = true;
                        break;
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            ensure!(exhausted, "bounded fixture did not exhaust its filesystem");
            let filled = filler.metadata()?.len();
            ensure!(filled >= PAGE as u64 && filled <= 65536 && filled % PAGE as u64 == 0);
            filler.set_len(filled - free_pages * PAGE as u64)?;
            let mut space: libc::statvfs = unsafe { std::mem::zeroed() };
            ensure!(unsafe { libc::fstatvfs(filler.as_raw_fd(), &mut space) } == 0);
            ensure!(space.f_blocks * space.f_frsize == 65536
                && space.f_bavail * space.f_frsize == free_pages * PAGE as u64);

            let failed = if phase == "identity" || phase == "digest" {
                receiver.confirm_with_offset(0, 0).await.map(|_| ())
            } else { write(&mut receiver, &vec![b'b'; 2 * PAGE]).await };
            let error = failed.err().ok_or_else(|| anyhow!("full-filesystem operation reported success"))?;
            ensure!(error.downcast_ref::<io::Error>()
                .is_some_and(|error| error.raw_os_error() == Some(libc::ENOSPC)));
            let artifacts = match prepared_artifacts {
                Some(artifacts) => artifacts,
                None => staging(base)?,
            };
            if phase == "block" {
                let staged = fs::read(artifacts.join("payload.download"))?;
                let mut expected_partial = vec![b'a'; PAGE];
                expected_partial.extend(vec![b'b'; free_pages as usize * PAGE]);
                ensure!(staged == expected_partial, "unexpected native partial-block bytes");
            } else {
                ensure!(!artifacts.try_exists()?, "failed setup retained per-file artifacts");
                if phase == "identity" {
                    let container = artifacts.parent().ok_or_else(|| anyhow!("namespace parent absent"))?;
                    let marker = container.join("identity");
                    let before_marker = snapshot(&marker)?;
                    ensure!(before_marker["length"] == 0 && before_marker["uid"] == 0
                        && before_marker["mode"] == 0o600 && before_marker["links"] == 1);
                    let before_records = coordination_inventory()?;
                    // A fresh owner must reuse the same preparing intent after failure.
                    receiver.retire_current_file_state()?;
                    drop(receiver);
                    receiver = new_receiver()?;
                    let repeated = receiver.inspect_receive_digest(&digest, false).await
                        .err().ok_or_else(|| anyhow!("repeated full-filesystem setup succeeded"))?;
                    ensure!(repeated.downcast_ref::<io::Error>()
                        .is_some_and(|error| error.raw_os_error() == Some(libc::ENOSPC)));
                    let after_marker = snapshot(&marker)?;
                    let same_marker = ["device", "inode", "uid", "gid", "mode", "links", "length", "bytes"]
                        .iter().all(|key| after_marker[*key] == before_marker[*key]);
                    ensure!(staging(base)? == artifacts && same_marker
                        && coordination_inventory()? == before_records,
                        "repeated setup failure changed its preparing namespace or records");
                }
            }
            ensure!((receiver.finished_size(), receiver.transferred()) == counters);
            ensure!(receiver.file_num() == 0 && snapshot(&final_path)? == original);
            ensure!(receiver.finalize_write(1).await.is_err(), "failed block was published");
            receiver.retire_current_file_state()?;
            ensure!(!artifacts.try_exists()? && snapshot(&final_path)? == original);
            drop(receiver);

            // Cleanup must succeed before releasing the unrelated filler. A fresh
            // job then reacquires the destination and completes after space returns.
            drop(filler);
            fs::remove_file(&filler_path)?;
            let mut fresh = new_receiver()?;
            fresh.inspect_receive_digest(&digest, false).await?;
            fresh.confirm_with_offset(0, 0).await?;
            let expected = vec![b'c'; expected_size as usize];
            write(&mut fresh, &expected).await?;
            fresh.finalize_write(1).await?;
            fresh.retire_current_file_state()?;
            ensure!(fs::read(&final_path)? == expected && fs::read_dir(base)?.count() == 1);
            Ok::<_, hbb_common::anyhow::Error>(json!({"filesystem":"tmpfs", "phase":phase,
                "capacity_bytes":65536, "free_bytes_before_block":free_pages * PAGE as u64,
                "block_bytes":if phase == "block" {2 * PAGE} else {0},
                "partial_block_bytes":free_pages * PAGE as u64,
                "error":"ENOSPC", "counters_unchanged":true, "publication_refused":true,
                "prior_final_preserved":true, "cleanup_before_space_release":true,
                "repeated_preparing_state_preserved":phase == "identity",
                "fresh_transfer_exact":true}))
        }.await;
        if unsafe { libc::umount2(target.as_ptr(), 0) } != 0 {
            return Err(anyhow!("receive storage fixture unmount failed: {}; operation: {result:?}",
                io::Error::last_os_error()));
        }
        fs::remove_dir(base)?;
        result
    }

    async fn readonly_enrollment(base: &Path) -> ResultType<Value> {
        use std::{ffi::CString, os::unix::ffi::OsStrExt};
        fs::create_dir(base)?;
        let target = CString::new(base.as_os_str().as_bytes())?;
        let flags = libc::MS_NODEV | libc::MS_NOSUID | libc::MS_NOEXEC;
        if unsafe { libc::mount(b"tmpfs\0".as_ptr().cast(), target.as_ptr(),
            b"tmpfs\0".as_ptr().cast(), flags,
            b"size=65536,nr_inodes=128,mode=0700,huge=never\0".as_ptr().cast()) } != 0 {
            let error = io::Error::last_os_error();
            fs::remove_dir(base)?;
            return Err(error.into());
        }
        let result = async {
            let mut destinations = Vec::new();
            for index in 0..8 {
                let path = base.join(index.to_string());
                fs::create_dir(&path)?;
                create(&path.join("incoming.bin"), b"original", 0o600)?;
                destinations.push(path);
            }
            let before = coordination_inventory()?;
            let originals = destinations.iter().map(|path| snapshot(&path.join("incoming.bin")))
                .collect::<ResultType<Vec<_>>>()?;
            ensure!(unsafe { libc::mount(std::ptr::null(), target.as_ptr(), std::ptr::null(),
                flags | libc::MS_REMOUNT | libc::MS_RDONLY, std::ptr::null()) } == 0,
                "read-only fixture remount failed: {}", io::Error::last_os_error());
            let calibration = fs::create_dir(base.join("must-refuse"))
                .err().ok_or_else(|| anyhow!("read-only mount allowed directory creation"))?;
            ensure!(calibration.raw_os_error() == Some(libc::EROFS));
            let mut retained_counts = Vec::new();
            for (index, path) in destinations.iter().enumerate() {
                for _ in 0..2 {
                    let mut receiver = job(path)?;
                    let counters = (receiver.finished_size(), receiver.transferred());
                    let error = admit(&mut receiver, false, 0).await.err()
                        .ok_or_else(|| anyhow!("read-only receive admission succeeded"))?;
                    ensure!(error.downcast_ref::<io::Error>()
                        .is_some_and(|error| error.raw_os_error() == Some(libc::EROFS)),
                        "unexpected read-only admission error: {error}");
                    ensure!((receiver.finished_size(), receiver.transferred()) == counters);
                    ensure!(receiver.finalize_write(1).await.is_err());
                    receiver.retire_current_file_state()?;
                    drop(receiver);
                    ensure!(snapshot(&path.join("incoming.bin"))? == originals[index]
                        && fs::read_dir(path)?.count() == 1);
                    let after = coordination_inventory()?;
                    retained_counts.push(after.keys().filter(|key| !before.contains_key(*key)).count());
                }
            }
            let after = coordination_inventory()?;
            let retained_bytes: u64 = after.iter().filter(|(key, _)| !before.contains_key(*key))
                .map(|(_, bytes)| *bytes).sum();
            let safe = after == before && retained_counts.iter().all(|count| *count == 0);
            ensure!(unsafe { libc::mount(std::ptr::null(), target.as_ptr(), std::ptr::null(),
                flags | libc::MS_REMOUNT, std::ptr::null()) } == 0,
                "writable fixture remount failed: {}", io::Error::last_os_error());
            for path in &destinations {
                complete_transfer(path).await?;
            }
            ensure!(coordination_inventory()? == before, "successful retries did not retire coordination");
            Ok::<_, hbb_common::anyhow::Error>(json!({"filesystem":"tmpfs", "destinations":8,
                "attempts":16, "admission_error":"EROFS", "calibrated_mkdir_errno":libc::EROFS,
                "originals_preserved":true, "counters_unchanged":true, "publication_refused":true,
                "destination_entries_unchanged":true, "retained_counts":retained_counts,
                "coordination_allocated_bytes_added":retained_bytes, "safe":safe,
                "writable_retries_exact":true, "coordination_restored_after_retries":true}))
        }.await;
        if unsafe { libc::umount2(target.as_ptr(), 0) } != 0 {
            return Err(anyhow!("read-only fixture unmount failed: {}; operation: {result:?}",
                io::Error::last_os_error()));
        }
        fs::remove_dir(base)?;
        result
    }

    async fn inode_limited_enrollment(base: &Path, limit: u64) -> ResultType<Value> {
        use std::{ffi::CString, os::unix::{ffi::OsStrExt, io::AsRawFd}};
        ensure!((4..=7).contains(&limit));
        fs::create_dir(base)?;
        let target = CString::new(base.as_os_str().as_bytes())?;
        let options = CString::new(format!("size=65536,nr_inodes={limit},mode=0700,huge=never"))?;
        let flags = libc::MS_NODEV | libc::MS_NOSUID | libc::MS_NOEXEC;
        if unsafe { libc::mount(b"tmpfs\0".as_ptr().cast(), target.as_ptr(),
            b"tmpfs\0".as_ptr().cast(), flags, options.as_ptr().cast()) } != 0 {
            let error = io::Error::last_os_error();
            fs::remove_dir(base)?;
            return Err(error.into());
        }
        let result = async {
            let directory = fs::File::open(base)?;
            let space = || -> ResultType<libc::statvfs> {
                let mut value = unsafe { std::mem::zeroed() };
                ensure!(unsafe { libc::fstatvfs(directory.as_raw_fd(), &mut value) } == 0,
                    "inode fixture statvfs failed: {}", io::Error::last_os_error());
                Ok(value)
            };
            create(&base.join("incoming.bin"), b"original", 0o600)?;
            let original = snapshot(&base.join("incoming.bin"))?;
            let initial = space()?;
            ensure!(initial.f_files == limit && initial.f_ffree == limit - 2
                && initial.f_bavail * initial.f_frsize >= 32768);
            // Calibrate actual inode exhaustion independently of receive setup.
            for index in 0..initial.f_ffree {
                create(&base.join(format!("calibration-{index}")), b"", 0o600)?;
            }
            ensure!(space()?.f_ffree == 0);
            let calibration = fs::create_dir(base.join("must-refuse"))
                .err().ok_or_else(|| anyhow!("inode-exhausted mount allowed mkdir"))?;
            ensure!(calibration.raw_os_error() == Some(libc::ENOSPC));
            for index in 0..initial.f_ffree {
                fs::remove_file(base.join(format!("calibration-{index}")))?;
            }
            ensure!(space()?.f_ffree == initial.f_ffree);
            let before = coordination_inventory()?;
            let mut attempts = Vec::new();
            let mut safe = true;
            for _ in 0..2 {
                let mut receiver = job(base)?;
                let counters = (receiver.finished_size(), receiver.transferred());
                let error = admit(&mut receiver, false, 0).await.err()
                    .ok_or_else(|| anyhow!("inode-limited receive admission succeeded"))?;
                ensure!(error.downcast_ref::<io::Error>()
                    .is_some_and(|error| error.raw_os_error() == Some(libc::ENOSPC)),
                    "unexpected inode-limited admission error: {error}");
                ensure!((receiver.finished_size(), receiver.transferred()) == counters);
                ensure!(receiver.finalize_write(1).await.is_err());
                receiver.retire_current_file_state()?;
                drop(receiver);
                ensure!(snapshot(&base.join("incoming.bin"))? == original);
                let after = coordination_inventory()?;
                let retained_records = after.keys().filter(|key| !before.contains_key(*key)).count();
                let retained_bytes: u64 = after.iter().filter(|(key, _)| !before.contains_key(*key))
                    .map(|(_, bytes)| *bytes).sum();
                let entries = fs::read_dir(base)?.count();
                let free = space()?;
                let mut container_entries = Vec::new();
                let mut file_entries = Vec::new();
                if entries != 1 {
                    let artifacts = staging(base)?;
                    let container = artifacts.parent().ok_or_else(|| anyhow!("staging parent absent"))?;
                    for entry in fs::read_dir(container)? {
                        container_entries.push(entry?.file_name().to_string_lossy().into_owned());
                    }
                    if artifacts.try_exists()? {
                        for entry in fs::read_dir(artifacts)? {
                            file_entries.push(entry?.file_name().to_string_lossy().into_owned());
                        }
                    }
                    container_entries.sort();
                    file_entries.sort();
                }
                let clean = entries == 1 && after == before && free.f_ffree == initial.f_ffree;
                safe &= clean;
                attempts.push(json!({"clean":clean, "destination_entries":entries,
                    "coordination_entries_added":retained_records,
                    "coordination_allocated_bytes_added":retained_bytes,
                    "free_inodes":free.f_ffree, "free_bytes":free.f_bavail * free.f_frsize,
                    "container_entries":container_entries, "file_entries":file_entries}));
            }
            ensure!(unsafe { libc::mount(std::ptr::null(), target.as_ptr(), std::ptr::null(),
                flags | libc::MS_REMOUNT, b"nr_inodes=128\0".as_ptr().cast()) } == 0,
                "inode fixture expansion failed: {}", io::Error::last_os_error());
            complete_transfer(base).await?;
            ensure!(coordination_inventory()? == before && fs::read_dir(base)?.count() == 1);
            Ok::<_, hbb_common::anyhow::Error>(json!({"filesystem":"tmpfs", "inode_limit":limit,
                "capacity_bytes":65536, "calibrated_mkdir_errno":libc::ENOSPC,
                "admission_error":"ENOSPC", "attempts":attempts, "safe":safe,
                "original_preserved":true, "counters_unchanged":true, "publication_refused":true,
                "expanded_retry_exact":true, "coordination_restored_after_retry":true}))
        }.await;
        if unsafe { libc::umount2(target.as_ptr(), 0) } != 0 {
            return Err(anyhow!("inode fixture unmount failed: {}; operation: {result:?}",
                io::Error::last_os_error()));
        }
        fs::remove_dir(base)?;
        result
    }

    async fn crash_receiver(base: &Path) -> ResultType<()> {
        identity(0)?;
        io::stdout().write_all(syscall_window::ARMED)?;
        let mut receiver = job(base)?;
        admit(&mut receiver, false, 0).await?;
        Err(anyhow!("required enrollment crash point was not reached"))
    }

    async fn descriptor_receiver(base: &Path) -> ResultType<()> {
        identity(0)?;
        // Warm the blocking worker before measuring descriptors or arming the fault.
        tokio::task::spawn_blocking(|| ()).await?;
        let descriptors = || -> ResultType<usize> {
            Ok(fs::read_dir("/proc/self/fd")?.collect::<io::Result<Vec<_>>>()?.len())
        };
        let before = descriptors()?;
        let original = snapshot(&base.join("incoming.bin"))?;
        let mut receiver = job(base)?;
        io::stdout().write_all(syscall_window::ARMED)?;
        let result = admit(&mut receiver, false, 0).await;
        let unchanged = (receiver.finished_size(), receiver.transferred()) == (0, 0)
            && !receiver.file_confirmed();
        let finalize_refused = receiver.finalize_write(1).await.is_err();
        let retired = receiver.retire_current_file_state();
        drop(receiver);
        // The controller restores a sustained limit only after every admission
        // error/cleanup path has returned. Existing stdout needs no new descriptor.
        io::stdout().write_all(syscall_window::RETURNED)?;
        let after = descriptors()?;
        let error = result.err().ok_or_else(|| anyhow!("descriptor-limited admission succeeded"))?;
        let raw_errno = error.downcast_ref::<io::Error>().and_then(io::Error::raw_os_error);
        let cleanup_failed = error.to_string().contains("cleanup failed:");
        ensure!(unchanged && finalize_refused && retired.is_ok() && before == after);
        ensure!(snapshot(&base.join("incoming.bin"))? == original);
        println!("RECEIVE_NATIVE_DESCRIPTOR_RECEIVER={}", json!({"error":error.to_string(),
            "raw_errno":raw_errno, "cleanup_failed":cleanup_failed, "counters_unchanged":unchanged,
            "publication_refused":finalize_refused, "original_preserved":true,
            "descriptors_before":before, "descriptors_after":after, "job_retired":true}));
        Ok(())
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
        pub const RETURNED: &[u8] = b"RECEIVE_NATIVE_DESCRIPTOR_RETURNED\n";

        fn descriptor_limit(pid: i32, limit: Option<&libc::rlimit>) -> io::Result<libc::rlimit> {
            let mut previous = unsafe { std::mem::zeroed() };
            if unsafe { libc::prlimit(pid, libc::RLIMIT_NOFILE,
                limit.map_or(std::ptr::null(), |value| value as *const _), &mut previous) } != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(previous)
        }

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
                && name != b".." && (name != b"." || info.data[0] as i64 == libc::SYS_openat),
                "unexpected syscall source name");
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
            let descriptor = operation.starts_with("fd-");
            let sustained = descriptor && operation.ends_with("-held");
            let boundary = operation.strip_suffix("-held").unwrap_or(&operation);
            let (number, suffix) = match boundary {
                "payload-rename" => (libc::SYS_renameat, ".download"),
                "digest-unlink" => (libc::SYS_unlinkat, ".digest"),
                "lease-unlink" => (libc::SYS_unlinkat, ".download.lock"),
                "crash-directory" => (libc::SYS_mkdirat, ""),
                "crash-identity" => (libc::SYS_fsync, "identity"),
                "crash-record" => (libc::SYS_renameat, ".tmp"),
                "crash-payload-sync" => (libc::SYS_fsync, "payload.download"),
                "crash-retire-intent" => (libc::SYS_renameat2, ".json"),
                "crash-retire-identity" => (libc::SYS_unlinkat, "identity"),
                "crash-retire-directory" => (libc::SYS_unlinkat, ""),
                "crash-retire-record" => (libc::SYS_unlinkat, ".json.retiring"),
                "fd-directory-open" | "fd-lease-open" => (libc::SYS_openat, ""),
                "fd-parent-clone" => (libc::SYS_fcntl, ""),
                _ => return Err(anyhow!("unknown syscall window")),
            };
            let crash = operation.starts_with("crash-");
            let retirement = operation.starts_with("crash-retire-");
            let mut killed = false;
            let mut command = Command::new(std::env::current_exe()?);
            command.arg(if descriptor { "descriptor-receiver" }
                else if crash && !retirement { "crash-receiver" } else { "window-receiver" }).arg(&base)
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
            let mut original_limit: Option<libc::rlimit> = None;
            let mut limit_restored = false;
            let mut returned = false;
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
                        if descriptor && info.data[0] as i64 == libc::SYS_write && info.data[1] == 1
                            && info.data[3] == RETURNED.len() as u64
                            && read_memory(pid, usize::try_from(info.data[2])?, RETURNED.len())? == RETURNED {
                            ensure!(!returned && syscall_result.is_some());
                            returned = true;
                            if sustained {
                                let original = original_limit.as_ref().ok_or_else(|| anyhow!("limit absent"))?;
                                let limited = descriptor_limit(root, Some(original))?;
                                ensure!(limited.rlim_cur == 1 && limited.rlim_max == original.rlim_max);
                                limit_restored = true;
                            }
                        }
                        if armed && observation.is_none() && info.data[0] as i64 == number
                            && (!descriptor || info.data[1] as i32 >= 0) {
                            let path = if number == libc::SYS_fsync || number == libc::SYS_fcntl {
                                fs::read_link(format!("/proc/{pid}/fd/{}", info.data[1]))?
                            } else { source_path(pid, &info)? };
                            let selected = if descriptor {
                                let artifact_directory = if boundary == "fd-lease-open" { path.parent() }
                                    else { Some(path.as_path()) };
                                let matches_directory = artifact_directory.is_some_and(|directory|
                                    directory.parent().and_then(Path::parent) == Some(base.as_path())
                                        && directory.file_name().is_some_and(|name|
                                            name.as_encoded_bytes().len() == 64
                                                && name.as_encoded_bytes().iter().all(u8::is_ascii_hexdigit)));
                                matches_directory && match boundary {
                                    "fd-parent-clone" => info.data[2] == libc::F_DUPFD_CLOEXEC as u64
                                        && info.data[3] == 0,
                                    "fd-directory-open" => info.data[3] & libc::O_DIRECTORY as u64 != 0,
                                    "fd-lease-open" => path.file_name().is_some_and(|name| name == "claim.download.lock")
                                        && info.data[3] & libc::O_CREAT as u64 != 0,
                                    _ => false,
                                }
                            } else if operation == "crash-directory" || operation == "crash-retire-directory" {
                                path.parent() == Some(base.as_path()) && path.file_name()
                                    .is_some_and(|n| n.as_encoded_bytes().starts_with(b".rustdesk-receive-"))
                                    && (operation == "crash-directory" || info.data[3] == libc::AT_REMOVEDIR as u64)
                            } else if operation == "crash-record" {
                                path.parent() == Some(coordinator()?.as_path())
                                    && path.extension().is_some_and(|s| s == "tmp")
                                    && fs::metadata(&path)?.len() <= 256
                                    && hbb_common::serde_json::from_slice::<Value>(&fs::read(&path)?)?
                                        ["inode"].as_u64().is_some()
                            } else if operation == "crash-retire-intent" || operation == "crash-retire-record" {
                                path.parent() == Some(coordinator()?.as_path())
                                    && path.file_name().is_some_and(|n| n.as_encoded_bytes().ends_with(suffix.as_bytes()))
                                    && (operation != "crash-retire-intent"
                                        || (info.data[1] == info.data[3] && info.data[5] == libc::RENAME_NOREPLACE as u64))
                            } else if operation == "crash-retire-identity" {
                                path.parent().and_then(Path::parent) == Some(base.as_path())
                                    && path.file_name().is_some_and(|n| n == "identity")
                                    && info.data[3] == 0
                            } else {
                                path.file_name().is_some_and(|n| n.as_encoded_bytes().ends_with(suffix.as_bytes()))
                            };
                            if selected && descriptor {
                                let original = descriptor_limit(root, None)?;
                                ensure!(original.rlim_cur > 0 && original.rlim_cur <= original.rlim_max
                                    && original.rlim_max == 128);
                                // fd 0 is already occupied. Keep the duplicate's
                                // minimum fd (0) below the limit; a zero limit
                                // would cause EINVAL instead of exhaustion.
                                ensure!(fs::read_link(format!("/proc/{root}/fd/0"))? == Path::new("/dev/null"));
                                let limited = libc::rlimit { rlim_cur: 1, rlim_max: original.rlim_max };
                                descriptor_limit(root, Some(&limited))?;
                                let observed = descriptor_limit(root, None)?;
                                ensure!(observed.rlim_cur == 1 && observed.rlim_max == original.rlim_max);
                                original_limit = Some(original);
                                observation = Some(json!({"source":path,"tid":pid,"syscall":number,
                                    "soft_limit_before":original.rlim_cur,"soft_limit_during":1,
                                    "hard_limit":original.rlim_max,"sustained_through_cleanup":sustained}));
                                selected_task = Some(pid);
                            } else if selected && crash {
                                ensure!(path.starts_with(&base) || path.parent() == Some(coordinator()?.as_path()));
                                let published = if retirement { private_final(&base)? } else { Value::Null };
                                observation = Some(json!({"source":path,"tid":pid,"syscall":number,
                                    "published_before_kill":published}));
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
                        if descriptor {
                            ensure!(info.data[0] as i64 == -(libc::EMFILE as i64)
                                && info.data[1] & 255 != 0,
                                "selected allocation did not return EMFILE: boundary={boundary} return={} is_error={}",
                                info.data[0] as i64, info.data[1] & 255);
                            if !sustained {
                                let original = original_limit.as_ref().ok_or_else(|| anyhow!("limit absent"))?;
                                let limited = descriptor_limit(root, Some(original))?;
                                ensure!(limited.rlim_cur == 1 && limited.rlim_max == original.rlim_max);
                                limit_restored = true;
                            }
                        } else if crash {
                            ensure!(info.data[0] == 0 && info.data[1] & 255 == 0,
                                "selected receive syscall did not succeed");
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
            if descriptor {
                ensure!(returned && limit_restored && err.is_empty());
                let reports: Vec<_> = text.lines().filter_map(|line|
                    line.strip_prefix("RECEIVE_NATIVE_DESCRIPTOR_RECEIVER=")).collect();
                ensure!(reports.len() == 1 && text.lines().count() == 3);
                let receiver: Value = hbb_common::serde_json::from_str(reports[0])?;
                let observation = observation.ok_or_else(|| anyhow!("descriptor boundary absent"))?;
                return Ok(json!({"operation":operation,"selected":observation,"syscall_exit":syscall_result,
                    "receiver":receiver,"limit_restored":limit_restored,"children_joined":true,
                    "trace_events":events}));
            }
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
            let safe = recovery.is_ok() && containers == 0 && temporary.is_empty()
                && private_final(&base).is_ok();
            recovered += usize::from(safe);
            println!("RECEIVE_NATIVE_CASE={}", json!({"case":operation,"observed":{
                "crash":crash,"recovery_ok":recovery.is_ok(),"recovery_error":recovery.err().map(|e|e.to_string()),
                "containers":containers,"temporary_records_added":temporary.len(),"safe":safe}}));
            fs::remove_dir_all(&base)?;
        }
        println!("RECEIVE_NATIVE_ENROLLMENT_SUMMARY=observed cases=3 recovered={recovered} children=joined fixture=retired");
        ensure!(recovered == 3, "receive enrollment crash cases failed: {recovered}/3 recovered");
        let mut recovered = 0;
        for saved in [false, true] {
            let case = format!("crash-receive-setup-{saved}");
            let base = root.join(&case);
            fs::create_dir(&base)?;
            create(&base.join("incoming.bin"), b"original", 0o600)?;
            let original = snapshot(&base.join("incoming.bin"))?;
            if saved {
                let artifacts = prepare_staging(&base).await?;
                create(&artifacts.join("payload.download"), b"abc", 0o600)?;
                create(&artifacts.join("resume.digest"), DIGEST, 0o600)?;
            }
            let selected = base.clone();
            let crash = tokio::task::spawn_blocking(move ||
                syscall_window::run(selected, "crash-payload-sync".to_owned())).await??;
            let artifacts = staging(&base)?;
            let payload = snapshot(&artifacts.join("payload.download"))?;
            let digest = snapshot(&artifacts.join("resume.digest"))?;
            ensure!(snapshot(&base.join("incoming.bin"))? == original);
            let mut inspection = job(&base)?;
            let inspected = inspection.inspect_receive_digest(&incoming(), true).await;
            inspection.retire_current_file_state()?;
            ensure!(snapshot(&artifacts.join("payload.download"))? == payload
                && snapshot(&artifacts.join("resume.digest"))? == digest
                && snapshot(&base.join("incoming.bin"))? == original);
            let recovery = complete_transfer(&base).await;
            let safe = inspected.is_ok() && recovery.is_ok() && private_final(&base).is_ok();
            if recovery.is_err() { ensure!(snapshot(&base.join("incoming.bin"))? == original); }
            recovered += usize::from(safe);
            println!("RECEIVE_NATIVE_CASE={}", json!({"case":case,"observed":{
                "saved_partial":saved,"crash":crash,"payload_after_crash":payload,
                "digest_after_crash":digest,"inspection_ok":inspected.is_ok(),
                "inspection_error":inspected.err().map(|e|e.to_string()),
                "inspection_preserved":true,"recovery_ok":recovery.is_ok(),
                "recovery_error":recovery.err().map(|e|e.to_string()),"safe":safe}}));
            fs::remove_dir_all(&base)?;
        }
        println!("RECEIVE_NATIVE_SETUP_SUMMARY=observed cases=2 recovered={recovered} children=joined fixture=retired");
        ensure!(recovered == 2, "receive setup crash cases failed: {recovered}/2 recovered");
        for (phase, free_pages) in [("block", 0), ("block", 1), ("identity", 0), ("digest", 0)] {
            let case = if phase == "block" { format!("full-filesystem-{free_pages}") }
                else { format!("full-filesystem-{phase}") };
            let observed = full_filesystem(&root.join(&case), phase, free_pages).await?;
            println!("RECEIVE_NATIVE_CASE={}", json!({"case":case,"observed":observed}));
        }
        println!("RECEIVE_NATIVE_STORAGE_SUMMARY=observed cases=4 safe=4 mounts=retired fixture=retired");
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
        let retained_locks = added.iter().filter(|(path, _)| path.extension().is_some_and(|s| s == "lock")).count();
        let retention_ok = added.is_empty();
        retired += usize::from(retention_ok);
        println!("RECEIVE_NATIVE_CASE={}", json!({"case":"completed-destinations",
            "observed":{"destinations":32,"coordination_records_added":added.len(),
                "coordination_locks_added":retained_locks,
                "coordination_allocated_bytes_added":retained_bytes,"safe":retention_ok}}));
        fs::remove_dir_all(&base)?;
        println!("RECEIVE_NATIVE_RETIREMENT_SUMMARY=observed cases=3 retired={retired} children=joined fixture=retired");
        ensure!(retired == 3, "receive completed-destination cases failed: {retired}/3 retired");
        let mut recovered = 0;
        for operation in ["crash-retire-intent", "crash-retire-identity",
            "crash-retire-directory", "crash-retire-record"] {
            let base = root.join(operation);
            fs::create_dir(&base)?;
            // Retire any old lookup record from earlier fixtures whose deleted
            // destination inode was reused, before taking this case's baseline.
            let mut initial = job(&base)?;
            initial.inspect_receive_digest(&incoming(), false).await?;
            initial.retire_current_file_state()?;
            drop(initial);
            let before = coordination_inventory()?;
            let selected = base.clone();
            let phase = operation.to_owned();
            let crash = tokio::task::spawn_blocking(move || syscall_window::run(selected, phase)).await??;
            let published = private_final(&base)?;
            ensure!(published == crash["selected"]["published_before_kill"],
                "receiver death changed the published file");
            let after_crash = coordination_inventory()?;
            let added: Vec<_> = after_crash.keys().filter(|path| !before.contains_key(*path)).collect();
            let retiring_records = added.iter().filter(|path| path.extension().is_some_and(|s| s == "retiring")).count();
            let generation_locks = added.iter().filter(|path| path.extension().is_some_and(|s| s == "lock")).count();
            let record_remaining = operation != "crash-retire-record";
            ensure!(retiring_records == usize::from(record_remaining) && generation_locks == 1
                && added.len() == 1 + usize::from(record_remaining), "unexpected killed retirement records");
            let mut containers = 0;
            let mut markers = 0;
            for entry in fs::read_dir(&base)? {
                let entry = entry?;
                if entry.file_name() == "incoming.bin" { continue; }
                ensure!(entry.file_name().as_encoded_bytes().starts_with(b".rustdesk-receive-"));
                containers += 1;
                for marker in fs::read_dir(entry.path())? {
                    ensure!(marker?.file_name() == "identity", "retirement retained transfer artifacts");
                    markers += 1;
                }
            }
            ensure!(containers == usize::from(matches!(operation, "crash-retire-intent" | "crash-retire-identity"))
                && markers == usize::from(operation == "crash-retire-intent"), "unexpected killed retirement namespace");
            let recovery = async {
                let mut receiver = job(&base)?;
                receiver.inspect_receive_digest(&incoming(), false).await?;
                receiver.retire_current_file_state()?;
                Ok::<_, hbb_common::anyhow::Error>(())
            }.await;
            let final_preserved = snapshot(&base.join("incoming.bin"))? == published;
            let namespace_retired = fs::read_dir(&base)?.count() == 1;
            let coordination_restored = coordination_inventory()? == before;
            let safe = recovery.is_ok() && final_preserved && namespace_retired && coordination_restored;
            recovered += usize::from(safe);
            println!("RECEIVE_NATIVE_CASE={}", json!({"case":operation,"observed":{
                "crash":crash,"containers_after_crash":containers,"markers_after_crash":markers,
                "retiring_records_after_crash":retiring_records,"generation_locks_after_crash":generation_locks,
                "recovery_ok":recovery.is_ok(),"recovery_error":recovery.err().map(|e|e.to_string()),
                "published_preserved":final_preserved,"namespace_retired":namespace_retired,
                "coordination_restored":coordination_restored,"safe":safe}}));
            fs::remove_dir_all(&base)?;
        }
        println!("RECEIVE_NATIVE_RETIREMENT_CRASH_SUMMARY=observed cases=4 recovered={recovered} children=joined fixture=retired");
        ensure!(recovered == 4, "receive retirement crash cases failed: {recovered}/4 recovered");
        let observed = readonly_enrollment(&root.join("readonly-enrollment")).await?;
        println!("RECEIVE_NATIVE_CASE={}", json!({"case":"readonly-enrollment","observed":observed}));
        println!("RECEIVE_NATIVE_ADMISSION_SUMMARY=observed destinations=8 attempts=16 safe={} mounts=retired fixture=retired", observed["safe"]);
        ensure!(observed["safe"] == true, "read-only receive attempts retained coordination state");
        let mut safe = 0;
        for limit in 4..=7 {
            let observed = inode_limited_enrollment(&root.join(format!("inode-enrollment-{limit}")), limit).await?;
            safe += usize::from(observed["safe"] == true);
            println!("RECEIVE_NATIVE_CASE={}", json!({"case":format!("inode-enrollment-{limit}"), "observed":observed}));
        }
        println!("RECEIVE_NATIVE_INODE_SUMMARY=observed cases=4 attempts=8 safe={safe} mounts=retired fixture=retired");
        ensure!(safe == 4, "inode-limited receive attempts retained unused state: {safe}/4 safe");
        let mut safe = 0;
        for boundary in ["fd-directory-open", "fd-parent-clone", "fd-lease-open"] {
            for sustained in [false, true] {
                let operation = format!("{boundary}{}", if sustained { "-held" } else { "" });
                let base = root.join(&operation);
                fs::create_dir(&base)?;
                fs::set_permissions(&base, fs::Permissions::from_mode(0o700))?;
                create(&base.join("incoming.bin"), b"original", 0o600)?;
                let original = snapshot(&base.join("incoming.bin"))?;
                let before = coordination_inventory()?;
                let selected = base.clone();
                let name = operation.clone();
                let traced = tokio::task::spawn_blocking(move || syscall_window::run(selected, name)).await??;
                ensure!(snapshot(&base.join("incoming.bin"))? == original);
                let after = coordination_inventory()?;
                let added: Vec<_> = after.keys().filter(|key| !before.contains_key(*key)).collect();
                let entries = fs::read_dir(&base)?.count();
                let namespace_clean = after == before && entries == 1;
                let uncertain = traced["receiver"]["cleanup_failed"] == true;
                let observed_safe = if sustained {
                    let artifacts = staging(&base)?;
                    uncertain && added.len() == 2 && entries == 2
                        && fs::read_dir(&artifacts)?.count() == 0
                        && added.iter().filter(|key| key.extension().is_some_and(|e| e == "lock")).count() == 1
                        && added.iter().filter(|key| key.extension().is_some_and(|e| e == "json")).count() == 1
                } else {
                    namespace_clean && !uncertain && traced["receiver"]["raw_errno"] == libc::EMFILE
                };
                complete_transfer(&base).await?;
                ensure!(coordination_inventory()? == before && fs::read_dir(&base)?.count() == 1);
                safe += usize::from(observed_safe);
                println!("RECEIVE_NATIVE_CASE={}", json!({"case":operation,"observed":{
                    "trace":traced,"coordination_entries_after_failure":added.len(),
                    "destination_entries_after_failure":entries,"namespace_clean":namespace_clean,
                    "original_preserved":true,"retry_exact":true,"coordination_restored":true,
                    "safe":observed_safe}}));
                fs::remove_dir_all(&base)?;
            }
        }
        println!("RECEIVE_NATIVE_DESCRIPTOR_SUMMARY=observed cases=6 safe={safe} children=joined limits=restored fixture=retired");
        ensure!(safe == 6, "descriptor-limited receive ownership failed: {safe}/6 safe");
        println!("RECEIVE_NATIVE_AUTHORITY=pass cases=43 actors={actors} receiver_uid=0 actor_uid=4001 children=joined fixture=retired");
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
        } else if args.len() == 3 && args[1] == "descriptor-receiver" {
            let base = Path::new(&args[2]);
            ensure!(base.starts_with(&owned) && base != owned);
            descriptor_receiver(base).await
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
