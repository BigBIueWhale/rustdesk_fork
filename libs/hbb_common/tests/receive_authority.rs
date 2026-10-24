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
        os::unix::fs::{symlink, MetadataExt, OpenOptionsExt, PermissionsExt},
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
        if expected == ACTOR_UID {
            ensure!(field("Groups:")?.is_empty());
            for key in ["CapEff:", "CapPrm:", "CapInh:", "CapAmb:"] {
                ensure!(u64::from_str_radix(&field(key)?, 16)? == 0);
            }
        }
        Ok(json!({"pid": std::process::id(), "uids": uids, "gids": gids,
            "effective_capabilities": capabilities, "no_new_privileges": true}))
    }

    fn create(path: &Path, bytes: &[u8], mode: u32) -> ResultType<()> {
        OpenOptions::new().write(true).create_new(true).mode(mode).open(path)?
            .write_all(bytes)?;
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

    fn state(base: &Path) -> ResultType<Vec<Value>> {
        ["incoming.bin", "incoming.bin.download", "incoming.bin.digest",
            "incoming.bin.download.lock"].iter().map(|n| snapshot(&base.join(n))).collect()
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
                let path = if operation == "probe-final" { base.join("incoming.bin") } else { data };
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
                let path = if operation == "replace-data" { data } else { digest };
                let held = base.join("held");
                fs::rename(&path, &held)?;
                create(&path, b"replacement", 0o600)?;
                ensure!(denied(fs::read(&held)), "actor read a private root artifact");
                json!({"replacement":snapshot(&path)?, "held_read_denied":true})
            }
            "swap-parent" => {
                fs::rename(base.join("selected"), base.join("held-parent"))?;
                symlink(base.join("outside"), base.join("selected"))?;
                json!({"parent_replaced":true})
            }
            _ => return Err(anyhow!("unknown actor operation")),
        };
        println!("{}", json!({"operation":operation, "identity":who, "details":details}));
        Ok(())
    }

    async fn actor(base: &Path, operation: &str, count: &mut usize) -> ResultType<Value> {
        let mut command = tokio::process::Command::new(std::env::current_exe()?);
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
        ensure!(out.len() <= 16384 && err.len() <= 16384, "actor output bound exceeded");
        ensure!(status.success(), "actor failed: {}", String::from_utf8_lossy(&err));
        let value: Value = hbb_common::serde_json::from_slice(&out)?;
        ensure!(value["operation"] == operation);
        *count += 1;
        println!("RECEIVE_NATIVE_ACTOR={value}");
        Ok(value["details"].clone())
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
        for suffix in [".download", ".digest", ".download.lock"] {
            ensure!(!base.join(format!("incoming.bin{suffix}")).exists());
        }
        snapshot(&path)
    }

    async fn parent(root: &Path) -> ResultType<()> {
        let who = identity(0)?;
        ensure!(fs::metadata(root)?.uid() == 0);
        let cases = ["fresh", "resume", "foreign-final", "foreign-lease", "foreign-data",
            "foreign-digest", "read-shared-data", "writable-digest", "replace-data-finalize",
            "replace-data-cancel", "replace-digest-finalize", "replace-parent"];
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
                        create(&base.join("incoming.bin.download"), b"abc", 0o600)?;
                        create(&base.join("incoming.bin.digest"), DIGEST, 0o600)?;
                    }
                    if case == "foreign-final" {
                        actor(&base, "foreign-final", &mut actors).await?;
                        ensure!(fs::read(base.join("incoming.bin"))? == b"original",
                            "privileged read calibration failed");
                    }
                    admit(&mut receiver, case == "resume", if case == "resume" {3} else {0}).await?;
                    if case != "resume" { write(&mut receiver, b"abc").await?; }
                    let probe = actor(&base, "probe-data", &mut actors).await?;
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
                                let probe = actor(&base, "probe-data", &mut actors).await?;
                                ensure!(probe["bytes"] == json!(b"abc".to_vec())
                                    && probe["write_denied"] == true);
                            }
                            _ => { actor(&base, "mutate-digest", &mut actors).await?; }
                        }
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
                    let changed = actor(&base, op, &mut actors).await?;
                    ensure!(changed["held_read_denied"] == true);
                    let replacement = if op == "replace-data" {"incoming.bin.download"} else {"incoming.bin.digest"};
                    let before = snapshot(&base.join(replacement))?;
                    let refused = if case == "replace-data-cancel" {
                        receiver.retire_current_file_state().is_err()
                    } else {
                        let failed = receiver.finalize_write(1).await.is_err();
                        ensure!(receiver.retire_current_file_state().is_err());
                        failed
                    };
                    ensure!(refused && snapshot(&base.join(replacement))? == before);
                    ensure!(fs::read(base.join("incoming.bin"))? == b"original");
                    let held = fs::metadata(base.join("held"))?;
                    ensure!(held.uid() == 0 && held.mode() & 0o7777 == 0o600);
                    json!({"refused":refused, "replacement":before,
                        "held_private":true, "target_preserved":true})
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
        ensure!(actors == 16, "unexpected joined actor total: {actors}");
        println!("RECEIVE_NATIVE_AUTHORITY=pass cases=12 actors={actors} receiver_uid=0 actor_uid=4001 children=joined fixture=retired");
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
