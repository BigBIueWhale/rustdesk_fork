use super::*;
use std::os::unix::fs::PermissionsExt;

#[path = "local_transaction_tests.rs"]
mod local_transaction_tests;

#[cfg(target_arch = "x86_64")]
#[path = "directory_tests.rs"]
mod directory_tests;

#[cfg(target_arch = "x86_64")]
fn core_recovery_sync_case(test: &str, mode: &str) {
    use std::os::unix::fs::MetadataExt;

    in_private_process(test, |root| {
        assert_ne!(unsafe { crate::libc::getegid() }, 0);
        let base = root.join("recovery-sync");
        fs::create_dir(&base).unwrap();
        let path = base.join("broken.toml");
        let bytes = b"== invalid TOML [[[";
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let before = fs::metadata(&path).unwrap();
        let valid = base.join("valid.toml");
        fs::write(&valid, b"marker = 'retained'\n").unwrap();
        let fds = || fs::read_dir("/proc/self/fd").unwrap().count();
        let before_fds = fds();
        let directory = fs::File::open(&base).unwrap();
        directory.sync_all().unwrap();
        let loaded: ConfigLoad<HashMap<String, String>> = load_path_with_status_after_read(path.clone(), || {
            let mut matching = Vec::new();
            let mut scanned = 0;
            for entry in fs::read_dir("/proc/self/fd").unwrap() {
                scanned += 1;
                assert!(scanned < 64);
                let fd = entry.unwrap().file_name().to_str().unwrap().parse::<i32>().unwrap();
                let mut stat = std::mem::MaybeUninit::<crate::libc::stat>::uninit();
                if unsafe { crate::libc::fstat(fd, stat.as_mut_ptr()) } != 0 {
                    assert_eq!(io::Error::last_os_error().raw_os_error(), Some(crate::libc::EBADF));
                    continue;
                }
                let stat = unsafe { stat.assume_init() };
                if stat.st_dev as u64 == before.dev() && stat.st_ino as u64 == before.ino() {
                    matching.push(fd);
                }
            }
            assert_eq!(matching.len(), 1);
            let source_fd = matching[0];
            if mode != "healthy" {
                let statement = |code, k| crate::libc::sock_filter { code: code as u16, jt: 0, jf: 0, k };
                let jump = |code, k, jt, jf| crate::libc::sock_filter { code: code as u16, jt, jf, k };
                let load = crate::libc::BPF_LD | crate::libc::BPF_W | crate::libc::BPF_ABS;
                let equal = crate::libc::BPF_JMP | crate::libc::BPF_JEQ | crate::libc::BPF_K;
                let bits = crate::libc::BPF_JMP | crate::libc::BPF_JSET | crate::libc::BPF_K;
                let ret = crate::libc::BPF_RET | crate::libc::BPF_K;
                let mut filter = [
                    statement(load, 4),
                    jump(equal, 0xc000003e, 1, 0),
                    statement(ret, crate::libc::SECCOMP_RET_KILL_PROCESS),
                    statement(load, 0),
                    jump(bits, 0x40000000, 0, 1),
                    statement(ret, crate::libc::SECCOMP_RET_KILL_PROCESS),
                    jump(equal, crate::libc::SYS_fsync as u32, 0, 3),
                    statement(load, 16),
                    jump(equal, source_fd as u32, u8::from(mode == "parent"), u8::from(mode == "file")),
                    statement(ret, crate::libc::SECCOMP_RET_ERRNO | crate::libc::EIO as u32),
                    statement(ret, crate::libc::SECCOMP_RET_ALLOW),
                ];
                let program = crate::libc::sock_fprog { len: filter.len() as u16, filter: filter.as_mut_ptr() };
                assert_eq!(unsafe { crate::libc::prctl(crate::libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) }, 0);
                assert_eq!(unsafe {
                    crate::libc::syscall(crate::libc::SYS_seccomp, crate::libc::SECCOMP_SET_MODE_FILTER,
                        crate::libc::SECCOMP_FILTER_FLAG_TSYNC, &program)
                }, 0, "install child fsync filter: {}", io::Error::last_os_error());
            }
            let file_errno = if unsafe { crate::libc::fsync(source_fd) } == 0 {
                0
            } else { io::Error::last_os_error().raw_os_error().unwrap() };
            let directory_result = directory.sync_all();
            let directory_errno = directory_result.as_ref().err().and_then(io::Error::raw_os_error).unwrap_or(0);
            assert_eq!(file_errno, if mode == "file" { crate::libc::EIO } else { 0 });
            assert_eq!(directory_errno, if mode == "parent" { crate::libc::EIO } else { 0 });
            println!("OPTION_COMMIT_RECOVERY_SYNC=probe mode={mode} file_errno={file_errno} directory_errno={directory_errno}");
        });
        drop(directory);
        let backup = base.join(config_recovery_file_name(&path, 0).unwrap());
        let backup = fs::read_dir(&base).unwrap().map(|entry| entry.unwrap().path())
            .find(|entry| entry.file_name().unwrap().to_string_lossy().starts_with("config.corrupt."))
            .unwrap_or(backup);
        let preserved = fs::metadata(&backup).map(|after| {
            (after.dev(), after.ino()) == (before.dev(), before.ino())
                && after.mode() & 0o777 == 0o600 && after.nlink() == 1
                && fs::read(&backup).unwrap() == bytes
        }).unwrap_or(false) && !path.exists();
        let expected = if mode == "healthy" { ConfigLoadStatus::Corrupt } else { ConfigLoadStatus::TransientError };
        let correct = loaded.status == expected && loaded.value.is_empty();
        let valid_loaded: ConfigLoad<HashMap<String, String>> = load_path_with_status(valid);
        let valid_control = valid_loaded.status == ConfigLoadStatus::Loaded
            && valid_loaded.value.get("marker").map(String::as_str) == Some("retained");
        let after_fds = fds();
        println!("OPTION_COMMIT_RECOVERY_SYNC=observed mode={mode} status={:?} correct={correct} backup_preserved={preserved} valid_control={valid_control}", loaded.status);
        println!("OPTION_COMMIT_RECOVERY_SYNC=handles mode={mode} before={before_fds} after={after_fds}");
        assert!(correct && preserved && valid_control);
        assert_eq!(before_fds, after_fds);
    });
}

#[test]
#[cfg(target_arch = "x86_64")]
fn core_recovery_file_sync_error_is_transient() {
    core_recovery_sync_case("config::option_tests::core_recovery_file_sync_error_is_transient", "file");
}

#[test]
#[cfg(target_arch = "x86_64")]
fn core_recovery_parent_sync_error_is_transient() {
    core_recovery_sync_case("config::option_tests::core_recovery_parent_sync_error_is_transient", "parent");
}

#[test]
#[cfg(target_arch = "x86_64")]
fn core_recovery_success_syncs_and_preserves() {
    core_recovery_sync_case("config::option_tests::core_recovery_success_syncs_and_preserves", "healthy");
}

#[test]
fn core_recovery_requires_syncable_parent_before_publication() {
    use std::os::unix::fs::MetadataExt;
    in_private_process("config::option_tests::core_recovery_requires_syncable_parent_before_publication", |root| {
        let base = root.join("recovery-parent-read");
        fs::create_dir(&base).unwrap();
        let path = base.join("broken.toml");
        let bytes = b"== invalid TOML [[[";
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let before = fs::metadata(&path).unwrap();
        let valid = base.join("valid.toml");
        fs::write(&valid, b"marker = 'retained'\n").unwrap();
        let fds = || fs::read_dir("/proc/self/fd").unwrap().count();
        let before_fds = fds();
        fs::set_permissions(&base, fs::Permissions::from_mode(0o300)).unwrap();
        let valid_loaded: ConfigLoad<HashMap<String, String>> = load_path_with_status(valid);
        let valid_control = valid_loaded.status == ConfigLoadStatus::Loaded
            && valid_loaded.value.get("marker").map(String::as_str) == Some("retained");
        let loaded: ConfigLoad<HashMap<String, String>> = load_path_with_status(path.clone());
        let refused = loaded.status == ConfigLoadStatus::TransientError;
        let mode_preserved = fs::metadata(&base).unwrap().mode() & 0o777 == 0o300;
        let preserved = fs::metadata(&path).map(|after| {
            (after.dev(), after.ino(), after.mode()) == (before.dev(), before.ino(), before.mode())
                && fs::read(&path).unwrap() == bytes
        }).unwrap_or(false);
        fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).unwrap();
        let retried: ConfigLoad<HashMap<String, String>> = load_path_with_status(path.clone());
        let backups = fs::read_dir(&base).unwrap().map(|entry| entry.unwrap().path())
            .filter(|entry| entry.file_name().unwrap().to_string_lossy().starts_with("config.corrupt.")).collect::<Vec<_>>();
        let recovered = retried.status == ConfigLoadStatus::Corrupt && !path.exists() && backups.len() == 1
            && fs::read(&backups[0]).unwrap() == bytes;
        let after_fds = fds();
        println!("OPTION_COMMIT_RECOVERY_SYNC=preflight refused={refused} source_preserved={preserved} mode_preserved={mode_preserved} valid_control={valid_control} retry_recovered={recovered}");
        println!("OPTION_COMMIT_RECOVERY_SYNC=handles mode=preflight before={before_fds} after={after_fds}");
        assert!(refused && preserved && mode_preserved && valid_control && recovered);
        assert_eq!(before_fds, after_fds);
    });
}

fn config_store_native_name_round_trip(path: &Path) -> bool {
    use std::os::unix::{ffi::OsStrExt, fs::MetadataExt};
    fs::write(path, b"marker = 'native-probe'\n").unwrap();
    assert_eq!(read_config_view::<HashMap<String, String>>(path).unwrap().get("marker").map(String::as_str), Some("native-probe"));
    fs::remove_file(path).unwrap();
    let mut stored = true;
    for value in ["first", "replacement"] {
        let expected = HashMap::from([("marker".to_owned(), value.to_owned())]);
        let result = store_path(path.to_path_buf(), &expected);
        let readback = read_config_view::<HashMap<String, String>>(path).map(|value| value == expected).unwrap_or(false);
        let private_mode = fs::metadata(path).map(|metadata| metadata.mode() & 0o777 == 0o600).unwrap_or(false);
        println!("OPTION_COMMIT_TEMP_NAME=observed bytes={} utf8={} stage={value} native_probe=true saved={} readback={readback} private_mode={private_mode}", path.file_name().unwrap().as_bytes().len(), path.file_name().unwrap().to_str().is_some(), result.is_ok());
        stored &= result.is_ok() && readback && private_mode;
    }
    let entries = fs::read_dir(path.parent().unwrap()).unwrap().map(|entry| entry.unwrap().file_name()).collect::<Vec<_>>();
    stored && entries == vec![path.file_name().unwrap()]
}

#[test]
fn config_store_full_length_native_names_round_trip() {
    in_private_process("config::option_tests::config_store_full_length_native_names_round_trip", |root| {
        let mut all_stored = true;
        for (index, name) in ["a".repeat(190), "a".repeat(240), "a".repeat(255), format!("a{}", "é".repeat(127))].iter().enumerate() {
            let base = root.join(format!("length-{index}"));
            fs::create_dir(&base).unwrap();
            all_stored &= config_store_native_name_round_trip(&base.join(name));
        }
        assert!(all_stored);
    });
}

#[test]
fn config_store_non_utf8_native_names_round_trip() {
    in_private_process("config::option_tests::config_store_non_utf8_native_names_round_trip", |root| {
        use std::os::unix::ffi::OsStringExt;
        let mut all_stored = true;
        for (index, bytes) in [b"record-\xff.toml".as_slice(), b"\x80.toml".as_slice()].iter().enumerate() {
            let base = root.join(format!("bytes-{index}"));
            fs::create_dir(&base).unwrap();
            let name = std::ffi::OsString::from_vec(bytes.to_vec());
            all_stored &= config_store_native_name_round_trip(&base.join(name));
        }
        assert!(all_stored);
    });
}

#[test]
fn config_store_native_names_preserve_precommit_and_retire_temps() {
    in_private_process("config::option_tests::config_store_native_names_preserve_precommit_and_retire_temps", |root| {
        use std::{cell::Cell, os::unix::{ffi::OsStringExt, fs::MetadataExt}};
        let fds = || fs::read_dir("/proc/self/fd").unwrap().count();
        let before_fds = fds();
        let mut all_preserved = true;
        for (index, name) in [std::ffi::OsString::from("n".repeat(255)), std::ffi::OsString::from_vec(b"record-\xff.toml".to_vec())].iter().enumerate() {
            let base = root.join(format!("fault-{index}"));
            fs::create_dir(&base).unwrap();
            let path = base.join(name);
            fs::write(&path, b"confirmed").unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
            let before = fs::metadata(&path).unwrap();
            let mut entered = 0;
            let mut preserved = true;
            for _ in 0..16 {
                let reached = Cell::new(false);
                let result = store_config_bytes_transaction_unix(&path, b"requested", ConfigStoreFault::BeforeReplace,
                    &|_| panic!("precommit refusal reached fatal callback"), &|_, temporary_name, temporary| {
                        reached.set(true);
                        assert!(temporary_name.to_bytes().len() <= 100 && temporary_name.to_bytes().is_ascii());
                        assert_eq!(temporary.metadata()?.mode() & 0o777, 0o600);
                        Ok(())
                    });
                entered += usize::from(reached.get());
                let after = fs::metadata(&path).unwrap();
                preserved &= result.is_err() && fs::read(&path).unwrap() == b"confirmed"
                    && (before.dev(), before.ino(), before.mode()) == (after.dev(), after.ino(), after.mode())
                    && fs::read_dir(&base).unwrap().map(|entry| entry.unwrap().file_name()).collect::<Vec<_>>() == vec![name.clone()];
            }
            println!("OPTION_COMMIT_TEMP_NAME=observed kind=precommit index={index} iterations=16 entered={entered} preserved={preserved}");
            all_preserved &= entered == 16 && preserved;
        }
        let after_fds = fds();
        println!("OPTION_COMMIT_TEMP_NAME=observed kind=handles before={before_fds} after={after_fds}");
        assert!(all_preserved);
        assert_eq!(after_fds, before_fds);
    });
}

fn config_store_test_path_length(root: &Path, length: usize) -> PathBuf {
    use std::os::unix::ffi::OsStrExt;
    let mut path = root.join("uncreated");
    while path.as_os_str().as_bytes().len() + 100 < length {
        path.push("d".repeat(80));
    }
    let remaining = length - path.as_os_str().as_bytes().len() - 1;
    assert!((1..=100).contains(&remaining));
    path.push("f".repeat(remaining));
    assert_eq!(path.as_os_str().as_bytes().len(), length);
    path
}

#[test]
fn config_store_invalid_paths_preserve_namespace() {
    in_private_process("config::option_tests::config_store_invalid_paths_preserve_namespace", |root| {
        use std::os::unix::fs::MetadataExt;
        let mut all_preserved = true;
        for (index, suffix) in ["/", "//", "/.", "/./"].iter().enumerate() {
            for present in [false, true] {
                let base = root.join(format!("suffix-{index}-{present}"));
                fs::create_dir(&base).unwrap();
                let file = base.join("record.toml");
                let bytes = b"marker = 'confirmed'\n";
                let original = if present {
                    fs::write(&file, bytes).unwrap();
                    fs::set_permissions(&file, fs::Permissions::from_mode(0o640)).unwrap();
                    Some(fs::metadata(&file).unwrap())
                } else { None };
                let mut spelling = file.clone().into_os_string();
                spelling.push(suffix);
                let result = store_path(PathBuf::from(spelling), HashMap::from([("marker", "requested")]));
                let entries = fs::read_dir(&base).unwrap().map(|entry| entry.unwrap().file_name()).collect::<Vec<_>>();
                let preserved = match original {
                    Some(before) => fs::metadata(&file).map(|after| {
                        after.is_file() && (before.dev(), before.ino(), before.mode()) == (after.dev(), after.ino(), after.mode())
                    }).unwrap_or(false) && fs::read(&file).map(|data| data == bytes).unwrap_or(false)
                        && entries == vec![file.file_name().unwrap()],
                    None => entries.is_empty(),
                };
                println!("OPTION_COMMIT_STORE_PATH=observed kind=suffix index={index} present={present} refused={} preserved={preserved}", result.is_err());
                all_preserved &= result.is_err() && preserved;
            }
        }
        for (index, selected) in ["missing/record\0.toml", "missing/../record.toml", "missing/\0parent/record.toml"].iter().enumerate() {
            let base = root.join(format!("invalid-{index}"));
            fs::create_dir(&base).unwrap();
            let result = store_path(base.join(selected), HashMap::from([("marker", "requested")]));
            let preserved = fs::read_dir(&base).unwrap().next().is_none();
            println!("OPTION_COMMIT_STORE_PATH=observed kind=invalid index={index} refused={} preserved={preserved}", result.is_err());
            all_preserved &= result.is_err() && preserved;
        }
        assert!(all_preserved);
    });
}

#[test]
fn config_store_overlong_paths_refuse_before_creation() {
    in_private_process("config::option_tests::config_store_overlong_paths_refuse_before_creation", |root| {
        let mut all_refused = true;
        for length in [crate::libc::PATH_MAX as usize, crate::libc::PATH_MAX as usize + 1] {
            let base = root.join(format!("length-{length}"));
            fs::create_dir(&base).unwrap();
            let path = config_store_test_path_length(&base, length);
            let result = store_path(path.clone(), HashMap::from([("marker", "requested")]));
            let reader_refused = read_config_view::<HashMap<String, String>>(&path).is_err();
            let preserved = fs::read_dir(&base).unwrap().next().is_none();
            println!("OPTION_COMMIT_STORE_PATH=observed kind=length bytes={length} refused={} reader_refused={reader_refused} preserved={preserved}", result.is_err());
            all_refused &= result.is_err() && reader_refused && preserved;
        }
        assert!(all_refused);
    });
}

#[test]
fn config_store_path_controls_round_trip() {
    in_private_process("config::option_tests::config_store_path_controls_round_trip", |root| {
        use std::os::unix::{ffi::{OsStrExt, OsStringExt}, fs::MetadataExt};
        let previous = std::env::current_dir().unwrap();
        std::env::set_current_dir(root).unwrap();
        let mut paths = vec![
            PathBuf::from("relative/record.toml"), PathBuf::from("./dotparent/record.toml"),
            PathBuf::from("..."), PathBuf::from("space/данные.toml"), PathBuf::from("back\\slash.toml"),
            PathBuf::from("repeated//middle/./record.toml"),
            PathBuf::from(std::ffi::OsString::from_vec(b"nonutf8-\xff/record.toml".to_vec())),
            root.join("absolute/record.toml"),
        ];
        let boundary = config_store_test_path_length(root, crate::libc::PATH_MAX as usize - 1);
        assert_eq!(boundary.as_os_str().as_bytes().len(), crate::libc::PATH_MAX as usize - 1);
        paths.push(boundary);
        for (index, path) in paths.iter().enumerate() {
            for value in ["first", "replacement"] {
                let expected = HashMap::from([("marker".to_owned(), value.to_owned())]);
                store_path(path.clone(), &expected).unwrap();
                assert_eq!(read_config_view::<HashMap<String, String>>(path).unwrap(), expected);
                assert_eq!(fs::metadata(path).unwrap().mode() & 0o777, 0o600);
            }
            println!("OPTION_COMMIT_STORE_PATH=observed kind=control index={index} first_and_replacement=true readback=true mode=600");
        }
        std::env::set_current_dir(previous).unwrap();
    });
}

#[test]
fn config_read_shared_write_modes_refuse_without_recovery() {
    use std::os::unix::fs::MetadataExt;
    in_private_process("config::option_tests::config_read_shared_write_modes_refuse_without_recovery", |root| {
        let mut all_refused = true;
        for mode in [0o602, 0o620, 0o622, 0o646, 0o664, 0o666] {
            for corrupt in [false, true] {
                let base = root.join(format!("{mode:o}-{corrupt}"));
                fs::create_dir(&base).unwrap();
                let path = base.join("record.toml");
                let bytes = if corrupt { b"= = invalid TOML [[[".as_slice() } else { b"[options]\nk = 'kept'\n".as_slice() };
                fs::write(&path, bytes).unwrap();
                fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
                let before = fs::metadata(&path).unwrap();
                let mut refused = true;
                for _ in 0..2 {
                    let loaded: ConfigLoad<Config2> = load_path_with_status(path.clone());
                    refused &= loaded.status == ConfigLoadStatus::TransientError && loaded.value == Config2::default();
                }
                let preserved = fs::metadata(&path).map(|after| {
                    (after.dev(), after.ino(), after.mode()) == (before.dev(), before.ino(), before.mode())
                }).unwrap_or(false) && fs::read(&path).map(|actual| actual == bytes).unwrap_or(false)
                    && fs::read_dir(&base).unwrap().map(|e| e.unwrap().file_name()).collect::<Vec<_>>() == vec![path.file_name().unwrap()];
                println!("OPTION_COMMIT_READ_AUTHORITY=observed kind=mode mode={mode:o} corrupt={corrupt} refused={refused} preserved={preserved}");
                if refused && preserved {
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
                    let retry: ConfigLoad<Config2> = load_path_with_status(path.clone());
                    if corrupt {
                        assert_eq!(retry.status, ConfigLoadStatus::Corrupt);
                        let archive = fs::read_dir(&base).unwrap().next().unwrap().unwrap().path();
                        let after = fs::metadata(&archive).unwrap();
                        assert!(!path.exists());
                        assert_eq!(fs::read(archive).unwrap(), bytes);
                        assert_eq!((after.dev(), after.ino()), (before.dev(), before.ino()));
                        assert_eq!(after.mode() & 0o777, 0o600);
                    } else {
                        assert_eq!(retry.status, ConfigLoadStatus::Loaded);
                        assert_eq!(retry.value.options.get("k").map(String::as_str), Some("kept"));
                        assert_eq!(fs::read(&path).unwrap(), bytes);
                        assert_eq!(fs::metadata(&path).unwrap().ino(), before.ino());
                    }
                    println!("OPTION_COMMIT_READ_AUTHORITY=observed kind=retry mode={mode:o} corrupt={corrupt} recovered=true");
                }
                all_refused &= refused && preserved;
            }
        }
        assert!(all_refused);
    });
}

#[test]
fn config_read_foreign_owner_refuses_and_retires_handles() {
    use std::os::unix::fs::MetadataExt;
    in_private_process("config::option_tests::config_read_foreign_owner_refuses_and_retires_handles", |_| {
        // Public, immutable builder-image fixture; no host file or service is involved.
        let path = Path::new("/etc/passwd");
        let original = fs::read(path).unwrap();
        let before = fs::metadata(path).unwrap();
        assert!(before.is_file() && before.nlink() == 1 && before.uid() == 0);
        let fds = || fs::read_dir("/proc/self/fd").unwrap().count();
        let before_fds = fds();
        let mut refused = true;
        for _ in 0..16 { refused &= read_config_record(path).is_err(); }
        let after = fs::metadata(path).unwrap();
        let preserved = (before.dev(), before.ino(), before.uid(), before.mode()) == (after.dev(), after.ino(), after.uid(), after.mode())
            && fs::read(path).unwrap() == original;
        let after_fds = fds();
        println!("OPTION_COMMIT_READ_AUTHORITY=observed kind=owner source_uid=0 reader_uid={} iterations=16 refused={refused} preserved={preserved} fds_before={before_fds} fds_after={after_fds}", unsafe { crate::libc::geteuid() });
        assert!(refused && preserved);
        assert_eq!(before_fds, after_fds);
    });
}

#[test]
fn peer_read_shared_write_acl_refuses_mutation_and_retries() {
    use std::os::unix::{fs::MetadataExt, io::AsRawFd};
    in_private_process("config::option_tests::peer_read_shared_write_acl_refuses_mutation_and_retries", |_| {
        let id = "read-authority-acl";
        let mut peer = PeerConfig::default();
        peer.password_prs = b"fixture-read-authority-prs".to_vec();
        peer.options.insert("unrelated".into(), "preserved".into());
        peer.store(id).unwrap();
        let path = PeerConfig::path(id);
        let acl = config_parent_acl(&path, 7);
        let original = fs::read(&path).unwrap();
        let before = fs::metadata(&path).unwrap();
        assert_ne!(before.mode() & 0o020, 0);
        let view_refused = PeerConfig::read_option(id, "unrelated").is_err();
        let write_refused = PeerConfig::set_option(id, "alias", "selected".into()).is_err();
        let after = fs::metadata(&path).unwrap();
        let file = fs::File::open(&path).unwrap();
        let mut observed = vec![0; acl.len()];
        let acl_preserved = unsafe { crate::libc::fgetxattr(file.as_raw_fd(), b"system.posix_acl_access\0".as_ptr().cast(), observed.as_mut_ptr().cast(), observed.len()) } == acl.len() as isize && observed == acl;
        let preserved = (before.dev(), before.ino(), before.mode()) == (after.dev(), after.ino(), after.mode())
            && fs::read(&path).unwrap() == original && acl_preserved;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        PeerConfig::set_option(id, "alias", "selected".into()).unwrap();
        let loaded = PeerConfig::load_for_write(id).unwrap();
        let retried = loaded.options.get("alias").map(String::as_str) == Some("selected")
            && loaded.options.get("unrelated").map(String::as_str) == Some("preserved") && loaded.password_prs == peer.password_prs;
        println!("OPTION_COMMIT_READ_AUTHORITY=observed kind=acl view_refused={view_refused} write_refused={write_refused} preserved={preserved} retried={retried}");
        assert!(view_refused && write_refused && preserved && retried);
    });
}

#[test]
fn config_read_owned_readonly_and_masked_acl_controls() {
    use std::os::unix::{fs::MetadataExt, io::AsRawFd};
    in_private_process("config::option_tests::config_read_owned_readonly_and_masked_acl_controls", |root| {
        for mode in [0o400, 0o600, 0o640, 0o644] {
            let path = root.join(format!("{mode:o}.toml"));
            let bytes = b"[options]\nk = 'kept'\n";
            fs::write(&path, bytes).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
            let before = fs::metadata(&path).unwrap();
            let loaded: ConfigLoad<Config2> = load_path_with_status(path.clone());
            let view: Config2 = read_config_view(&path).unwrap();
            let after = fs::metadata(&path).unwrap();
            assert_eq!(loaded.status, ConfigLoadStatus::Loaded);
            assert_eq!(view, loaded.value);
            assert_eq!(view.options.get("k").map(String::as_str), Some("kept"));
            assert_eq!(fs::read(&path).unwrap(), bytes);
            assert_eq!((before.dev(), before.ino(), before.mode()), (after.dev(), after.ino(), after.mode()));
        }
        let path = root.join("masked.toml");
        fs::write(&path, b"answer = 7\n").unwrap();
        let acl = config_parent_acl(&path, 5);
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o022, 0);
        let loaded: HashMap<String, u32> = read_config_view(&path).unwrap();
        assert_eq!(loaded.get("answer"), Some(&7));
        let file = fs::File::open(&path).unwrap();
        let mut observed = vec![0; acl.len()];
        assert_eq!(unsafe { crate::libc::fgetxattr(file.as_raw_fd(), b"system.posix_acl_access\0".as_ptr().cast(), observed.as_mut_ptr().cast(), observed.len()) }, acl.len() as isize);
        assert_eq!(observed, acl);
        println!("OPTION_COMMIT_READ_AUTHORITY=observed kind=controls safe_modes=4 masked_acl_preserved=true");
    });
}

#[test]
fn core_load_links_are_transient_without_recovery() {
    use std::os::unix::fs::{symlink, MetadataExt};
    in_private_process("config::option_tests::core_load_links_are_transient_without_recovery", |root| {
        let mut all_refused = true;
        for kind in ["file", "corrupt_file", "dangling_file", "parent", "ancestor", "dangling_parent"] {
            let base = root.join(kind);
            fs::create_dir(&base).unwrap();
            let target = base.join("target");
            let link = base.join("selected");
            let directory = matches!(kind, "parent" | "ancestor" | "dangling_parent");
            let suffix = if kind == "ancestor" { "child/record.toml" } else { "record.toml" };
            let (path, target_file) = if directory {
                (link.join(suffix), target.join(suffix))
            } else { (link.clone(), target.clone()) };
            let dangling = kind.starts_with("dangling");
            let source: &[u8] = if kind == "corrupt_file" { b"= = invalid TOML [[[" } else { b"[options]\nkey = 'preserved'\n" };
            if !dangling {
                fs::create_dir_all(target_file.parent().unwrap()).unwrap();
                fs::write(&target_file, source).unwrap();
            }
            symlink(&target, &link).unwrap();
            let before = fs::symlink_metadata(&link).unwrap();
            let names = || {
                let mut names = fs::read_dir(&base).unwrap().map(|entry| entry.unwrap().file_name()).collect::<Vec<_>>();
                names.sort(); names
            };
            let original_names = names();
            let mut refused = true;
            for _ in 0..2 {
                let loaded: ConfigLoad<Config2> = load_path_with_status(path.clone());
                refused &= loaded.status == ConfigLoadStatus::TransientError && loaded.value == Config2::default();
            }
            let preserved = fs::symlink_metadata(&link).map(|after| {
                after.file_type().is_symlink() && (before.dev(), before.ino(), before.mode()) == (after.dev(), after.ino(), after.mode())
            }).unwrap_or(false) && fs::read_link(&link).ok().as_ref() == Some(&target)
                && names() == original_names
                && if dangling { !target.exists() } else { fs::read(&target_file).unwrap() == source };
            println!("OPTION_COMMIT_CORE_LOAD_LINK=observed kind={kind} refused={refused} preserved={preserved}");
            all_refused &= refused && preserved;
        }
        assert!(all_refused);
    });
}

#[test]
fn core_recovery_full_length_native_names_archive_exact_sources() {
    use std::os::unix::{ffi::{OsStrExt, OsStringExt}, fs::MetadataExt, io::{AsRawFd, FromRawFd}};
    in_private_process("config::option_tests::core_recovery_full_length_native_names_archive_exact_sources", |root| {
        let names = [std::ffi::OsString::from("a".repeat(240)), std::ffi::OsString::from("b".repeat(255)),
            std::ffi::OsString::from(format!("{}a", "é".repeat(127))),
            std::ffi::OsString::from_vec([vec![b'n'; 254], vec![0xff]].concat())];
        let mut paths = names.iter().enumerate().map(|(i, name)| root.join(i.to_string()).join(name)).collect::<Vec<_>>();
        paths.push(config_store_test_path_length(&root.join("path-limit"), crate::libc::PATH_MAX as usize - 1));
        let mut all_recovered = true;
        for (index, path) in paths.iter().enumerate() {
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            let bytes = format!("= = original corrupt source {index} [[[").into_bytes();
            fs::write(path, &bytes).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o640)).unwrap();
            let original = fs::metadata(path).unwrap();
            let parent = open_existing_config_parent(path).unwrap().unwrap();
            let result = preserve_corrupt_config_at(path, u128::MAX);
            let entries = fs::read_dir(path.parent().unwrap()).unwrap().map(|e| e.unwrap().file_name()).collect::<Vec<_>>();
            let mut archive_exact = false;
            let mut bounded = false;
            if result.is_ok() && entries.len() == 1 && !path.exists() {
                bounded = entries[0].as_bytes().len() <= 119 && entries[0].as_bytes().is_ascii();
                let name = std::ffi::CString::new(entries[0].as_bytes()).unwrap();
                let fd = unsafe { crate::libc::openat(parent.as_raw_fd(), name.as_ptr(), crate::libc::O_RDONLY | crate::libc::O_CLOEXEC | crate::libc::O_NOFOLLOW) };
                assert!(fd >= 0);
                let mut archive = unsafe { fs::File::from_raw_fd(fd) };
                let metadata = archive.metadata().unwrap();
                let mut actual = Vec::new();
                std::io::Read::read_to_end(&mut archive, &mut actual).unwrap();
                archive_exact = actual == bytes && (metadata.dev(), metadata.ino()) == (original.dev(), original.ino())
                    && metadata.mode() & 0o777 == 0o600;
            }
            let intact_on_error = result.is_ok() || fs::metadata(path).map(|m| {
                (m.dev(), m.ino(), m.mode()) == (original.dev(), original.ino(), original.mode())
            }).unwrap_or(false) && fs::read(path).unwrap() == bytes && entries.len() == 1;
            println!("OPTION_COMMIT_RECOVERY_NAME=observed kind=length index={index} source_bytes={} archived={archive_exact} bounded={bounded} intact_on_error={intact_on_error}", path.file_name().unwrap().as_bytes().len());
            all_recovered &= archive_exact && bounded && intact_on_error;
        }
        assert!(all_recovered);
    });
}

#[test]
fn core_recovery_native_name_tags_separate_sources_and_preserve_collisions() {
    use std::os::unix::{ffi::OsStringExt, fs::MetadataExt};
    in_private_process("config::option_tests::core_recovery_native_name_tags_separate_sources_and_preserve_collisions", |root| {
        let fds = || fs::read_dir("/proc/self/fd").unwrap().count();
        let before_fds = fds();
        let cases = [
            (b"record-\xff.toml".as_slice(), "130b490ce9dc9849821bb01e70564cc9c2c932a1cde647854756dec410e9c3f8"),
            (b"record-\xfe.toml".as_slice(), "10ed6322d1d57196310fdc38836117d8071eb2b9d5dafb6820cd058a38d1e051"),
            ("record-�.toml".as_bytes(), "66fb20ed5746088a82eb42f77081aa7b14362652d1fe1229a3ec507f1a85d978"),
        ];
        let mut all_recovered = true;
        let mut archives = Vec::new();
        for (index, (name, tag)) in cases.iter().enumerate() {
            let path = root.join(std::ffi::OsString::from_vec(name.to_vec()));
            let bytes = format!("= = source {index} corrupt bytes [[[").into_bytes();
            fs::write(&path, &bytes).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
            let source = fs::metadata(&path).unwrap();
            let expected = root.join(format!("config.corrupt.{tag}.0"));
            let result = preserve_corrupt_config_at(&path, 0);
            let recovered = result.is_ok() && !path.exists() && fs::metadata(&expected).map(|m| {
                (m.dev(), m.ino()) == (source.dev(), source.ino()) && m.mode() & 0o777 == 0o600
            }).unwrap_or(false) && fs::read(&expected).map(|b| b == bytes).unwrap_or(false);
            println!("OPTION_COMMIT_RECOVERY_NAME=observed kind=association index={index} moved={} source_tag_matches={recovered}", result.is_ok());
            all_recovered &= recovered;
            archives.push((expected, bytes, (source.dev(), source.ino())));
        }
        if all_recovered {
            let path = root.join(std::ffi::OsString::from_vec(cases[0].0.to_vec()));
            fs::write(&path, b"later corrupt source").unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
            let before = fs::metadata(&path).unwrap();
            let refused = preserve_corrupt_config_at(&path, 0).is_err();
            let after = fs::metadata(&path).unwrap();
            let preserved = (before.dev(), before.ino(), before.mode()) == (after.dev(), after.ino(), after.mode())
                && fs::read(&path).unwrap() == b"later corrupt source"
                && archives.iter().all(|(p, b, id)| fs::read(p).unwrap() == *b && fs::metadata(p).map(|m| (m.dev(), m.ino()) == *id && m.mode() & 0o777 == 0o600).unwrap_or(false));
            println!("OPTION_COMMIT_RECOVERY_NAME=observed kind=collision refused={refused} preserved={preserved}");
            assert!(refused && preserved);
        }
        let after_fds = fds();
        println!("OPTION_COMMIT_RECOVERY_NAME=observed kind=handles before={before_fds} after={after_fds}");
        assert_eq!(before_fds, after_fds);
        assert!(all_recovered);
    });
}

#[test]
fn core_recovery_source_changes_after_read_are_refused() {
    use std::{cell::{Cell, RefCell}, os::unix::fs::{symlink, MetadataExt}};
    in_private_process("config::option_tests::core_recovery_source_changes_after_read_are_refused", |root| {
        let mut all_preserved = true;
        for kind in ["file", "symlink", "missing"] {
            let base = root.join(kind);
            fs::create_dir(&base).unwrap();
            let path = base.join("selected.toml");
            let saved = base.join("read-source");
            let outside = base.join("outside");
            fs::write(&path, b"= = read corrupt bytes [[[ ").unwrap();
            fs::write(&outside, b"outside sentinel").unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
            let identity = |p: &Path| fs::symlink_metadata(p).map(|m| (m.dev(), m.ino(), m.mode(), m.nlink())).ok();
            let original = identity(&path);
            let expected_source = Cell::new(None);
            let expected_names = RefCell::new(Vec::new());
            let entered = Cell::new(false);
            let names = || {
                let mut names = fs::read_dir(&base).unwrap().map(|e| e.unwrap().file_name()).collect::<Vec<_>>();
                names.sort(); names
            };
            let loaded: ConfigLoad<Config2> = load_path_with_status_after_read(path.clone(), || {
                entered.set(true);
                fs::rename(&path, &saved).unwrap();
                match kind {
                    "file" => { fs::write(&path, b"replacement bytes").unwrap(); fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap(); }
                    "symlink" => symlink(&outside, &path).unwrap(),
                    _ => {}
                }
                expected_source.set(identity(&path));
                *expected_names.borrow_mut() = names();
            });
            let refused = loaded.status == ConfigLoadStatus::TransientError;
            let preserved = entered.get() && identity(&saved) == original && identity(&path) == expected_source.get()
                && names() == *expected_names.borrow() && fs::read(&saved).unwrap() == b"= = read corrupt bytes [[[ "
                && fs::read(&outside).unwrap() == b"outside sentinel";
            println!("OPTION_COMMIT_RECOVERY_OWNER=observed kind=source_{kind} entered={} refused={refused} preserved={preserved}", entered.get());
            all_preserved &= refused && preserved;
        }
        assert!(all_preserved);
    });
}

#[test]
fn core_recovery_parent_changes_stay_with_the_read_parent() {
    use std::os::unix::fs::MetadataExt;
    in_private_process("config::option_tests::core_recovery_parent_changes_stay_with_the_read_parent", |root| {
        let base = root.join("selected-parent");
        let retained = root.join("retained-parent");
        fs::create_dir(&base).unwrap();
        let path = base.join("selected.toml");
        fs::write(&path, b"= = read corrupt bytes [[[ ").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        let original = fs::metadata(&path).unwrap();
        let loaded: ConfigLoad<Config2> = load_path_with_status_after_read(path.clone(), || {
            fs::rename(&base, &retained).unwrap();
            fs::create_dir(&base).unwrap();
            fs::write(&path, b"replacement bytes").unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        });
        let backup = fs::read_dir(&retained).unwrap().map(|e| e.unwrap().path())
            .find(|p| p.file_name().unwrap().to_string_lossy().contains(".corrupt."));
        let recovered = loaded.status == ConfigLoadStatus::Corrupt && backup.map(|p| {
            let m = fs::metadata(&p).unwrap();
            (m.dev(), m.ino()) == (original.dev(), original.ino()) && m.mode() & 0o777 == 0o600
                && fs::read(&p).unwrap() == b"= = read corrupt bytes [[[ "
        }).unwrap_or(false) && !retained.join("selected.toml").exists();
        let preserved = fs::read(&path).map(|b| b == b"replacement bytes").unwrap_or(false)
            && fs::metadata(&path).map(|m| m.mode() & 0o777 == 0o644).unwrap_or(false)
            && fs::read_dir(&base).unwrap().count() == 1;
        println!("OPTION_COMMIT_RECOVERY_OWNER=observed kind=parent recovered={recovered} replacement_preserved={preserved}");
        assert!(recovered && preserved);
    });
}

#[test]
fn core_recovery_replaced_backup_is_never_permission_hardened() {
    use std::{cell::Cell, os::unix::fs::MetadataExt};
    in_private_process("config::option_tests::core_recovery_replaced_backup_is_never_permission_hardened", |root| {
        let path = root.join("selected.toml");
        let saved = root.join("admitted-recovery");
        let backup = root.join(config_recovery_file_name(&path, 17).unwrap());
        fs::write(&path, b"read corrupt bytes").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        let identity = |p: &Path| fs::metadata(p).map(|m| (m.dev(), m.ino(), m.mode(), m.nlink())).ok();
        let original = identity(&path);
        let replacement = Cell::new(None);
        let entered = Cell::new(false);
        let record = read_config_record(&path).unwrap();
        let result = record.preserve_corrupt_at_with(17, |named| {
            entered.set(true);
            fs::rename(named, &saved)?;
            fs::write(named, b"replacement recovery bytes")?;
            fs::set_permissions(named, fs::Permissions::from_mode(0o644))?;
            replacement.set(identity(named));
            Ok(())
        });
        let refused = result.is_err();
        let preserved = entered.get() && identity(&saved) == original && identity(&backup) == replacement.get()
            && fs::read(&saved).unwrap() == b"read corrupt bytes"
            && fs::read(&backup).unwrap() == b"replacement recovery bytes";
        println!("OPTION_COMMIT_RECOVERY_OWNER=observed kind=backup entered={} refused={refused} preserved={preserved}", entered.get());
        assert!(refused && preserved);
    });
}

#[test]
fn core_recovery_read_owners_retire_on_every_outcome() {
    in_private_process("config::option_tests::core_recovery_read_owners_retire_on_every_outcome", |root| {
        let fds = || fs::read_dir("/proc/self/fd").unwrap().count();
        let before = fds();
        for index in 0..24 {
            let base = root.join(index.to_string());
            fs::create_dir(&base).unwrap();
            let path = base.join("selected.toml");
            let (bytes, status): (&[u8], _) = match index % 3 {
                0 => (b"[options]\nmarker = 'retained'\n", ConfigLoadStatus::Loaded),
                1 => (b"= = corrupt bytes [[[", ConfigLoadStatus::Corrupt),
                _ => (b"\xff", ConfigLoadStatus::TransientError),
            };
            fs::write(&path, bytes).unwrap();
            let loaded: ConfigLoad<Config2> = load_path_with_status(path);
            assert_eq!(loaded.status, status);
        }
        let after = fds();
        println!("OPTION_COMMIT_RECOVERY_OWNER=observed kind=controls loaded=8 recovered=8 transient=8 fds_before={before} fds_after={after}");
        assert_eq!(before, after);
    });
}

#[test]
fn core_recovery_collision_preserves_source_and_prior_backup() {
    use std::os::unix::fs::{symlink, MetadataExt};
    in_private_process("config::option_tests::core_recovery_collision_preserves_source_and_prior_backup", |root| {
        let mut all_preserved = true;
        for kind in ["file", "symlink", "dangling", "hardlink", "directory"] {
            let base = root.join(kind);
            fs::create_dir(&base).unwrap();
            let source = base.join("selected.toml");
            let backup = base.join(config_recovery_file_name(&source, 0).unwrap());
            let outside = base.join("outside");
            fs::write(&source, b"= = current corrupt bytes [[[").unwrap();
            fs::set_permissions(&source, fs::Permissions::from_mode(0o640)).unwrap();
            fs::write(&outside, b"outside sentinel").unwrap();
            match kind {
                "symlink" => symlink(&outside, &backup).unwrap(),
                "dangling" => symlink(base.join("absent"), &backup).unwrap(),
                "hardlink" => fs::hard_link(&source, &backup).unwrap(),
                "directory" => fs::create_dir(&backup).unwrap(),
                _ => fs::write(&backup, b"prior recovery bytes").unwrap(),
            }
            let identity = |p: &Path| fs::symlink_metadata(p).map(|m| (m.dev(), m.ino(), m.mode(), m.nlink())).ok();
            let before_source = identity(&source);
            let before_backup = identity(&backup);
            let refused = preserve_corrupt_config_at(&source, 0).is_err();
            let preserved = identity(&source) == before_source && identity(&backup) == before_backup
                && fs::read(&source).map(|b| b == b"= = current corrupt bytes [[[").unwrap_or(false)
                && fs::read(&outside).unwrap() == b"outside sentinel"
                && match kind {
                    "file" => fs::read(&backup).map(|b| b == b"prior recovery bytes").unwrap_or(false),
                    "symlink" => fs::read_link(&backup).ok().as_ref() == Some(&outside),
                    "dangling" => fs::read_link(&backup).ok().as_ref() == Some(&base.join("absent")),
                    "directory" => fs::read_dir(&backup).unwrap().next().is_none(),
                    _ => true,
                };
            println!("OPTION_COMMIT_RECOVERY_PUBLICATION=observed kind={kind} refused={refused} preserved={preserved}");
            all_preserved &= refused && preserved;
        }
        assert!(all_preserved);
    });
}

#[test]
fn core_recovery_failure_is_transient_and_the_same_load_retries() {
    use std::os::unix::fs::MetadataExt;
    in_private_process("config::option_tests::core_recovery_failure_is_transient_and_the_same_load_retries", |root| {
        let base = root.join("denied");
        fs::create_dir(&base).unwrap();
        let path = base.join("selected.toml");
        let bytes = b"= = corrupt recovery source [[[";
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        let before = fs::metadata(&path).unwrap();
        fs::set_permissions(&base, fs::Permissions::from_mode(0o500)).unwrap();
        let mut refused = true;
        for _ in 0..2 {
            let loaded: ConfigLoad<Config2> = load_path_with_status(path.clone());
            refused &= loaded.status == ConfigLoadStatus::TransientError && loaded.value == Config2::default();
        }
        let after = fs::metadata(&path).unwrap();
        let preserved = (before.dev(), before.ino(), before.mode()) == (after.dev(), after.ino(), after.mode())
            && fs::read(&path).unwrap() == bytes && fs::read_dir(&base).unwrap().count() == 1;
        fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).unwrap();
        let retried: ConfigLoad<Config2> = load_path_with_status(path.clone());
        let backup = fs::read_dir(&base).unwrap().next().unwrap().unwrap().path();
        let recovered = retried.status == ConfigLoadStatus::Corrupt && !path.exists()
            && fs::read(&backup).unwrap() == bytes && fs::metadata(&backup).unwrap().mode() & 0o777 == 0o600;
        println!("OPTION_COMMIT_RECOVERY_PUBLICATION=observed kind=denial refused={refused} preserved={preserved} retry_recovered={recovered}");
        assert!(refused && preserved && recovered);
    });
}

#[test]
fn core_recovery_vacant_backup_preserves_native_names_and_handles() {
    use std::os::unix::{ffi::OsStringExt, fs::MetadataExt};
    in_private_process("config::option_tests::core_recovery_vacant_backup_preserves_native_names_and_handles", |root| {
        let fds = || fs::read_dir("/proc/self/fd").unwrap().count();
        let before_fds = fds();
        for (index, name) in [std::ffi::OsString::from("record.toml"), std::ffi::OsString::from("данные.toml"), std::ffi::OsString::from_vec(b"record-\xff.toml".to_vec())].iter().enumerate() {
            let ancestor = root.join(index.to_string());
            fs::create_dir(&ancestor).unwrap();
            let base = ancestor.join("readable-parent");
            fs::create_dir(&base).unwrap();
            let path = base.join(name);
            fs::write(&path, b"original corrupt bytes").unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
            let before = fs::metadata(&path).unwrap();
            fs::set_permissions(&ancestor, fs::Permissions::from_mode(0o111)).unwrap();
            preserve_corrupt_config_at(&path, 17).unwrap();
            let backup = fs::read_dir(&base).unwrap().next().unwrap().unwrap().path();
            let after = fs::metadata(&backup).unwrap();
            assert!(!path.exists());
            assert_eq!((before.dev(), before.ino()), (after.dev(), after.ino()));
            assert_eq!(fs::read(&backup).unwrap(), b"original corrupt bytes");
            assert_eq!(after.mode() & 0o777, 0o600);
            fs::set_permissions(&ancestor, fs::Permissions::from_mode(0o700)).unwrap();
            println!("OPTION_COMMIT_RECOVERY_PUBLICATION=observed kind=control index={index} identity_preserved=true mode=600 search_only_ancestor=true");
        }
        let after_fds = fds();
        println!("OPTION_COMMIT_RECOVERY_PUBLICATION=observed kind=handles before={before_fds} after={after_fds}");
        assert_eq!(before_fds, after_fds);
    });
}

#[test]
fn core_load_hard_links_refuse_without_recovery_mutation() {
    use std::os::unix::fs::MetadataExt;
    in_private_process("config::option_tests::core_load_hard_links_refuse_without_recovery_mutation", |root| {
        let mut all_preserved = true;
        for corrupt in [false, true] {
            for aliases in [1, 2] {
                let base = root.join(format!("links-{corrupt}-{aliases}"));
                fs::create_dir(&base).unwrap();
                let path = base.join("selected.toml");
                let bytes: &[u8] = if corrupt { b"= = invalid TOML [[[" } else { b"[options]\nmarker = 'retained'\n" };
                fs::write(&path, bytes).unwrap();
                fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
                let links = (0..aliases).map(|i| base.join(format!("alias-{i}"))).collect::<Vec<_>>();
                for link in &links { fs::hard_link(&path, link).unwrap(); }
                let identity = |p: &Path| fs::metadata(p).map(|m| (m.dev(), m.ino(), m.mode(), m.nlink())).ok();
                let before = identity(&path);
                let names = || {
                    let mut names = fs::read_dir(&base).unwrap().map(|e| e.unwrap().file_name()).collect::<Vec<_>>();
                    names.sort(); names
                };
                let original_names = names();
                let loaded: ConfigLoad<Config2> = load_path_with_status(path.clone());
                let refused = loaded.status == ConfigLoadStatus::TransientError && loaded.value == Config2::default();
                let preserved = identity(&path) == before && names() == original_names
                    && std::iter::once(&path).chain(links.iter()).all(|p| identity(p) == before && fs::read(p).map(|b| b == bytes).unwrap_or(false));
                println!("OPTION_COMMIT_CORE_RECOVERY_LINK=observed kind=load corrupt={corrupt} links={} refused={refused} preserved={preserved}", aliases + 1);
                all_preserved &= refused && preserved;
                if refused && preserved {
                    for link in &links { fs::remove_file(link).unwrap(); }
                    let restored: ConfigLoad<Config2> = load_path_with_status(path.clone());
                    if corrupt {
                        assert_eq!(restored.status, ConfigLoadStatus::Corrupt);
                        assert!(!path.exists());
                        let backup = fs::read_dir(&base).unwrap().next().unwrap().unwrap().path();
                        assert_eq!(fs::read(&backup).unwrap(), bytes);
                        assert_eq!(fs::metadata(&backup).unwrap().mode() & 0o777, 0o600);
                    } else {
                        assert_eq!(restored.status, ConfigLoadStatus::Loaded);
                        assert_eq!(restored.value.options.get("marker").map(String::as_str), Some("retained"));
                        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o640);
                    }
                    println!("OPTION_COMMIT_CORE_RECOVERY_LINK=observed kind=load_control corrupt={corrupt} links=1 functional=true");
                }
            }
        }
        assert!(all_preserved);
    });
}

#[test]
fn core_recovery_hard_links_refuse_before_permission_mutation() {
    use std::os::unix::fs::MetadataExt;
    in_private_process("config::option_tests::core_recovery_hard_links_refuse_before_permission_mutation", |root| {
        let fds = || fs::read_dir("/proc/self/fd").unwrap().count();
        let before_fds = fds();
        let mut all_preserved = true;
        for aliases in [1, 2] {
            let base = root.join(format!("hardener-{aliases}"));
            fs::create_dir(&base).unwrap();
            let path = base.join("recovery.toml");
            fs::write(&path, b"preserved recovery bytes").unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
            let links = (0..aliases).map(|i| base.join(format!("alias-{i}"))).collect::<Vec<_>>();
            for link in &links { fs::hard_link(&path, link).unwrap(); }
            let identity = |p: &Path| fs::metadata(p).map(|m| (m.dev(), m.ino(), m.mode(), m.nlink())).ok();
            let before = identity(&path);
            let refused = (0..16).map(|_| harden_preserved_config_file(&path).is_err()).fold(true, |all, refused| all && refused);
            let preserved = std::iter::once(&path).chain(links.iter()).all(|p| identity(p) == before && fs::read(p).unwrap() == b"preserved recovery bytes");
            println!("OPTION_COMMIT_CORE_RECOVERY_LINK=observed kind=hardener links={} iterations=16 refused={refused} preserved={preserved}", aliases + 1);
            all_preserved &= refused && preserved;
            for link in &links { fs::remove_file(link).unwrap(); }
            harden_preserved_config_file(&path).unwrap();
            assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
            println!("OPTION_COMMIT_CORE_RECOVERY_LINK=observed kind=hardener_control links=1 functional=true");
        }
        let after_fds = fds();
        println!("OPTION_COMMIT_CORE_RECOVERY_LINK=observed kind=handles before={before_fds} after={after_fds}");
        assert_eq!(before_fds, after_fds);
        assert!(all_preserved);
    });
}

#[test]
fn core_recovery_fifo_refuses_and_retires_handles() {
    const TEST: &str = "config::option_tests::core_recovery_fifo_refuses_and_retires_handles";
    const CHILD: &str = "RUSTDESK_CORE_RECOVERY_FIFO_CHILD";
    in_private_process(TEST, |root| {
        use std::os::unix::fs::{FileTypeExt, MetadataExt};
        let path = root.join("recovery-fifo");
        if std::env::var_os(CHILD).is_some() {
            println!("CORE_RECOVERY_FIFO_BEGIN=entered");
            std::io::stdout().flush().unwrap();
            let fds = || fs::read_dir("/proc/self/fd").unwrap().count();
            let before = fds();
            for _ in 0..100 {
                assert!(harden_preserved_config_file(&path).is_err());
            }
            let after = fds();
            println!("OPTION_COMMIT_CORE_RECOVERY_FIFO=observed iterations=100 refused=true fds_before={before} fds_after={after}");
            assert_eq!(after, before);
            return;
        }
        let name = std::ffi::CString::new(std::os::unix::ffi::OsStrExt::as_bytes(path.as_os_str())).unwrap();
        assert_eq!(unsafe { crate::libc::mkfifo(name.as_ptr(), 0o640) }, 0);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        let before = fs::metadata(&path).unwrap();
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([TEST, "--exact", "--color", "never", "--test-threads=1", "--nocapture"])
            .env(CHILD, "1")
            .stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped())
            .spawn().unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        let timed_out = loop {
            if child.try_wait().unwrap().is_some() { break false; }
            if Instant::now() >= deadline { child.kill().unwrap(); break true; }
            std::thread::sleep(Duration::from_millis(10));
        };
        let output = child.wait_with_output().unwrap();
        assert!(output.stdout.len() + output.stderr.len() <= 16384);
        let stdout = String::from_utf8(output.stdout).unwrap();
        let entered = stdout.lines().any(|line| line.contains("CORE_RECOVERY_FIFO_BEGIN=entered"));
        for line in stdout.lines().filter(|line| line.starts_with("OPTION_COMMIT_")) { println!("{line}"); }
        let after = fs::metadata(&path).unwrap();
        let preserved = after.file_type().is_fifo() && (before.dev(), before.ino(), before.mode()) == (after.dev(), after.ino(), after.mode());
        println!("OPTION_COMMIT_CORE_RECOVERY_FIFO=observed child_entered={entered} timed_out={timed_out} child_success={} fifo_preserved={preserved} cleanup=joined", output.status.success());
        assert!(entered && !timed_out && output.status.success() && preserved);
    });
}

#[test]
fn core_recovery_terminal_refuses_without_controlling_tty() {
    in_private_process("config::option_tests::core_recovery_terminal_refuses_without_controlling_tty", |_| {
        use std::os::unix::{ffi::OsStrExt, fs::{MetadataExt, OpenOptionsExt}, io::{AsRawFd, FromRawFd}};
        assert!(unsafe { crate::libc::setsid() } > 0);
        let previous_hup = unsafe { crate::libc::signal(crate::libc::SIGHUP, crate::libc::SIG_IGN) };
        assert_ne!(previous_hup, crate::libc::SIG_ERR);
        let fd = unsafe { crate::libc::posix_openpt(crate::libc::O_RDWR | crate::libc::O_NOCTTY | crate::libc::O_CLOEXEC) };
        assert!(fd >= 0);
        let master = unsafe { fs::File::from_raw_fd(fd) };
        assert_eq!(unsafe { crate::libc::grantpt(master.as_raw_fd()) }, 0);
        assert_eq!(unsafe { crate::libc::unlockpt(master.as_raw_fd()) }, 0);
        let mut name = [0 as crate::libc::c_char; 256];
        assert_eq!(unsafe { crate::libc::ptsname_r(master.as_raw_fd(), name.as_mut_ptr(), name.len()) }, 0);
        let bytes = unsafe { std::ffi::CStr::from_ptr(name.as_ptr()) }.to_bytes();
        let path = Path::new(std::ffi::OsStr::from_bytes(bytes));
        let has_terminal = || fs::OpenOptions::new().read(true)
            .custom_flags(crate::libc::O_NOCTTY | crate::libc::O_NONBLOCK | crate::libc::O_CLOEXEC)
            .open("/dev/tty").is_ok();
        let before = has_terminal();
        let metadata = fs::metadata(path).unwrap();
        let refused = harden_preserved_config_file(path).is_err();
        let after = has_terminal();
        let preserved = metadata.mode() == fs::metadata(path).unwrap().mode();
        drop(master);
        assert_ne!(unsafe { crate::libc::signal(crate::libc::SIGHUP, previous_hup) }, crate::libc::SIG_ERR);
        println!("OPTION_COMMIT_CORE_RECOVERY_TTY=observed refused={refused} terminal_before={before} terminal_after={after} device_mode_preserved={preserved}");
        assert!(refused && !before && !after && preserved);
    });
}

#[test]
fn core_recovery_regular_and_nonregular_preserve_files() {
    in_private_process("config::option_tests::core_recovery_regular_and_nonregular_preserve_files", |root| {
        use std::os::unix::fs::{symlink, MetadataExt};
        let file = root.join("regular-recovery");
        let bytes = b"invalid configuration \xff preserved verbatim";
        fs::write(&file, bytes).unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
        let before = fs::metadata(&file).unwrap();
        for _ in 0..2 { harden_preserved_config_file(&file).unwrap(); }
        let after = fs::metadata(&file).unwrap();
        assert_eq!((after.dev(), after.ino()), (before.dev(), before.ino()));
        assert_eq!(after.mode() & 0o777, 0o600);
        assert_eq!(fs::read(&file).unwrap(), bytes);
        let directory = root.join("recovery-directory");
        fs::create_dir(&directory).unwrap();
        let directory_mode = fs::metadata(&directory).unwrap().mode();
        let socket = root.join("recovery-socket");
        let _listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        let socket_before = fs::metadata(&socket).unwrap();
        let target = root.join("recovery-link-target");
        fs::write(&target, b"unrelated").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o644)).unwrap();
        let link = root.join("recovery-link");
        symlink(&target, &link).unwrap();
        let missing = root.join("absent-recovery");
        for path in [&directory, &socket, &link, &missing] {
            assert!(harden_preserved_config_file(path).is_err());
        }
        assert_eq!(fs::metadata(&directory).unwrap().mode(), directory_mode);
        let socket_after = fs::metadata(&socket).unwrap();
        assert_eq!((socket_before.dev(), socket_before.ino(), socket_before.mode()), (socket_after.dev(), socket_after.ino(), socket_after.mode()));
        assert_eq!(fs::read(&target).unwrap(), b"unrelated");
        assert_eq!(fs::metadata(&target).unwrap().mode() & 0o777, 0o644);
        assert!(fs::symlink_metadata(&link).unwrap().file_type().is_symlink());
        assert!(!missing.exists());
        println!("OPTION_COMMIT_CORE_RECOVERY_FILES=observed regular_bytes_identity_preserved=true regular_mode=600 directory_socket_link_missing_refused=true targets_preserved=true");
    });
}

#[test]
fn core_load_fifo_refuses_and_retires_handles() {
    const TEST: &str = "config::option_tests::core_load_fifo_refuses_and_retires_handles";
    const CHILD: &str = "RUSTDESK_CORE_CONFIG_FIFO_CHILD";
    in_private_process(TEST, |_| {
        use std::os::unix::fs::{FileTypeExt, MetadataExt};
        let file = Config::file_("_core_fifo");
        if std::env::var_os(CHILD).is_some() {
            println!("CORE_LOAD_FIFO_BEGIN=entered");
            std::io::stdout().flush().unwrap();
            let fds = || fs::read_dir("/proc/self/fd").unwrap().count();
            let before = fds();
            for _ in 0..100 {
                let loaded: ConfigLoad<Config> = load_path_with_status(file.clone());
                assert_eq!(loaded.status, ConfigLoadStatus::TransientError);
                assert_eq!(loaded.value, Config::default());
            }
            let after = fds();
            assert_eq!(after, before);
            println!("OPTION_COMMIT_CORE_LOAD_FIFO=observed kind=reader iterations=100 refused=true fds_before={before} fds_after={after}");
            return;
        }
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        let name = std::ffi::CString::new(std::os::unix::ffi::OsStrExt::as_bytes(file.as_os_str())).unwrap();
        assert_eq!(unsafe { crate::libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        let before = fs::metadata(&file).unwrap();
        assert!(before.file_type().is_fifo());
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([TEST, "--exact", "--color", "never", "--test-threads=1", "--nocapture"])
            .env(CHILD, "1")
            .stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped())
            .spawn().unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        let timed_out = loop {
            if child.try_wait().unwrap().is_some() { break false; }
            if Instant::now() >= deadline { child.kill().unwrap(); break true; }
            std::thread::sleep(Duration::from_millis(10));
        };
        let output = child.wait_with_output().unwrap();
        assert!(output.stdout.len() + output.stderr.len() <= 16384);
        let stdout = String::from_utf8(output.stdout).unwrap();
        let entered = stdout.lines().any(|line| line.contains("CORE_LOAD_FIFO_BEGIN=entered"));
        for line in stdout.lines().filter(|line| line.starts_with("OPTION_COMMIT_")) { println!("{line}"); }
        let after = fs::metadata(&file).unwrap();
        let preserved = after.file_type().is_fifo() && (before.dev(), before.ino(), before.mode()) == (after.dev(), after.ino(), after.mode());
        println!("OPTION_COMMIT_CORE_LOAD_FIFO=observed kind=parent child_entered={entered} timed_out={timed_out} child_success={} fifo_preserved={preserved} cleanup=joined", output.status.success());
        assert!(entered && !timed_out && output.status.success() && preserved);
    });
}

#[test]
#[cfg(target_arch = "x86_64")]
fn config_read_admits_metadata_before_io_open() {
    use std::os::unix::{ffi::OsStrExt, fs::{symlink, MetadataExt, OpenOptionsExt}, io::{AsRawFd, FromRawFd}};

    in_private_process("config::option_tests::config_read_admits_metadata_before_io_open", |root| {
        let regular = root.join("preopen-regular");
        fs::write(&regular, b"marker = 'retained'\n").unwrap();
        fs::set_permissions(&regular, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(read_config_record(&regular).unwrap().bytes, b"marker = 'retained'\n");
        let fifo = root.join("preopen-fifo");
        let name = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { crate::libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        let directory = root.join("preopen-directory");
        fs::create_dir(&directory).unwrap();
        let socket = root.join("preopen-socket");
        let _listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        let link = root.join("preopen-link");
        symlink(&regular, &link).unwrap();
        let linked = root.join("preopen-hardlink");
        fs::write(&linked, b"unchanged").unwrap();
        fs::hard_link(&linked, root.join("preopen-alias")).unwrap();
        let shared = root.join("preopen-shared");
        fs::write(&shared, b"unchanged").unwrap();
        fs::set_permissions(&shared, fs::Permissions::from_mode(0o620)).unwrap();
        // The immutable guest image provides the foreign-owned regular-file control.
        assert_eq!(fs::metadata("/etc/passwd").unwrap().uid(), 0);
        let master = unsafe { crate::libc::posix_openpt(crate::libc::O_RDWR | crate::libc::O_NOCTTY | crate::libc::O_CLOEXEC) };
        assert!(master >= 0);
        let master = unsafe { fs::File::from_raw_fd(master) };
        assert_eq!(unsafe { crate::libc::grantpt(master.as_raw_fd()) }, 0);
        assert_eq!(unsafe { crate::libc::unlockpt(master.as_raw_fd()) }, 0);
        let mut terminal = [0 as crate::libc::c_char; 256];
        assert_eq!(unsafe { crate::libc::ptsname_r(master.as_raw_fd(), terminal.as_mut_ptr(), terminal.len()) }, 0);
        let terminal = PathBuf::from(std::ffi::OsStr::from_bytes(unsafe { std::ffi::CStr::from_ptr(terminal.as_ptr()) }.to_bytes()));
        let cases = [
            ("fifo", fifo, io::ErrorKind::InvalidInput),
            ("directory", directory, io::ErrorKind::InvalidInput),
            ("socket", socket, io::ErrorKind::InvalidInput),
            ("symlink", link, io::ErrorKind::InvalidInput),
            ("hardlink", linked, io::ErrorKind::InvalidInput),
            ("shared", shared, io::ErrorKind::PermissionDenied),
            ("foreign", PathBuf::from("/etc/passwd"), io::ErrorKind::PermissionDenied),
            ("terminal", terminal, io::ErrorKind::InvalidInput),
        ];
        let identity = |path: &Path| {
            let m = fs::symlink_metadata(path).unwrap();
            (m.dev(), m.ino(), m.uid(), m.gid(), m.mode(), m.nlink(), m.len())
        };
        let original = cases.iter().map(|(_, path, _)| identity(path)).collect::<Vec<_>>();
        let handles = || fs::read_dir("/proc/self/fd").unwrap().count();
        let before = handles();
        let statement = |code, k| crate::libc::sock_filter { code: code as u16, jt: 0, jf: 0, k };
        let jump = |code, k, jt, jf| crate::libc::sock_filter { code: code as u16, jt, jf, k };
        let load = crate::libc::BPF_LD | crate::libc::BPF_W | crate::libc::BPF_ABS;
        let equal = crate::libc::BPF_JMP | crate::libc::BPF_JEQ | crate::libc::BPF_K;
        let bits = crate::libc::BPF_JMP | crate::libc::BPF_JSET | crate::libc::BPF_K;
        let ret = crate::libc::BPF_RET | crate::libc::BPF_K;
        let mut filter = [
            statement(load, 4),
            jump(equal, 0xc000003e, 1, 0),
            statement(ret, crate::libc::SECCOMP_RET_KILL_PROCESS),
            statement(load, 0),
            jump(bits, 0x40000000, 0, 1),
            statement(ret, crate::libc::SECCOMP_RET_KILL_PROCESS),
            jump(equal, crate::libc::SYS_openat as u32, 3, 0),
            jump(equal, crate::libc::SYS_open as u32, 4, 0),
            jump(equal, crate::libc::SYS_openat2 as u32, 5, 0),
            statement(ret, crate::libc::SECCOMP_RET_ALLOW),
            statement(load, 32),
            statement(crate::libc::BPF_JMP | crate::libc::BPF_JA, 1),
            statement(load, 24),
            jump(bits, (crate::libc::O_PATH | crate::libc::O_DIRECTORY) as u32, 1, 0),
            statement(ret, crate::libc::SECCOMP_RET_ERRNO | crate::libc::EOWNERDEAD as u32),
            statement(ret, crate::libc::SECCOMP_RET_ALLOW),
        ];
        let program = crate::libc::sock_fprog { len: filter.len() as u16, filter: filter.as_mut_ptr() };
        assert_eq!(unsafe { crate::libc::prctl(crate::libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) }, 0);
        assert_eq!(unsafe { crate::libc::syscall(crate::libc::SYS_seccomp, crate::libc::SECCOMP_SET_MODE_FILTER, crate::libc::SECCOMP_FILTER_FLAG_TSYNC, &program) }, 0);
        // Prove the filter distinguishes metadata acquisition from a real I/O open.
        assert_eq!(fs::File::open(&regular).unwrap_err().raw_os_error(), Some(crate::libc::EOWNERDEAD));
        let metadata = fs::OpenOptions::new().read(true).custom_flags(crate::libc::O_PATH | crate::libc::O_NOFOLLOW).open(&regular).unwrap();
        assert!(metadata.metadata().unwrap().is_file());
        drop(metadata);
        let mut admitted_before_io = true;
        for ((kind, path, expected), original) in cases.iter().zip(&original) {
            for attempt in 0..2 {
                let error = read_config_record(path).err().expect("unsafe configuration must refuse");
                let refused_before_io = error.kind() == *expected && error.raw_os_error() != Some(crate::libc::EOWNERDEAD);
                let preserved = identity(path) == *original;
                println!("OPTION_COMMIT_READ_PREOPEN=observed kind={kind} attempt={attempt} refused_before_io={refused_before_io} preserved={preserved}");
                admitted_before_io &= refused_before_io && preserved;
            }
        }
        let reopen_refused = read_config_record(&regular).err().unwrap().raw_os_error() == Some(crate::libc::EOWNERDEAD);
        let after = handles();
        println!("OPTION_COMMIT_READ_PREOPEN=observed kind=controls metadata_allowed=true io_canary_denied=true regular_reopen_refused={reopen_refused} fds_before={before} fds_after={after}");
        assert!(admitted_before_io && reopen_refused);
        assert_eq!(before, after);
    });
}

#[test]
fn core_load_regular_data_and_read_failures_keep_status() {
    use std::os::unix::fs::MetadataExt;
    in_private_process("config::option_tests::core_load_regular_data_and_read_failures_keep_status", |root| {
        let path = Config::file_("");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let expected = Config {
            id: "legacy-id".into(), enc_id: "stored-id".into(),
            password: "storage".into(), password_prs: "prs".into(),
            salt: "sält".into(), key_pair: (vec![1, 2], vec![3, 4]),
        };
        let literal = "id = \"legacy\\u002did\"\r\nenc_id = 'stored-id'\r\npassword = 'storage'\r\npassword_prs = 'prs'\r\nsalt = 'sält'\r\nkey_pair = [[1, 2], [3, 4]]\r\nfuture = 'ignored'\r\n";
        for source in [toml::to_string_pretty(&expected).unwrap().into_bytes(), literal.as_bytes().to_vec()] {
            fs::write(&path, &source).unwrap();
            let before = fs::metadata(&path).unwrap();
            for _ in 0..2 {
                let loaded: ConfigLoad<Config> = load_path_with_status(path.clone());
                assert_eq!(loaded.status, ConfigLoadStatus::Loaded);
                assert_eq!(loaded.value, expected);
                assert_eq!(Config::load_::<Config>(""), expected);
            }
            let after = fs::metadata(&path).unwrap();
            assert_eq!((before.ino(), before.mode()), (after.ino(), after.mode()));
            assert_eq!(fs::read(&path).unwrap(), source);
        }
        let invalid = b"password = 'invalid \xff'";
        fs::write(&path, invalid).unwrap();
        let before = fs::metadata(&path).unwrap();
        for _ in 0..2 {
            let loaded: ConfigLoad<Config> = load_path_with_status(path.clone());
            assert_eq!(loaded.status, ConfigLoadStatus::TransientError);
            assert_eq!(loaded.value, Config::default());
        }
        let after = fs::metadata(&path).unwrap();
        assert_eq!((before.ino(), before.mode()), (after.ino(), after.mode()));
        assert_eq!(fs::read(&path).unwrap(), invalid);
        assert_eq!(fs::read_dir(path.parent().unwrap()).unwrap().count(), 1);
        fs::write(&path, literal).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap();
        assert_eq!(fs::read(&path).unwrap_err().kind(), io::ErrorKind::PermissionDenied);
        let denied: ConfigLoad<Config> = load_path_with_status(path.clone());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(denied.status, ConfigLoadStatus::TransientError);
        let retry: ConfigLoad<Config> = load_path_with_status(path.clone());
        assert_eq!(retry.status, ConfigLoadStatus::Loaded);
        assert_eq!(retry.value, expected);
        assert_eq!(fs::read(&path).unwrap(), literal.as_bytes());
        let missing = root.join("absent/nested/config.toml");
        let first: ConfigLoad<Config> = load_path_with_status(missing);
        assert_eq!(first.status, ConfigLoadStatus::NotFound);
        assert!(!root.join("absent").exists());
        println!("OPTION_COMMIT_CORE_LOAD_CONTROL=pass current_round_trip=true legacy_literals=true repeats=2 bytes_identity_preserved=true utf8_transient_preserved=true eacces_retry=true missing_no_create=true");
    });
}

#[test]
fn config_initial_load_keeps_credentials_out_of_trace_logs() {
    use std::os::unix::fs::MetadataExt;

    in_private_process("config::option_tests::config_initial_load_keeps_credentials_out_of_trace_logs", |_| {
        struct CapturedLogs(Mutex<Vec<(log::Level, String)>>);
        impl log::Log for CapturedLogs {
            fn enabled(&self, _: &log::Metadata<'_>) -> bool { true }
            fn log(&self, record: &log::Record<'_>) {
                self.0.lock().unwrap().push((record.level(), record.args().to_string()));
            }
            fn flush(&self) {}
        }
        static LOGS: CapturedLogs = CapturedLogs(Mutex::new(Vec::new()));

        let path = Config::file_("");
        let original = Config {
            id: "fixture-load-identity".into(),
            enc_id: "fixture-load-encoded-identity".into(),
            password: "fixture-load-password".into(),
            password_prs: "fixture-load-prs".into(),
            salt: "fixture-load-salt".into(),
            key_pair: (vec![11, 12, 13], vec![21, 22, 23]),
        };
        store_path(path.clone(), &original).unwrap();
        let bytes = fs::read(&path).unwrap();
        let before = fs::metadata(&path).unwrap();
        assert_eq!(log::STATIC_MAX_LEVEL, log::LevelFilter::Trace);
        log::set_logger(&LOGS).unwrap();
        log::set_max_level(log::LevelFilter::Trace);
        log::trace!(target: "hbb_common::config", "config-load-capture-before");

        for _ in 0..2 {
            assert_eq!(Config::load_::<Config>(""), original);
        }
        let after = fs::metadata(&path).unwrap();
        assert_eq!(fs::read(&path).unwrap(), bytes);
        assert_eq!((after.ino(), after.mode()), (before.ino(), before.mode()));
        let absent = Config::file_("_trace_absent");
        assert_eq!(Config::load_::<Config>("_trace_absent"), Config::default());
        assert!(!absent.exists());
        let denied = Config::file_("_trace_directory");
        fs::create_dir(&denied).unwrap();
        assert_eq!(Config::load_::<Config>("_trace_directory"), Config::default());
        assert!(denied.is_dir());
        log::trace!(target: "hbb_common::config", "config-load-capture-after");

        let logs = LOGS.0.lock().unwrap();
        assert!(logs.len() <= 32);
        let controls = ["config-load-capture-before", "config-load-capture-after"]
            .iter().all(|control| logs.iter().any(|(_, message)| message == control));
        let error_visible = logs.iter().any(|(level, _)| *level == log::Level::Error);
        let exposed_fields = [
            &original.id, &original.enc_id, &original.password,
            &original.password_prs, &original.salt,
        ].iter().filter(|field| logs.iter().any(|(_, message)| message.contains(field.as_str()))).count();
        println!("OPTION_COMMIT_CONFIG_LOAD_LOG=observed trace_controls={controls} error_visible={error_visible} exposed_fields={exposed_fields} healthy_reads=2 source_preserved=true missing_no_create=true directory_preserved=true");
        assert!(controls && error_visible);
        assert_eq!(exposed_fields, 0, "configuration fields reached the log sink");
    });
}

#[test]
fn linux_config_read_links_are_errors_without_source_changes() {
    use std::os::unix::fs::{symlink, MetadataExt};
    in_private_process("config::option_tests::linux_config_read_links_are_errors_without_source_changes", |root| {
        let mut all_refused = true;
        for kind in ["file", "dangling_file", "parent", "ancestor", "dangling_parent"] {
            let base = root.join(kind);
            fs::create_dir(&base).unwrap();
            let directory_link = matches!(kind, "parent" | "ancestor" | "dangling_parent");
            let target = base.join("target");
            let link = base.join("selected");
            let suffix = if kind == "ancestor" { "child/record.toml" } else { "record.toml" };
            let (path, target_file) = if directory_link {
                (link.join(suffix), target.join(suffix))
            } else { (link.clone(), target.clone()) };
            let dangling = kind.starts_with("dangling");
            if !dangling {
                fs::create_dir_all(target_file.parent().unwrap()).unwrap();
                fs::write(&target_file, b"answer = 7\n").unwrap();
            }
            symlink(&target, &link).unwrap();
            let before = fs::symlink_metadata(&link).unwrap();
            let mut refused = true;
            for _ in 0..2 {
                refused &= matches!(read_config_file::<toml::Value>(&path), Err(ConfigReadFailure::Unreadable));
            }
            let after = fs::symlink_metadata(&link).unwrap();
            let preserved = before.ino() == after.ino() && before.mode() == after.mode()
                && after.file_type().is_symlink() && fs::read_link(&link).unwrap() == target
                && if dangling { !target.exists() } else { fs::read(&target_file).unwrap() == b"answer = 7\n" };
            println!("OPTION_COMMIT_CONFIG_READ_LINK=observed kind={kind} refused={refused} preserved={preserved}");
            all_refused &= refused && preserved;
        }
        assert!(all_refused);
    });
}

#[test]
fn linux_config_read_peer_views_and_mutation_refuse_linked_source() {
    use std::os::unix::fs::symlink;
    in_private_process("config::option_tests::linux_config_read_peer_views_and_mutation_refuse_linked_source", |root| {
        let id = "linked-peer-source";
        let path = PeerConfig::path(id);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let target = root.join("outside-peer.toml");
        let source = b"[options]\nalias = 'linked source'\n[info]\nhostname = 'host'\nplatform = 'Linux'\n";
        fs::write(&target, source).unwrap();
        symlink(&target, &path).unwrap();
        let mut refused = true;
        for _ in 0..2 {
            refused &= [
                PeerConfig::read_option(id, "alias").is_err(),
                PeerConfig::ui_info_json(id).is_err(),
                PeerConfig::credential_status(id).is_err(),
                PeerConfig::load_list_info(path.clone()).is_err(),
                PeerConfig::load_for_write(id).is_err(),
            ].iter().all(|result| *result);
            let all = vec![(id.into(), SystemTime::UNIX_EPOCH, path.clone())];
            let (peers, next) = PeerConfig::batch_peers(&all, 0, None);
            refused &= peers.is_empty() && next == 1;
        }
        let mutation_refused = PeerConfig::set_option(id, "alias", "after".into()).is_err();
        let preserved = fs::read(&target).unwrap() == source
            && fs::symlink_metadata(&path).unwrap().file_type().is_symlink();
        println!("OPTION_COMMIT_CONFIG_READ_PEER=observed views_refused={refused} mutation_refused={mutation_refused} source_preserved={preserved}");
        fs::remove_file(&path).unwrap();
        fs::write(&path, source).unwrap();
        PeerConfig::set_option(id, "alias", "after".into()).unwrap();
        assert_eq!(PeerConfig::read_option(id, "alias").unwrap(), "after");
        assert_eq!(fs::read(target).unwrap(), source);
        assert!(refused && mutation_refused && preserved);
    });
}

#[test]
fn linux_config_read_invalid_paths_do_not_become_missing_defaults() {
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    in_private_process("config::option_tests::linux_config_read_invalid_paths_do_not_become_missing_defaults", |root| {
        let missing = root.join("invalid-absent");
        let long = missing.join("component/".repeat(500)).join("record.toml");
        assert!(long.as_os_str().as_bytes().len() >= crate::libc::PATH_MAX as usize);
        let nul = missing.join(std::ffi::OsString::from_vec(b"invalid\0name".to_vec()));
        let parent = missing.join("../record.toml");
        let slash = missing.join("record.toml/");
        let dot = missing.join("record.toml/.");
        let mut all_refused = true;
        for (kind, path) in [("long", long), ("nul", nul), ("parent", parent), ("slash", slash), ("dot", dot)] {
            let refused = matches!(read_config_file::<toml::Value>(&path), Err(ConfigReadFailure::Unreadable));
            println!("OPTION_COMMIT_CONFIG_READ_PATH=observed kind={kind} refused={refused}");
            all_refused &= refused;
        }
        assert!(!missing.exists());
        assert!(all_refused);
    });
}

#[test]
fn linux_config_read_regular_missing_and_search_only_controls() {
    in_private_process("config::option_tests::linux_config_read_regular_missing_and_search_only_controls", |root| {
        let ancestor = root.join("search-only");
        let parent = ancestor.join("config");
        fs::create_dir_all(&parent).unwrap();
        let path = parent.join("record.toml");
        fs::write(&path, b"answer = 7\n").unwrap();
        fs::set_permissions(&ancestor, fs::Permissions::from_mode(0o111)).unwrap();
        let healthy = |path: &Path| match read_config_file::<toml::Value>(path) {
            Ok(Some(value)) => value.get("answer").and_then(toml::Value::as_integer) == Some(7),
            _ => false,
        };
        let absolute = healthy(&path);
        let previous = std::env::current_dir().unwrap();
        std::env::set_current_dir(root).unwrap();
        let relative = healthy(Path::new("./search-only/config/record.toml"));
        std::env::set_current_dir(previous).unwrap();
        fs::set_permissions(&ancestor, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(absolute && relative);
        let missing = root.join("absent/nested/record.toml");
        assert!(matches!(read_config_file::<toml::Value>(&missing), Ok(None)));
        assert!(!root.join("absent").exists());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap();
        assert_eq!(fs::read(&path).unwrap_err().kind(), io::ErrorKind::PermissionDenied);
        let denied = matches!(read_config_file::<toml::Value>(&path), Err(ConfigReadFailure::Unreadable));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(denied && healthy(&path));
        assert_eq!(fs::read(path).unwrap(), b"answer = 7\n");
        println!("OPTION_COMMIT_CONFIG_READ_CONTROL=pass absolute=true relative=true search_only=true missing_no_create=true eacces=true");
    });
}

#[cfg(target_os = "linux")]
fn config_parent_acl(directory: &Path, mask: u16) -> Vec<u8> {
    use std::os::unix::io::AsRawFd;
    // Linux UAPI posix_acl_xattr: version, then little-endian tag/permissions/id entries.
    let mut acl = 2u32.to_le_bytes().to_vec();
    for (tag, permissions, id) in [
        (1u16, 7u16, u32::MAX), (2, 7, 1001), (4, 0, u32::MAX),
        (16, mask, u32::MAX), (32, 0, u32::MAX),
    ] {
        acl.extend_from_slice(&tag.to_le_bytes());
        acl.extend_from_slice(&permissions.to_le_bytes());
        acl.extend_from_slice(&id.to_le_bytes());
    }
    let directory = fs::File::open(directory).unwrap();
    let name = b"system.posix_acl_access\0";
    assert_eq!(unsafe { crate::libc::fsetxattr(directory.as_raw_fd(), name.as_ptr().cast(), acl.as_ptr().cast(), acl.len(), 0) }, 0, "{}", io::Error::last_os_error());
    let mut observed = vec![0; acl.len()];
    assert_eq!(unsafe { crate::libc::fgetxattr(directory.as_raw_fd(), name.as_ptr().cast(), observed.as_mut_ptr().cast(), observed.len()) }, acl.len() as isize);
    assert_eq!(observed, acl);
    acl
}

#[cfg(target_os = "linux")]
fn exercise_config_parent_refusal(modes: &[u32], acl: bool) {
    use std::{cell::Cell, os::unix::fs::MetadataExt};
    let path = Config2::file();
    let parent = path.parent().unwrap();
    fs::create_dir_all(parent).unwrap();
    let mut all_refused = true;
    for mode in modes {
        for present in [false, true] {
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
            if path.exists() { fs::remove_file(&path).unwrap(); }
            if present {
                fs::write(&path, b"original configuration").unwrap();
                fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            }
            if acl { config_parent_acl(parent, 7); }
            else { fs::set_permissions(parent, fs::Permissions::from_mode(*mode)).unwrap(); }
            let before = fs::metadata(&path).ok();
            let directory = fs::metadata(parent).unwrap();
            assert_eq!(directory.mode() & 0o7777, *mode);
            let names = || {
                let mut names = fs::read_dir(parent).unwrap().map(|e| e.unwrap().file_name()).collect::<Vec<_>>();
                names.sort(); names
            };
            let original_names = names();
            let mut refused = true;
            let mut preserved = true;
            for _ in 0..2 {
                let entered = Cell::new(false);
                let result = store_config_bytes_transaction_unix(
                    &path, b"replacement configuration", ConfigStoreFault::None,
                    &|_| panic!("directory refusal must precede publication"),
                    &|_, _, _| { entered.set(true); Ok(()) },
                );
                refused &= result.is_err() && !entered.get();
                preserved &= match &before {
                    Some(before) => fs::metadata(&path).map(|after| after.ino() == before.ino() && after.mode() == before.mode()).unwrap_or(false)
                        && fs::read(&path).map(|bytes| bytes == b"original configuration").unwrap_or(false),
                    None => !path.exists(),
                };
                let after = fs::metadata(parent).unwrap();
                preserved &= after.ino() == directory.ino() && after.mode() == directory.mode() && names() == original_names;
            }
            println!("OPTION_COMMIT_CONFIG_PARENT=observed acl={acl} mode={mode:o} present={present} refused={refused} preserved={preserved}");
            all_refused &= refused && preserved;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
            store_config_bytes_transaction(&path, b"legitimate retry", ConfigStoreFault::None).unwrap();
            assert_eq!(fs::read(&path).unwrap(), b"legitimate retry");
            assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
        }
    }
    assert!(all_refused);
}

#[cfg(target_os = "linux")]
#[test]
fn config_parent_writable_modes_refuse_without_mutation() {
    in_private_process("config::option_tests::config_parent_writable_modes_refuse_without_mutation", |_| {
        exercise_config_parent_refusal(&[0o730, 0o703, 0o770, 0o777, 0o1777, 0o2770], false);
    });
}

#[cfg(target_os = "linux")]
#[test]
fn config_parent_acl_write_mask_refuses_without_mutation() {
    in_private_process("config::option_tests::config_parent_acl_write_mask_refuses_without_mutation", |_| {
        exercise_config_parent_refusal(&[0o770], true);
    });
}

#[cfg(target_os = "linux")]
#[test]
fn config_parent_safe_modes_and_masked_acl_remain_functional() {
    use std::os::unix::{fs::MetadataExt, io::AsRawFd};
    in_private_process("config::option_tests::config_parent_safe_modes_and_masked_acl_remain_functional", |_| {
        let path = Config2::file();
        let parent = path.parent().unwrap();
        fs::create_dir_all(parent).unwrap();
        for mode in [0o700, 0o750, 0o755, 0o2750] {
            fs::set_permissions(parent, fs::Permissions::from_mode(mode)).unwrap();
            store_config_bytes_transaction(&path, b"healthy configuration", ConfigStoreFault::None).unwrap();
            assert_eq!(fs::read(&path).unwrap(), b"healthy configuration");
            assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
            assert_eq!(fs::metadata(parent).unwrap().mode() & 0o7777, mode);
        }
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
        let acl = config_parent_acl(parent, 5);
        assert_eq!(fs::metadata(parent).unwrap().mode() & 0o777, 0o750);
        store_config_bytes_transaction(&path, b"masked ACL configuration", ConfigStoreFault::None).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"masked ACL configuration");
        let directory = fs::File::open(parent).unwrap();
        let mut observed = vec![0; acl.len()];
        assert_eq!(unsafe { crate::libc::fgetxattr(directory.as_raw_fd(), b"system.posix_acl_access\0".as_ptr().cast(), observed.as_mut_ptr().cast(), observed.len()) }, acl.len() as isize);
        assert_eq!(observed, acl);
        println!("OPTION_COMMIT_CONFIG_PARENT_CONTROL=pass modes=4 masked_named_user_acl=preserved file_mode=600");
    });
}

fn exercise_config_temp_ownership(kind: &str) {
    use std::{cell::RefCell, os::unix::{ffi::OsStrExt, fs::MetadataExt}};
    let path = Config2::file();
    let parent = path.parent().unwrap();
    fs::create_dir_all(parent).unwrap();
    let old = b"original config bytes";
    let next = b"new config bytes";
    if kind == "publication_failure" {
        fs::create_dir(&path).unwrap();
        fs::write(path.join("preserved"), old).unwrap();
        let probe = parent.join("native-probe");
        fs::write(&probe, b"probe").unwrap();
        assert_eq!(fs::rename(&probe, &path).unwrap_err().raw_os_error(), Some(crate::libc::EISDIR));
        fs::remove_file(probe).unwrap();
    } else {
        fs::write(&path, old).unwrap();
    }
    let temporary = RefCell::new(None);
    let relocated = parent.join("relocated-owned-temp");
    let result = store_config_bytes_transaction_unix(
        &path, next, ConfigStoreFault::None,
        &|_| panic!("refusal must precede publication"),
        &|_, name, source| {
            let named = parent.join(std::ffi::OsStr::from_bytes(name.to_bytes()));
            assert_eq!(fs::read(&named).unwrap(), next);
            match kind {
                "substitution" => {
                    fs::remove_file(&named)?;
                    fs::write(&named, b"foreign temporary entry")?;
                    assert_eq!(source.metadata()?.nlink(), 0);
                }
                "publication_failure" => {
                    fs::rename(&named, &relocated)?;
                    fs::write(&named, b"foreign temporary entry")?;
                    assert_eq!(source.metadata()?.nlink(), 1);
                }
                "hardlink" => {
                    fs::hard_link(&named, &relocated)?;
                    assert_eq!(source.metadata()?.nlink(), 2);
                }
                _ => panic!("unknown test scenario"),
            }
            *temporary.borrow_mut() = Some(named);
            Ok(())
        },
    );
    let temporary = temporary.into_inner().unwrap();
    let target_preserved = if kind == "publication_failure" {
        path.is_dir() && fs::read(path.join("preserved")).unwrap() == old
    } else {
        fs::read(&path).unwrap() == old
    };
    let unrelated_preserved = if kind == "hardlink" {
        fs::read(&relocated).unwrap() == next
    } else {
        fs::read(&temporary).map(|v| v == b"foreign temporary entry").unwrap_or(false)
    };
    println!("OPTION_COMMIT_CONFIG_TEMP=observed kind={kind} refused={} target_preserved={target_preserved} unrelated_preserved={unrelated_preserved}", result.is_err());
    assert!(result.is_err() && target_preserved && unrelated_preserved);
}

#[test]
fn config_temp_substitution_refuses_foreign_publication() {
    in_private_process("config::option_tests::config_temp_substitution_refuses_foreign_publication", |_| {
        exercise_config_temp_ownership("substitution");
    });
}

#[test]
fn config_temp_failed_publication_cannot_delete_a_replacement_entry() {
    in_private_process("config::option_tests::config_temp_failed_publication_cannot_delete_a_replacement_entry", |_| {
        exercise_config_temp_ownership("publication_failure");
    });
}

#[test]
fn config_temp_link_count_change_refuses_publication() {
    in_private_process("config::option_tests::config_temp_link_count_change_refuses_publication", |_| {
        exercise_config_temp_ownership("hardlink");
    });
}

#[test]
fn config_temp_special_modes_refuse_publication_and_allow_repair() {
    use std::{cell::RefCell, os::unix::{ffi::OsStrExt, fs::MetadataExt}};

    in_private_process("config::option_tests::config_temp_special_modes_refuse_publication_and_allow_repair", |_| {
        let config = Config2::file();
        let parent = config.parent().unwrap();
        fs::create_dir_all(parent).unwrap();
        let fds = || fs::read_dir("/proc/self/fd").unwrap().count();
        let before_fds = fds();
        let mut all_refused = true;
        for replacement in [false, true] {
            for special in 1..=7 {
                let mode = 0o600 | (special << 9);
                let path = parent.join(format!("mode-{replacement}-{special}.toml"));
                if replacement {
                    fs::write(&path, b"original config bytes").unwrap();
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
                }
                let original = fs::metadata(&path).ok();
                let temporary = RefCell::new(None);
                let result = store_config_bytes_transaction_unix(
                    &path, b"requested config bytes", ConfigStoreFault::None,
                    &|_| panic!("mode refusal must precede publication"),
                    &|_, name, source| {
                        source.set_permissions(fs::Permissions::from_mode(mode))?;
                        let metadata = source.metadata()?;
                        assert_eq!(metadata.mode() & 0o7777, mode);
                        assert_eq!(metadata.gid(), unsafe { crate::libc::getegid() });
                        let named = parent.join(std::ffi::OsStr::from_bytes(name.to_bytes()));
                        *temporary.borrow_mut() = Some((named, metadata.dev(), metadata.ino()));
                        Ok(())
                    },
                );
                let (temporary, device, inode) = temporary.into_inner().unwrap();
                let target_preserved = match original {
                    Some(before) => fs::metadata(&path).map(|after| {
                        (after.dev(), after.ino(), after.mode(), after.nlink())
                            == (before.dev(), before.ino(), before.mode(), before.nlink())
                            && fs::read(&path).unwrap() == b"original config bytes"
                    }).unwrap_or(false),
                    None => matches!(fs::symlink_metadata(&path),
                        Err(error) if error.kind() == io::ErrorKind::NotFound),
                };
                let staged_preserved = fs::metadata(&temporary).map(|after| {
                    (after.dev(), after.ino()) == (device, inode)
                        && after.mode() & 0o7777 == mode && after.nlink() == 1
                        && fs::read(&temporary).unwrap() == b"requested config bytes"
                }).unwrap_or(false);
                let published_special = fs::metadata(&path).map(|after| {
                    after.mode() & 0o7000 == mode & 0o7000
                        && fs::read(&path).unwrap() == b"requested config bytes"
                }).unwrap_or(false);
                println!("OPTION_COMMIT_TEMP_MODE=observed replacement={replacement} mode={mode:04o} refused={} target_preserved={target_preserved} staged_preserved={staged_preserved} published_special={published_special}", result.is_err());
                all_refused &= result.is_err() && target_preserved && staged_preserved;
                if temporary.exists() {
                    let retained = fs::metadata(&temporary).unwrap();
                    assert_eq!((retained.dev(), retained.ino()), (device, inode));
                    fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600)).unwrap();
                    fs::remove_file(&temporary).unwrap();
                }
                store_config_bytes_transaction(&path, b"healthy retry", ConfigStoreFault::None).unwrap();
                assert_eq!(fs::read(&path).unwrap(), b"healthy retry");
                assert_eq!(fs::metadata(&path).unwrap().mode() & 0o7777, 0o600);
                assert!(!temporary.exists());
                println!("OPTION_COMMIT_TEMP_MODE=retry replacement={replacement} mode={mode:04o} saved=true exact_mode=true temporary_retired=true");
            }
        }
        let after_fds = fds();
        println!("OPTION_COMMIT_TEMP_MODE=handles before={before_fds} after={after_fds}");
        assert_eq!(before_fds, after_fds);
        assert!(all_refused);
    });
}

fn exercise_peer_projection_types(kind: &str, id: &str, cases: &[&str]) {
    use std::os::unix::fs::MetadataExt;
    let path = PeerConfig::path(id);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let global = Config::file_("");
    let global_source = b"password = [private-projection-global\n";
    fs::write(&global, global_source).unwrap();
    let mut all_refused = true;
    for (case, source) in cases.iter().enumerate() {
        fs::write(&path, source).unwrap();
        let before = fs::metadata(&path).unwrap();
        let names = || {
            let mut names = fs::read_dir(path.parent().unwrap()).unwrap()
                .map(|e| e.unwrap().file_name()).collect::<Vec<_>>();
            names.sort(); names
        };
        let original_names = names();
        let mut refused = true;
        let mut batch_ok = true;
        for _ in 0..2 {
            let result = match kind {
                "options" => PeerConfig::read_option(id, "alias").map(|_| ()),
                "ui" => PeerConfig::ui_info_json(id).map(|_| ()),
                "list" => PeerConfig::load_list_info(path.clone()).map(|_| ()),
                _ => panic!("unknown test view"),
            };
            if let Err(error) = &result {
                assert!(!format!("{error:?}").contains("private-projection"));
            }
            refused &= result.is_err();
            if kind == "list" {
                let all = vec![(id.into(), SystemTime::UNIX_EPOCH, path.clone())];
                let (peers, next) = PeerConfig::batch_peers(&all, 0, None);
                batch_ok &= peers.is_empty() && next == 1;
            }
        }
        let after = fs::metadata(&path).unwrap();
        let preserved = fs::read(&path).unwrap() == source.as_bytes()
            && (before.dev(), before.ino(), before.permissions().mode())
                == (after.dev(), after.ino(), after.permissions().mode())
            && names() == original_names && fs::read(&global).unwrap() == global_source;
        println!("OPTION_COMMIT_PEER_VIEW_SCHEMA=observed kind={kind} case={case} refused={refused} batch_ok={batch_ok} preserved={preserved}");
        all_refused &= refused && batch_ok && preserved;
    }
    let healthy = match kind {
        "options" => "password_prs = {private = 'ignored'}\ninfo = 42\nport_forwards = false\ntransfer = 42\n[options]\nalias = 'visible alias'\n",
        "ui" => "password_prs = {private = 'ignored'}\noptions = 42\ntransfer = 42\nport_forwards = [[8000, 'destination', 80]]\n[info]\nhostname = 'host'\nusername = 42\nplatform = []\n",
        "list" => "password_prs = {private = 'ignored'}\nport_forwards = false\ntransfer = 42\n[info]\nusername = 'owner'\nhostname = 'host'\nplatform = 'Linux'\n[options]\nalias = 'visible alias'\nunrelated = 42\n",
        _ => panic!("unknown test view"),
    };
    fs::write(&path, healthy).unwrap();
    match kind {
        "options" => assert_eq!(PeerConfig::read_option(id, "alias").unwrap(), "visible alias"),
        "ui" => {
            let value: serde_json::Value = serde_json::from_str(&PeerConfig::ui_info_json(id).unwrap()).unwrap();
            assert_eq!(value, serde_json::json!({"info": {"hostname": "host"}, "port_forwards": [[8000, "destination", 80]]}));
        }
        "list" => {
            let all = vec![(id.into(), SystemTime::UNIX_EPOCH, path.clone())];
            let (peers, next) = PeerConfig::batch_peers(&all, 0, None);
            assert_eq!(next, 1);
            assert_eq!(peers.len(), 1);
            assert_eq!(peers[0].2.alias, "visible alias");
            assert_eq!(peers[0].2.info.hostname, "host");
        }
        _ => panic!("unknown test view"),
    }
    assert_eq!(fs::read(&path).unwrap(), healthy.as_bytes());
    assert_eq!(fs::read(global).unwrap(), global_source);
    println!("OPTION_COMMIT_PEER_VIEW_SCHEMA=observed kind={kind} healthy_retry=true unrelated_shapes_ignored=true global_preserved=true");
    assert!(all_refused);
}

#[test]
fn peer_option_projection_wrong_types_are_explicit_without_mutation() {
    in_private_process("config::option_tests::peer_option_projection_wrong_types_are_explicit_without_mutation", |_| {
        exercise_peer_projection_types("options", "peer-view-options", &[
            "options = 42\n", "options = []\n", "[options]\nalias = 42\n",
            "[options]\nalias = 'visible alias'\nother = false\n",
        ]);
    });
}

#[test]
fn peer_ui_projection_wrong_types_are_explicit_without_mutation() {
    in_private_process("config::option_tests::peer_ui_projection_wrong_types_are_explicit_without_mutation", |_| {
        exercise_peer_projection_types("ui", "peer-view-ui", &[
            "info = 42\n", "[info]\nhostname = 42\n", "[info]\nhostname = []\n",
            "port_forwards = true\n", "port_forwards = [[8000, 7, 80]]\n",
            "port_forwards = [[8000, 'destination', 80], [2147483648, 'other', 80]]\n",
        ]);
    });
}

#[test]
fn peer_list_projection_wrong_alias_types_are_omitted_without_mutation() {
    in_private_process("config::option_tests::peer_list_projection_wrong_alias_types_are_omitted_without_mutation", |_| {
        exercise_peer_projection_types("list", "peer-view-list", &[
            "options = 42\n[info]\nplatform = 'Linux'\n",
            "[info]\nplatform = 'Linux'\n[options]\nalias = 42\n",
            "[info]\nplatform = 'Linux'\n[options]\nalias = false\n",
            "[info]\nplatform = 'Linux'\n[options]\nalias = []\n",
        ]);
    });
}

fn exercise_peer_schema_cases(id: &str, cases: &[(&str, &str)]) {
    use std::os::unix::fs::MetadataExt;
    let mut peer = PeerConfig::default();
    peer.password_prs = b"fixture-schema-prs".to_vec();
    peer.options.insert("selected".into(), "before".into());
    peer.options.insert("unrelated".into(), "preserved".into());
    peer.ui_flutter.insert("canvas".into(), "preserved".into());
    peer.info.hostname = "preserved-host".into();
    peer.transfer.read_jobs = vec!["preserved-job".into()];
    peer.port_forwards = vec![(8000, "localhost".into(), 80)];
    peer.custom_resolutions.insert("0".into(), Resolution { w: 1920, h: 1080 });
    peer.store(id).unwrap();
    let path = PeerConfig::path(id);
    let healthy = fs::read_to_string(&path).unwrap();
    let mut expected = PeerConfig::load_for_write(id).unwrap();
    expected.options.insert("selected".into(), "after".into());
    let mut all_preserved = true;
    for (case, (field, value)) in cases.iter().enumerate() {
        let mut document: toml::Value = toml::from_str(&healthy).unwrap();
        let replacement: toml::Value = toml::from_str(&format!("value = {value}")).unwrap();
        let parts: Vec<_> = field.split('.').collect();
        let mut table = document.as_table_mut().unwrap();
        for part in &parts[..parts.len() - 1] {
            table = table.get_mut(*part).unwrap().as_table_mut().unwrap();
        }
        table.insert(parts[parts.len() - 1].into(), replacement["value"].clone());
        let invalid = toml::to_string(&document).unwrap();
        let mut refused = true;
        let mut preserved = true;
        for _ in 0..2 {
            fs::write(&path, &invalid).unwrap();
            let before = fs::metadata(&path).unwrap();
            let names = || {
                let mut names = fs::read_dir(path.parent().unwrap()).unwrap()
                    .map(|e| e.unwrap().file_name()).collect::<Vec<_>>();
                names.sort(); names
            };
            let original_names = names();
            let loaded = PeerConfig::load_with_status(id);
            let checked = PeerConfig::load_for_write(id);
            let result = PeerConfig::set_option(id, "selected", "after".into());
            refused &= loaded.status == ConfigLoadStatus::Corrupt && checked.is_err() && result.is_err();
            preserved &= fs::read(&path).unwrap() == invalid.as_bytes()
                && fs::metadata(&path).unwrap().ino() == before.ino()
                && fs::metadata(&path).unwrap().permissions().mode() == before.permissions().mode()
                && names() == original_names;
        }
        fs::write(&path, &healthy).unwrap();
        let retry = PeerConfig::set_option(id, "selected", "after".into()).is_ok()
            && PeerConfig::load_for_write(id).unwrap() == expected;
        println!("OPTION_COMMIT_PEER_SCHEMA=observed case={case} field={field} refused={refused} preserved={preserved} retry={retry}");
        all_preserved &= refused && preserved && retry;
    }
    assert!(all_preserved);
}

#[test]
fn peer_schema_scalars_refuse_wrong_types_without_replacing_state() {
    in_private_process("config::option_tests::peer_schema_scalars_refuse_wrong_types_without_replacing_state", |_| {
        let mut cases = Vec::new();
        for field in ["show_remote_cursor", "follow_remote_cursor", "follow_remote_window",
            "show_quality_monitor", "disable_audio", "enable-file-copy-paste", "disable_clipboard",
            "lock_after_session_end", "terminal-persistent", "privacy_mode", "allow_swap_key",
            "view_only", "show_my_cursor", "sync-init-clipboard"] {
            cases.push((field, "'wrong-boolean'"));
            cases.push((field, "42"));
        }
        for field in ["view_style", "scroll_style", "image_quality", "reverse_mouse_wheel",
            "displays_as_individual_windows", "use_all_my_displays_for_the_remote_session", "keyboard_mode"] {
            cases.push((field, "42"));
            cases.push((field, "[]"));
        }
        cases.extend([("trackpad-speed", "'wrong-integer'"),
            ("edge_scroll_edge_thickness", "false")]);
        exercise_peer_schema_cases("peer-schema-scalars", &cases);
    });
}

#[test]
fn peer_schema_collections_and_metadata_refuse_lossy_defaults() {
    in_private_process("config::option_tests::peer_schema_collections_and_metadata_refuse_lossy_defaults", |_| {
        exercise_peer_schema_cases("peer-schema-collections", &[
            ("size", "false"), ("size", "[1, 2, 3]"),
            ("size_ft", "[1, 2, 'wrong', 4]"), ("size_pf", "{}"),
            ("port_forwards", "true"), ("port_forwards", "[[8000, 7, 80]]"),
            ("port_forwards", "[[8000, 'localhost', 80], [2147483648, 'other', 80]]"),
            ("custom_resolutions", "true"),
            ("custom_resolutions", "{'0' = {w = 'wrong', h = 1080}}"),
            ("custom_resolutions", "{'0' = {w = 1920, h = 1080}, '1' = {w = 640}}"),
            ("options", "42"), ("options", "{preserved = 'keep', invalid = 7}"),
            ("ui_flutter", "[]"), ("ui_flutter", "{canvas = 'keep', invalid = false}"),
            ("custom_image_quality", "'wrong-array'"), ("custom_image_quality", "[50, 'wrong']"),
            ("info", "42"), ("info.username", "true"),
            ("info.hostname", "42"), ("info.platform", "[]"),
            ("transfer", "42"), ("transfer.read_jobs", "true"),
            ("transfer.read_jobs", "['keep', 7]"), ("transfer.write_jobs", "'wrong-array'"),
            ("transfer.write_jobs", "[false]"),
        ]);
    });
}

#[test]
fn peer_schema_failure_precedes_credential_migration_and_global_loading() {
    in_private_process("config::option_tests::peer_schema_failure_precedes_credential_migration_and_global_loading", |_| {
        let id = "peer-schema-no-migration";
        let path = PeerConfig::path(id);
        let global = Config::file_("");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let source = b"password_prs = [1, 2, 3]\nkeyboard_mode = 42\n[options]\nrdp_password = 'private-retired'\n";
        let global_source = b"password = [private-invalid-global\n";
        fs::write(&path, source).unwrap();
        fs::write(&global, global_source).unwrap();
        let loaded = PeerConfig::load_with_status(id);
        let corrupt = loaded.status == ConfigLoadStatus::Corrupt;
        let peer_preserved = fs::read(&path).map(|b| b == source).unwrap_or(false);
        let global_preserved = fs::read(&global).map(|b| b == global_source).unwrap_or(false);
        println!("OPTION_COMMIT_PEER_SCHEMA=observed kind=admission corrupt={corrupt} peer_preserved={peer_preserved} global_preserved={global_preserved}");
        assert!(corrupt && peer_preserved && global_preserved && loaded.value.password_prs.is_empty());
    });
}

#[test]
fn peer_schema_healthy_sparse_and_normalized_values_keep_their_semantics() {
    in_private_process("config::option_tests::peer_schema_healthy_sparse_and_normalized_values_keep_their_semantics", |_| {
        let id = "peer-schema-valid";
        let path = PeerConfig::path(id);
        assert_eq!(PeerConfig::load_with_status(id).status, ConfigLoadStatus::NotFound);
        assert!(!path.exists());
        let mut peer = PeerConfig::default();
        peer.password_prs = b"fixture-schema-healthy-prs".to_vec();
        peer.size = (-10, 20, 1920, 1080);
        peer.size_ft = (1, 2, 640, 480);
        peer.size_pf = (3, 4, 800, 600);
        peer.options.insert("alias".into(), "preserved".into());
        peer.ui_flutter.insert("canvas".into(), "preserved".into());
        peer.port_forwards = vec![(8000, "localhost".into(), 80)];
        peer.custom_resolutions.insert("0".into(), Resolution { w: 1920, h: 1080 });
        peer.info = PeerInfoSerde { username: "owner".into(), hostname: "host".into(), platform: "Linux".into() };
        peer.transfer = TransferSerde { read_jobs: vec!["read".into()], write_jobs: vec!["write".into()] };
        peer.store(id).unwrap();
        assert_eq!(PeerConfig::load_for_write(id).unwrap(), peer);
        let source = "view_style = ''\nscroll_style = ''\ncustom_image_quality = []\ntrackpad-speed = 0\nedge_scroll_edge_thickness = 1\nfuture_field = 'ignored'\n[custom_resolutions.0]\nw = 1920\nh = 1080\nfuture_field = 'ignored'\n";
        fs::write(&path, source).unwrap();
        let loaded = PeerConfig::load_for_write(id).unwrap();
        let mut expected = PeerConfig::default();
        expected.options.clear();
        expected.custom_resolutions.insert("0".into(), Resolution { w: 1920, h: 1080 });
        assert_eq!(loaded, expected);
        assert_eq!(fs::read(&path).unwrap(), source.as_bytes());
        PeerConfig::set_option(id, "alias", "after".into()).unwrap();
        expected.options.insert("alias".into(), "after".into());
        assert_eq!(PeerConfig::load_for_write(id).unwrap(), expected);
        fs::write(&path, "").unwrap();
        let mut empty = PeerConfig::default();
        empty.options.clear();
        assert_eq!(PeerConfig::load_for_write(id).unwrap(), empty);
        println!("OPTION_COMMIT_PEER_SCHEMA=observed kind=healthy full_round_trip=true sparse=true empty_defaults=true normalization=true unknown_fields_ignored=true");
    });
}

pub(super) fn in_private_process(test: &str, run: impl FnOnce(&Path)) {
    const ROOT_ENV: &str = "RUSTDESK_OPTION_COMMIT_TEST_ROOT";
    if let Some(root) = std::env::var_os(ROOT_ENV) {
        let root = PathBuf::from(root);
        assert_ne!(unsafe { crate::libc::geteuid() }, 0);
        assert!(Config2::file().starts_with(&root));
        run(&root);
        return;
    }
    let root = std::env::temp_dir().join(format!("option-commit-{}", crate::uuid::Uuid::new_v4()));
    fs::create_dir(&root).unwrap();
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([test, "--exact", "--color", "never", "--test-threads=1", "--nocapture"])
        .env(ROOT_ENV, &root)
        .env("XDG_CONFIG_HOME", &root)
        .output().unwrap();
    fs::remove_dir_all(&root).unwrap();
    assert!(output.stdout.len() + output.stderr.len() <= 16384);
    for line in String::from_utf8(output.stdout).unwrap().lines() {
        if let Some(start) = line.find("OPTION_COMMIT_") {
            println!("{}", &line[start..]);
        }
    }
    assert!(output.status.success(), "option worker failed: {}", String::from_utf8_lossy(&output.stderr));
}

fn insert_retired_peer_password(id: &str) {
    let path = PeerConfig::path(id);
    let source = fs::read_to_string(&path).unwrap();
    let document: toml::Value = toml::from_str(&source).unwrap();
    let source = if let Some(value) = document.get("password") {
        assert_eq!(value, &toml::Value::Array(vec![]));
        let mut removed = 0;
        let lines: Vec<_> = source.lines().filter(|line| {
            if *line == "password = []" { removed += 1; false } else { true }
        }).collect();
        assert_eq!(removed, 1);
        lines.join("\n")
    } else {
        source
    };
    let value = b"fixture-retired-peer-hash".iter().map(u8::to_string).collect::<Vec<_>>().join(", ");
    fs::write(path, format!("password = [{value}]\n{source}\n")).unwrap();
}

#[test]
fn peer_port_forward_write_failure_reports_error_and_retries_add_remove() {
    in_private_process("config::option_tests::peer_port_forward_write_failure_reports_error_and_retries_add_remove", |_| {
        let id = "peer-port-forward-write";
        let mapping = (8000, "localhost".into(), 80);
        let mut peer = PeerConfig::default();
        peer.password_prs = b"fixture-port-forward-prs".to_vec();
        peer.options.insert("unrelated".into(), "preserved".into());
        peer.store(id).unwrap();
        let path = PeerConfig::path(id);
        let parent = path.parent().unwrap();
        for removing in [false, true] {
            let original = fs::read(&path).unwrap();
            fs::set_permissions(parent, fs::Permissions::from_mode(0o500)).unwrap();
            let result = if removing {
                PeerConfig::remove_port_forward(id, mapping.0).map(|_| ())
            } else {
                PeerConfig::add_port_forward(id, &mapping).map(|_| ())
            };
            let preserved = fs::read(&path).unwrap() == original;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
            println!("OPTION_COMMIT_PEER_PORT_FORWARD=observed kind=write removing={removing} reported={} file_preserved={preserved}", result.is_err());
            assert!(result.is_err() && preserved);
            if removing {
                assert!(PeerConfig::remove_port_forward(id, mapping.0).unwrap().is_empty());
            } else {
                assert_eq!(PeerConfig::add_port_forward(id, &mapping).unwrap(), (vec![mapping.clone()], true));
            }
            let stored = PeerConfig::load_for_write(id).unwrap();
            assert_eq!(stored.port_forwards.is_empty(), removing);
            assert_eq!(stored.password_prs, peer.password_prs);
            assert_eq!(stored.options, peer.options);
        }
    });
}

#[test]
fn peer_port_forward_unreadable_source_refuses_add_remove() {
    in_private_process("config::option_tests::peer_port_forward_unreadable_source_refuses_add_remove", |_| {
        let id = "peer-port-forward-read";
        let mapping = (8000, "localhost".into(), 80);
        let mut peer = PeerConfig::default();
        peer.password_prs = b"fixture-port-forward-prs".to_vec();
        peer.port_forwards.push(mapping.clone());
        peer.store(id).unwrap();
        let path = PeerConfig::path(id);
        for removing in [false, true] {
            let original = fs::read(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap();
            let native = fs::read(&path).unwrap_err();
            let result = if removing {
                PeerConfig::remove_port_forward(id, mapping.0).map(|_| ())
            } else {
                PeerConfig::add_port_forward(id, &(9000, "other".into(), 443)).map(|_| ())
            };
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            let preserved = fs::read(&path).unwrap() == original;
            println!("OPTION_COMMIT_PEER_PORT_FORWARD=observed kind=read removing={removing} errno={} reported={} file_preserved={preserved}", native.raw_os_error().unwrap(), result.is_err());
            assert_eq!(native.kind(), std::io::ErrorKind::PermissionDenied);
            assert!(result.is_err() && preserved);
        }
        assert_eq!(PeerConfig::load_for_write(id).unwrap(), peer);
    });
}

#[test]
fn peer_port_forward_edits_preserve_other_fields_siblings_and_capacity() {
    in_private_process("config::option_tests::peer_port_forward_edits_preserve_other_fields_siblings_and_capacity", |_| {
        let id = "peer-port-forward-fields";
        let sibling = "peer-port-forward-sibling";
        let mut expected = PeerConfig::default();
        expected.password_prs = b"fixture-port-forward-prs".to_vec();
        expected.info.hostname = "preserved-host".into();
        expected.options.insert("alias".into(), "preserved".into());
        expected.ui_flutter.insert("canvas".into(), "preserved".into());
        expected.transfer.read_jobs.push("preserved-job".into());
        expected.store(id).unwrap();
        expected.store(sibling).unwrap();
        let sibling_bytes = fs::read(PeerConfig::path(sibling)).unwrap();
        for i in 0..MAX_OWNED_PORT_FORWARD_MAPPINGS as i32 {
            let mapping = (8000 + i, "localhost".into(), 80 + i);
            let (saved, added) = PeerConfig::add_port_forward(id, &mapping).unwrap();
            expected.port_forwards.push(mapping);
            assert!(added);
            assert_eq!(saved, expected.port_forwards);
            assert_eq!(PeerConfig::load_for_write(id).unwrap(), expected);
        }
        let path = PeerConfig::path(id);
        let full = fs::read(&path).unwrap();
        let duplicate = PeerConfig::add_port_forward(id, &(8000, "different".into(), 443)).unwrap();
        assert_eq!(duplicate, (expected.port_forwards.clone(), false));
        assert!(PeerConfig::add_port_forward(id, &(9000, "localhost".into(), 80)).is_err());
        assert_eq!(fs::read(&path).unwrap(), full);
        expected.port_forwards.retain(|entry| entry.0 != 8000);
        assert_eq!(PeerConfig::remove_port_forward(id, 8000).unwrap(), expected.port_forwards);
        assert_eq!(PeerConfig::load_for_write(id).unwrap(), expected);
        assert!(PeerConfig::add_port_forward(id, &(9000, "localhost".into(), 80)).unwrap().1);
        assert_eq!(fs::read(PeerConfig::path(sibling)).unwrap(), sibling_bytes);
    });
}

#[test]
fn peer_port_forward_idempotent_edits_avoid_writes() {
    in_private_process("config::option_tests::peer_port_forward_idempotent_edits_avoid_writes", |_| {
        use std::os::unix::fs::MetadataExt;
        let id = "peer-port-forward-unchanged";
        let mapping = (8000, "localhost".into(), 80);
        PeerConfig::add_port_forward(id, &mapping).unwrap();
        let path = PeerConfig::path(id);
        let before = fs::metadata(&path).unwrap();
        let original = fs::read(&path).unwrap();
        assert!(!PeerConfig::add_port_forward(id, &mapping).unwrap().1);
        assert_eq!(PeerConfig::remove_port_forward(id, 9000).unwrap(), vec![mapping]);
        let after = fs::metadata(&path).unwrap();
        let unchanged = (before.dev(), before.ino()) == (after.dev(), after.ino());
        println!("OPTION_COMMIT_PEER_PORT_FORWARD=observed kind=idempotent unchanged_inode={unchanged}");
        assert!(unchanged);
        assert_eq!(fs::read(path).unwrap(), original);
    });
}

#[test]
fn peer_port_forward_missing_removal_does_not_create_record() {
    in_private_process("config::option_tests::peer_port_forward_missing_removal_does_not_create_record", |_| {
        let id = "peer-port-forward-missing";
        assert!(PeerConfig::remove_port_forward(id, 8000).unwrap().is_empty());
        let absent = !PeerConfig::path(id).exists();
        println!("OPTION_COMMIT_PEER_PORT_FORWARD=observed kind=missing absent={absent}");
        assert!(absent);
    });
}

#[test]
fn peer_ui_info_does_not_load_controlled_credentials() {
    in_private_process("config::option_tests::peer_ui_info_does_not_load_controlled_credentials", |_| {
        let global_path = Config::file_("");
        fs::create_dir_all(global_path.parent().unwrap()).unwrap();
        let source = b"password = [private-display-source\n";
        fs::write(&global_path, source).unwrap();
        let info: serde_json::Value = serde_json::from_str(&PeerConfig::ui_info_json("peer-ui-no-global-load").unwrap()).unwrap();
        let preserved = fs::read(&global_path).map(|bytes| bytes == source).unwrap_or(false);
        println!("OPTION_COMMIT_PEER_UI_READONLY=observed kind=global_config file_preserved={preserved}");
        assert!(preserved);
        assert_eq!(info, serde_json::json!({"info": {"hostname": ""}, "port_forwards": []}));
    });
}

#[test]
fn peer_ui_info_corrupt_record_stays_in_place() {
    in_private_process("config::option_tests::peer_ui_info_corrupt_record_stays_in_place", |_| {
        let source = b"password_prs = [private-display-source\n";
        assert!(toml::from_str::<toml::Value>(std::str::from_utf8(source).unwrap()).is_err());
        assert_display_read_refusal_preserves_file("peer-ui-corrupt", source, "syntax");
    });
}

#[test]
fn peer_ui_info_wrong_display_shape_stays_in_place() {
    in_private_process("config::option_tests::peer_ui_info_wrong_display_shape_stays_in_place", |_| {
        let source = b"password_prs = [1, 2, 3]\ninfo = 42\n";
        assert!(toml::from_str::<toml::Value>(std::str::from_utf8(source).unwrap()).is_ok());
        assert!(toml::from_str::<PeerUiInfo>(std::str::from_utf8(source).unwrap()).is_err());
        assert_display_read_refusal_preserves_file("peer-ui-wrong-shape", source, "shape");
    });
}

#[test]
fn peer_ui_info_invalid_utf8_and_directory_refuse_without_mutation() {
    in_private_process("config::option_tests::peer_ui_info_invalid_utf8_and_directory_refuse_without_mutation", |_| {
        let id = "peer-ui-invalid-input";
        assert_display_read_refusal_preserves_file(id, b"\xffprivate-display-source", "utf8");
        let path = PeerConfig::path(id);
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        let child = path.join("preserved");
        fs::write(&child, b"private-display-source").unwrap();
        assert!(PeerConfig::ui_info_json(id).is_err());
        let preserved = path.is_dir() && fs::read(child).unwrap() == b"private-display-source";
        println!("OPTION_COMMIT_PEER_UI_READONLY=observed kind=directory children_preserved={preserved}");
        assert!(preserved);
    });
}

fn assert_display_read_refusal_preserves_file(id: &str, source: &[u8], kind: &str) {
    use std::os::unix::fs::MetadataExt;
    let path = PeerConfig::path(id);
    let parent = path.parent().unwrap();
    fs::create_dir_all(parent).unwrap();
    fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(&path, source).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let before = fs::metadata(&path).unwrap();
    let names = || {
        let mut names = fs::read_dir(parent).unwrap().map(|entry| entry.unwrap().file_name()).collect::<Vec<_>>();
        names.sort();
        names
    };
    let original_names = names();
    let error = PeerConfig::ui_info_json(id).unwrap_err();
    let preserved = fs::read(&path).map(|bytes| bytes == source).unwrap_or(false);
    let same_file = fs::metadata(&path).map(|after| (before.dev(), before.ino()) == (after.dev(), after.ino())).unwrap_or(false);
    let directory_unchanged = names() == original_names;
    println!("OPTION_COMMIT_PEER_UI_READONLY=observed kind={kind} file_preserved={preserved} same_file={same_file} directory_unchanged={directory_unchanged}");
    assert!(!format!("{error:?}").contains("private-display-source"));
    assert!(preserved && same_file && directory_unchanged);
}

#[test]
fn peer_ui_info_excludes_credentials_and_unrelated_state() {
    in_private_process("config::option_tests::peer_ui_info_excludes_credentials_and_unrelated_state", |_| {
        let id = "peer-ui-fields";
        let mut peer = PeerConfig::default();
        peer.password_prs = b"fixture-private-ui-prs".to_vec();
        peer.info.hostname = "public-host".into();
        peer.info.username = "private-username".into();
        peer.info.platform = "Linux".into();
        peer.port_forwards = vec![(8000, "destination".into(), 80), (9000, "other".into(), 443)];
        peer.options.insert("private-option".into(), "private-value".into());
        peer.ui_flutter.insert("canvas".into(), "private-canvas".into());
        peer.transfer.read_jobs.push("private-transfer".into());
        peer.store(id).unwrap();
        let path = PeerConfig::path(id);
        let original = fs::read(&path).unwrap();
        let info: serde_json::Value = serde_json::from_str(&PeerConfig::ui_info_json(id).unwrap()).unwrap();
        let fields = info.as_object().unwrap();
        let exposed = fields.contains_key("password_prs");
        println!("OPTION_COMMIT_PEER_UI=observed kind=fields credential_returned={exposed} fields={}", fields.len());
        assert!(!exposed && fields.len() == 2);
        assert_eq!(info["info"], serde_json::json!({"hostname": "public-host"}));
        assert_eq!(info["port_forwards"], serde_json::json!([[8000, "destination", 80], [9000, "other", 443]]));
        assert_eq!(fs::read(path).unwrap(), original);
    });
}

#[test]
fn peer_ui_info_read_denial_reports_error_and_preserves_the_record() {
    in_private_process("config::option_tests::peer_ui_info_read_denial_reports_error_and_preserves_the_record", |_| {
        let id = "peer-ui-read";
        let mut peer = PeerConfig::default();
        peer.password_prs = b"fixture-private-ui-prs".to_vec();
        peer.info.hostname = "public-host".into();
        peer.store(id).unwrap();
        let path = PeerConfig::path(id);
        let original = fs::read(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap();
        let native = fs::read(&path).unwrap_err();
        let result = PeerConfig::ui_info_json(id);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let preserved = fs::read(&path).unwrap() == original;
        println!("OPTION_COMMIT_PEER_UI=observed kind=read errno={} reported={} file_preserved={preserved}", native.raw_os_error().unwrap(), result.is_err());
        assert_eq!(native.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(result.is_err() && preserved);
        let info: serde_json::Value = serde_json::from_str(&PeerConfig::ui_info_json(id).unwrap()).unwrap();
        assert_eq!(info["info"]["hostname"], "public-host");
    });
}

#[test]
fn peer_ui_info_does_not_migrate_credentials_for_a_display_read() {
    in_private_process("config::option_tests::peer_ui_info_does_not_migrate_credentials_for_a_display_read", |_| {
        let id = "peer-ui-no-credential-work";
        let mut peer = PeerConfig::default();
        peer.password_prs = b"fixture-unwrapped-ui-prs".to_vec();
        peer.info.hostname = "public-host".into();
        peer.port_forwards = vec![(8000, "destination".into(), 80)];
        let path = PeerConfig::path(id);
        store_path(path.clone(), &peer).unwrap();
        let original = fs::read(&path).unwrap();
        let info: serde_json::Value = serde_json::from_str(&PeerConfig::ui_info_json(id).unwrap()).unwrap();
        let untouched = fs::read(&path).unwrap() == original;
        println!("OPTION_COMMIT_PEER_UI=observed kind=credential_work file_unchanged={untouched}");
        assert!(untouched);
        assert_eq!(info["info"]["hostname"], "public-host");
        assert_eq!(info["port_forwards"], serde_json::json!([[8000, "destination", 80]]));
        assert_eq!(PeerConfig::load_for_write(id).unwrap().password_prs, peer.password_prs);
        assert_ne!(fs::read(path).unwrap(), original);
    });
}

#[test]
fn peer_ui_info_missing_record_has_empty_display_fields_without_creation() {
    in_private_process("config::option_tests::peer_ui_info_missing_record_has_empty_display_fields_without_creation", |_| {
        let id = "peer-ui-missing";
        let path = PeerConfig::path(id);
        assert!(!path.exists());
        let info: serde_json::Value = serde_json::from_str(&PeerConfig::ui_info_json(id).unwrap()).unwrap();
        assert_eq!(info["info"]["hostname"], "");
        assert_eq!(info["port_forwards"], serde_json::json!([]));
        assert!(!path.exists());
    });
}

#[test]
fn peer_retired_password_read_does_not_rewrite_or_publish_the_value() {
    in_private_process("config::option_tests::peer_retired_password_read_does_not_rewrite_or_publish_the_value", |_| {
        let id = "peer-retired-read";
        let mut peer = PeerConfig::default();
        peer.info.platform = "Linux".into();
        peer.options.insert("alias".into(), "preserved".into());
        peer.store(id).unwrap();
        insert_retired_peer_password(id);
        let path = PeerConfig::path(id);
        let original = fs::read(&path).unwrap();
        let loaded = PeerConfig::load_for_write(id).unwrap();
        let public = serde_json::to_value(&loaded).unwrap();
        let untouched = fs::read(&path).unwrap() == original;
        let excluded = public.get("password").is_none();
        println!("OPTION_COMMIT_PEER_RETIRED=observed kind=read file_unchanged={untouched} value_excluded={excluded}");
        assert!(untouched && excluded);
        assert!(loaded.password_prs.is_empty());
        assert_eq!(loaded.info.platform, "Linux");
        assert_eq!(loaded.options.get("alias").map(String::as_str), Some("preserved"));
    });
}

#[test]
fn peer_retired_password_normal_save_omits_the_field_and_preserves_prs() {
    in_private_process("config::option_tests::peer_retired_password_normal_save_omits_the_field_and_preserves_prs", |_| {
        let id = "peer-retired-save";
        let mut peer = PeerConfig::default();
        peer.password_prs = b"fixture-current-peer-prs".to_vec();
        peer.options.insert("unrelated".into(), "preserved".into());
        peer.store(id).unwrap();
        insert_retired_peer_password(id);
        assert_eq!(PeerConfig::load_for_write(id).unwrap().password_prs, peer.password_prs);
        PeerConfig::set_option(id, "alias", "selected".into()).unwrap();
        let document: toml::Value = toml::from_str(&fs::read_to_string(PeerConfig::path(id)).unwrap()).unwrap();
        let excluded = document.get("password").is_none();
        println!("OPTION_COMMIT_PEER_RETIRED=observed kind=save field_omitted={excluded}");
        assert!(excluded);
        let loaded = PeerConfig::load_for_write(id).unwrap();
        assert_eq!(loaded.password_prs, b"fixture-current-peer-prs");
        assert_eq!(loaded.options.get("unrelated").map(String::as_str), Some("preserved"));
        assert_eq!(loaded.options.get("alias").map(String::as_str), Some("selected"));
    });
}

#[test]
fn peer_retired_password_forget_purges_old_only_files_and_retries_failure() {
    in_private_process("config::option_tests::peer_retired_password_forget_purges_old_only_files_and_retries_failure", |_| {
        let id = "peer-retired-forget";
        let mut peer = PeerConfig::default();
        peer.options.insert("unrelated".into(), "preserved".into());
        peer.store(id).unwrap();
        insert_retired_peer_password(id);
        let path = PeerConfig::path(id);
        let parent = path.parent().unwrap();
        let original = fs::read(&path).unwrap();
        fs::set_permissions(parent, fs::Permissions::from_mode(0o500)).unwrap();
        let failed = PeerConfig::forget_password(id).is_err();
        let preserved = fs::read(&path).unwrap() == original;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(failed && preserved);
        PeerConfig::forget_password(id).unwrap();
        let document: toml::Value = toml::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        let excluded = document.get("password").is_none();
        println!("OPTION_COMMIT_PEER_RETIRED=observed kind=forget failure_reported={failed} failed_file_preserved={preserved} field_omitted={excluded}");
        assert!(excluded);
        let loaded = PeerConfig::load_for_write(id).unwrap();
        assert!(loaded.password_prs.is_empty());
        assert_eq!(loaded.options.get("unrelated").map(String::as_str), Some("preserved"));
        let bytes = fs::read(&path).unwrap();
        let before = std::os::unix::fs::MetadataExt::ino(&fs::metadata(&path).unwrap());
        PeerConfig::forget_password(id).unwrap();
        assert_eq!(fs::read(&path).unwrap(), bytes);
        assert_eq!(std::os::unix::fs::MetadataExt::ino(&fs::metadata(path).unwrap()), before);
    });
}

#[test]
fn peer_credential_status_read_does_not_migrate_the_record() {
    in_private_process("config::option_tests::peer_credential_status_read_does_not_migrate_the_record", |_| {
        let id = "peer-credential-status-readonly";
        let mut peer = PeerConfig::default();
        peer.password_prs = b"fixture-status-unwrapped-prs".to_vec();
        let path = PeerConfig::path(id);
        store_path(path.clone(), &peer).unwrap();
        let original = fs::read(&path).unwrap();
        let status = PeerConfig::credential_status(id).unwrap();
        let preserved = fs::read(&path).unwrap() == original;
        println!("OPTION_COMMIT_PEER_CREDENTIAL_STATUS=observed kind=migration file_preserved={preserved}");
        assert!(preserved && status.has_saved_prs && status.can_forget);
        assert_eq!(serde_json::to_value(status).unwrap(), serde_json::json!({"has_saved_prs": true, "can_forget": true}));
        assert_eq!(PeerConfig::load_for_write(id).unwrap().password_prs, peer.password_prs);
        assert_ne!(fs::read(path).unwrap(), original);
    });
}

#[test]
fn peer_credential_status_corruption_refuses_without_recovery() {
    in_private_process("config::option_tests::peer_credential_status_corruption_refuses_without_recovery", |_| {
        use std::os::unix::fs::MetadataExt;
        let id = "peer-credential-status-corrupt";
        let path = PeerConfig::path(id);
        let parent = path.parent().unwrap();
        fs::create_dir_all(parent).unwrap();
        for source in [b"password_prs = [private-status-source\n".as_slice(), b"\xff\n".as_slice()] {
            fs::write(&path, source).unwrap();
            let before = fs::metadata(&path).unwrap();
            let names = || {
                let mut names = fs::read_dir(parent).unwrap().map(|entry| entry.unwrap().file_name()).collect::<Vec<_>>();
                names.sort();
                names
            };
            let original_names = names();
            let status = PeerConfig::credential_status(id);
            let preserved = fs::read(&path).map(|bytes| bytes == source).unwrap_or(false);
            let same_file = fs::metadata(&path).map(|after| (before.dev(), before.ino()) == (after.dev(), after.ino())).unwrap_or(false);
            let directory_unchanged = names() == original_names;
            println!("OPTION_COMMIT_PEER_CREDENTIAL_STATUS=observed kind=corrupt error_reported={} file_preserved={preserved} same_file={same_file} directory_unchanged={directory_unchanged}", status.is_err());
            assert!(status.is_err() && preserved && same_file && directory_unchanged);
            let error = status.unwrap_err().to_string();
            assert!(!error.contains("private-status-source"));
        }
    });
}

#[test]
fn peer_credential_status_read_denial_is_reported_and_retryable() {
    in_private_process("config::option_tests::peer_credential_status_read_denial_is_reported_and_retryable", |_| {
        let id = "peer-credential-status-denied";
        let mut peer = PeerConfig::default();
        peer.password_prs = b"fixture-status-prs".to_vec();
        peer.store(id).unwrap();
        let path = PeerConfig::path(id);
        let original = fs::read(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap();
        assert_eq!(fs::read(&path).unwrap_err().kind(), std::io::ErrorKind::PermissionDenied);
        let status = PeerConfig::credential_status(id);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let preserved = fs::read(&path).unwrap() == original;
        println!("OPTION_COMMIT_PEER_CREDENTIAL_STATUS=observed kind=read_denial error_reported={} file_preserved={preserved}", status.is_err());
        assert!(status.is_err() && preserved);
        assert_eq!(PeerConfig::credential_status(id).unwrap(), PeerCredentialStatus { has_saved_prs: true, can_forget: true });
    });
}

#[test]
fn peer_credential_status_does_not_initialize_controlled_config() {
    in_private_process("config::option_tests::peer_credential_status_does_not_initialize_controlled_config", |_| {
        let id = "peer-credential-status-no-global";
        let path = PeerConfig::path(id);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let peer = b"password_prs = []\n";
        fs::write(&path, peer).unwrap();
        let global_path = Config::file_("");
        let global = b"password = [private-status-source\n";
        fs::write(&global_path, global).unwrap();
        let status = PeerConfig::credential_status(id).unwrap();
        let preserved = fs::read(global_path).map(|bytes| bytes == global).unwrap_or(false);
        println!("OPTION_COMMIT_PEER_CREDENTIAL_STATUS=observed kind=global_config file_preserved={preserved}");
        assert!(preserved && status == PeerCredentialStatus::default());
        assert_eq!(fs::read(path).unwrap(), peer);
    });
}

#[test]
fn peer_credential_status_distinguishes_saved_prs_and_retired_data() {
    in_private_process("config::option_tests::peer_credential_status_distinguishes_saved_prs_and_retired_data", |_| {
        let id = "peer-credential-status-presence";
        assert_eq!(PeerConfig::credential_status(id).unwrap(), PeerCredentialStatus::default());
        assert!(!PeerConfig::path(id).exists());
        for has_prs in [false, true] {
            for retired in ["", "password = 'private-status-source'\n", "password = [111,108,100]\n", "password = {unexpected = 'private-status-source'}\n"] {
                let mut peer = PeerConfig::default();
                if has_prs { peer.password_prs = b"fixture-status-presence-prs".to_vec(); }
                peer.store(id).unwrap();
                let path = PeerConfig::path(id);
                let mut original = retired.as_bytes().to_vec();
                original.extend(fs::read(&path).unwrap());
                fs::write(&path, &original).unwrap();
                let status = PeerConfig::credential_status(id).unwrap();
                println!("OPTION_COMMIT_PEER_CREDENTIAL_STATUS=observed kind=presence prs={has_prs} retired={} can_forget={}", !retired.is_empty(), status.can_forget);
                assert_eq!(status, PeerCredentialStatus { has_saved_prs: has_prs, can_forget: has_prs || !retired.is_empty() });
                assert_eq!(fs::read(&path).unwrap(), original);
                PeerConfig::forget_password(id).unwrap();
                assert_eq!(PeerConfig::credential_status(id).unwrap(), PeerCredentialStatus::default());
            }
        }
    });
}

#[test]
fn peer_credential_status_rejects_malformed_prs_shape() {
    in_private_process("config::option_tests::peer_credential_status_rejects_malformed_prs_shape", |_| {
        let id = "peer-credential-status-shape";
        let path = PeerConfig::path(id);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        for source in ["password_prs = 42\n", "password_prs = 'private-status-source'\n", "password_prs = ['private-status-source']\n"] {
            fs::write(&path, source).unwrap();
            let status = PeerConfig::credential_status(id);
            println!("OPTION_COMMIT_PEER_CREDENTIAL_STATUS=observed kind=prs_shape error_reported={} file_preserved={}", status.is_err(), fs::read(&path).unwrap() == source.as_bytes());
            assert!(status.is_err());
            assert!(!status.unwrap_err().to_string().contains("private-status-source"));
            assert_eq!(fs::read(&path).unwrap(), source.as_bytes());
        }
    });
}

#[test]
fn peer_listing_does_not_migrate_credentials() {
    in_private_process("config::option_tests::peer_listing_does_not_migrate_credentials", |_| {
        let id = "peer-listing-no-migration";
        let mut peer = PeerConfig::default();
        peer.info.platform = "Linux".into();
        peer.info.hostname = "visible-host".into();
        peer.options.insert("alias".into(), "visible-alias".into());
        peer.password_prs = b"fixture-unwrapped-list-prs".to_vec();
        let path = PeerConfig::path(id);
        store_path(path.clone(), &peer).unwrap();
        let original = fs::read(&path).unwrap();
        let (peers, next) = PeerConfig::batch_peers(&vec![(id.into(), SystemTime::UNIX_EPOCH, path.clone())], 0, None);
        let preserved = fs::read(&path).unwrap() == original;
        println!("OPTION_COMMIT_PEER_LIST_VIEW=observed kind=credential_work file_preserved={preserved}");
        assert!(preserved && peers.len() == 1 && next == 1);
        assert_eq!(peers[0].2.info, peer.info);
        assert_eq!(peers[0].2.alias, "visible-alias");
        assert_eq!(PeerConfig::load_for_write(id).unwrap().password_prs, peer.password_prs);
        assert_ne!(fs::read(path).unwrap(), original);
    });
}

#[test]
fn peer_listing_corrupt_records_stay_in_place() {
    in_private_process("config::option_tests::peer_listing_corrupt_records_stay_in_place", |_| {
        use std::os::unix::fs::MetadataExt;
        let id = "peer-listing-corrupt";
        let path = PeerConfig::path(id);
        let parent = path.parent().unwrap();
        fs::create_dir_all(parent).unwrap();
        for source in [b"password_prs = [private-list-source\n".as_slice(), b"info = 42\n".as_slice()] {
            fs::write(&path, source).unwrap();
            let before = fs::metadata(&path).unwrap();
            let names = || {
                let mut names = fs::read_dir(parent).unwrap().map(|entry| entry.unwrap().file_name()).collect::<Vec<_>>();
                names.sort();
                names
            };
            let original_names = names();
            let (peers, next) = PeerConfig::batch_peers(&vec![(id.into(), SystemTime::UNIX_EPOCH, path.clone())], 0, None);
            let preserved = fs::read(&path).map(|bytes| bytes == source).unwrap_or(false);
            let same_file = fs::metadata(&path).map(|after| (before.dev(), before.ino()) == (after.dev(), after.ino())).unwrap_or(false);
            let directory_unchanged = names() == original_names;
            println!("OPTION_COMMIT_PEER_LIST_VIEW=observed kind=corrupt file_preserved={preserved} same_file={same_file} directory_unchanged={directory_unchanged}");
            assert!(peers.is_empty() && next == 1 && preserved && same_file && directory_unchanged);
        }
    });
}

#[test]
fn peer_listing_does_not_load_controlled_credentials() {
    in_private_process("config::option_tests::peer_listing_does_not_load_controlled_credentials", |_| {
        let id = "peer-listing-no-global";
        let path = PeerConfig::path(id);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let peer = b"[info]\nusername = 'user'\nhostname = 'host'\nplatform = 'Linux'\n[options]\nalias = 'alias'\n";
        fs::write(&path, peer).unwrap();
        let global_path = Config::file_("");
        let global = b"password = [private-list-source\n";
        fs::write(&global_path, global).unwrap();
        let (peers, next) = PeerConfig::batch_peers(&vec![(id.into(), SystemTime::UNIX_EPOCH, path.clone())], 0, None);
        let preserved = fs::read(global_path).map(|bytes| bytes == global).unwrap_or(false);
        println!("OPTION_COMMIT_PEER_LIST_VIEW=observed kind=global_config file_preserved={preserved}");
        assert!(preserved && peers.len() == 1 && next == 1);
        assert_eq!(peers[0].2.alias, "alias");
        assert_eq!(fs::read(path).unwrap(), peer);
    });
}

#[test]
fn peer_listing_returns_only_metadata_and_alias() {
    in_private_process("config::option_tests::peer_listing_returns_only_metadata_and_alias", |_| {
        let id = "peer-listing-closed-view";
        let mut peer = PeerConfig::default();
        peer.info = PeerInfoSerde { username: "user".into(), hostname: "host".into(), platform: "Linux".into() };
        peer.options.insert("alias".into(), "alias".into());
        peer.options.insert("private".into(), "private-list-source".into());
        peer.password_prs = b"fixture-private-list-prs".to_vec();
        peer.ui_flutter.insert("canvas".into(), "private-list-source".into());
        peer.transfer.read_jobs.push("private-list-source".into());
        peer.store(id).unwrap();
        let path = PeerConfig::path(id);
        let original = fs::read(&path).unwrap();
        let (peers, next) = PeerConfig::batch_peers(&vec![(id.into(), SystemTime::UNIX_EPOCH, path.clone())], 0, None);
        assert_eq!(next, 1);
        assert_eq!(peers.len(), 1);
        let info = serde_json::to_value(&peers[0].2).unwrap();
        assert_eq!(info, serde_json::json!({"info": {"username": "user", "hostname": "host", "platform": "Linux"}, "alias": "alias"}));
        assert_eq!(fs::read(path).unwrap(), original);
    });
}

#[test]
fn peer_listing_omits_empty_records_without_deleting_them() {
    in_private_process("config::option_tests::peer_listing_omits_empty_records_without_deleting_them", |_| {
        let id = "peer-listing-empty";
        PeerConfig::default().store(id).unwrap();
        let path = PeerConfig::path(id);
        let original = fs::read(&path).unwrap();
        let all = vec![(id.into(), SystemTime::UNIX_EPOCH, path.clone())];
        let (peers, next) = PeerConfig::batch_peers(&all, 0, None);
        let preserved = fs::read(&path).ok().as_deref() == Some(original.as_slice());
        println!("OPTION_COMMIT_PEER_LISTING=observed kind=empty omitted={} next={next} file_preserved={preserved}", peers.is_empty());
        assert!(peers.is_empty() && next == 1 && preserved);
    });
}

#[test]
fn peer_listing_empty_snapshot_cannot_delete_a_replacement_record() {
    in_private_process("config::option_tests::peer_listing_empty_snapshot_cannot_delete_a_replacement_record", |_| {
        let id = "peer-listing-replacement";
        PeerConfig::default().store(id).unwrap();
        let path = PeerConfig::path(id);
        let all = vec![(id.into(), SystemTime::UNIX_EPOCH, path.clone())];
        let mut replacement = PeerConfig::default();
        replacement.password_prs = b"fixture-replacement-prs".to_vec();
        replacement.info.platform = "Linux".into();
        replacement.options.insert("alias".into(), "replacement".into());
        let mut written = Vec::new();
        let mut reads = 0;
        let (peers, next) = PeerConfig::batch_peers_with_loader(&all, 0, None, |actual| {
            assert_eq!(actual, path);
            let loaded = PeerConfig::load_list_info(actual).unwrap();
            assert_eq!(loaded, PeerListInfo::default());
            replacement.store(id).unwrap();
            written = fs::read(&path).unwrap();
            reads += 1;
            Ok(loaded)
        });
        let preserved = fs::read(&path).ok().as_deref() == Some(written.as_slice());
        println!("OPTION_COMMIT_PEER_LISTING=observed kind=replacement real_reads={reads} replacement_committed={} snapshot_omitted={} next={next} replacement_preserved={preserved}", !written.is_empty(), peers.is_empty());
        assert!(reads == 1 && !written.is_empty() && peers.is_empty() && next == 1 && preserved);
        let stored = PeerConfig::load_for_write(id).unwrap();
        assert_eq!(stored.password_prs, b"fixture-replacement-prs");
        assert_eq!(stored.options.get("alias").map(String::as_str), Some("replacement"));
        assert_eq!(stored.info.platform, "Linux");
    });
}

#[test]
fn peer_listing_preserves_visible_and_incomplete_records_and_batch_boundaries() {
    in_private_process("config::option_tests::peer_listing_preserves_visible_and_incomplete_records_and_batch_boundaries", |_| {
        let visible_id = "peer-listing-visible";
        let incomplete_id = "peer-listing-incomplete";
        let mut visible = PeerConfig::default();
        visible.info.platform = "Linux".into();
        visible.options.insert("alias".into(), "visible".into());
        visible.store(visible_id).unwrap();
        let mut incomplete = PeerConfig::default();
        incomplete.password_prs = b"fixture-incomplete-prs".to_vec();
        incomplete.store(incomplete_id).unwrap();
        let visible_path = PeerConfig::path(visible_id);
        let incomplete_path = PeerConfig::path(incomplete_id);
        let visible_bytes = fs::read(&visible_path).unwrap();
        let incomplete_bytes = fs::read(&incomplete_path).unwrap();
        let all = vec![
            (visible_id.into(), SystemTime::UNIX_EPOCH, visible_path.clone()),
            (incomplete_id.into(), SystemTime::UNIX_EPOCH, incomplete_path.clone()),
        ];
        let (peers, next) = PeerConfig::batch_peers(&all, 0, Some(1));
        assert_eq!(next, 1);
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].0, visible_id);
        assert_eq!(peers[0].1, SystemTime::UNIX_EPOCH);
        assert_eq!(peers[0].2.info.platform, "Linux");
        assert_eq!(peers[0].2.alias, "visible");
        let (peers, next) = PeerConfig::batch_peers(&all, 1, None);
        assert!(peers.is_empty() && next == 2);
        let (peers, next) = PeerConfig::batch_peers(&all, 2, None);
        assert!(peers.is_empty() && next == 0);
        let (peers, next) = PeerConfig::batch_peers(&all, 1, Some(0));
        assert!(peers.is_empty() && next == 1);
        assert_eq!(fs::read(visible_path).unwrap(), visible_bytes);
        assert_eq!(fs::read(incomplete_path).unwrap(), incomplete_bytes);
    });
}

#[test]
fn peer_listing_reads_the_enumerated_alias_and_preserves_read_denial() {
    in_private_process("config::option_tests::peer_listing_reads_the_enumerated_alias_and_preserves_read_denial", |root| {
        let id = "peer-listing-alias";
        PeerConfig::default().store(id).unwrap();
        let canonical = PeerConfig::path(id);
        let canonical_bytes = fs::read(&canonical).unwrap();
        let alias = root.join("alternate").join("alias.toml");
        let mut peer = PeerConfig::default();
        peer.password_prs = b"fixture-alias-prs".to_vec();
        peer.info.platform = "Linux".into();
        peer.options.insert("alias".into(), "enumerated".into());
        PeerConfig::store_path(&alias, &peer).unwrap();
        let alias_bytes = fs::read(&alias).unwrap();
        let all = vec![(id.into(), SystemTime::UNIX_EPOCH, alias.clone())];
        let (peers, next) = PeerConfig::batch_peers(&all, 0, None);
        assert_eq!(next, 1);
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].2.info, peer.info);
        assert_eq!(peers[0].2.alias, "enumerated");
        fs::set_permissions(&alias, fs::Permissions::from_mode(0o000)).unwrap();
        assert_eq!(fs::read(&alias).unwrap_err().kind(), std::io::ErrorKind::PermissionDenied);
        let (peers, next) = PeerConfig::batch_peers(&all, 0, None);
        fs::set_permissions(&alias, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(peers.is_empty() && next == 1);
        assert_eq!(fs::read(&alias).unwrap(), alias_bytes);
        assert_eq!(PeerConfig::load_path_with_status(alias).value.password_prs, peer.password_prs);
        assert_eq!(fs::read(canonical).unwrap(), canonical_bytes);
    });
}

#[test]
fn peer_transfer_write_failure_is_reported_and_retryable() {
    in_private_process("config::option_tests::peer_transfer_write_failure_is_reported_and_retryable", |_| {
        let id = "peer-transfer-write";
        let mut peer = PeerConfig::default();
        peer.password_prs = b"fixture-transfer-prs".to_vec();
        peer.options.insert("unrelated".into(), "preserved".into());
        peer.transfer.read_jobs.push("old-read".into());
        peer.store(id).unwrap();
        let path = PeerConfig::path(id);
        let parent = path.parent().unwrap();
        for transfer in [TransferSerde { read_jobs: vec!["new-read".into()], write_jobs: vec!["new-write".into()] }, TransferSerde::default()] {
            let original = fs::read(&path).unwrap();
            fs::set_permissions(parent, fs::Permissions::from_mode(0o500)).unwrap();
            let result = PeerConfig::set_transfer(id, &transfer);
            let preserved = fs::read(&path).unwrap() == original;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
            println!("OPTION_COMMIT_PEER_TRANSFER=observed kind=write clearing={} reported={} file_preserved={preserved}", transfer == TransferSerde::default(), result.is_err());
            assert!(result.is_err() && preserved);
            PeerConfig::set_transfer(id, &transfer).unwrap();
            let stored = PeerConfig::load_for_write(id).unwrap();
            assert_eq!(stored.transfer, transfer);
            assert_eq!(stored.password_prs, b"fixture-transfer-prs");
            assert_eq!(stored.options.get("unrelated").map(String::as_str), Some("preserved"));
        }
    });
}

#[test]
fn peer_transfer_unreadable_source_refuses_without_replacing_credentials() {
    in_private_process("config::option_tests::peer_transfer_unreadable_source_refuses_without_replacing_credentials", |_| {
        let id = "peer-transfer-read";
        let mut peer = PeerConfig::default();
        peer.password_prs = b"fixture-transfer-prs".to_vec();
        peer.options.insert("unrelated".into(), "preserved".into());
        peer.transfer.read_jobs.push("old-read".into());
        peer.store(id).unwrap();
        let path = PeerConfig::path(id);
        let original = fs::read(&path).unwrap();
        let transfer = TransferSerde { read_jobs: vec!["new-read".into()], write_jobs: vec!["new-write".into()] };
        fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap();
        let native = fs::read(&path).unwrap_err();
        let result = PeerConfig::set_transfer(id, &transfer);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let preserved = fs::read(&path).unwrap() == original;
        println!("OPTION_COMMIT_PEER_TRANSFER=observed kind=read errno={} reported={} file_preserved={preserved}", native.raw_os_error().unwrap(), result.is_err());
        assert_eq!(native.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(result.is_err() && preserved);
        PeerConfig::set_transfer(id, &transfer).unwrap();
        let stored = PeerConfig::load_for_write(id).unwrap();
        assert_eq!(stored.transfer, transfer);
        assert_eq!(stored.password_prs, b"fixture-transfer-prs");
        assert_eq!(stored.options.get("unrelated").map(String::as_str), Some("preserved"));
    });
}

#[test]
fn peer_transfer_changes_only_the_checkpoint_and_preserves_siblings() {
    in_private_process("config::option_tests::peer_transfer_changes_only_the_checkpoint_and_preserves_siblings", |_| {
        let id = "peer-transfer-selected";
        let sibling = "peer-transfer-sibling";
        let mut peer = PeerConfig::default();
        peer.password_prs = b"fixture-transfer-prs".to_vec();
        peer.options.insert("alias".into(), "preserved".into());
        peer.ui_flutter.insert("canvas".into(), "preserved".into());
        peer.info.platform = "Linux".into();
        peer.store(id).unwrap();
        peer.store(sibling).unwrap();
        let sibling_bytes = fs::read(PeerConfig::path(sibling)).unwrap();
        let mut expected = PeerConfig::load_for_write(id).unwrap();
        for transfer in [TransferSerde { read_jobs: vec!["read-1".into(), "read-2".into()], write_jobs: vec!["write-1".into()] }, TransferSerde::default()] {
            PeerConfig::set_transfer(id, &transfer).unwrap();
            expected.transfer = transfer;
            assert_eq!(PeerConfig::load_for_write(id).unwrap(), expected);
            assert_eq!(fs::read(PeerConfig::path(sibling)).unwrap(), sibling_bytes);
        }
    });
}

#[test]
fn peer_transfer_unchanged_and_missing_empty_checkpoints_avoid_writes() {
    in_private_process("config::option_tests::peer_transfer_unchanged_and_missing_empty_checkpoints_avoid_writes", |_| {
        use std::os::unix::fs::MetadataExt;
        let id = "peer-transfer-unchanged";
        let missing = "peer-transfer-missing";
        PeerConfig::set_transfer(missing, &TransferSerde::default()).unwrap();
        assert!(!PeerConfig::path(missing).exists());
        let transfer = TransferSerde { read_jobs: vec!["read".into()], write_jobs: vec!["write".into()] };
        PeerConfig::set_transfer(id, &transfer).unwrap();
        let path = PeerConfig::path(id);
        let bytes = fs::read(&path).unwrap();
        let before = fs::metadata(&path).unwrap();
        let parent = path.parent().unwrap();
        fs::set_permissions(parent, fs::Permissions::from_mode(0o500)).unwrap();
        let unchanged = PeerConfig::set_transfer(id, &transfer);
        let missing_empty = PeerConfig::set_transfer(missing, &TransferSerde::default());
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
        let after = fs::metadata(&path).unwrap();
        assert!(unchanged.is_ok() && missing_empty.is_ok());
        assert_eq!(fs::read(&path).unwrap(), bytes);
        assert_eq!((before.dev(), before.ino()), (after.dev(), after.ino()));
        assert!(!PeerConfig::path(missing).exists());
    });
}

#[test]
fn peer_load_corruption_preserves_source_and_repeated_actions_refuse() {
    in_private_process("config::option_tests::peer_load_corruption_preserves_source_and_repeated_actions_refuse", |_| {
        use std::os::unix::fs::MetadataExt;
        let id = "peer-load-preserve-source";
        let path = PeerConfig::path(id);
        let parent = path.parent().unwrap();
        fs::create_dir_all(parent).unwrap();
        let actions: [(&str, fn(&str) -> crate::ResultType<()>); 6] = [
            ("read", |id| PeerConfig::load_for_write(id).map(|_| ())),
            ("option", |id| PeerConfig::set_option(id, "alias", "requested".into())),
            ("forget", PeerConfig::forget_password),
            ("transfer", |id| PeerConfig::set_transfer(id, &TransferSerde::default())),
            ("add_forward", |id| PeerConfig::add_port_forward(id, &(8001, "destination".into(), 80)).map(|_| ())),
            ("remove_forward", |id| PeerConfig::remove_port_forward(id, 8001).map(|_| ())),
        ];
        let mut all_preserved = true;
        for (kind, source) in [("syntax", b"password_prs = [private-peer-source\n".as_slice()), ("utf8", b"\xffprivate-peer-source".as_slice())] {
            for (name, action) in actions {
                fs::write(&path, source).unwrap();
                let before = fs::metadata(&path).unwrap();
                let names = || {
                    let mut names = fs::read_dir(parent).unwrap().map(|e| e.unwrap().file_name()).collect::<Vec<_>>();
                    names.sort(); names
                };
                let original_names = names();
                let first = action(id);
                let second = action(id);
                let preserved = fs::read(&path).map(|bytes| bytes == source).unwrap_or(false);
                let same_file = fs::metadata(&path).map(|m| (m.dev(), m.ino()) == (before.dev(), before.ino())).unwrap_or(false);
                let directory_unchanged = names() == original_names;
                println!("OPTION_COMMIT_PEER_LOAD=observed kind={kind} action={name} first_refused={} repeated_refused={} file_preserved={preserved} same_file={same_file} directory_unchanged={directory_unchanged}", first.is_err(), second.is_err());
                if let Err(err) = first.as_ref() { assert!(!err.to_string().contains("private-peer-source")); }
                all_preserved &= first.is_err() && second.is_err() && preserved && same_file && directory_unchanged;
            }
        }
        assert!(all_preserved);
    });
}

#[test]
fn peer_load_missing_does_not_initialize_controlled_config() {
    in_private_process("config::option_tests::peer_load_missing_does_not_initialize_controlled_config", |_| {
        let global = Config::file_("");
        fs::create_dir_all(global.parent().unwrap()).unwrap();
        let source = b"password = [private-peer-global\n";
        fs::write(&global, source).unwrap();
        let id = "peer-load-missing-no-global";
        let path = PeerConfig::path(id);
        assert!(!path.exists());
        let loaded = PeerConfig::load_with_status(id);
        let preserved = fs::read(&global).map(|bytes| bytes == source).unwrap_or(false);
        println!("OPTION_COMMIT_PEER_LOAD=observed kind=missing_global global_preserved={preserved} peer_absent={}", !path.exists());
        assert_eq!(loaded.status, ConfigLoadStatus::NotFound);
        assert!(preserved && !path.exists() && loaded.value.password_prs.is_empty());
    });
}

#[test]
fn peer_load_corrupt_does_not_initialize_controlled_config() {
    in_private_process("config::option_tests::peer_load_corrupt_does_not_initialize_controlled_config", |_| {
        let id = "peer-load-corrupt-no-global";
        let path = PeerConfig::path(id);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let peer = b"password_prs = [private-peer-source\n";
        fs::write(&path, peer).unwrap();
        let global = Config::file_("");
        let source = b"password = [private-peer-global\n";
        fs::write(&global, source).unwrap();
        let loaded = PeerConfig::load_with_status(id);
        let preserved = fs::read(global).map(|bytes| bytes == source).unwrap_or(false);
        let peer_preserved = fs::read(path).map(|bytes| bytes == peer).unwrap_or(false);
        println!("OPTION_COMMIT_PEER_LOAD=observed kind=corrupt_global global_preserved={preserved} peer_preserved={peer_preserved}");
        assert_eq!(loaded.status, ConfigLoadStatus::Corrupt);
        assert!(preserved && peer_preserved && loaded.value.password_prs.is_empty());
    });
}

#[test]
fn peer_load_utf8_is_corrupt_without_recovery() {
    in_private_process("config::option_tests::peer_load_utf8_is_corrupt_without_recovery", |_| {
        let id = "peer-load-bad-utf8";
        let path = PeerConfig::path(id);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let source = b"\xffprivate-peer-source";
        fs::write(&path, source).unwrap();
        let loaded = PeerConfig::load_with_status(id);
        let preserved = fs::read(path).unwrap() == source;
        println!("OPTION_COMMIT_PEER_LOAD=observed kind=utf8_classification corrupt={} file_preserved={preserved}", loaded.status == ConfigLoadStatus::Corrupt);
        assert_eq!(loaded.status, ConfigLoadStatus::Corrupt);
        assert!(preserved && loaded.value.password_prs.is_empty());
    });
}

#[test]
fn peer_load_malformed_prs_refuses_without_defaulting_or_mutation() {
    in_private_process("config::option_tests::peer_load_malformed_prs_refuses_without_defaulting_or_mutation", |_| {
        use std::os::unix::fs::MetadataExt;
        let id = "peer-load-malformed-prs";
        let path = PeerConfig::path(id);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let mut all_refused = true;
        for (index, value) in ["'private-invalid-prs'", "42", "{private = 'invalid-prs'}", "[256]", "[-1]", "['invalid-prs']"].iter().enumerate() {
            let source = format!("password_prs = {value}\n[options]\nalias = 'preserved'\n");
            fs::write(&path, &source).unwrap();
            let before = fs::metadata(&path).unwrap();
            let loaded = PeerConfig::load_with_status(id);
            let checked = PeerConfig::load_for_write(id);
            let first = PeerConfig::set_option(id, "alias", "requested".into());
            let repeated = PeerConfig::set_option(id, "alias", "requested".into());
            let corrupt = loaded.status == ConfigLoadStatus::Corrupt;
            let preserved = fs::read(&path).unwrap() == source.as_bytes();
            let same_file = fs::metadata(&path).unwrap().ino() == before.ino();
            println!("OPTION_COMMIT_PEER_LOAD=observed kind=prs_shape case={index} corrupt={corrupt} checked_refused={} write_refused={} repeated_refused={} file_preserved={preserved} same_file={same_file}", checked.is_err(), first.is_err(), repeated.is_err());
            all_refused &= corrupt && checked.is_err() && first.is_err() && repeated.is_err() && preserved && same_file;
            assert!(loaded.value.password_prs.is_empty());
        }
        assert!(all_refused);
    });
}

#[test]
fn peer_load_status_controls_preserve_missing_denied_and_directory() {
    in_private_process("config::option_tests::peer_load_status_controls_preserve_missing_denied_and_directory", |_| {
        let id = "peer-load-status-controls";
        let path = PeerConfig::path(id);
        assert_eq!(PeerConfig::load_with_status(id).status, ConfigLoadStatus::NotFound);
        assert!(PeerConfig::load_for_write(id).is_ok() && !path.exists());
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let source = b"password_prs = []\n[options]\nalias = 'preserved'\n";
        fs::write(&path, source).unwrap();
        let loaded = PeerConfig::load_with_status(id);
        assert_eq!(loaded.status, ConfigLoadStatus::Loaded);
        assert_eq!(loaded.value.options.get("alias").map(String::as_str), Some("preserved"));
        assert_eq!(fs::read(&path).unwrap(), source);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap();
        let native = fs::read(&path).unwrap_err();
        let denied = PeerConfig::load_with_status(id);
        let refused = PeerConfig::load_for_write(id).is_err();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(native.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(denied.status, ConfigLoadStatus::TransientError);
        assert!(refused && fs::read(&path).unwrap() == source);
        assert_eq!(PeerConfig::load_with_status(id).status, ConfigLoadStatus::Loaded);
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        let child = path.join("preserved");
        fs::write(&child, source).unwrap();
        assert_eq!(PeerConfig::load_with_status(id).status, ConfigLoadStatus::TransientError);
        assert!(PeerConfig::load_for_write(id).is_err());
        assert_eq!(fs::read(child).unwrap(), source);
        println!("OPTION_COMMIT_PEER_LOAD=observed kind=controls missing_absent=true loaded_preserved=true denied_errno={} transient=true retry_loaded=true directory_preserved=true", native.raw_os_error().unwrap());
    });
}

#[test]
fn peer_option_read_preserves_credentials_and_file_identity() {
    in_private_process("config::option_tests::peer_option_read_preserves_credentials_and_file_identity", |_| {
        use std::os::unix::fs::MetadataExt;
        let id = "peer-option-display-migration";
        let mut peer = PeerConfig::default();
        peer.password_prs = b"fixture-unwrapped-option-prs".to_vec();
        peer.options.insert("alias".into(), "visible alias".into());
        peer.options.insert("rdp_password".into(), "fixture-retired-secret".into());
        let path = PeerConfig::path(id);
        store_path(path.clone(), &peer).unwrap();
        let original = fs::read(&path).unwrap();
        let before = fs::metadata(&path).unwrap();
        let value = PeerConfig::read_option(id, "alias").unwrap();
        let after = fs::metadata(&path).unwrap();
        let preserved = fs::read(&path).unwrap() == original;
        let same_file = (before.dev(), before.ino()) == (after.dev(), after.ino());
        println!("OPTION_COMMIT_PEER_OPTION_READ=observed kind=migration file_preserved={preserved} same_file={same_file}");
        assert_eq!(value, "visible alias");
        assert!(preserved && same_file);
        assert_eq!(PeerConfig::read_option(id, "rdp_password").unwrap(), "");
        assert_eq!(fs::read(&path).unwrap(), original);
        let loaded = PeerConfig::load_for_write(id).unwrap();
        assert_eq!(loaded.password_prs, peer.password_prs);
        assert!(!loaded.options.contains_key("rdp_password"));
        assert_ne!(fs::read(path).unwrap(), original);
    });
}

#[test]
fn peer_option_read_corrupt_records_refuse_without_recovery() {
    in_private_process("config::option_tests::peer_option_read_corrupt_records_refuse_without_recovery", |_| {
        use std::os::unix::fs::MetadataExt;
        let path = PeerConfig::path("peer-option-display-corrupt");
        let parent = path.parent().unwrap();
        fs::create_dir_all(parent).unwrap();
        for (kind, source) in [("syntax", b"password = [private-option-source\n".as_slice()), ("utf8", b"\xffprivate-option-source".as_slice())] {
            fs::write(&path, source).unwrap();
            let before = fs::metadata(&path).unwrap();
            let names = || {
                let mut names = fs::read_dir(parent).unwrap().map(|e| e.unwrap().file_name()).collect::<Vec<_>>();
                names.sort(); names
            };
            let original_names = names();
            let result = PeerConfig::read_option("peer-option-display-corrupt", "alias");
            let preserved = fs::read(&path).map(|bytes| bytes == source).unwrap_or(false);
            let same_file = fs::metadata(&path).map(|m| (m.dev(), m.ino()) == (before.dev(), before.ino())).unwrap_or(false);
            println!("OPTION_COMMIT_PEER_OPTION_READ=observed kind={kind} refused={} file_preserved={preserved} same_file={same_file}", result.is_err());
            assert!(result.is_err() && preserved && same_file && names() == original_names);
            assert!(!result.unwrap_err().to_string().contains("private-option-source"));
        }
    });
}

#[test]
fn peer_option_read_denial_is_reported_and_retryable() {
    in_private_process("config::option_tests::peer_option_read_denial_is_reported_and_retryable", |_| {
        let id = "peer-option-display-denied";
        let path = PeerConfig::path(id);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let source = b"[options]\nalias = 'visible alias'\n";
        fs::write(&path, source).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap();
        let native = fs::read(&path).unwrap_err();
        let result = PeerConfig::read_option(id, "alias");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let preserved = fs::read(&path).unwrap() == source;
        println!("OPTION_COMMIT_PEER_OPTION_READ=observed kind=denial errno={} refused={} file_preserved={preserved}", native.raw_os_error().unwrap(), result.is_err());
        assert_eq!(native.kind(), io::ErrorKind::PermissionDenied);
        assert!(result.is_err() && preserved);
        assert_eq!(PeerConfig::read_option(id, "alias").unwrap(), "visible alias");
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        let child = path.join("preserved");
        fs::write(&child, source).unwrap();
        assert!(PeerConfig::read_option(id, "alias").is_err());
        assert_eq!(fs::read(child).unwrap(), source);
    });
}

#[test]
fn peer_option_read_does_not_initialize_controlled_credentials() {
    in_private_process("config::option_tests::peer_option_read_does_not_initialize_controlled_credentials", |_| {
        let id = "peer-option-display-no-global";
        let path = PeerConfig::path(id);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let source = b"[options]\nalias = 'visible alias'\n";
        fs::write(&path, source).unwrap();
        let global_path = Config::file_("");
        let global = b"password = [private-option-global\n";
        fs::write(&global_path, global).unwrap();
        let result = PeerConfig::read_option(id, "alias").unwrap();
        let preserved = fs::read(global_path).map(|bytes| bytes == global).unwrap_or(false);
        println!("OPTION_COMMIT_PEER_OPTION_READ=observed kind=global_config file_preserved={preserved}");
        assert!(preserved);
        assert_eq!(result, "visible alias");
        assert_eq!(fs::read(path).unwrap(), source);
    });
}

#[test]
fn peer_option_read_ignores_unrelated_record_shapes() {
    in_private_process("config::option_tests::peer_option_read_ignores_unrelated_record_shapes", |_| {
        let id = "peer-option-display-projection";
        let path = PeerConfig::path(id);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let source = b"password_prs = {private = 'ignored'}\npassword = ['ignored']\ninfo = 42\ntransfer = 42\nui_flutter = 42\n[options]\nalias = 'visible alias'\nrdp_port = '3390'\n";
        fs::write(&path, source).unwrap();
        let value = PeerConfig::read_option(id, "alias").unwrap();
        let preserved = fs::read(&path).map(|bytes| bytes == source).unwrap_or(false);
        println!("OPTION_COMMIT_PEER_OPTION_READ=observed kind=projection value_preserved={} file_preserved={preserved}", value == "visible alias");
        assert!(preserved && value == "visible alias");
        assert_eq!(PeerConfig::read_option(id, "rdp_port").unwrap(), "3390");
    });
}

#[test]
fn peer_option_read_preserves_values_defaults_and_retired_key_masking() {
    in_private_process("config::option_tests::peer_option_read_preserves_values_defaults_and_retired_key_masking", |_| {
        let id = "peer-option-display-values";
        let path = PeerConfig::path(id);
        let key = keys::OPTION_CUSTOM_FPS;
        UserDefaultConfig::set_option(key.into(), "25".into()).unwrap();
        assert_eq!(PeerConfig::read_option(id, key).unwrap(), "25");
        assert_eq!(PeerConfig::read_option(id, "alias").unwrap(), "");
        assert!(!path.exists());
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        for source in ["password_prs = []\n", "[options]\n", "[options]\nalias = 'visible alias'\nrdp_port = '3390'\nrdp_username = 'retired-user'\nrdp_password = 'retired-secret'\n"] {
            fs::write(&path, source).unwrap();
            assert_eq!(PeerConfig::read_option(id, key).unwrap(), "");
            assert_eq!(PeerConfig::read_option(id, "alias").unwrap(), if source.contains("visible alias") { "visible alias" } else { "" });
            for name in RETIRED_RDP_CREDENTIAL_OPTIONS {
                assert_eq!(PeerConfig::read_option(id, name).unwrap(), "");
            }
        }
        println!("OPTION_COMMIT_PEER_OPTION_READ=observed kind=controls inherited_missing_default=true existing_empty_distinct=true retired_keys_masked=true");
    });
}

#[test]
fn peer_option_write_failure_preserves_settings_and_retries_set_and_remove() {
    in_private_process("config::option_tests::peer_option_write_failure_preserves_settings_and_retries_set_and_remove", |_| {
        let id = "peer-option-write";
        let mut peer = PeerConfig::default();
        peer.password_prs = b"fixture-option-prs".to_vec();
        peer.options.insert("unrelated".into(), "preserved".into());
        peer.store(id).unwrap();
        let path = PeerConfig::path(id);
        let parent = path.parent().unwrap();
        for value in ["selected", ""] {
            let original = fs::read(&path).unwrap();
            fs::set_permissions(parent, fs::Permissions::from_mode(0o500)).unwrap();
            let result = PeerConfig::set_option(id, "alias", value.into());
            let preserved = fs::read(&path).unwrap() == original;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
            println!("OPTION_COMMIT_PEER_OPTION=observed kind=write remove={} reported={} file_preserved={preserved}", value.is_empty(), result.is_err());
            assert!(preserved && result.is_err());
            PeerConfig::set_option(id, "alias", value.into()).unwrap();
            let stored = PeerConfig::load_for_write(id).unwrap();
            assert_eq!(stored.options.get("alias").map(String::as_str), if value.is_empty() { None } else { Some(value) });
            assert_eq!(stored.options.get("unrelated").map(String::as_str), Some("preserved"));
            assert_eq!(stored.password_prs, b"fixture-option-prs");
        }
    });
}

#[test]
fn peer_option_unreadable_source_refuses_without_losing_credentials() {
    in_private_process("config::option_tests::peer_option_unreadable_source_refuses_without_losing_credentials", |_| {
        let id = "peer-option-read";
        let mut peer = PeerConfig::default();
        peer.password_prs = b"fixture-option-prs".to_vec();
        peer.options.insert("unrelated".into(), "preserved".into());
        peer.store(id).unwrap();
        let path = PeerConfig::path(id);
        let original = fs::read(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap();
        let native = fs::read(&path).unwrap_err();
        let result = PeerConfig::set_option(id, "alias", "selected".into());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let preserved = fs::read(&path).unwrap() == original;
        println!("OPTION_COMMIT_PEER_OPTION=observed kind=read errno={} reported={} file_preserved={preserved}", native.raw_os_error().unwrap(), result.is_err());
        assert_eq!(native.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(preserved && result.is_err());
        PeerConfig::set_option(id, "alias", "selected".into()).unwrap();
        let stored = PeerConfig::load_for_write(id).unwrap();
        assert_eq!(stored.options.get("alias").map(String::as_str), Some("selected"));
        assert_eq!(stored.options.get("unrelated").map(String::as_str), Some("preserved"));
        assert_eq!(stored.password_prs, b"fixture-option-prs");
    });
}

#[test]
fn peer_option_preserves_other_state_and_avoids_idempotent_or_missing_removal_writes() {
    in_private_process("config::option_tests::peer_option_preserves_other_state_and_avoids_idempotent_or_missing_removal_writes", |_| {
        let id = "peer-option-selected";
        let sibling = "peer-option-sibling";
        let mut peer = PeerConfig::default();
        peer.password_prs = b"fixture-option-prs".to_vec();
        peer.ui_flutter.insert("canvas".into(), "preserved".into());
        peer.options.insert("unrelated".into(), "preserved".into());
        peer.store(id).unwrap();
        peer.store(sibling).unwrap();
        let sibling_bytes = fs::read(PeerConfig::path(sibling)).unwrap();
        let mut expected = PeerConfig::load_for_write(id).unwrap();
        expected.options.insert("alias".into(), "selected".into());
        PeerConfig::set_option(id, "alias", "selected".into()).unwrap();
        assert_eq!(PeerConfig::load_for_write(id).unwrap(), expected);
        assert_eq!(fs::read(PeerConfig::path(sibling)).unwrap(), sibling_bytes);
        let path = PeerConfig::path(id);
        let original = fs::read(&path).unwrap();
        let before = fs::metadata(&path).unwrap();
        PeerConfig::set_option(id, "alias", "selected".into()).unwrap();
        let unchanged_inode = std::os::unix::fs::MetadataExt::ino(&before)
            == std::os::unix::fs::MetadataExt::ino(&fs::metadata(&path).unwrap());
        let missing = "peer-option-missing";
        PeerConfig::set_option(missing, "alias", String::new()).unwrap();
        let absent = !PeerConfig::path(missing).exists();
        println!("OPTION_COMMIT_PEER_OPTION=observed kind=idempotent unchanged_inode={unchanged_inode} missing_removal_absent={absent} credential_and_unrelated_preserved=true sibling_preserved=true");
        assert_eq!(fs::read(&path).unwrap(), original);
        assert!(unchanged_inode && absent);
    });
}

#[test]
fn peer_option_explicit_inherited_default_persists_and_missing_removal_is_absent() {
    in_private_process("config::option_tests::peer_option_explicit_inherited_default_persists_and_missing_removal_is_absent", |_| {
        let key = keys::OPTION_CUSTOM_FPS;
        assert_eq!(UserDefaultConfig::set_option(key.into(), "25".into()).unwrap(), "25");
        let id = "peer-option-explicit-default";
        assert!(!PeerConfig::path(id).exists());
        assert_eq!(PeerConfig::load_for_write(id).unwrap().options.get(key).map(String::as_str), Some("25"));
        PeerConfig::set_option(id, key, "25".into()).unwrap();
        let explicit_file = PeerConfig::path(id).exists();
        assert_eq!(UserDefaultConfig::set_option(key.into(), "26".into()).unwrap(), "26");
        let retained = PeerConfig::load_for_write(id).unwrap().options.get(key).map(String::as_str) == Some("25");
        let missing = "peer-option-default-removal";
        PeerConfig::set_option(missing, key, String::new()).unwrap();
        let removal_absent = !PeerConfig::path(missing).exists();
        println!("OPTION_COMMIT_PEER_OPTION=observed kind=inherited_default explicit_file={explicit_file} retained_after_default_change={retained} missing_removal_absent={removal_absent}");
        assert!(explicit_file && retained && removal_absent);
    });
}

#[test]
fn peer_forget_write_failure_is_reported_and_retryable() {
    in_private_process("config::option_tests::peer_forget_write_failure_is_reported_and_retryable", |_| {
        let id = "peer-forget-write";
        let mut peer = PeerConfig::default();
        peer.password_prs = b"fixture-forget-prs".to_vec();
        peer.options.insert("unrelated".into(), "preserved".into());
        peer.store(id).unwrap();
        let path = PeerConfig::path(id);
        let parent = path.parent().unwrap();
        let original = fs::read(&path).unwrap();
        fs::set_permissions(parent, fs::Permissions::from_mode(0o500)).unwrap();
        let result = PeerConfig::forget_password(id);
        let preserved = fs::read(&path).unwrap() == original;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
        println!("OPTION_COMMIT_PEER_FORGET=observed kind=write reported={} file_preserved={preserved}", result.is_err());
        assert!(preserved && result.is_err());
        PeerConfig::forget_password(id).unwrap();
        let stored = PeerConfig::load_for_write(id).unwrap();
        assert!(stored.password_prs.is_empty());
        assert_eq!(stored.options.get("unrelated").map(String::as_str), Some("preserved"));
    });
}

#[test]
fn peer_forget_unreadable_source_refuses_without_replacing_settings() {
    in_private_process("config::option_tests::peer_forget_unreadable_source_refuses_without_replacing_settings", |_| {
        let id = "peer-forget-read";
        let mut peer = PeerConfig::default();
        peer.password_prs = b"fixture-forget-prs".to_vec();
        peer.options.insert("unrelated".into(), "preserved".into());
        peer.store(id).unwrap();
        let path = PeerConfig::path(id);
        let original = fs::read(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap();
        let native = fs::read(&path).unwrap_err();
        let result = PeerConfig::forget_password(id);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let preserved = fs::read(&path).unwrap() == original;
        println!("OPTION_COMMIT_PEER_FORGET=observed kind=read errno={} reported={} file_preserved={preserved}", native.raw_os_error().unwrap(), result.is_err());
        assert_eq!(native.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(preserved && result.is_err());
        PeerConfig::forget_password(id).unwrap();
        let stored = PeerConfig::load_for_write(id).unwrap();
        assert!(stored.password_prs.is_empty());
        assert_eq!(stored.options.get("unrelated").map(String::as_str), Some("preserved"));
    });
}

#[test]
fn peer_forget_clears_both_credentials_preserves_settings_and_is_idempotent() {
    in_private_process("config::option_tests::peer_forget_clears_both_credentials_preserves_settings_and_is_idempotent", |_| {
        let id = "peer-forget-selected";
        let sibling = "peer-forget-sibling";
        let mut peer = PeerConfig::default();
        peer.password_prs = b"fixture-forget-prs".to_vec();
        peer.options.insert("unrelated".into(), "preserved".into());
        peer.ui_flutter.insert("selected".into(), "preserved".into());
        peer.store(id).unwrap();
        peer.store(sibling).unwrap();
        let sibling_bytes = fs::read(PeerConfig::path(sibling)).unwrap();
        let mut expected = PeerConfig::load_for_write(id).unwrap();
        expected.password_prs.clear();
        insert_retired_peer_password(id);
        PeerConfig::forget_password(id).unwrap();
        assert_eq!(PeerConfig::load_for_write(id).unwrap(), expected);
        assert_eq!(fs::read(PeerConfig::path(sibling)).unwrap(), sibling_bytes);
        let path = PeerConfig::path(id);
        let original = fs::read(&path).unwrap();
        let before = fs::metadata(&path).unwrap();
        PeerConfig::forget_password(id).unwrap();
        let unchanged_inode = std::os::unix::fs::MetadataExt::ino(&before)
            == std::os::unix::fs::MetadataExt::ino(&fs::metadata(&path).unwrap());
        println!("OPTION_COMMIT_PEER_FORGET=observed kind=repeat both_cleared=true settings_preserved=true sibling_preserved=true unchanged_inode={unchanged_inode}");
        assert_eq!(fs::read(&path).unwrap(), original);
        assert!(unchanged_inode);
    });
}

#[test]
fn peer_forget_missing_record_does_not_create_a_peer() {
    in_private_process("config::option_tests::peer_forget_missing_record_does_not_create_a_peer", |_| {
        let id = "peer-forget-missing";
        let path = PeerConfig::path(id);
        assert!(!path.exists());
        PeerConfig::forget_password(id).unwrap();
        let absent = !path.exists();
        println!("OPTION_COMMIT_PEER_FORGET=observed kind=missing absent={absent}");
        assert!(absent);
    });
}

#[test]
fn peer_removal_permission_failure_is_reported_and_retryable() {
    in_private_process("config::option_tests::peer_removal_permission_failure_is_reported_and_retryable", |_| {
        let id = "peer-removal-permission";
        let mut peer = PeerConfig::default();
        peer.password_prs = b"fixture-removal-prs".to_vec();
        peer.store(id).unwrap();
        let path = PeerConfig::path(id);
        let parent = path.parent().unwrap();
        let original = fs::read(&path).unwrap();
        fs::set_permissions(parent, fs::Permissions::from_mode(0o500)).unwrap();
        let native = fs::remove_file(&path).unwrap_err();
        let result = PeerConfig::remove(id);
        let preserved = fs::read(&path).unwrap() == original;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
        println!("OPTION_COMMIT_PEER_REMOVE=observed kind=permission errno={} reported={} file_preserved={preserved}",
            native.raw_os_error().unwrap(), result.is_err());
        assert_eq!(native.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(preserved);
        assert!(result.is_err());
        PeerConfig::remove(id).unwrap();
        assert!(!path.exists());
    });
}

#[test]
fn peer_removal_directory_failure_preserves_its_contents() {
    in_private_process("config::option_tests::peer_removal_directory_failure_preserves_its_contents", |_| {
        let id = "peer-removal-directory";
        PeerConfig::default().store(id).unwrap();
        let path = PeerConfig::path(id);
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        let sentinel = path.join("sentinel");
        fs::write(&sentinel, b"unchanged").unwrap();
        let native = fs::remove_file(&path).unwrap_err();
        let result = PeerConfig::remove(id);
        println!("OPTION_COMMIT_PEER_REMOVE=observed kind=directory errno={} reported={}",
            native.raw_os_error().unwrap(), result.is_err());
        assert!(path.is_dir());
        assert_eq!(fs::read(&sentinel).unwrap(), b"unchanged");
        assert!(result.is_err());
    });
}

#[test]
fn peer_removal_missing_file_is_idempotent() {
    in_private_process("config::option_tests::peer_removal_missing_file_is_idempotent", |_| {
        let id = "peer-removal-missing";
        let path = PeerConfig::path(id);
        assert!(!path.exists());
        PeerConfig::remove(id).unwrap();
        assert!(!path.exists());
    });
}

#[test]
fn peer_removal_deletes_only_the_selected_file_and_allows_repeat() {
    in_private_process("config::option_tests::peer_removal_deletes_only_the_selected_file_and_allows_repeat", |_| {
        let id = "peer-removal-selected";
        let other = "peer-removal-sibling";
        PeerConfig::default().store(id).unwrap();
        PeerConfig::default().store(other).unwrap();
        let sibling = PeerConfig::path(other);
        let original = fs::read(&sibling).unwrap();
        PeerConfig::remove(id).unwrap();
        PeerConfig::remove(id).unwrap();
        assert!(!PeerConfig::path(id).exists());
        assert_eq!(fs::read(&sibling).unwrap(), original);
    });
}

#[test]
fn peer_removal_unlinks_a_symlink_without_removing_its_target() {
    in_private_process("config::option_tests::peer_removal_unlinks_a_symlink_without_removing_its_target", |_| {
        let id = "peer-removal-link";
        PeerConfig::default().store(id).unwrap();
        let path = PeerConfig::path(id);
        let target = path.with_file_name("unrelated-target");
        fs::write(&target, b"unchanged target").unwrap();
        fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();
        PeerConfig::remove(id).unwrap();
        assert!(fs::symlink_metadata(&path).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"unchanged target");
    });
}

#[test]
#[cfg(target_os = "linux")]
fn peer_removal_refuses_a_symlinked_peer_parent() {
    in_private_process("config::option_tests::peer_removal_refuses_a_symlinked_peer_parent", |root| {
        let id = "peer-removal-linked-parent";
        let path = PeerConfig::path(id);
        let parent = path.parent().unwrap();
        fs::create_dir_all(parent.parent().unwrap()).unwrap();
        let outside = root.join("outside-peers");
        fs::create_dir(&outside).unwrap();
        let target = outside.join(path.file_name().unwrap());
        fs::write(&target, b"outside peer bytes").unwrap();
        std::os::unix::fs::symlink(&outside, parent).unwrap();
        let result = PeerConfig::remove(id);
        let preserved = fs::read(&target).ok().as_deref() == Some(b"outside peer bytes".as_slice());
        println!("OPTION_COMMIT_PEER_REMOVE_PARENT=observed kind=parent_link refused={} outside_preserved={preserved}", result.is_err());
        assert!(result.is_err() && preserved);
        assert!(fs::symlink_metadata(parent).unwrap().file_type().is_symlink());
    });
}

#[test]
#[cfg(target_os = "linux")]
fn peer_removal_refuses_a_symlinked_config_ancestor() {
    in_private_process("config::option_tests::peer_removal_refuses_a_symlinked_config_ancestor", |root| {
        let id = "peer-removal-linked-ancestor";
        let path = PeerConfig::path(id);
        let config_root = path.parent().unwrap().parent().unwrap();
        fs::create_dir_all(config_root.parent().unwrap()).unwrap();
        let outside = root.join("outside-config");
        let outside_peers = outside.join(PEERS);
        fs::create_dir_all(&outside_peers).unwrap();
        let target = outside_peers.join(path.file_name().unwrap());
        fs::write(&target, b"outside ancestor bytes").unwrap();
        std::os::unix::fs::symlink(&outside, config_root).unwrap();
        let result = PeerConfig::remove(id);
        let preserved = fs::read(&target).ok().as_deref() == Some(b"outside ancestor bytes".as_slice());
        println!("OPTION_COMMIT_PEER_REMOVE_PARENT=observed kind=ancestor_link refused={} outside_preserved={preserved}", result.is_err());
        assert!(result.is_err() && preserved);
        assert!(fs::symlink_metadata(config_root).unwrap().file_type().is_symlink());
    });
}

#[test]
#[cfg(target_os = "linux")]
fn peer_removal_retains_its_parent_across_path_replacement() {
    in_private_process("config::option_tests::peer_removal_retains_its_parent_across_path_replacement", |root| {
        let id = "peer-removal-parent-replaced";
        let path = PeerConfig::path(id);
        let parent = path.parent().unwrap();
        fs::create_dir_all(parent).unwrap();
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(&path, b"selected original bytes").unwrap();
        let sibling = parent.join("sibling.toml");
        fs::write(&sibling, b"retained sibling bytes").unwrap();
        let outside = root.join("replacement-target");
        fs::create_dir(&outside).unwrap();
        let target = outside.join(path.file_name().unwrap());
        fs::write(&target, b"outside replacement bytes").unwrap();
        let moved = parent.with_file_name("retained-original-peers");
        let mut hooks = 0;
        let result = PeerConfig::remove_with_unlink_hook(id, || {
            fs::rename(parent, &moved).unwrap();
            std::os::unix::fs::symlink(&outside, parent).unwrap();
            hooks += 1;
        });
        let outside_preserved = fs::read(&target).ok().as_deref() == Some(b"outside replacement bytes".as_slice());
        let selected_removed = !moved.join(path.file_name().unwrap()).exists();
        println!("OPTION_COMMIT_PEER_REMOVE_PARENT=observed kind=replacement hooks={hooks} success={} selected_removed={selected_removed} outside_preserved={outside_preserved}", result.is_ok());
        assert!(result.is_ok() && hooks == 1 && selected_removed && outside_preserved);
        assert_eq!(fs::read(moved.join("sibling.toml")).unwrap(), b"retained sibling bytes");
        assert!(fs::symlink_metadata(parent).unwrap().file_type().is_symlink());
    });
}

#[test]
#[cfg(target_os = "linux")]
fn peer_removal_refuses_shared_writable_parents_without_repair() {
    in_private_process("config::option_tests::peer_removal_refuses_shared_writable_parents_without_repair", |_| {
        let id = "peer-removal-shared-parent";
        let path = PeerConfig::path(id);
        let parent = path.parent().unwrap();
        fs::create_dir_all(parent).unwrap();
        for mode in [0o720, 0o702] {
            fs::write(&path, b"selected private bytes").unwrap();
            fs::set_permissions(parent, fs::Permissions::from_mode(mode)).unwrap();
            let result = PeerConfig::remove(id);
            let preserved = fs::read(&path).ok().as_deref() == Some(b"selected private bytes".as_slice());
            let unchanged_mode = fs::metadata(parent).unwrap().permissions().mode() & 0o777 == mode;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
            println!("OPTION_COMMIT_PEER_REMOVE_PARENT=observed kind=shared_parent mode={mode:o} refused={} file_preserved={preserved} mode_unchanged={unchanged_mode}", result.is_err());
            assert!(result.is_err() && preserved && unchanged_mode);
        }
        PeerConfig::remove(id).unwrap();
        assert!(!path.exists());
    });
}

#[test]
#[cfg(target_os = "linux")]
fn peer_removal_missing_parents_and_repeats_release_descriptors() {
    in_private_process("config::option_tests::peer_removal_missing_parents_and_repeats_release_descriptors", |_| {
        let id = "peer-removal-fd-control";
        let path = PeerConfig::path(id);
        let parent = path.parent().unwrap();
        assert!(!parent.exists());
        PeerConfig::remove(id).unwrap();
        PeerConfig::remove(id).unwrap();
        assert!(!parent.exists());
        fs::create_dir_all(parent).unwrap();
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
        let fds = || fs::read_dir("/proc/self/fd").unwrap().count();
        let before = fds();
        for _ in 0..100 {
            fs::write(&path, b"selected bytes").unwrap();
            PeerConfig::remove(id).unwrap();
            PeerConfig::remove(id).unwrap();
        }
        let after = fds();
        println!("OPTION_COMMIT_PEER_REMOVE_PARENT=observed kind=repeat iterations=100 missing_parents_not_created=true fds_before={before} fds_after={after}");
        assert_eq!(after, before);
        assert!(!path.exists());
    });
}

#[test]
#[cfg(target_os = "linux")]
fn peer_removal_supports_write_search_only_parents() {
    in_private_process("config::option_tests::peer_removal_supports_write_search_only_parents", |_| {
        let id = "peer-removal-search-only";
        let path = PeerConfig::path(id);
        let parent = path.parent().unwrap();
        fs::create_dir_all(parent).unwrap();
        fs::write(&path, b"selected bytes").unwrap();
        let sibling = parent.join("sibling.toml");
        fs::write(&sibling, b"preserved bytes").unwrap();
        fs::set_permissions(parent, fs::Permissions::from_mode(0o300)).unwrap();
        assert_eq!(fs::read_dir(parent).err().unwrap().kind(), std::io::ErrorKind::PermissionDenied);
        let result = PeerConfig::remove(id);
        let unchanged_mode = fs::metadata(parent).unwrap().permissions().mode() & 0o777 == 0o300;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
        println!("OPTION_COMMIT_PEER_REMOVE_PARENT=observed kind=search_only success={} mode_unchanged={unchanged_mode}", result.is_ok());
        assert!(result.is_ok() && unchanged_mode && !path.exists());
        assert_eq!(fs::read(sibling).unwrap(), b"preserved bytes");
    });
}

#[test]
fn peer_store_reports_failure_preserves_the_file_and_refuses_unreadable_source() {
    in_private_process("config::option_tests::peer_store_reports_failure_preserves_the_file_and_refuses_unreadable_source", |_| {
        let id = "peer-commit-fixture";
        let mut candidate = PeerConfig::default();
        candidate.password_prs = b"fixture-peer-prs".to_vec();
        candidate.options.insert("unrelated".into(), "preserved".into());
        candidate.store(id).unwrap();
        // Mutations start from a loaded config, including its normalised defaults.
        candidate = PeerConfig::load_for_write(id).unwrap();
        assert_eq!(candidate.password_prs, b"fixture-peer-prs");
        let file = PeerConfig::path(id);
        let parent = file.parent().unwrap();
        let original = fs::read(&file).unwrap();
        candidate.options.insert("selected".into(), "replacement".into());
        fs::set_permissions(parent, fs::Permissions::from_mode(0o500)).unwrap();
        let failed = candidate.store(id).is_err();
        let file_preserved = fs::read(&file).unwrap() == original;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
        candidate.store(id).unwrap();
        let durable_retry = PeerConfig::load_for_write(id).unwrap() == candidate;
        let committed = fs::read(&file).unwrap();
        let mut oversized = candidate.clone();
        oversized.password_prs = vec![b'x'; ENCRYPT_MAX_LEN + 1];
        assert!(oversized.store(id).is_err());
        assert_eq!(fs::read(&file).unwrap(), committed);
        fs::set_permissions(&file, fs::Permissions::from_mode(0o000)).unwrap();
        let unreadable_refused = PeerConfig::load_for_write(id).is_err();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        let read_failure_preserved = fs::read(&file).unwrap() == committed;
        println!("OPTION_COMMIT_PEER_NATIVE=observed failure_reported={failed} file_preserved={file_preserved} retry_durable={durable_retry} unreadable_refused={unreadable_refused} read_failure_preserved={read_failure_preserved}");
        assert!(failed && file_preserved && durable_retry && unreadable_refused && read_failure_preserved);
    });
}

#[test]
fn default_initial_read_preserves_corrupt_files() {
    in_private_process("config::option_tests::default_initial_read_preserves_corrupt_files", |_| {
        use std::os::unix::fs::MetadataExt;
        let file = Config::file_("_default");
        let parent = file.parent().unwrap();
        fs::create_dir_all(parent).unwrap();
        for (kind, source) in [("syntax", b"[options]\nprivate-default-source = [\n".as_slice()), ("utf8", b"\xffprivate-default-source".as_slice())] {
            fs::write(&file, source).unwrap();
            fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
            let before = fs::metadata(&file).unwrap();
            let names = || {
                let mut names = fs::read_dir(parent).unwrap().map(|e| e.unwrap().file_name()).collect::<Vec<_>>();
                names.sort(); names
            };
            let original_names = names();
            let loaded = UserDefaultConfig::load();
            let preserved = fs::read(&file).map(|bytes| bytes == source).unwrap_or(false);
            let same_file = fs::metadata(&file).map(|s| (s.dev(), s.ino(), s.mode()) == (before.dev(), before.ino(), before.mode())).unwrap_or(false);
            println!("OPTION_COMMIT_DEFAULT_READONLY=observed kind=initial_{kind} file_preserved={preserved} same_file={same_file}");
            assert!(preserved && same_file && names() == original_names);
            assert_eq!(loaded.get(keys::OPTION_CUSTOM_FPS), "30");
        }
    });
}

#[test]
fn default_refresh_preserves_corrupt_source_and_confirmed_values() {
    in_private_process("config::option_tests::default_refresh_preserves_corrupt_source_and_confirmed_values", |_| {
        UserDefaultConfig::set_option("confirmed".into(), "original".into()).unwrap();
        let file = Config::file_("_default");
        for (kind, source) in [("syntax", b"[options]\nprivate-default-source = [\n".as_slice()), ("utf8", b"\xffprivate-default-source".as_slice())] {
            fs::write(&file, source).unwrap();
            for round in 0..2 {
                USER_DEFAULT_CONFIG.write().unwrap().1 = Instant::now() - Duration::from_secs(2);
                let value = UserDefaultConfig::get_option("confirmed");
                let preserved = fs::read(&file).map(|bytes| bytes == source).unwrap_or(false);
                println!("OPTION_COMMIT_DEFAULT_READONLY=observed kind=refresh_{kind} round={round} file_preserved={preserved} confirmed_retained={}", value == "original");
                assert!(preserved && value == "original");
            }
        }
        let healthy = b"[options]\nconfirmed = 'external'\nunrelated = 'preserved'\n";
        fs::write(&file, healthy).unwrap();
        USER_DEFAULT_CONFIG.write().unwrap().1 = Instant::now() - Duration::from_secs(2);
        assert_eq!(UserDefaultConfig::get_option("confirmed"), "external");
        assert_eq!(UserDefaultConfig::get_option("unrelated"), "preserved");
        assert_eq!(fs::read(file).unwrap(), healthy);
    });
}

#[test]
fn default_corrupt_source_refuses_repeated_writes_without_recovery() {
    in_private_process("config::option_tests::default_corrupt_source_refuses_repeated_writes_without_recovery", |_| {
        UserDefaultConfig::set_option("confirmed".into(), "original".into()).unwrap();
        UserDefaultConfig::set_option("unrelated".into(), "preserved".into()).unwrap();
        let file = Config::file_("_default");
        let healthy = fs::read(&file).unwrap();
        let corrupt = b"[options]\nprivate-default-source = [\n";
        fs::write(&file, corrupt).unwrap();
        let first = UserDefaultConfig::set_option("confirmed".into(), "requested".into());
        let second = UserDefaultConfig::set_option("confirmed".into(), "requested".into());
        let preserved = fs::read(&file).map(|bytes| bytes == corrupt).unwrap_or(false);
        let cache_preserved = USER_DEFAULT_CONFIG.read().unwrap().0.get("confirmed") == "original";
        println!("OPTION_COMMIT_DEFAULT_READONLY=observed kind=write first_refused={} repeated_refused={} file_preserved={preserved} cache_preserved={cache_preserved}", first.is_err(), second.is_err());
        assert!(first.is_err() && second.is_err() && preserved && cache_preserved);
        assert!(!first.unwrap_err().to_string().contains("private-default-source"));
        fs::write(&file, healthy).unwrap();
        assert_eq!(UserDefaultConfig::set_option("confirmed".into(), "requested".into()).unwrap(), "requested");
        let stored = UserDefaultConfig::load();
        assert_eq!(stored.get("confirmed"), "requested");
        assert_eq!(stored.get("unrelated"), "preserved");
    });
}

#[test]
fn default_missing_peer_inheritance_does_not_recover_defaults() {
    in_private_process("config::option_tests::default_missing_peer_inheritance_does_not_recover_defaults", |_| {
        let file = Config::file_("_default");
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        let source = b"[options]\nprivate-default-source = [\n";
        fs::write(&file, source).unwrap();
        let id = "peer-defaults-display-only";
        let path = PeerConfig::path(id);
        assert!(!path.exists());
        let value = PeerConfig::read_option(id, keys::OPTION_CUSTOM_FPS).unwrap();
        let preserved = fs::read(&file).map(|bytes| bytes == source).unwrap_or(false);
        println!("OPTION_COMMIT_DEFAULT_READONLY=observed kind=missing_peer inherited={} defaults_preserved={preserved} peer_absent={}", value == "30", !path.exists());
        assert!(preserved && value == "30" && !path.exists());
    });
}

#[test]
fn default_initial_denial_directory_and_missing_reads_preserve_sources() {
    in_private_process("config::option_tests::default_initial_denial_directory_and_missing_reads_preserve_sources", |_| {
        let file = Config::file_("_default");
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        let source = b"[options]\ncustom-fps = '25'\n";
        fs::write(&file, source).unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o000)).unwrap();
        let native = fs::read(&file).unwrap_err();
        let initial = UserDefaultConfig::get_option(keys::OPTION_CUSTOM_FPS);
        let unchanged_mode = fs::metadata(&file).unwrap().permissions().mode() & 0o777 == 0;
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(native.kind(), io::ErrorKind::PermissionDenied);
        assert!(initial == "30" && unchanged_mode && fs::read(&file).unwrap() == source);
        USER_DEFAULT_CONFIG.write().unwrap().1 = Instant::now() - Duration::from_secs(2);
        assert_eq!(UserDefaultConfig::get_option(keys::OPTION_CUSTOM_FPS), "25");
        fs::remove_file(&file).unwrap();
        fs::create_dir(&file).unwrap();
        let child = file.join("preserved");
        fs::write(&child, source).unwrap();
        for _ in 0..2 {
            USER_DEFAULT_CONFIG.write().unwrap().1 = Instant::now() - Duration::from_secs(2);
            assert_eq!(UserDefaultConfig::get_option(keys::OPTION_CUSTOM_FPS), "25");
            assert_eq!(fs::read(&child).unwrap(), source);
        }
        fs::remove_file(child).unwrap();
        fs::remove_dir(&file).unwrap();
        USER_DEFAULT_CONFIG.write().unwrap().1 = Instant::now() - Duration::from_secs(2);
        assert_eq!(UserDefaultConfig::get_option(keys::OPTION_CUSTOM_FPS), "30");
        assert!(!file.exists());
        println!("OPTION_COMMIT_DEFAULT_READONLY=observed kind=controls denied_errno={} mode_unchanged={unchanged_mode} retry=true directory_preserved=true missing_not_created=true", native.raw_os_error().unwrap());
    });
}

#[test]
fn default_single_key_writes_preserve_other_keys_and_concurrent_writers() {
    in_private_process("config::option_tests::default_single_key_writes_preserve_other_keys_and_concurrent_writers", |_| {
        assert_eq!(UserDefaultConfig::set_option("left".into(), "one".into()).unwrap(), "one");
        assert_eq!(UserDefaultConfig::set_option("right".into(), "two".into()).unwrap(), "two");
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
        let writers: Vec<_> = (0..8).map(|i| {
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                let key = format!("default-worker-{i}");
                assert_eq!(UserDefaultConfig::set_option(key, i.to_string()).unwrap(), i.to_string());
            })
        }).collect();
        for writer in writers { writer.join().unwrap(); }
        let stored = UserDefaultConfig::load();
        let all_preserved = stored.get("left") == "one" && stored.get("right") == "two"
            && (0..8).all(|i| stored.get(&format!("default-worker-{i}")) == i.to_string());
        let cache_current = USER_DEFAULT_CONFIG.read().unwrap().0.options == stored.options;
        println!("OPTION_COMMIT_DEFAULT_CONCURRENT=observed writers=8 keys_preserved={all_preserved} cache_current={cache_current} cleanup=joined");
        assert!(all_preserved && cache_current);
    });
}

#[test]
fn default_write_failure_preserves_cache_file_and_identical_retry() {
    in_private_process("config::option_tests::default_write_failure_preserves_cache_file_and_identical_retry", |_| {
        UserDefaultConfig::set_option("default-unrelated".into(), "preserved".into()).unwrap();
        let file = Config::file_("_default");
        let parent = file.parent().unwrap();
        UserDefaultConfig::set_option(keys::OPTION_VIEW_STYLE.into(), "adaptive".into()).unwrap();
        for requested in ["original", ""] {
            UserDefaultConfig::set_option(keys::OPTION_VIEW_STYLE.into(), "adaptive".into()).unwrap();
            let original = fs::read(&file).unwrap();
            fs::set_permissions(parent, fs::Permissions::from_mode(0o500)).unwrap();
            let failed = UserDefaultConfig::set_option(keys::OPTION_VIEW_STYLE.into(), requested.into()).is_err();
            let cache_preserved = USER_DEFAULT_CONFIG.read().unwrap().0.get(keys::OPTION_VIEW_STYLE) == "adaptive";
            let file_preserved = fs::read(&file).unwrap() == original;
            let unchanged = UserDefaultConfig::set_option(keys::OPTION_VIEW_STYLE.into(), "adaptive".into()).unwrap() == "adaptive";
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
            let effective = UserDefaultConfig::set_option(keys::OPTION_VIEW_STYLE.into(), requested.into()).unwrap();
            let stored = UserDefaultConfig::load();
            let retry_persisted = effective == "original" && stored.get(keys::OPTION_VIEW_STYLE) == effective;
            let cache_current = UserDefaultConfig::read(keys::OPTION_VIEW_STYLE) == effective;
            let unrelated_preserved = stored.get("default-unrelated") == "preserved";
            println!("OPTION_COMMIT_DEFAULT_NATIVE=observed removal={} failure_reported={failed} cache_preserved={cache_preserved} file_preserved={file_preserved} unchanged_without_write={unchanged} retry_persisted={retry_persisted} cache_current={cache_current} unrelated_preserved={unrelated_preserved}", requested.is_empty());
            assert!(failed && cache_preserved && file_preserved && unchanged && retry_persisted && cache_current && unrelated_preserved);
        }
    });
}

#[test]
fn default_purge_is_retryable_and_returns_effective_normalized_values() {
    in_private_process("config::option_tests::default_purge_is_retryable_and_returns_effective_normalized_values", |_| {
        let file = Config::file_("_default");
        for overwritten in [false, true] {
            UserDefaultConfig::set_option("default-purge".into(), "stored".into()).unwrap();
            let policy = if overwritten { &*OVERWRITE_DISPLAY_SETTINGS } else { &*DEFAULT_DISPLAY_SETTINGS };
            policy.write().unwrap().insert("default-purge".into(), "policy".into());
            let original = fs::read(&file).unwrap();
            let parent = file.parent().unwrap();
            fs::set_permissions(parent, fs::Permissions::from_mode(0o500)).unwrap();
            let failed = UserDefaultConfig::set_option("default-purge".into(), "policy".into()).is_err();
            let file_preserved = fs::read(&file).unwrap() == original;
            let cache_preserved = USER_DEFAULT_CONFIG.read().unwrap().0.options.get("default-purge").map(String::as_str) == Some("stored");
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
            let effective = UserDefaultConfig::set_option("default-purge".into(), "policy".into()).unwrap();
            let retry_purged = effective == "policy" && !UserDefaultConfig::load().options.contains_key("default-purge");
            fs::set_permissions(parent, fs::Permissions::from_mode(0o500)).unwrap();
            let idempotent = UserDefaultConfig::set_option("default-purge".into(), "policy".into()).unwrap() == "policy";
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
            policy.write().unwrap().clear();
            println!("OPTION_COMMIT_DEFAULT_PURGE=observed overwritten={overwritten} failure_reported={failed} cache_preserved={cache_preserved} file_preserved={file_preserved} retry_purged={retry_purged} idempotent_without_write={idempotent}");
            assert!(failed && cache_preserved && file_preserved && retry_purged && idempotent);
        }
        let normalized = UserDefaultConfig::set_option(keys::OPTION_CUSTOM_FPS.into(), "25.0".into()).unwrap() == "25"
            && UserDefaultConfig::read(keys::OPTION_CUSTOM_FPS) == "25";
        let fallback = UserDefaultConfig::set_option(keys::OPTION_CUSTOM_FPS.into(), "9999".into()).unwrap() == "30"
            && UserDefaultConfig::read(keys::OPTION_CUSTOM_FPS) == "30";
        println!("OPTION_COMMIT_DEFAULT_EFFECTIVE=observed normalized={normalized} existing_fallback_reported={fallback}");
        assert!(normalized && fallback);
        let disabled = UserDefaultConfig::set_option(keys::OPTION_ENABLE_FILE_COPY_PASTE.into(), "N".into()).unwrap() == "N"
            && UserDefaultConfig::get_option(keys::OPTION_ENABLE_FILE_COPY_PASTE) == "N";
        let restored = UserDefaultConfig::set_option(keys::OPTION_ENABLE_FILE_COPY_PASTE.into(), String::new()).unwrap() == "Y"
            && UserDefaultConfig::get_option(keys::OPTION_ENABLE_FILE_COPY_PASTE) == "Y";
        println!("OPTION_COMMIT_DEFAULT_BOOL=observed explicit_disabled={disabled} empty_restores_enabled_default={restored}");
        assert!(disabled && restored);
    });
}

#[test]
fn default_unreadable_source_refuses_mutation_without_losing_existing_values() {
    in_private_process("config::option_tests::default_unreadable_source_refuses_mutation_without_losing_existing_values", |_| {
        UserDefaultConfig::set_option("default-read-test".into(), "original".into()).unwrap();
        let file = Config::file_("_default");
        let original = fs::read(&file).unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o000)).unwrap();
        USER_DEFAULT_CONFIG.write().unwrap().1 = Instant::now() - Duration::from_secs(2);
        let read_preserved = UserDefaultConfig::get_option("default-read-test") == "original";
        let failed = UserDefaultConfig::set_option("default-read-test".into(), "replacement".into()).is_err();
        let cache_preserved = USER_DEFAULT_CONFIG.read().unwrap().0.get("default-read-test") == "original";
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        let file_preserved = fs::read(&file).unwrap() == original;
        let retried = UserDefaultConfig::set_option("default-read-test".into(), "replacement".into()).unwrap() == "replacement"
            && UserDefaultConfig::load().get("default-read-test") == "replacement";
        println!("OPTION_COMMIT_DEFAULT_READ=observed last_confirmed_read_preserved={read_preserved} failure_reported={failed} cache_preserved={cache_preserved} file_preserved={file_preserved} retry_persisted={retried}");
        assert!(read_preserved && failed && cache_preserved && file_preserved && retried);
    });
}

#[test]
fn last_peer_failure_preserves_state_and_retries_the_identical_value() {
    in_private_process("config::option_tests::last_peer_failure_preserves_state_and_retries_the_identical_value", |_| {
        LocalConfig::set_option("last-peer-test".into(), "preserved".into()).unwrap();
        LocalConfig::set_favorites(vec!["favorite-peer".into()], true).unwrap();
        let file = Config::file_("_local");
        let parent = file.parent().unwrap();

        for requested in ["127.0.0.1:24002", ""] {
            LocalConfig::set_remote_id("127.0.0.1:24001").unwrap();
            let original = fs::read(&file).unwrap();
            fs::set_permissions(parent, fs::Permissions::from_mode(0o500)).unwrap();
            let failed = LocalConfig::set_remote_id(requested).is_err();
            let memory_preserved = LocalConfig::get_remote_id() == "127.0.0.1:24001";
            let file_preserved = fs::read(&file).unwrap() == original;
            let unchanged_accepted = LocalConfig::set_remote_id("127.0.0.1:24001").is_ok();
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
            LocalConfig::set_remote_id(requested).unwrap();
            let stored: LocalConfig = load_path(file.clone());
            let retry_persisted = stored.remote_id == requested
                && LocalConfig::get_remote_id() == requested;
            let unrelated_preserved = stored.options.get("last-peer-test").map(String::as_str) == Some("preserved")
                && stored.fav == ["favorite-peer"];
            println!("OPTION_COMMIT_LAST_PEER_NATIVE=observed empty={} failure_reported={failed} memory_preserved={memory_preserved} file_preserved={file_preserved} unchanged_accepted={unchanged_accepted} retry_persisted={retry_persisted} unrelated_preserved={unrelated_preserved}", requested.is_empty());
            assert!(failed && memory_preserved && file_preserved && unchanged_accepted && retry_persisted && unrelated_preserved);
        }
    });
}

#[test]
fn retired_local_geometry_is_ignored_without_losing_live_preferences() {
    in_private_process("config::option_tests::retired_local_geometry_is_ignored_without_losing_live_preferences", |_| {
        let legacy = r#"
remote_id = "127.0.0.1:24001"
kb_layout_type = "iso"
size = [10, 20, 800, 600]
fav = ["favorite-peer"]
[options]
last-peer-test = "preserved"
[ui_flutter]
peer-view = "grid"
"#;
        let loaded: LocalConfig = toml::from_str(legacy).unwrap();
        let file = Config::file_("_local");
        store_path(file.clone(), &loaded).unwrap();
        *LOCAL_CONFIG.write().unwrap() = loaded;
        LocalConfig::set_remote_id("127.0.0.1:24002").unwrap();
        let stored: LocalConfig = load_path(file.clone());
        let serialized: toml::Value = toml::from_str(&fs::read_to_string(&file).unwrap()).unwrap();
        let geometry_absent = serialized.get("size").is_none();
        let preferences_preserved = stored.kb_layout_type == "iso"
            && stored.fav == ["favorite-peer"]
            && stored.options.get("last-peer-test").map(String::as_str) == Some("preserved")
            && stored.ui_flutter.get("peer-view").map(String::as_str) == Some("grid");
        let history_persisted = stored.remote_id == "127.0.0.1:24002";
        println!("OPTION_COMMIT_LAST_PEER_LEGACY=observed retired_geometry_absent={geometry_absent} preferences_preserved={preferences_preserved} history_persisted={history_persisted}");
        assert!(geometry_absent && preferences_preserved && history_persisted);
    });
}

#[test]
fn failed_write_preserves_memory_and_allows_the_same_retry() {
    in_private_process("config::option_tests::failed_write_preserves_memory_and_allows_the_same_retry", |_| {
        let mut outcomes = Vec::new();
        for requested in ["replacement-source", ""] {
            let _ = Config::set_option("audio-input".into(), "original-source".into());
            let _ = Config::set_option("enable-abr".into(), "N".into());
            let file = Config2::file();
            let parent = file.parent().unwrap();
            let before = fs::read(&file).unwrap();
            fs::set_permissions(parent, fs::Permissions::from_mode(0o500)).unwrap();
            let _ = Config::set_option("audio-input".into(), requested.into());
            let memory_preserved = Config::get_option("audio-input") == "original-source";
            let file_preserved = fs::read(&file).unwrap() == before;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
            let _ = Config::set_option("audio-input".into(), requested.into());
            let stored: Config2 = load_path(file);
            let retry_persisted = stored.options.get("audio-input").map(String::as_str).unwrap_or("") == requested;
            let unrelated_preserved = Config::get_option("enable-abr") == "N"
                && stored.options.get("enable-abr").map(String::as_str) == Some("N");
            println!("OPTION_COMMIT_WRITE=observed removal={} memory_preserved={memory_preserved} file_preserved={file_preserved} retry_persisted={retry_persisted} unrelated_preserved={unrelated_preserved}", requested.is_empty());
            outcomes.push(memory_preserved && file_preserved && retry_persisted && unrelated_preserved);
        }
        assert!(outcomes.into_iter().all(|passed| passed));
    });
}

fn ordinary_option_source_seed(tag: &str) -> Config2 {
    Config2 { options: [("audio-input".into(), tag.into()), ("unrelated".into(), format!("keep-{tag}")), ("enable-keyboard".into(), "N".into())].into() }
}

fn ordinary_option_source_actions() -> [(&'static str, &'static str, &'static str); 3] {
    [("replacement", "audio-input", "requested-source"), ("removal", "audio-input", ""), ("purge", "enable-keyboard", "N")]
}

fn ordinary_option_source_expected(mut source: Config2, action: &str) -> Config2 {
    match action {
        "replacement" => { source.options.insert("audio-input".into(), "requested-source".into()); }
        "removal" => { source.options.remove("audio-input"); }
        "purge" => { source.options.remove("enable-keyboard"); }
        _ => panic!("unknown ordinary option action"),
    }
    source
}

#[test]
fn ordinary_option_source_invalid_records_refuse_repeated_changes() {
    in_private_process("config::option_tests::ordinary_option_source_invalid_records_refuse_repeated_changes", |_| {
        use std::os::unix::fs::MetadataExt;
        let confirmed = ordinary_option_source_seed("confirmed");
        let file = Config2::file();
        store_path(file.clone(), &confirmed).unwrap();
        *CONFIG2.write().unwrap() = confirmed.clone();
        let parent = file.parent().unwrap();
        let names = || {
            let mut names = fs::read_dir(parent).unwrap().map(|e| e.unwrap().file_name()).collect::<Vec<_>>();
            names.sort(); names
        };
        let mut all_preserved = true;
        for (kind, bytes) in [
            ("syntax", b"[options]\nprivate-option-source = [\n".as_slice()),
            ("utf8", b"\xffprivate-option-source".as_slice()),
            ("integer", b"options = 7\n".as_slice()), ("boolean", b"options = false\n".as_slice()),
            ("string", b"options = 'private-option-source'\n".as_slice()), ("array", b"options = []\n".as_slice()),
            ("entry", b"[options]\nunrelated = 'preserved'\ninvalid = 7\n".as_slice()),
        ] {
            for (action, key, value) in ordinary_option_source_actions() {
                *CONFIG2.write().unwrap() = confirmed.clone();
                fs::write(&file, bytes).unwrap();
                let before = fs::metadata(&file).unwrap();
                let original_names = names();
                let first = Config::set_option(key.into(), value.into());
                let second = Config::set_option(key.into(), value.into());
                let fixed_errors = [&first, &second].iter().all(|r| r.as_ref().err().map(|e| e.to_string()).as_deref() == Some("Failed to read options"));
                let preserved = fs::read(&file).unwrap() == bytes && names() == original_names;
                let after = fs::metadata(&file).unwrap();
                let same_file = (before.dev(), before.ino(), before.mode()) == (after.dev(), after.ino(), after.mode());
                let cache_preserved = *CONFIG2.read().unwrap() == confirmed;
                println!("OPTION_COMMIT_ORDINARY_SOURCE=observed kind={kind} action={action} first_refused={} repeated_refused={} fixed_errors={fixed_errors} file_preserved={preserved} same_file={same_file} cache_preserved={cache_preserved}", first.is_err(), second.is_err());
                all_preserved &= first.is_err() && second.is_err() && fixed_errors && preserved && same_file && cache_preserved;
            }
        }
        assert!(all_preserved);
    });
}

#[test]
fn ordinary_option_source_denial_preserves_state_and_allows_retry() {
    in_private_process("config::option_tests::ordinary_option_source_denial_preserves_state_and_allows_retry", |_| {
        use std::os::unix::fs::MetadataExt;
        let confirmed = ordinary_option_source_seed("confirmed");
        let file = Config2::file();
        let mut all_preserved = true;
        for (action, key, value) in ordinary_option_source_actions() {
            store_path(file.clone(), &confirmed).unwrap();
            *CONFIG2.write().unwrap() = confirmed.clone();
            let bytes = fs::read(&file).unwrap();
            let before = fs::metadata(&file).unwrap();
            fs::set_permissions(&file, fs::Permissions::from_mode(0o000)).unwrap();
            let native = fs::read(&file).unwrap_err();
            let result = Config::set_option(key.into(), value.into());
            fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
            let preserved = fs::read(&file).unwrap() == bytes;
            let after = fs::metadata(&file).unwrap();
            let same_file = (before.dev(), before.ino()) == (after.dev(), after.ino());
            let cache_preserved = *CONFIG2.read().unwrap() == confirmed;
            assert_eq!(native.kind(), io::ErrorKind::PermissionDenied);
            store_path(file.clone(), &confirmed).unwrap();
            *CONFIG2.write().unwrap() = confirmed.clone();
            Config::set_option(key.into(), value.into()).unwrap();
            let expected = ordinary_option_source_expected(confirmed.clone(), action);
            let retry_durable = Config2::load() == expected && *CONFIG2.read().unwrap() == expected;
            println!("OPTION_COMMIT_ORDINARY_SOURCE=observed kind=denial action={action} errno={} refused={} file_preserved={preserved} same_file={same_file} cache_preserved={cache_preserved} retry_durable={retry_durable}", native.raw_os_error().unwrap(), result.is_err());
            all_preserved &= result.is_err() && preserved && same_file && cache_preserved && retry_durable;
        }
        fs::remove_file(&file).unwrap();
        fs::create_dir(&file).unwrap();
        let child = file.join("preserved");
        fs::write(&child, b"unchanged option source").unwrap();
        let result = Config::set_option("audio-input".into(), "directory-request".into());
        let directory_preserved = file.is_dir() && fs::read(child).unwrap() == b"unchanged option source";
        println!("OPTION_COMMIT_ORDINARY_SOURCE=observed kind=directory refused={} children_preserved={directory_preserved}", result.is_err());
        assert!(all_preserved && result.is_err() && directory_preserved);
    });
}

#[test]
fn ordinary_option_source_fresh_state_controls_change_and_idempotence() {
    in_private_process("config::option_tests::ordinary_option_source_fresh_state_controls_change_and_idempotence", |_| {
        use std::os::unix::fs::MetadataExt;
        let cached = ordinary_option_source_seed("cached");
        let external = ordinary_option_source_seed("external");
        let file = Config2::file();
        let parent = file.parent().unwrap();
        let mut all_current = true;
        for phase in ["external", "durable_match", "cache_match"] {
            for (action, key, value) in ordinary_option_source_actions() {
                let expected = ordinary_option_source_expected(external.clone(), action);
                let source = if phase == "durable_match" { &expected } else { &external };
                store_path(file.clone(), source).unwrap();
                *CONFIG2.write().unwrap() = if phase == "cache_match" { ordinary_option_source_expected(cached.clone(), action) } else { cached.clone() };
                let before = fs::metadata(&file).unwrap();
                let bytes = fs::read(&file).unwrap();
                if phase == "durable_match" { fs::set_permissions(parent, fs::Permissions::from_mode(0o500)).unwrap(); }
                let result = Config::set_option(key.into(), value.into());
                fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
                let durable_current = Config2::load() == expected;
                let cache_current = *CONFIG2.read().unwrap() == expected;
                let unchanged_if_satisfied = phase != "durable_match" || (fs::read(&file).unwrap() == bytes && fs::metadata(&file).unwrap().ino() == before.ino());
                let policy_pinned = Config::get_option("enable-keyboard") == "Y";
                println!("OPTION_COMMIT_ORDINARY_SOURCE=observed kind={phase} action={action} accepted={} durable_current={durable_current} cache_current={cache_current} unchanged_if_satisfied={unchanged_if_satisfied} policy_pinned={policy_pinned}", result.is_ok());
                all_current &= result.is_ok() && durable_current && cache_current && unchanged_if_satisfied && policy_pinned;
            }
        }
        for (action, key, value) in ordinary_option_source_actions().iter().skip(1) {
            if file.exists() { fs::remove_file(&file).unwrap(); }
            *CONFIG2.write().unwrap() = cached.clone();
            let result = Config::set_option((*key).into(), (*value).into());
            let absent = !file.exists();
            let cache_current = *CONFIG2.read().unwrap() == Config2::default();
            println!("OPTION_COMMIT_ORDINARY_SOURCE=observed kind=missing action={action} accepted={} absent={absent} cache_current={cache_current}", result.is_ok());
            all_current &= result.is_ok() && absent && cache_current;
        }
        assert!(all_current);
    });
}

#[test]
fn ordinary_option_source_initial_reads_preserve_invalid_files() {
    in_private_process("config::option_tests::ordinary_option_source_initial_reads_preserve_invalid_files", |_| {
        use std::os::unix::fs::MetadataExt;
        let file = Config2::file();
        let parent = file.parent().unwrap();
        fs::create_dir_all(parent).unwrap();
        let names = || {
            let mut names = fs::read_dir(parent).unwrap().map(|e| e.unwrap().file_name()).collect::<Vec<_>>();
            names.sort(); names
        };
        let mut all_preserved = true;
        for (kind, bytes) in [("syntax", b"[options]\nprivate-option-source = [\n".as_slice()), ("utf8", b"\xffprivate-option-source".as_slice()), ("shape", b"options = 7\n".as_slice())] {
            fs::write(&file, bytes).unwrap();
            let before = fs::metadata(&file).unwrap();
            let original_names = names();
            let loaded = Config2::load();
            let preserved = fs::read(&file).map(|b| b == bytes).unwrap_or(false) && names() == original_names;
            let same_file = fs::metadata(&file).map(|s| (s.dev(), s.ino(), s.mode()) == (before.dev(), before.ino(), before.mode())).unwrap_or(false);
            println!("OPTION_COMMIT_ORDINARY_SOURCE=observed kind=initial_{kind} file_preserved={preserved} same_file={same_file}");
            all_preserved &= loaded == Config2::default() && preserved && same_file;
        }
        assert!(all_preserved);
    });
}

#[test]
fn ordinary_option_source_healthy_missing_sparse_and_concurrent_controls() {
    in_private_process("config::option_tests::ordinary_option_source_healthy_missing_sparse_and_concurrent_controls", |_| {
        let file = Config2::file();
        assert_eq!(Config2::load(), Config2::default());
        assert!(!file.exists());
        Config::set_option("audio-input".into(), String::new()).unwrap();
        Config::set_option("enable-keyboard".into(), "N".into()).unwrap();
        assert!(!file.exists());
        Config::set_option("audio-input".into(), "first-source".into()).unwrap();
        assert_eq!(Config2::load().options, HashMap::from([("audio-input".into(), "first-source".into())]));
        Config::set_option("audio-input".into(), String::new()).unwrap();
        assert!(Config2::load().options.is_empty());
        fs::write(&file, "").unwrap();
        assert_eq!(Config2::load(), Config2::default());
        Config::set_option("audio-input".into(), "confirmed-source".into()).unwrap();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
        let writers: Vec<_> = (0..8).map(|i| {
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                Config::set_option(format!("ordinary-source-worker-{i}"), i.to_string()).unwrap();
            })
        }).collect();
        for writer in writers { writer.join().unwrap(); }
        let stored = Config2::load();
        assert_eq!(stored.options.get("audio-input").map(String::as_str), Some("confirmed-source"));
        assert_eq!(stored.options.len(), 9);
        assert!((0..8).all(|i| stored.options.get(&format!("ordinary-source-worker-{i}")) == Some(&i.to_string())));
        assert_eq!(*CONFIG2.read().unwrap(), stored);
        assert!(keys::PINNED_SETTINGS.iter().all(|(key, value)| Config::get_option(key) == *value));
        println!("OPTION_COMMIT_ORDINARY_SOURCE=observed kind=controls missing_noops_absent=true first_save=true empty_removal=true sparse_fields_default=true concurrent_writers=8 keys_preserved=true policy_pinned=true cleanup=joined");
    });
}

#[test]
fn ordinary_option_source_fifo_refuses_without_waiting_or_replacement() {
    const TEST: &str = "config::option_tests::ordinary_option_source_fifo_refuses_without_waiting_or_replacement";
    const CHILD: &str = "RUSTDESK_ORDINARY_OPTION_FIFO_CHILD";
    in_private_process(TEST, |_| {
        use std::os::unix::fs::{FileTypeExt, MetadataExt};
        let file = Config2::file();
        if std::env::var_os(CHILD).is_some() {
            println!("ORDINARY_OPTION_FIFO_BEGIN=entered");
            std::io::stdout().flush().unwrap();
            let fds = || fs::read_dir("/proc/self/fd").unwrap().count();
            let before = fds();
            for _ in 0..100 {
                assert!(read_config_view::<Config2>(&file).is_err());
            }
            assert_eq!(Config2::load(), Config2::default());
            assert!(Config::set_option("audio-input".into(), "fifo-request".into()).is_err());
            assert_eq!(*CONFIG2.read().unwrap(), Config2::default());
            let after = fds();
            assert_eq!(after, before);
            println!("OPTION_COMMIT_ORDINARY_SOURCE=observed kind=fifo_reader iterations=100 refused=true initial_default=true mutation_refused=true fds_before={before} fds_after={after}");
            return;
        }
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        let name = std::ffi::CString::new(std::os::unix::ffi::OsStrExt::as_bytes(file.as_os_str())).unwrap();
        assert_eq!(unsafe { crate::libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        let before = fs::metadata(&file).unwrap();
        assert!(before.file_type().is_fifo());
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([TEST, "--exact", "--color", "never", "--test-threads=1", "--nocapture"])
            .env(CHILD, "1")
            .stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped())
            .spawn().unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        let timed_out = loop {
            if child.try_wait().unwrap().is_some() { break false; }
            if Instant::now() >= deadline {
                child.kill().unwrap();
                break true;
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        let output = child.wait_with_output().unwrap();
        assert!(output.stdout.len() + output.stderr.len() <= 16384);
        let stdout = String::from_utf8(output.stdout).unwrap();
        let entered = stdout.lines().any(|line| line.contains("ORDINARY_OPTION_FIFO_BEGIN=entered"));
        for line in stdout.lines().filter(|line| line.starts_with("OPTION_COMMIT_")) { println!("{line}"); }
        let after = fs::metadata(&file).unwrap();
        let preserved = after.file_type().is_fifo() && (before.dev(), before.ino(), before.mode()) == (after.dev(), after.ino(), after.mode());
        println!("OPTION_COMMIT_ORDINARY_SOURCE=observed kind=fifo_parent child_entered={entered} timed_out={timed_out} child_success={} fifo_preserved={preserved} cleanup=joined", output.status.success());
        assert!(entered && !timed_out && output.status.success() && preserved);
    });
}

#[test]
fn failed_pinned_entry_purge_remains_retryable() {
    in_private_process("config::option_tests::failed_pinned_entry_purge_remains_retryable", |_| {
        let _ = Config::set_option("audio-input".into(), "original-source".into());
        CONFIG2.write().unwrap().options.insert("enable-keyboard".into(), "N".into());
        let file = Config2::file();
        store_path(file.clone(), &*CONFIG2.read().unwrap()).unwrap();
        let before = fs::read(&file).unwrap();
        let parent = file.parent().unwrap();
        fs::set_permissions(parent, fs::Permissions::from_mode(0o500)).unwrap();
        let _ = Config::set_option("enable-keyboard".into(), "N".into());
        let memory_preserved = CONFIG2.read().unwrap().options.get("enable-keyboard").map(String::as_str) == Some("N");
        let file_preserved = fs::read(&file).unwrap() == before;
        let policy_preserved = Config::get_option("enable-keyboard") == "Y";
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
        let _ = Config::set_option("enable-keyboard".into(), "N".into());
        let stored: Config2 = load_path(file);
        let retry_purged = !stored.options.contains_key("enable-keyboard")
            && !CONFIG2.read().unwrap().options.contains_key("enable-keyboard");
        let unrelated_preserved = stored.options.get("audio-input").map(String::as_str) == Some("original-source");
        println!("OPTION_COMMIT_PURGE=observed memory_preserved={memory_preserved} file_preserved={file_preserved} policy_preserved={policy_preserved} retry_purged={retry_purged} unrelated_preserved={unrelated_preserved}");
        assert!(memory_preserved && file_preserved && policy_preserved && retry_purged && unrelated_preserved);
    });
}

#[test]
fn results_distinguish_failed_saves_from_durable_and_idempotent_success() {
    in_private_process("config::option_tests::results_distinguish_failed_saves_from_durable_and_idempotent_success", |_| {
        Config::set_option("audio-input".into(), "original-source".into()).unwrap();
        let file = Config2::file();
        let parent = file.parent().unwrap();
        fs::set_permissions(parent, fs::Permissions::from_mode(0o500)).unwrap();
        let failure_returned = Config::set_option("audio-input".into(), "replacement-source".into()).is_err();
        let unchanged_accepted = Config::set_option("audio-input".into(), "original-source".into()).is_ok();
        let pinned_accepted = Config::set_option("enable-keyboard".into(), "N".into()).is_ok()
            && Config::get_option("enable-keyboard") == "Y";
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
        let retry_accepted = Config::set_option("audio-input".into(), "replacement-source".into()).is_ok();
        let stored: Config2 = load_path(file);
        let retry_persisted = stored.options.get("audio-input").map(String::as_str) == Some("replacement-source");
        println!("OPTION_COMMIT_RESULT=observed failure_returned={failure_returned} unchanged_accepted={unchanged_accepted} pinned_accepted={pinned_accepted} retry_accepted={retry_accepted} retry_persisted={retry_persisted}");
        assert!(failure_returned && unchanged_accepted && pinned_accepted && retry_accepted && retry_persisted);
    });
}

fn local_source_seed(tag: &str) -> LocalConfig {
    LocalConfig {
        remote_id: format!("host-{tag}"),
        kb_layout_type: format!("layout-{tag}"),
        fav: vec![format!("peer-{tag}")],
        options: [("selected".into(), tag.into()), ("unrelated".into(), format!("keep-{tag}"))].into(),
        ui_flutter: [("selected".into(), tag.into()), ("unrelated".into(), format!("keep-{tag}"))].into(),
    }
}

fn local_source_actions() -> [(&'static str, fn() -> crate::ResultType<()>); 5] {
    [
        ("history", || LocalConfig::set_remote_id("requested-host")),
        ("keyboard", || LocalConfig::set_kb_layout_type("Not ISO".into())),
        ("favorites", || LocalConfig::set_favorites(vec!["requested-peer".into()], true)),
        ("option", || LocalConfig::set_option("selected".into(), "requested".into())),
        ("flutter", || LocalConfig::set_flutter_option("selected".into(), "requested".into())),
    ]
}

fn local_source_expected(mut source: LocalConfig, action: &str) -> serde_json::Value {
    match action {
        "history" => source.remote_id = "requested-host".into(),
        "keyboard" => source.kb_layout_type = "Not ISO".into(),
        "favorites" => source.fav.push("requested-peer".into()),
        "option" => { source.options.insert("selected".into(), "requested".into()); }
        "flutter" => { source.ui_flutter.insert("selected".into(), "requested".into()); }
        _ => panic!("unknown local action"),
    }
    serde_json::to_value(source).unwrap()
}

#[test]
fn local_source_schema_failures_preserve_all_fields_and_refuse_mutations() {
    in_private_process("config::option_tests::local_source_schema_failures_preserve_all_fields_and_refuse_mutations", |_| {
        use std::os::unix::fs::MetadataExt;
        let confirmed = local_source_seed("confirmed");
        let healthy = toml::to_string(&confirmed).unwrap();
        let document: toml::Value = toml::from_str(&healthy).unwrap();
        let file = Config::file_("_local");
        store_path(file.clone(), &confirmed).unwrap();
        let parent = file.parent().unwrap();
        let names = || {
            let mut entries = fs::read_dir(parent).unwrap().map(|e| e.unwrap().file_name()).collect::<Vec<_>>();
            entries.sort(); entries
        };
        let original_names = names();
        let mut all_preserved = true;
        for field in ["remote_id", "kb_layout_type", "fav", "options", "ui_flutter"] {
            let nested = match field {
                "fav" => toml::Value::Array(vec![toml::Value::Integer(7)]),
                "options" | "ui_flutter" => toml::Value::Table(vec![("preserved".into(), toml::Value::String("keep".into())), ("invalid".into(), toml::Value::Integer(7))].into_iter().collect()),
                _ => toml::Value::Array(vec![toml::Value::String("invalid".into())]),
            };
            for (kind, malformed) in [("integer", toml::Value::Integer(7)), ("boolean", toml::Value::Boolean(false)), ("nested", nested)] {
                let mut broken = document.clone();
                broken.as_table_mut().unwrap().insert(field.into(), malformed);
                let bytes = toml::to_string(&broken).unwrap().into_bytes();
                fs::write(&file, &bytes).unwrap();
                let initial_rejected = LocalConfig::load() == LocalConfig::default()
                    && LocalConfig::get_option_from_file("selected").is_empty();
                let mut refused = true;
                let mut repeated_refused = true;
                let mut fixed_errors = true;
                let mut file_preserved = true;
                let mut cache_preserved = true;
                let mut same_file = true;
                let mut retry_durable = true;
                for (name, action) in local_source_actions() {
                    *LOCAL_CONFIG.write().unwrap() = confirmed.clone();
                    fs::write(&file, &bytes).unwrap();
                    let before = fs::metadata(&file).unwrap();
                    let first = action();
                    let second = action();
                    refused &= first.is_err();
                    repeated_refused &= second.is_err();
                    fixed_errors &= [&first, &second].iter().all(|result| result.as_ref().err().map(|error| error.to_string()).as_deref() == Some("Failed to read local preferences"));
                    file_preserved &= fs::read(&file).unwrap() == bytes && names() == original_names;
                    cache_preserved &= *LOCAL_CONFIG.read().unwrap() == confirmed;
                    let after = fs::metadata(&file).unwrap();
                    same_file &= (before.dev(), before.ino(), before.mode()) == (after.dev(), after.ino(), after.mode());
                    fs::write(&file, &healthy).unwrap();
                    action().unwrap();
                    let expected = local_source_expected(confirmed.clone(), name);
                    retry_durable &= serde_json::to_value(LocalConfig::load()).unwrap() == expected
                        && serde_json::to_value(&*LOCAL_CONFIG.read().unwrap()).unwrap() == expected;
                }
                println!("OPTION_COMMIT_PREFERENCE_SCHEMA=observed store=local field={field} kind={kind} actions=5 initial_rejected={initial_rejected} refused={refused} repeated_refused={repeated_refused} fixed_errors={fixed_errors} file_preserved={file_preserved} cache_preserved={cache_preserved} same_file={same_file} retry_durable={retry_durable}");
                all_preserved &= initial_rejected && refused && repeated_refused && fixed_errors && file_preserved && cache_preserved && same_file && retry_durable;
            }
        }
        assert!(all_preserved);
    });
}

#[test]
fn default_schema_failures_preserve_source_cache_and_retry() {
    in_private_process("config::option_tests::default_schema_failures_preserve_source_cache_and_retry", |_| {
        use std::os::unix::fs::MetadataExt;
        UserDefaultConfig::set_option("selected".into(), "confirmed".into()).unwrap();
        UserDefaultConfig::set_option("unrelated".into(), "preserved".into()).unwrap();
        let file = Config::file_("_default");
        let healthy = fs::read(&file).unwrap();
        let confirmed = UserDefaultConfig::load();
        let parent = file.parent().unwrap();
        let names = || {
            let mut entries = fs::read_dir(parent).unwrap().map(|e| e.unwrap().file_name()).collect::<Vec<_>>();
            entries.sort(); entries
        };
        let original_names = names();
        let mut all_preserved = true;
        for (kind, source) in [
            ("integer", "options = 7\n"), ("boolean", "options = false\n"),
            ("string", "options = 'invalid'\n"), ("array", "options = []\n"),
            ("entry_integer", "[options]\nunrelated = 'preserved'\ninvalid = 7\n"),
            ("entry_array", "[options]\nunrelated = 'preserved'\ninvalid = ['invalid']\n"),
        ] {
            fs::write(&file, source).unwrap();
            *USER_DEFAULT_CONFIG.write().unwrap() = (confirmed.clone(), Instant::now() - Duration::from_secs(2));
            let before = fs::metadata(&file).unwrap();
            let initial_default = UserDefaultConfig::load().options.is_empty();
            let refresh_preserved = UserDefaultConfig::get_option("selected") == "confirmed"
                && UserDefaultConfig::get_option("unrelated") == "preserved";
            let first = UserDefaultConfig::set_option("selected".into(), "requested".into());
            let second = UserDefaultConfig::set_option("selected".into(), "requested".into());
            let fixed_errors = [&first, &second].iter().all(|result| result.as_ref().err().map(|error| error.to_string()).as_deref() == Some("Failed to read default settings"));
            let cache_preserved = USER_DEFAULT_CONFIG.read().unwrap().0.options == confirmed.options;
            let file_preserved = fs::read(&file).unwrap() == source.as_bytes() && names() == original_names;
            let after = fs::metadata(&file).unwrap();
            let same_file = (before.dev(), before.ino(), before.mode()) == (after.dev(), after.ino(), after.mode());
            fs::write(&file, &healthy).unwrap();
            let retry = UserDefaultConfig::set_option("selected".into(), "requested".into()).unwrap();
            let stored = UserDefaultConfig::load();
            let retry_durable = retry == "requested" && stored.get("selected") == "requested"
                && stored.get("unrelated") == "preserved" && USER_DEFAULT_CONFIG.read().unwrap().0.options == stored.options;
            println!("OPTION_COMMIT_PREFERENCE_SCHEMA=observed store=default kind={kind} initial_default={initial_default} refresh_preserved={refresh_preserved} refused={} repeated_refused={} fixed_errors={fixed_errors} file_preserved={file_preserved} cache_preserved={cache_preserved} same_file={same_file} retry_durable={retry_durable}", first.is_err(), second.is_err());
            all_preserved &= initial_default && refresh_preserved && first.is_err() && second.is_err() && fixed_errors && file_preserved && cache_preserved && same_file && retry_durable;
        }
        assert!(all_preserved);
    });
}

#[test]
fn local_source_schema_missing_fields_preserve_healthy_round_trips() {
    in_private_process("config::option_tests::local_source_schema_missing_fields_preserve_healthy_round_trips", |_| {
        let confirmed = local_source_seed("confirmed");
        let healthy = toml::to_string(&confirmed).unwrap();
        let document: toml::Value = toml::from_str(&healthy).unwrap();
        let file = Config::file_("_local");
        store_path(file.clone(), &confirmed).unwrap();
        for field in ["remote_id", "kb_layout_type", "fav", "options", "ui_flutter"] {
            let mut sparse = document.clone();
            sparse.as_table_mut().unwrap().remove(field);
            let bytes = toml::to_string(&sparse).unwrap();
            let mut expected = serde_json::to_value(&confirmed).unwrap();
            expected[field] = serde_json::to_value(LocalConfig::default()).unwrap()[field].clone();
            for (name, action) in local_source_actions() {
                fs::write(&file, &bytes).unwrap();
                let loaded = LocalConfig::load();
                assert_eq!(serde_json::to_value(&loaded).unwrap(), expected);
                let expected_after = local_source_expected(loaded, name);
                action().unwrap();
                assert_eq!(serde_json::to_value(LocalConfig::load()).unwrap(), expected_after);
                assert_eq!(serde_json::to_value(&*LOCAL_CONFIG.read().unwrap()).unwrap(), expected_after);
            }
        }
        fs::write(&file, "").unwrap();
        assert_eq!(LocalConfig::load(), LocalConfig::default());
        let file = Config::file_("_default");
        fs::write(&file, "").unwrap();
        assert!(UserDefaultConfig::load().options.is_empty());
        assert_eq!(UserDefaultConfig::set_option(keys::OPTION_CUSTOM_FPS.into(), "25".into()).unwrap(), "25");
        assert_eq!(UserDefaultConfig::load().get(keys::OPTION_CUSTOM_FPS), "25");
        assert_eq!(UserDefaultConfig::set_option(keys::OPTION_CUSTOM_FPS.into(), String::new()).unwrap(), "30");
        assert!(UserDefaultConfig::load().options.is_empty());
        println!("OPTION_COMMIT_PREFERENCE_SCHEMA=observed kind=controls sparse_local_fields=5 actions_per_field=5 missing_fields_default=true valid_round_trips=true display_defaults_and_removal=true");
    });
}

#[test]
fn local_source_initial_and_direct_reads_preserve_corruption() {
    in_private_process("config::option_tests::local_source_initial_and_direct_reads_preserve_corruption", |_| {
        use std::os::unix::fs::MetadataExt;
        let file = Config::file_("_local");
        let parent = file.parent().unwrap();
        fs::create_dir_all(parent).unwrap();
        let readers: [(&str, fn()); 2] = [("initial", || { let _ = LocalConfig::load(); }), ("direct", || { let _ = LocalConfig::get_option_from_file("selected"); })];
        let mut all_preserved = true;
        for (kind, bytes) in [("syntax", b"[options]\nprivate-local-source = [\n".as_slice()), ("utf8", b"\xffprivate-local-source".as_slice())] {
            for (reader, read) in readers {
                fs::write(&file, bytes).unwrap();
                let before = fs::metadata(&file).unwrap();
                read();
                let preserved = fs::read(&file).map(|b| b == bytes).unwrap_or(false);
                let same_file = fs::metadata(&file).map(|s| (s.dev(), s.ino()) == (before.dev(), before.ino())).unwrap_or(false);
                println!("OPTION_COMMIT_LOCAL_SOURCE=observed kind={kind} reader={reader} file_preserved={preserved} same_file={same_file}");
                all_preserved &= preserved && same_file;
            }
        }
        assert!(all_preserved);
    });
}

#[test]
fn local_source_denial_refuses_every_mutation_and_allows_retry() {
    in_private_process("config::option_tests::local_source_denial_refuses_every_mutation_and_allows_retry", |_| {
        let source = local_source_seed("confirmed");
        let file = Config::file_("_local");
        let mut all_preserved = true;
        for (name, action) in local_source_actions() {
            store_path(file.clone(), &source).unwrap();
            *LOCAL_CONFIG.write().unwrap() = source.clone();
            let bytes = fs::read(&file).unwrap();
            fs::set_permissions(&file, fs::Permissions::from_mode(0o000)).unwrap();
            let native = fs::read(&file).unwrap_err();
            let result = action();
            fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
            let preserved = fs::read(&file).unwrap() == bytes;
            let cache_preserved = serde_json::to_value(&*LOCAL_CONFIG.read().unwrap()).unwrap() == serde_json::to_value(&source).unwrap();
            assert_eq!(native.kind(), io::ErrorKind::PermissionDenied);
            println!("OPTION_COMMIT_LOCAL_SOURCE=observed kind=denial action={name} errno={} refused={} file_preserved={preserved} cache_preserved={cache_preserved}", native.raw_os_error().unwrap(), result.is_err());
            all_preserved &= result.is_err() && preserved && cache_preserved;
            store_path(file.clone(), &source).unwrap();
            *LOCAL_CONFIG.write().unwrap() = source.clone();
            action().unwrap();
            let stored: LocalConfig = toml::from_str(&fs::read_to_string(&file).unwrap()).unwrap();
            assert_eq!(serde_json::to_value(stored).unwrap(), local_source_expected(source.clone(), name));
        }
        assert!(all_preserved);
    });
}

#[test]
fn local_source_corruption_refuses_repeated_mutations_without_recovery() {
    in_private_process("config::option_tests::local_source_corruption_refuses_repeated_mutations_without_recovery", |_| {
        let source = local_source_seed("confirmed");
        let file = Config::file_("_local");
        store_path(file.clone(), &source).unwrap();
        let mut all_preserved = true;
        for (kind, bytes) in [("syntax", b"[options]\nprivate-local-source = [\n".as_slice()), ("utf8", b"\xffprivate-local-source".as_slice())] {
            for (name, action) in local_source_actions() {
                *LOCAL_CONFIG.write().unwrap() = source.clone();
                fs::write(&file, bytes).unwrap();
                let first = action();
                let second = action();
                let preserved = fs::read(&file).map(|b| b == bytes).unwrap_or(false);
                let cache_preserved = serde_json::to_value(&*LOCAL_CONFIG.read().unwrap()).unwrap() == serde_json::to_value(&source).unwrap();
                println!("OPTION_COMMIT_LOCAL_SOURCE=observed kind={kind} action={name} first_refused={} repeated_refused={} file_preserved={preserved} cache_preserved={cache_preserved}", first.is_err(), second.is_err());
                if let Err(error) = first.as_ref() { assert!(!error.to_string().contains("private-local-source")); }
                all_preserved &= first.is_err() && second.is_err() && preserved && cache_preserved;
            }
        }
        assert!(all_preserved);
    });
}

#[test]
fn local_source_mutations_preserve_completed_external_changes() {
    in_private_process("config::option_tests::local_source_mutations_preserve_completed_external_changes", |_| {
        let cached = local_source_seed("cached");
        let external = local_source_seed("external");
        let file = Config::file_("_local");
        let mut all_preserved = true;
        for (name, action) in local_source_actions() {
            store_path(file.clone(), &external).unwrap();
            *LOCAL_CONFIG.write().unwrap() = cached.clone();
            action().unwrap();
            let stored: LocalConfig = toml::from_str(&fs::read_to_string(&file).unwrap()).unwrap();
            let expected = local_source_expected(external.clone(), name);
            let file_current = serde_json::to_value(stored).unwrap() == expected;
            let cache_current = serde_json::to_value(&*LOCAL_CONFIG.read().unwrap()).unwrap() == expected;
            println!("OPTION_COMMIT_LOCAL_SOURCE=observed kind=external action={name} file_current={file_current} cache_current={cache_current}");
            all_preserved &= file_current && cache_current;
        }
        assert!(all_preserved);
    });
}

#[test]
fn local_source_idempotence_uses_durable_values_and_refreshes_cache() {
    in_private_process("config::option_tests::local_source_idempotence_uses_durable_values_and_refreshes_cache", |_| {
        use std::os::unix::fs::MetadataExt;
        let cached = local_source_seed("cached");
        let external = local_source_seed("external");
        let file = Config::file_("_local");
        let parent = file.parent().unwrap();
        let mut all_preserved = true;
        for (name, action) in local_source_actions() {
            let expected = local_source_expected(external.clone(), name);
            let durable: LocalConfig = serde_json::from_value(expected.clone()).unwrap();
            store_path(file.clone(), &durable).unwrap();
            *LOCAL_CONFIG.write().unwrap() = cached.clone();
            let before = fs::metadata(&file).unwrap();
            let bytes = fs::read(&file).unwrap();
            fs::set_permissions(parent, fs::Permissions::from_mode(0o500)).unwrap();
            let result = action();
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
            let same_file = fs::metadata(&file).unwrap().ino() == before.ino() && fs::read(&file).unwrap() == bytes;
            let cache_current = serde_json::to_value(&*LOCAL_CONFIG.read().unwrap()).unwrap() == expected;
            println!("OPTION_COMMIT_LOCAL_SOURCE=observed kind=idempotent action={name} success={} same_file={same_file} cache_current={cache_current}", result.is_ok());
            all_preserved &= result.is_ok() && same_file && cache_current;
        }
        assert!(all_preserved);
    });
}

#[test]
fn local_source_missing_noops_do_not_create_and_first_saves_work() {
    in_private_process("config::option_tests::local_source_missing_noops_do_not_create_and_first_saves_work", |_| {
        let file = Config::file_("_local");
        LocalConfig::set_remote_id("").unwrap();
        LocalConfig::set_kb_layout_type(String::new()).unwrap();
        LocalConfig::set_favorites(vec!["missing".into()], false).unwrap();
        LocalConfig::set_option("selected".into(), String::new()).unwrap();
        LocalConfig::set_flutter_option("selected".into(), String::new()).unwrap();
        assert!(!file.exists());
        for (name, action) in local_source_actions() {
            if file.exists() { fs::remove_file(&file).unwrap(); }
            *LOCAL_CONFIG.write().unwrap() = LocalConfig::default();
            action().unwrap();
            let stored: LocalConfig = toml::from_str(&fs::read_to_string(&file).unwrap()).unwrap();
            assert_eq!(serde_json::to_value(stored).unwrap(), local_source_expected(LocalConfig::default(), name));
        }
        println!("OPTION_COMMIT_LOCAL_SOURCE=observed kind=controls missing_noops_absent=true first_saves=5");
    });
}

#[test]
fn favorite_failure_preserves_state_and_retries_the_exact_membership_change() {
    in_private_process("config::option_tests::favorite_failure_preserves_state_and_retries_the_exact_membership_change", |_| {
        LocalConfig::set_flutter_option("favorite-test".into(), "preserved".into()).unwrap();
        LocalConfig::set_favorites(vec!["original".into()], true).unwrap();
        let file = Config::file_("_local");
        let parent = file.parent().unwrap();

        for favorite in [true, false] {
            let memory = LocalConfig::get_fav();
            let durable = fs::read(&file).unwrap();
            fs::set_permissions(parent, fs::Permissions::from_mode(0o500)).unwrap();
            let failed = LocalConfig::set_favorites(vec!["second".into()], favorite).is_err();
            let memory_preserved = LocalConfig::get_fav() == memory;
            let file_preserved = fs::read(&file).unwrap() == durable;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
            LocalConfig::set_favorites(vec!["second".into()], favorite).unwrap();
            let stored: LocalConfig = load_path(file.clone());
            let retry_persisted = stored.fav == LocalConfig::get_fav()
                && stored.fav.contains(&"second".to_owned()) == favorite;
            let unrelated_preserved = stored.ui_flutter.get("favorite-test").map(String::as_str) == Some("preserved")
                && stored.fav.contains(&"original".to_owned());
            println!("OPTION_COMMIT_FAVORITES_NATIVE=observed favorite={favorite} failure_reported={failed} memory_preserved={memory_preserved} file_preserved={file_preserved} retry_persisted={retry_persisted} unrelated_preserved={unrelated_preserved}");
            assert!(failed && memory_preserved && file_preserved && retry_persisted && unrelated_preserved);
        }
    });
}

#[test]
fn favorite_membership_preserves_order_and_avoids_idempotent_writes() {
    in_private_process("config::option_tests::favorite_membership_preserves_order_and_avoids_idempotent_writes", |_| {
        LocalConfig::set_favorites(vec!["one".into(), "two".into(), "one".into(), "three".into()], true).unwrap();
        assert_eq!(LocalConfig::get_fav(), ["one", "two", "three"]);
        LocalConfig::set_favorites(vec!["two".into(), "missing".into()], false).unwrap();
        LocalConfig::set_favorites(vec!["one".into(), "four".into()], true).unwrap();
        assert_eq!(LocalConfig::get_fav(), ["one", "three", "four"]);
        let file = Config::file_("_local");
        let parent = file.parent().unwrap();
        let durable = fs::read(&file).unwrap();
        fs::set_permissions(parent, fs::Permissions::from_mode(0o500)).unwrap();
        LocalConfig::set_favorites(vec!["one".into(), "three".into()], true).unwrap();
        LocalConfig::set_favorites(vec!["missing".into()], false).unwrap();
        assert_eq!(fs::read(&file).unwrap(), durable);
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
        println!("OPTION_COMMIT_FAVORITES_MEMBERSHIP=observed order=preserved duplicates=absent idempotent=without-write");
    });
}

#[test]
fn concurrent_favorite_membership_changes_preserve_every_admitted_id() {
    in_private_process("config::option_tests::concurrent_favorite_membership_changes_preserve_every_admitted_id", |_| {
        let start = std::sync::Barrier::new(8);
        std::thread::scope(|scope| {
            for index in 0..8 {
                let start = &start;
                scope.spawn(move || {
                    start.wait();
                    LocalConfig::set_favorites(vec![format!("peer-{index}")], true).unwrap();
                });
            }
        });
        let current = LocalConfig::get_fav();
        assert_eq!(current.len(), 8);
        for index in 0..8 {
            assert!(current.contains(&format!("peer-{index}")));
        }
        let stored: LocalConfig = load_path(Config::file_("_local"));
        assert_eq!(stored.fav, current);
        println!("OPTION_COMMIT_FAVORITES_CONCURRENT=observed writers=8 ids=8 durable=equal cleanup=joined");
    });
}

#[test]
fn keyboard_layout_failure_preserves_mapping_and_allows_retry() {
    in_private_process("config::option_tests::keyboard_layout_failure_preserves_mapping_and_allows_retry", |_| {
        let file = Config::file_("_local");
        let parent = file.parent().unwrap();

        LocalConfig::set_kb_layout_type("ISO".into()).unwrap();
        LocalConfig::set_favorites(vec!["original".into()], true).unwrap();
        let original = fs::read(&file).unwrap();
        fs::set_permissions(parent, fs::Permissions::from_mode(0o500)).unwrap();
        let failed = LocalConfig::set_kb_layout_type("Not ISO".into()).is_err();
        let memory_preserved = LocalConfig::get_kb_layout_type() == "ISO";
        let file_preserved = fs::read(&file).unwrap() == original;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
        LocalConfig::set_kb_layout_type("Not ISO".into()).unwrap();
        let stored: LocalConfig = load_path(file.clone());
        let retry_persisted = stored.kb_layout_type == "Not ISO"
            && LocalConfig::get_kb_layout_type() == stored.kb_layout_type;
        let unrelated_preserved = stored.fav == ["original"];
        let durable = fs::read(&file).unwrap();
        fs::set_permissions(parent, fs::Permissions::from_mode(0o500)).unwrap();
        LocalConfig::set_kb_layout_type("Not ISO".into()).unwrap();
        let idempotent = fs::read(&file).unwrap() == durable;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
        println!("OPTION_COMMIT_KEYBOARD_NATIVE=observed failure_reported={failed} memory_preserved={memory_preserved} file_preserved={file_preserved} retry_persisted={retry_persisted} unrelated_preserved={unrelated_preserved} idempotent_without_write={idempotent}");
        assert!(failed && memory_preserved && file_preserved && retry_persisted && unrelated_preserved && idempotent);
    });
}

#[test]
fn flutter_option_failure_preserves_state_and_retries_without_crossing_namespaces() {
    in_private_process("config::option_tests::flutter_option_failure_preserves_state_and_retries_without_crossing_namespaces", |_| {
        let key = "flutter-option-commit-test";
        LocalConfig::set_option(key.into(), "general-preserved".into()).unwrap();
        LocalConfig::set_favorites(vec!["preserved".into()], true).unwrap();
        LocalConfig::set_kb_layout_type("ISO".into()).unwrap();
        let file = Config::file_("_local");
        let parent = file.parent().unwrap();

        for value in ["ui-replacement", ""] {
            LocalConfig::set_flutter_option(key.into(), "ui-original".into()).unwrap();
            let original = fs::read(&file).unwrap();
            fs::set_permissions(parent, fs::Permissions::from_mode(0o500)).unwrap();
            let failed = LocalConfig::set_flutter_option(key.into(), value.into()).is_err();
            let memory_preserved = LocalConfig::get_flutter_option(key) == "ui-original";
            let file_preserved = fs::read(&file).unwrap() == original;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
            LocalConfig::set_flutter_option(key.into(), value.into()).unwrap();
            let stored: LocalConfig = load_path(file.clone());
            let retry_persisted = stored.ui_flutter.get(key).map(String::as_str).unwrap_or("") == value
                && LocalConfig::get_flutter_option(key) == value;
            let unrelated_preserved = LocalConfig::get_option(key) == "general-preserved"
                && stored.options.get(key).map(String::as_str) == Some("general-preserved")
                && stored.fav == ["preserved"] && stored.kb_layout_type == "ISO";
            let durable = fs::read(&file).unwrap();
            fs::set_permissions(parent, fs::Permissions::from_mode(0o500)).unwrap();
            LocalConfig::set_flutter_option(key.into(), value.into()).unwrap();
            let idempotent = fs::read(&file).unwrap() == durable;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
            println!("OPTION_COMMIT_UI_STATE_NATIVE=observed removal={} failure_reported={failed} memory_preserved={memory_preserved} file_preserved={file_preserved} retry_persisted={retry_persisted} unrelated_preserved={unrelated_preserved} idempotent_without_write={idempotent}", value.is_empty());
            assert!(failed && memory_preserved && file_preserved && retry_persisted && unrelated_preserved && idempotent);
        }
    });
}

#[test]
fn local_option_failure_preserves_state_and_retries_replacement_and_removal() {
    in_private_process("config::option_tests::local_option_failure_preserves_state_and_retries_replacement_and_removal", |_| {
        let key = "local-option-commit-test";
        let file = Config::file_("_local");
        let parent = file.parent().unwrap();
        LocalConfig::set_favorites(vec!["preserved".into()], true).unwrap();
        for value in ["replacement", ""] {
            LocalConfig::set_option(key.into(), "original".into()).unwrap();
            let original = fs::read(&file).unwrap();
            fs::set_permissions(parent, fs::Permissions::from_mode(0o500)).unwrap();
            let failed = LocalConfig::set_option(key.into(), value.into()).is_err();
            let memory = LocalConfig::get_option(key) == "original";
            let durable = fs::read(&file).unwrap() == original;
            LocalConfig::set_option(key.into(), "original".into()).unwrap();
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
            LocalConfig::set_option(key.into(), value.into()).unwrap();
            let stored: LocalConfig = load_path(file.clone());
            let retry = stored.options.get(key).map(String::as_str).unwrap_or("") == value
                && LocalConfig::get_option(key) == value;
            let unrelated = stored.fav == ["preserved"];
            println!("OPTION_COMMIT_LOCAL_NATIVE=observed removal={} failure_reported={failed} memory_preserved={memory} file_preserved={durable} retry_persisted={retry} unrelated_preserved={unrelated}", value.is_empty());
            assert!(failed && memory && durable && retry && unrelated);
        }
    });
}

#[test]
fn local_option_purge_failure_preserves_overrides_and_defaults() {
    in_private_process("config::option_tests::local_option_purge_failure_preserves_overrides_and_defaults", |_| {
        for overwritten in [true, false] {
            let key = if overwritten { "local-override-test" } else { "local-default-test" };
            if overwritten {
                OVERWRITE_LOCAL_SETTINGS.write().unwrap().insert(key.into(), "fixed".into());
            } else {
                DEFAULT_LOCAL_SETTINGS.write().unwrap().insert(key.into(), "fixed".into());
            }
            LOCAL_CONFIG.write().unwrap().options.insert(key.into(), "stale".into());
            let file = Config::file_("_local");
            store_path(file.clone(), &*LOCAL_CONFIG.read().unwrap()).unwrap();
            let original = fs::read(&file).unwrap();
            let parent = file.parent().unwrap();
            fs::set_permissions(parent, fs::Permissions::from_mode(0o500)).unwrap();
            let failed = LocalConfig::set_option(key.into(), "fixed".into()).is_err();
            let memory = LOCAL_CONFIG.read().unwrap().options.get(key).map(String::as_str) == Some("stale");
            let durable = fs::read(&file).unwrap() == original;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
            LocalConfig::set_option(key.into(), "fixed".into()).unwrap();
            let stored: LocalConfig = load_path(file.clone());
            let purged = !stored.options.contains_key(key) && LocalConfig::get_option(key) == "fixed";
            fs::set_permissions(parent, fs::Permissions::from_mode(0o500)).unwrap();
            LocalConfig::set_option(key.into(), "fixed".into()).unwrap();
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
            println!("OPTION_COMMIT_LOCAL_PURGE=observed overwritten={overwritten} failure_reported={failed} memory_preserved={memory} file_preserved={durable} retry_purged={purged} idempotent_without_write=true");
            assert!(failed && memory && durable && purged);
        }
    });
}

#[test]
fn local_system_language_is_explicit_durable_and_retryable() {
    in_private_process("config::option_tests::local_system_language_is_explicit_durable_and_retryable", |_| {
        DEFAULT_LOCAL_SETTINGS.write().unwrap().insert(keys::OPTION_LANGUAGE.into(), "de".into());
        LocalConfig::set_option(keys::OPTION_LANGUAGE.into(), "fr".into()).unwrap();
        let file = Config::file_("_local");
        let parent = file.parent().unwrap();
        let original = fs::read(&file).unwrap();
        fs::set_permissions(parent, fs::Permissions::from_mode(0o500)).unwrap();
        let failed = LocalConfig::set_option(keys::OPTION_LANGUAGE.into(), "default".into()).is_err();
        let memory = LocalConfig::get_option(keys::OPTION_LANGUAGE) == "fr";
        let durable = fs::read(&file).unwrap() == original;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
        LocalConfig::set_option(keys::OPTION_LANGUAGE.into(), "default".into()).unwrap();
        let stored: LocalConfig = load_path(file.clone());
        let explicit = stored.options.get(keys::OPTION_LANGUAGE).map(String::as_str) == Some("")
            && LocalConfig::get_option(keys::OPTION_LANGUAGE).is_empty();
        fs::set_permissions(parent, fs::Permissions::from_mode(0o500)).unwrap();
        LocalConfig::set_option(keys::OPTION_LANGUAGE.into(), "default".into()).unwrap();
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
        LocalConfig::set_option(keys::OPTION_LANGUAGE.into(), "".into()).unwrap();
        let stored: LocalConfig = load_path(file);
        let default_restored = !stored.options.contains_key(keys::OPTION_LANGUAGE)
            && LocalConfig::get_option(keys::OPTION_LANGUAGE) == "de";
        println!("OPTION_COMMIT_LOCAL_LANGUAGE=observed failure_reported={failed} memory_preserved={memory} file_preserved={durable} retry_explicit={explicit} default_restored={default_restored} idempotent_without_write=true");
        assert!(failed && memory && durable && explicit && default_restored);
    });
}

#[test]
fn peer_retired_password_shapes_preserve_live_state_and_allow_explicit_cleanup() {
    in_private_process("config::option_tests::peer_retired_password_shapes_preserve_live_state_and_allow_explicit_cleanup", |_| {
        for (index, retired) in ["[]", "\"discard-me\"", "\"\"", "true", "42", "{ obsolete = [1, 2] }"].iter().enumerate() {
            for remembered in [false, true] {
                let id = format!("peer-retired-shape-{index}-{remembered}");
                let mut peer = PeerConfig::default();
                peer.info.platform = "Linux".into();
                peer.options.insert("alias".into(), "preserved".into());
                if remembered { peer.password_prs = b"fixture-current-peer-prs".to_vec(); }
                peer.store(&id).unwrap();
                let mut expected = PeerConfig::load_for_write(&id).unwrap();
                let path = PeerConfig::path(&id);
                let original = fs::read_to_string(&path).unwrap();
                let document: toml::Value = toml::from_str(&original).unwrap();
                assert!(document.get("password").is_none());
                fs::write(&path, format!("password = {retired}\n{original}")).unwrap();
                let old_bytes = fs::read(&path).unwrap();
                assert_eq!(PeerConfig::load_for_write(&id).unwrap(), expected);
                assert_eq!(fs::read(&path).unwrap(), old_bytes);
                PeerConfig::forget_password(&id).unwrap();
                expected.password_prs.clear();
                assert_eq!(PeerConfig::load_for_write(&id).unwrap(), expected);
                let document: toml::Value = toml::from_str(&fs::read_to_string(path).unwrap()).unwrap();
                assert!(document.get("password").is_none());
            }
        }
        println!("OPTION_COMMIT_PEER_RETIRED=observed kind=shapes formats=6 prs_states=2 live_state_preserved=true old_field_purged=true");
    });
}
