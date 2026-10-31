use super::{
    cstring_from_os_str, ensure_recv_child_matches_open_file, io_invalid_input,
    open_regular_child_no_follow, remove_recv_child_at, sync_recv_directory,
    sync_recv_regular_file, unix_directory_entry_names, unix_fstat, unix_fstatat_no_follow,
    unix_require_same_object, EmptyDirectoryRemovalState, ReceiveFileCreation,
    ReceiveOwnedArtifact, RegularFileAccess,
};
use crate::{libc, sha2::{Digest, Sha256}};
use serde_derive::{Deserialize, Serialize};
use std::{
    ffi::{CStr, CString, OsStr},
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    os::unix::{ffi::OsStrExt, fs::{MetadataExt, OpenOptionsExt}, io::{AsRawFd, FromRawFd}},
    path::{Component, Path},
};

fn refused(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}

fn name(value: &str) -> io::Result<CString> {
    cstring_from_os_str(OsStr::new(value), "receive namespace")
}

fn lock(file: &File, operation: i32) -> io::Result<()> {
    loop {
        if unsafe { libc::flock(file.as_raw_fd(), operation) } == 0 { return Ok(()); }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted { return Err(error); }
    }
}

fn directory_at(parent: &File, child: &CStr) -> io::Result<File> {
    let fd = unsafe {
        libc::openat(parent.as_raw_fd(), child.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
    };
    if fd < 0 { return Err(io::Error::last_os_error()); }
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn private_directory(directory: &File) -> io::Result<()> {
    let metadata = directory.metadata()?;
    if !metadata.is_dir() || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o7777 != 0o700 {
        return Err(refused("receive namespace must be an effective-owner private directory"));
    }
    Ok(())
}

fn is_empty(directory: &File) -> io::Result<bool> {
    // A dup shares its directory offset. Reopen the retained object so retries
    // cannot mistake an exhausted enumeration for an empty namespace.
    let scan = directory_at(directory, &name(".")?)?;
    Ok(unix_directory_entry_names(&scan, &mut EmptyDirectoryRemovalState::default())?.is_empty())
}

fn mkdir_at(parent: &File, child: &CStr) -> io::Result<()> {
    if unsafe { libc::mkdirat(parent.as_raw_fd(), child.as_ptr(), 0o700) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn private_child(parent: &File, child: &CStr) -> io::Result<File> {
    match mkdir_at(parent, child) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    let directory = directory_at(parent, child)?;
    private_directory(&directory)?;
    sync_recv_directory(&directory)?;
    sync_recv_directory(parent)?;
    Ok(directory)
}

fn coordinator() -> io::Result<File> {
    // Credential/service configuration selects this same effective principal from NSS.
    // Neither HOME nor a peer-selected destination chooses the coordination authority.
    let home = crate::platform::linux::get_effective_home_dir_trusted()
        .ok_or_else(|| refused("receive namespace effective-owner home is unavailable"))?;
    if !home.is_absolute() { return Err(io_invalid_input("receive owner home must be absolute")); }
    let mut directory = OpenOptions::new().read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC).open("/")?;
    let owner = unsafe { libc::geteuid() };
    for component in home.components() {
        let metadata = directory.metadata()?;
        if ![0, owner].contains(&metadata.uid())
            || (metadata.mode() & 0o022 != 0 && metadata.mode() & 0o1000 == 0) {
            return Err(refused("receive coordination ancestry is mutable by another principal"));
        }
        match component {
            Component::RootDir => {}
            Component::Normal(child) => {
                directory = directory_at(&directory, &cstring_from_os_str(child, "receive owner home")?)?;
            }
            _ => return Err(io_invalid_input("receive owner home contains an invalid component")),
        }
    }
    let metadata = directory.metadata()?;
    if metadata.uid() != owner
        || (metadata.mode() & 0o022 != 0 && metadata.mode() & 0o1000 == 0) {
        return Err(refused("receive coordination home is not protected by its effective owner"));
    }
    private_child(&directory, &name(".rustdesk-receive")?)
}

fn directory_key(directory: &File) -> io::Result<String> {
    let mut filesystem: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs(directory.as_raw_fd(), &mut filesystem) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut digest = Sha256::new();
    digest.update(b"rustdesk.receive.directory.v1\0");
    // This is a lookup key, not object authority or a portable remount guarantee.
    // Admission also proves the private directory and its recorded identity below.
    let fsid = unsafe { std::slice::from_raw_parts(
        (&filesystem.f_fsid as *const libc::fsid_t).cast::<u8>(),
        std::mem::size_of::<libc::fsid_t>(),
    ) };
    digest.update(fsid);
    digest.update((filesystem.f_type as u64).to_le_bytes());
    digest.update(directory.metadata()?.ino().to_le_bytes());
    Ok(format!("{:x}", digest.finalize()))
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DirectoryRecord {
    version: u8,
    name: String,
    // None records durable setup intent; only Some admits transfer artifacts.
    inode: Option<u64>,
    // The protected record name carries retirement state without a new data write.
    #[serde(skip)]
    retiring: bool,
}

fn retirement_record_name(record_name: &CStr) -> io::Result<CString> {
    let record = record_name.to_str()
        .map_err(|_| io_invalid_input("receive record name is not UTF-8"))?;
    name(&format!("{record}.retiring"))
}

fn read_record(coordinator: &File, record_name: &CStr) -> io::Result<Option<DirectoryRecord>> {
    let retirement_name = retirement_record_name(record_name)?;
    let mut selected = None;
    for (candidate, retiring) in [(record_name, false), (retirement_name.as_c_str(), true)] {
        let file = match open_regular_child_no_follow(coordinator, candidate,
            RegularFileAccess::Read, ReceiveFileCreation::Existing) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        ReceiveOwnedArtifact::Payload.validate(&file)?;
        if selected.is_some() {
            return Err(refused("receive directory has conflicting lifecycle records"));
        }
        selected = Some((file, retiring));
    }
    let Some((file, retiring)) = selected else {
        return Ok(None);
    };
    let mut bytes = Vec::new();
    file.take(257).read_to_end(&mut bytes)?;
    if bytes.len() > 256 { return Err(io_invalid_input("receive directory record is too large")); }
    let mut record: DirectoryRecord = serde_json::from_slice(&bytes)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    record.retiring = retiring;
    let suffix = record.name.strip_prefix(".rustdesk-receive-")
        .ok_or_else(|| io_invalid_input("invalid receive directory record name"))?;
    if record.version != 1 || suffix.len() != 32 || !suffix.bytes().all(|b| b.is_ascii_hexdigit())
        || (record.retiring && record.inode.is_none()) {
        return Err(io_invalid_input("invalid receive directory record"));
    }
    Ok(Some(record))
}

fn record_directory(destination: &File, record: &DirectoryRecord) -> io::Result<File> {
    let directory = directory_at(destination, &name(&record.name)?)?;
    private_directory(&directory)?;
    let metadata = directory.metadata()?;
    if Some(metadata.ino()) != record.inode || metadata.dev() != destination.metadata()?.dev() {
        return Err(refused("receive directory record identifies a different namespace"));
    }
    let identity = open_regular_child_no_follow(&directory, &name("identity")?,
        RegularFileAccess::Read, ReceiveFileCreation::Existing)?;
    ReceiveOwnedArtifact::Payload.validate(&identity)?;
    let mut bytes = Vec::new();
    identity.take(65).read_to_end(&mut bytes)?;
    if bytes != record.name.as_bytes() {
        return Err(refused("receive directory identity does not match its protected record"));
    }
    Ok(directory)
}

fn retire_private_temporary(parent: &File, temporary: &CStr) -> io::Result<()> {
    let file = match open_regular_child_no_follow(parent, temporary,
        RegularFileAccess::Read, ReceiveFileCreation::Existing) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    ReceiveOwnedArtifact::Payload.validate(&file)?;
    remove_recv_child_at(parent, temporary, &file)?;
    sync_recv_directory(parent)
}

fn write_record(coordinator: &File, record_name: &CStr, temporary: &CStr,
    record: &DirectoryRecord) -> io::Result<()> {
    if record.retiring {
        return Err(io_invalid_input("cannot rewrite a retiring receive record"));
    }
    let mut file = open_regular_child_no_follow(coordinator, &temporary,
        RegularFileAccess::Write, ReceiveFileCreation::CreateNew)?;
    let mut published = false;
    let result = (|| {
        ReceiveOwnedArtifact::Payload.validate(&file)?;
        let bytes = serde_json::to_vec(record)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        file.write_all(&bytes)?;
        sync_recv_regular_file(&file)?;
        ensure_recv_child_matches_open_file(coordinator, &temporary, &file)?;
        if unsafe { libc::renameat(coordinator.as_raw_fd(), temporary.as_ptr(),
            coordinator.as_raw_fd(), record_name.as_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        published = true;
        sync_recv_directory(coordinator)
    })();
    let cleanup = if published { Ok(()) } else {
        remove_recv_child_at(coordinator, &temporary, &file)
            .and_then(|()| sync_recv_directory(coordinator))
    };
    match (result, cleanup) {
        (Ok(()), result) | (result, Ok(())) => result,
        (Err(error), Err(cleanup)) => Err(io::Error::new(error.kind(),
            format!("{error}; receive record cleanup failed: {cleanup}"))),
    }
}

fn prepare_directory(destination: &File, record: &DirectoryRecord) -> io::Result<File> {
    let container_name = name(&record.name)?;
    match mkdir_at(destination, &container_name) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    let directory = directory_at(destination, &container_name)?;
    private_directory(&directory)?;
    if directory.metadata()?.dev() != destination.metadata()?.dev() {
        return Err(refused("receive setup directory is on a different filesystem"));
    }
    // A preparing namespace has no transfer artifacts. Recovery may complete only
    // its private identity marker, never adopt existing payloads or other contents.
    let identity_name = name("identity")?;
    let scan = directory_at(&directory, &name(".")?)?;
    if unix_directory_entry_names(&scan, &mut EmptyDirectoryRemovalState::default())?
        .iter().any(|entry| entry != &identity_name) {
        return Err(refused("preparing receive namespace contains unexpected entries"));
    }
    unix_require_same_object(&unix_fstat(&directory)?,
        &unix_fstatat_no_follow(destination.as_raw_fd(), &container_name)?, "receive setup namespace")?;
    let mut identity = open_regular_child_no_follow(&directory, &identity_name,
        RegularFileAccess::ReadWrite, ReceiveFileCreation::OpenOrCreate)?;
    ReceiveOwnedArtifact::Payload.validate(&identity)?;
    let mut bytes = Vec::new();
    (&mut identity).take(65).read_to_end(&mut bytes)?;
    if !record.name.as_bytes().starts_with(&bytes) {
        return Err(refused("preparing receive identity differs from its protected intent"));
    }
    identity.write_all(&record.name.as_bytes()[bytes.len()..])?;
    sync_recv_regular_file(&identity)?;
    sync_recv_directory(&directory)?;
    sync_recv_directory(destination)?;
    Ok(directory)
}

fn retirement_parent_is_protected(destination: &File) -> io::Result<bool> {
    let metadata = destination.metadata()?;
    let owner = unsafe { libc::geteuid() };
    // The group class includes the POSIX ACL mask. A sticky parent protects
    // this effective-owner child only when the parent owner is also trusted.
    Ok([0, owner].contains(&metadata.uid())
        && (metadata.mode() & 0o022 == 0 || metadata.mode() & 0o1000 != 0))
}

fn begin_retirement(coordinator: &File, record_name: &CStr,
    record: &mut DirectoryRecord) -> io::Result<()> {
    let file = open_regular_child_no_follow(coordinator, record_name,
        RegularFileAccess::Read, ReceiveFileCreation::Existing)?;
    ReceiveOwnedArtifact::Payload.validate(&file)?;
    ensure_recv_child_matches_open_file(coordinator, record_name, &file)?;
    let retirement_name = retirement_record_name(record_name)?;
    if unsafe { libc::syscall(libc::SYS_renameat2, coordinator.as_raw_fd(), record_name.as_ptr(),
        coordinator.as_raw_fd(), retirement_name.as_ptr(), libc::RENAME_NOREPLACE) } != 0 {
        return Err(io::Error::last_os_error());
    }
    record.retiring = true;
    sync_recv_directory(coordinator)
}

fn retire_directory(coordinator: &File, record_name: &CStr,
    destination: &File, record: &mut DirectoryRecord) -> io::Result<bool> {
    if !retirement_parent_is_protected(destination)? {
        if record.retiring {
            return Err(refused("receive retirement parent is no longer protected"));
        }
        return Ok(false);
    }
    if record.retiring {
        // A previous owner may have renamed intent before its directory sync
        // failed. Reestablish that barrier before continuing destructive cleanup.
        sync_recv_directory(coordinator)?;
    }
    let container = name(&record.name)?;
    let directory = match directory_at(destination, &container) {
        Ok(directory) => Some(directory),
        Err(error) if record.retiring && error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(error),
    };
    if let Some(directory) = directory {
        private_directory(&directory)?;
        let metadata = directory.metadata()?;
        if Some(metadata.ino()) != record.inode || metadata.dev() != destination.metadata()?.dev() {
            return Err(refused("receive retirement directory identity changed"));
        }
        let identity_name = name("identity")?;
        let scan = directory_at(&directory, &name(".")?)?;
        if unix_directory_entry_names(&scan, &mut EmptyDirectoryRemovalState::default())?
            .iter().any(|entry| entry != &identity_name) {
            if record.retiring {
                return Err(refused("retiring receive directory contains unexpected entries"));
            }
            // An inactive saved transfer still owns its resumable artifacts.
            return Ok(false);
        }
        let identity = match open_regular_child_no_follow(&directory, &identity_name,
            RegularFileAccess::Read, ReceiveFileCreation::Existing) {
            Ok(mut identity) => {
                ReceiveOwnedArtifact::Payload.validate(&identity)?;
                let mut bytes = Vec::new();
                (&mut identity).take(65).read_to_end(&mut bytes)?;
                if bytes != record.name.as_bytes() {
                    return Err(refused("receive retirement marker identity changed"));
                }
                Some(identity)
            }
            Err(error) if record.retiring && error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(error),
        };
        if !record.retiring {
            // Recovery must distinguish intentional marker removal from an
            // incomplete or substituted ready namespace before anything is unlinked.
            begin_retirement(coordinator, record_name, record)?;
        }
        if let Some(identity) = identity {
            remove_recv_child_at(&directory, &identity_name, &identity)?;
        }
        sync_recv_directory(&directory)?;
        if !retirement_parent_is_protected(destination)? {
            return Err(refused("receive retirement parent lost protection"));
        }
        unix_require_same_object(&unix_fstat(&directory)?,
            &unix_fstatat_no_follow(destination.as_raw_fd(), &container)?, "retiring receive namespace")?;
        if unsafe { libc::unlinkat(destination.as_raw_fd(), container.as_ptr(), libc::AT_REMOVEDIR) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    sync_recv_directory(destination)?;
    let retirement_name = retirement_record_name(record_name)?;
    let record_file = open_regular_child_no_follow(coordinator, &retirement_name,
        RegularFileAccess::Read, ReceiveFileCreation::Existing)?;
    ReceiveOwnedArtifact::Payload.validate(&record_file)?;
    remove_recv_child_at(coordinator, &retirement_name, &record_file)?;
    sync_recv_directory(coordinator)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::{FileDigest, ReceiveWriteClaim};
    use std::os::unix::fs::{symlink, PermissionsExt};

    #[test]
    fn inspection_without_saved_state_preserves_destination_layout() {
        use super::super::{DigestCheckResult, FileTransferDigest, ReceivePathLease};
        let mut failures = Vec::new();
        for mode in [0o777, 0o555] {
            for present in [false, true] {
                for resume in [false, true] {
                    let root = std::env::temp_dir().join(format!(
                        "receive-inspection-layout-{}", crate::uuid::Uuid::new_v4()));
                    std::fs::create_dir(&root).unwrap();
                    let destination = root.join("incoming");
                    if present { std::fs::write(&destination, b"original").unwrap(); }
                    // Exclude stale lookup records from an earlier fixture whose
                    // deleted destination inode was reused by this fresh directory.
                    let mut initial = ReceivePathLease::acquire(&destination, false).unwrap();
                    initial.retire().unwrap();
                    drop(initial);
                    let coordinator = coordinator().unwrap();
                    let inventory = || {
                        let scan = directory_at(&coordinator, &name(".").unwrap()).unwrap();
                        let mut names = unix_directory_entry_names(&scan,
                            &mut EmptyDirectoryRemovalState::default()).unwrap();
                        names.sort();
                        names
                    };
                    let before = inventory();
                    let original = std::fs::metadata(&destination).ok().map(|m|
                        (m.dev(), m.ino(), m.uid(), m.gid(), m.mode(), m.nlink(), m.len(), m.mtime(), m.mtime_nsec()));
                    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(mode)).unwrap();
                    let result = super::super::inspect_write_destination(resume, &destination,
                        &FileTransferDigest { id: 881, file_num: 0, file_size: 8,
                            last_modified: 31, ..Default::default() });
                    let metadata = std::fs::metadata(&destination).ok().map(|m|
                        (m.dev(), m.ino(), m.uid(), m.gid(), m.mode(), m.nlink(), m.len(), m.mtime(), m.mtime_nsec()));
                    let preserved = metadata == original
                        && (!present || std::fs::read(&destination).unwrap() == b"original");
                    let correct = match &result {
                        Ok(DigestCheckResult::NoSuchFile) => !present,
                        Ok(DigestCheckResult::NeedConfirm(digest)) => present
                            && digest.file_size == 8 && digest.transferred_size == 0,
                        Err(_) => false,
                    };
                    let entries = std::fs::read_dir(&root).unwrap().collect::<Result<Vec<_>, _>>().unwrap().len();
                    let clean = entries == usize::from(present) && inventory() == before;
                    let parent_preserved = std::fs::metadata(&root).unwrap().mode() & 0o7777 == mode;
                    println!("RECEIVE_INSPECTION_LAYOUT=observed mode={mode:o} present={present} resume={resume} correct={correct} preserved={preserved} namespace_absent={clean} parent_preserved={parent_preserved} error={:?}",
                        result.err().map(|e| e.to_string()));
                    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
                    std::fs::remove_dir_all(&root).unwrap();
                    if !(correct && preserved && clean && parent_preserved) {
                        failures.push((mode, present, resume));
                    }
                }
            }
        }
        assert!(failures.is_empty(), "read-only inspection changed layout or failed: {failures:?}");
    }

    #[tokio::test]
    async fn fresh_confirmation_replaces_saved_partial() {
        use super::super::{file_transfer_send_confirm_request::Union, DigestCheckResult,
            FileEntry, FileTransferBlock, FileTransferDigest, FileTransferSendConfirmRequest,
            JobType, ReceiveClaimCleanup, TransferJob};
        use crate::protobuf::Message as _;
        use std::os::unix::fs::FileExt;

        let mut failures = Vec::new();
        for saved in ["none", "matching", "nonmatching"] {
            for prior_final in [false, true] {
                for producer in [false, true] {
                    let root = std::env::temp_dir().join(format!(
                        "receive-fresh-confirmation-{}", crate::uuid::Uuid::new_v4()));
                    std::fs::create_dir(&root).unwrap();
                    let destination = root.join("incoming");
                    if prior_final { std::fs::write(&destination, b"original").unwrap(); }
                    let original = std::fs::read(&destination).ok();
                    let saved_payload = if saved == "none" { None } else {
                        let digest = FileDigest { size: 3,
                            modified: if saved == "matching" { 17 } else { 16 } };
                        let (mut stream, mut claim) =
                            ReceiveWriteClaim::start_new(destination.clone(), digest).unwrap();
                        stream.write_all(b"ol").unwrap();
                        stream.sync_all().unwrap();
                        let payload = claim.download_file.try_clone().unwrap();
                        // Retain the same durable files that abrupt owner loss leaves.
                        // No lease or active transfer survives into the new job.
                        claim.cleanup_on_drop = ReceiveClaimCleanup::None;
                        drop((stream, claim));
                        Some(payload)
                    };
                    let mut receiver = TransferJob::new_write(581, JobType::Generic,
                        String::new(), root.clone(), 0, false, true, true);
                    receiver.set_files(vec![FileEntry { name: "incoming".into(),
                        size: 3, modified_time: 17, ..Default::default() }]).unwrap();
                    let (inspection, path) = receiver.inspect_receive_digest(&FileTransferDigest {
                        id: 581, file_num: 0, file_size: 3, last_modified: 17,
                        ..Default::default()
                    }, true).await.unwrap();
                    assert_eq!(path, destination);
                    match inspection {
                        DigestCheckResult::NeedConfirm(digest) =>
                            assert_eq!(digest.transferred_size, if saved == "matching" { 2 } else { 0 }),
                        DigestCheckResult::NoSuchFile => assert!(!prior_final && saved != "matching"),
                    }
                    if let Some(payload) = &saved_payload {
                        let mut bytes = [0; 2];
                        payload.read_exact_at(&mut bytes, 0).unwrap();
                        assert_eq!(&bytes, b"ol");
                        assert_eq!(payload.metadata().unwrap().nlink(), 1);
                    }
                    assert_eq!(std::fs::read(&destination).ok(), original);
                    let request = FileTransferSendConfirmRequest { id: 581, file_num: 0,
                        union: Some(Union::OffsetBlk(0)), ..Default::default() };
                    let wire = request.write_to_bytes().unwrap();
                    let decoded = FileTransferSendConfirmRequest::parse_from_bytes(&wire).unwrap();
                    if producer {
                        assert_eq!(receiver.confirm_with_offset(0, 0).await.unwrap(), decoded);
                    } else {
                        receiver.confirm(&decoded).await.unwrap();
                    }
                    assert_eq!(std::fs::read(&destination).ok(), original);
                    let written = receiver.write(FileTransferBlock { id: 581, file_num: 0,
                        data: b"new".to_vec().into(), ..Default::default() }).await;
                    assert_eq!(std::fs::read(&destination).ok(), original);
                    let result = match written {
                        Ok(()) => receiver.finalize_write(1).await,
                        Err(error) => Err(error),
                    };
                    let completed = result.is_ok();
                    if completed {
                        assert_eq!(std::fs::read(&destination).unwrap(), b"new");
                        assert_eq!((receiver.finished_size(), receiver.transferred()), (3, 3));
                    } else {
                        assert_eq!(std::fs::read(&destination).ok(), original);
                        failures.push(format!("{saved}/{prior_final}/{producer}: {result:?}"));
                    }
                    receiver.retire_current_file_state().unwrap();
                    drop((receiver, saved_payload));
                    std::fs::remove_dir_all(&root).unwrap();
                    println!("RECEIVE_FRESH_CONFIRMATION=observed saved={saved} prior_final={prior_final} producer={producer} completed={completed} inspection=preserved final_before_commit=preserved result={result:?} fixture=retired");
                }
            }
        }
        assert!(failures.is_empty(), "fresh receive failures: {failures:?}");
    }

    #[tokio::test]
    async fn fresh_confirmation_preserves_refused_artifacts() {
        use super::super::{file_transfer_send_confirm_request::Union, FileEntry,
            FileTransferBlock, FileTransferSendConfirmRequest, JobType,
            ReceiveClaimCleanup, TransferJob};
        use std::os::unix::fs::FileExt;

        let snapshot = |file: &File| {
            let metadata = file.metadata().unwrap();
            assert!(metadata.len() < 128);
            let mut bytes = vec![0; metadata.len() as usize];
            file.read_exact_at(&mut bytes, 0).unwrap();
            (metadata.dev(), metadata.ino(), metadata.mode(), metadata.nlink(), bytes)
        };
        for case in ["active", "payload-shared", "payload-linked", "digest-linked", "digest-invalid"] {
            for producer in [false, true] {
                let root = std::env::temp_dir().join(format!(
                    "receive-fresh-refusal-{}", crate::uuid::Uuid::new_v4()));
                std::fs::create_dir(&root).unwrap();
                let destination = root.join("incoming");
                std::fs::write(&destination, b"original").unwrap();
                let (mut stream, mut claim) = ReceiveWriteClaim::start_new(
                    destination.clone(), FileDigest { size: 3, modified: 17 }).unwrap();
                stream.write_all(b"ol").unwrap();
                stream.sync_all().unwrap();
                let payload = claim.download_file.try_clone().unwrap();
                let resume = claim.digest_file.try_clone().unwrap();
                if case == "payload-shared" {
                    payload.set_permissions(std::fs::Permissions::from_mode(0o644)).unwrap();
                } else if case.ends_with("-linked") {
                    let suffix = if case == "payload-linked" { ".download" } else { ".digest" };
                    let selected = ReceiveNamespace::artifact_name(suffix).unwrap();
                    let held = cstring_from_os_str(root.join("held").as_os_str(), "fixture link").unwrap();
                    assert_eq!(unsafe { libc::linkat(claim._lease.parent.as_raw_fd(), selected.as_ptr(),
                        libc::AT_FDCWD, held.as_ptr(), 0) }, 0);
                } else if case == "digest-invalid" {
                    resume.set_len(8).unwrap();
                    resume.write_all_at(b"not-json", 0).unwrap();
                }
                claim.cleanup_on_drop = ReceiveClaimCleanup::None;
                drop(stream);
                let active = if case == "active" { Some(claim) } else { drop(claim); None };
                let before = (snapshot(&payload), snapshot(&resume));
                let mut receiver = TransferJob::new_write(582, JobType::Generic,
                    String::new(), root.clone(), 0, false, true, true);
                receiver.set_files(vec![FileEntry { name: "incoming".into(),
                    size: 3, modified_time: 17, ..Default::default() }]).unwrap();
                let refused = if producer {
                    receiver.confirm_with_offset(0, 0).await.map(|_| ())
                } else {
                    receiver.confirm(&FileTransferSendConfirmRequest { id: 582, file_num: 0,
                        union: Some(Union::OffsetBlk(0)), ..Default::default() }).await
                };
                assert!(refused.is_err(), "restart admitted {case}");
                assert!(!receiver.file_confirmed());
                assert_eq!((receiver.finished_size(), receiver.transferred()), (0, 0));
                assert!(receiver.write(FileTransferBlock { id: 582, file_num: 0,
                    data: b"new".to_vec().into(), ..Default::default() }).await.is_err());
                receiver.retire_current_file_state().unwrap();
                assert_eq!((snapshot(&payload), snapshot(&resume)), before);
                assert_eq!(std::fs::read(&destination).unwrap(), b"original");
                drop((receiver, active, payload, resume));
                std::fs::remove_dir_all(&root).unwrap();
                println!("RECEIVE_FRESH_CONFIRMATION_REFUSAL=observed case={case} producer={producer} confirmation=refused later_write=refused state=preserved fixture=retired");
            }
        }
    }

    #[test]
    fn interrupted_digest_preparation_requires_private_file_and_exclusive_lease() {
        use super::super::{ReceiveClaimCleanup, ReceivePathLease};
        for case in ["empty", "partial", "complete", "shared", "linked", "symlink", "directory"] {
            let root = std::env::temp_dir().join(format!(
                "receive-digest-preparation-{}", crate::uuid::Uuid::new_v4()));
            std::fs::create_dir(&root).unwrap();
            let target = root.join("incoming");
            std::fs::write(&target, b"original").unwrap();
            let (mut stream, mut claim) = ReceiveWriteClaim::start_new(
                target.clone(), FileDigest { size: 6, modified: 31 }).unwrap();
            stream.write_all(b"abc").unwrap();
            stream.sync_all().unwrap();
            let parent = std::fs::read_link(format!("/proc/thread-self/fd/{}", claim._lease.parent.as_raw_fd())).unwrap();
            let temporary = parent.join("resume.digest.tmp");
            let payload = parent.join("payload.download");
            let digest = parent.join("resume.digest");
            let digest_before = std::fs::read(&digest).unwrap();
            let bytes: &[u8] = match case {
                "empty" => b"", "partial" => b"{", "complete" => &digest_before,
                _ => b"uncommitted",
            };
            let content = if case == "symlink" { root.join("held") }
                else if case == "directory" {
                    std::fs::create_dir(&temporary).unwrap();
                    temporary.join("held")
                } else { temporary.clone() };
            let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(&content).unwrap();
            file.write_all(bytes).unwrap();
            drop(file);
            if case == "shared" {
                std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o644)).unwrap();
            } else if case == "linked" {
                std::fs::hard_link(&temporary, root.join("held")).unwrap();
            } else if case == "symlink" { symlink(&content, &temporary).unwrap(); }
            let identity = |path: &Path| {
                let m = std::fs::symlink_metadata(path).unwrap();
                (m.dev(), m.ino(), m.mode(), m.nlink())
            };
            let before = identity(&temporary);
            assert_eq!(ReceivePathLease::acquire(&target, false).unwrap_err().kind(), io::ErrorKind::WouldBlock);
            assert_eq!(identity(&temporary), before);
            assert_eq!(std::fs::read(&content).unwrap(), bytes);
            drop(stream);
            claim.cleanup_on_drop = ReceiveClaimCleanup::Lease;
            claim.cleanup().unwrap();
            let acquired = ReceivePathLease::acquire(&target, false);
            let accepted = matches!(case, "empty" | "partial" | "complete");
            if accepted {
                let mut lease = acquired.unwrap();
                assert!(!temporary.exists());
                lease.retire().unwrap();
            } else {
                assert!(acquired.is_err(), "unsafe temporary admitted: {case}");
                assert_eq!(identity(&temporary), before);
                assert_eq!(std::fs::read(&content).unwrap(), bytes);
            }
            assert_eq!(std::fs::read(&target).unwrap(), b"original");
            assert_eq!(std::fs::read(&payload).unwrap(), b"abc");
            assert_eq!(std::fs::read(&digest).unwrap(), digest_before);
            std::fs::remove_dir_all(&root).unwrap();
            println!("RECEIVE_DIGEST_PREPARATION=pass case={case} retired={accepted} active_lease=preserved saved_pair=preserved final=preserved fixture=retired");
        }
    }

    #[test]
    fn retirement_retries_the_containing_directory_barrier() {
        use std::io::{Seek, SeekFrom};
        let root = std::env::temp_dir().join(format!("receive-retirement-sync-{}", crate::uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        let target = root.join("incoming");
        let digest = FileDigest { size: 9, modified: 31 };
        let (mut stream, mut claim) = ReceiveWriteClaim::start_new(target.clone(), digest).unwrap();
        stream.write_all(b"published").unwrap();
        // Keep the exact directory and working namespace operations, but make
        // fsync fail in the kernel. O_PATH cannot provide a durability barrier.
        let fd = unsafe { libc::openat(claim._lease.namespace.directory.as_raw_fd(),
            name(".").unwrap().as_ptr(), libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) };
        assert!(fd >= 0);
        let path_only = unsafe { File::from_raw_fd(fd) };
        unix_require_same_object(&unix_fstat(&path_only).unwrap(),
            &unix_fstat(&claim._lease.namespace.directory).unwrap(), "faulted directory").unwrap();
        let original = std::mem::replace(&mut claim._lease.namespace.directory, path_only);
        let first = claim.finish(9, 31);
        assert_eq!(first.unwrap_err().raw_os_error(), Some(libc::EBADF));
        assert!(claim.published);
        assert_eq!(claim._lease.namespace.artifacts.metadata().unwrap().nlink(), 0);
        assert!(!claim._lease.retired);

        // A new transfer may already own the old child name. Retrying the
        // predecessor must sync its parent without unlinking that successor.
        let (mut next_stream, next) = ReceiveWriteClaim::start_new(target.clone(), digest).unwrap();
        next_stream.write_all(b"successor").unwrap();
        let next_identity = unix_fstat(&next._lease.namespace.artifacts).unwrap();
        let retry = claim.retire();
        let repeated_failure = retry.as_ref().err().and_then(|error| error.raw_os_error()) == Some(libc::EBADF);
        let still_pending = !claim._lease.retired;
        let successor_preserved = unix_require_same_object(&next_identity,
            &unix_fstatat_no_follow(original.as_raw_fd(), &next._lease.namespace.child).unwrap(),
            "successor namespace").is_ok() && next.download_file.metadata().unwrap().len() == 9;
        let failed_descriptor = std::mem::replace(&mut claim._lease.namespace.directory, original);
        drop(failed_descriptor);
        claim.retire().unwrap();
        let recovered = claim._lease.retired;
        claim.cleanup().unwrap();
        let mut successor_bytes = Vec::new();
        let mut successor = next.download_file.try_clone().unwrap();
        successor.seek(SeekFrom::Start(0)).unwrap();
        successor.read_to_end(&mut successor_bytes).unwrap();
        assert_eq!(successor_bytes, b"successor");
        drop((stream, next_stream, successor));
        next.cleanup().unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"published");
        std::fs::remove_dir_all(&root).unwrap();
        println!("RECEIVE_RETIREMENT_SYNC=observed first_failure=EBADF child=unlinked repeated_failure={repeated_failure} still_pending={still_pending} successor_preserved={successor_preserved} recovered={recovered} final_bytes=exact fixture=retired");
        assert!(repeated_failure && still_pending && successor_preserved && recovered);
    }

    #[test]
    fn generation_lock_retires_only_after_last_owner() {
        let root = std::env::temp_dir().join(format!("receive-generation-{}", crate::uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        let (mut one, mut first) = ReceiveWriteClaim::start_new(root.join("one"), FileDigest::default()).unwrap();
        let (mut two, mut second) = ReceiveWriteClaim::start_new(root.join("two"), FileDigest::default()).unwrap();
        let generation = first._lease.namespace.generation.try_clone().unwrap();
        let original = unix_fstat(&generation).unwrap();
        one.write_all(b"one").unwrap();
        first.finish(3, 31).unwrap();
        let shared_preserved = generation.metadata().unwrap().nlink() == 1;

        let (mut three, mut third) = ReceiveWriteClaim::start_new(root.join("three"), FileDigest::default()).unwrap();
        let contender_shared = unix_require_same_object(&original,
            &unix_fstat(&third._lease.namespace.generation).unwrap(), "live generation").is_ok();
        three.write_all(b"three").unwrap();
        third.finish(5, 33).unwrap();
        let remaining_preserved = generation.metadata().unwrap().nlink() == 1;
        two.write_all(b"two").unwrap();
        second.finish(3, 32).unwrap();
        // Completed claim objects and an old descriptor remain alive deliberately.
        let last_retired = generation.metadata().unwrap().nlink() == 0;

        let (mut four, mut fourth) = ReceiveWriteClaim::start_new(root.join("four"), FileDigest::default()).unwrap();
        let replacement = fourth._lease.namespace.generation.try_clone().unwrap();
        let fresh_generation = unix_require_same_object(&original,
            &unix_fstat(&replacement).unwrap(), "retired generation").is_err();
        first._lease.namespace.retire(|| Ok(())).unwrap();
        let stale_retry_preserved = replacement.metadata().unwrap().nlink() == 1;
        four.write_all(b"four").unwrap();
        fourth.finish(4, 34).unwrap();
        let next_retired = replacement.metadata().unwrap().nlink() == 0;
        assert!(read_record(&fourth._lease.namespace.coordinator,
            &fourth._lease.namespace.record_name).unwrap().is_none());
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 4);
        for (file, bytes) in [("one", b"one".as_slice()), ("two", b"two"),
            ("three", b"three"), ("four", b"four")] {
            assert_eq!(std::fs::read(root.join(file)).unwrap(), bytes);
        }
        drop((one, two, three, four, first, second, third, fourth, generation, replacement));
        std::fs::remove_dir_all(&root).unwrap();
        println!("RECEIVE_GENERATION_RETIREMENT=observed shared_preserved={shared_preserved} contender_shared={contender_shared} remaining_preserved={remaining_preserved} last_retired={last_retired} fresh_generation={fresh_generation} stale_retry_preserved={stale_retry_preserved} next_retired={next_retired} final_bytes=exact fixture=retired");
        assert!(shared_preserved && contender_shared && remaining_preserved && last_retired
            && fresh_generation && stale_retry_preserved && next_retired);
    }

    #[test]
    fn generation_retirement_error_releases_exclusion() {
        let root = std::env::temp_dir().join(format!("receive-generation-error-{}", crate::uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        let (mut stream, mut claim) = ReceiveWriteClaim::start_new(root.join("incoming"), FileDigest::default()).unwrap();
        let generation = claim._lease.namespace.generation.try_clone().unwrap();
        let coordinator = claim._lease.namespace.coordinator.try_clone().unwrap();
        let selected = claim._lease.namespace.generation_name.clone();
        let held = name(&format!("test-held-{}", crate::uuid::Uuid::new_v4())).unwrap();
        assert_eq!(unsafe { libc::renameat(coordinator.as_raw_fd(), selected.as_ptr(),
            coordinator.as_raw_fd(), held.as_ptr()) }, 0);
        let replacement = open_regular_child_no_follow(&coordinator, &selected,
            RegularFileAccess::Write, ReceiveFileCreation::CreateNew).unwrap();
        stream.write_all(b"exact").unwrap();
        let result = claim.finish(5, 31);
        let refusal = result.as_ref().err().is_some_and(|e| e.kind() == io::ErrorKind::PermissionDenied);
        let replacement_preserved = ensure_recv_child_matches_open_file(&coordinator,
            &selected, &replacement).is_ok() && replacement.metadata().unwrap().len() == 0;
        let probe = open_regular_child_no_follow(&coordinator, &held,
            RegularFileAccess::Read, ReceiveFileCreation::Existing).unwrap();
        let released = lock(&probe, libc::LOCK_SH | libc::LOCK_NB).is_ok();
        lock(&probe, libc::LOCK_UN).unwrap();
        remove_recv_child_at(&coordinator, &selected, &replacement).unwrap();
        assert_eq!(unsafe { libc::renameat(coordinator.as_raw_fd(), held.as_ptr(),
            coordinator.as_raw_fd(), selected.as_ptr()) }, 0);
        claim.cleanup().unwrap();
        let recovered = generation.metadata().unwrap().nlink() == 0;
        assert_eq!(std::fs::read(root.join("incoming")).unwrap(), b"exact");
        drop((stream, generation, coordinator, replacement, probe));
        std::fs::remove_dir_all(&root).unwrap();
        println!("RECEIVE_GENERATION_ERROR=observed refusal={refusal} replacement_preserved={replacement_preserved} exclusion_released={released} retry_retired={recovered} final_bytes=exact fixture=retired");
        assert!(refusal && replacement_preserved && released && recovered);

        for phase in ["intent", "marker", "directory", "lost-protection", "replacement"] {
            let root = std::env::temp_dir().join(format!("receive-retire-recovery-{}", crate::uuid::Uuid::new_v4()));
            std::fs::create_dir(&root).unwrap();
            let namespace = ReceiveNamespace::acquire(File::open(&root).unwrap(), &name("incoming").unwrap()).unwrap();
            let old_path = root.join(namespace.directory_name.to_str().unwrap());
            let record_name = namespace.record_name.clone();
            let mut record = read_record(&namespace.coordinator, &record_name).unwrap().unwrap();
            assert_eq!(unsafe { libc::unlinkat(namespace.directory.as_raw_fd(),
                namespace.child.as_ptr(), libc::AT_REMOVEDIR) }, 0);
            sync_recv_directory(&namespace.directory).unwrap();
            begin_retirement(&namespace.coordinator, &record_name, &mut record).unwrap();
            if phase != "intent" {
                std::fs::remove_file(old_path.join("identity")).unwrap();
                sync_recv_directory(&namespace.directory).unwrap();
            }
            if phase == "directory" {
                std::fs::remove_dir(&old_path).unwrap();
                sync_recv_directory(&namespace.destination).unwrap();
            }
            let coordinator = namespace.coordinator.try_clone().unwrap();
            namespace.complete_enrollment().unwrap();
            drop(namespace);
            let record_path = name(record_name.to_str().unwrap()).unwrap();
            let held = root.join("held");
            if phase == "lost-protection" {
                std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o777)).unwrap();
            } else if phase == "replacement" {
                std::fs::rename(&old_path, &held).unwrap();
                std::fs::create_dir(&old_path).unwrap();
                std::fs::set_permissions(&old_path, std::fs::Permissions::from_mode(0o700)).unwrap();
            }
            if matches!(phase, "lost-protection" | "replacement") {
                let before = std::fs::metadata(&old_path).unwrap().ino();
                assert!(ReceiveNamespace::acquire(File::open(&root).unwrap(), &name("next").unwrap()).is_err());
                assert_eq!(std::fs::metadata(&old_path).unwrap().ino(), before);
                assert!(read_record(&coordinator, &record_path).unwrap().unwrap().retiring);
                assert_eq!(std::fs::read_dir(&old_path).unwrap().count(), 0);
                if phase == "lost-protection" {
                    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
                } else {
                    std::fs::remove_dir(&old_path).unwrap();
                    std::fs::rename(&held, &old_path).unwrap();
                }
            }
            let next = ReceiveNamespace::acquire(File::open(&root).unwrap(), &name("next").unwrap()).unwrap();
            next.complete_enrollment().unwrap();
            assert!(!old_path.exists());
            assert!(!read_record(&coordinator, &record_path).unwrap().unwrap().retiring);
            next.retire(|| Ok(())).unwrap();
            assert!(read_record(&coordinator, &record_path).unwrap().is_none());
            assert_eq!(std::fs::read_dir(&root).unwrap().count(), 0);
            drop((next, coordinator));
            std::fs::remove_dir(&root).unwrap();
            println!("RECEIVE_GENERATION_ERROR=observed retirement_phase={phase} recovery=completed record=retired fixture=retired");
        }
    }

    #[test]
    fn setup_recovers_only_private_identity_prefixes() {
        let root = std::env::temp_dir().join(format!("receive-setup-{}", crate::uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        let destination = File::open(&root).unwrap();
        for case in ["absent", "empty", "partial", "complete", "wrong", "unexpected", "symlink", "shared"] {
            let record = DirectoryRecord { version: 1,
                name: format!(".rustdesk-receive-{}", crate::uuid::Uuid::new_v4().simple()),
                inode: None, retiring: false };
            let path = root.join(&record.name);
            let marker = path.join("identity");
            let allowed = matches!(case, "absent" | "empty" | "partial" | "complete");
            if case != "absent" {
                mkdir_at(&destination, &name(&record.name).unwrap()).unwrap();
                if case == "unexpected" {
                    std::fs::write(path.join("payload.download"), b"unrelated").unwrap();
                } else if case == "symlink" {
                    symlink("../outside", &marker).unwrap();
                } else {
                    let bytes = match case {
                        "empty" => b"".as_slice(),
                        "partial" => &record.name.as_bytes()[..11],
                        "wrong" => b"unrelated".as_slice(),
                        _ => record.name.as_bytes(),
                    };
                    OpenOptions::new().write(true).create_new(true).mode(0o600)
                        .open(&marker).unwrap().write_all(bytes).unwrap();
                    if case == "shared" {
                        std::fs::set_permissions(&marker, std::fs::Permissions::from_mode(0o644)).unwrap();
                    }
                }
            }
            let inventory = || {
                let mut entries: Vec<_> = std::fs::read_dir(&path).unwrap().map(|entry| {
                    let entry = entry.unwrap();
                    let metadata = std::fs::symlink_metadata(entry.path()).unwrap();
                    let bytes = if metadata.file_type().is_symlink() {
                        std::fs::read_link(entry.path()).unwrap().as_os_str().as_bytes().to_vec()
                    } else { std::fs::read(entry.path()).unwrap() };
                    (entry.file_name(), metadata.ino(), metadata.mode(), bytes)
                }).collect();
                entries.sort();
                entries
            };
            let before = if allowed { Vec::new() } else { inventory() };
            let result = prepare_directory(&destination, &record);
            if allowed {
                let recovered = result.unwrap();
                assert_eq!(std::fs::read(&marker).unwrap(), record.name.as_bytes());
                assert_eq!(std::fs::read_dir(&path).unwrap().count(), 1);
                private_directory(&recovered).unwrap();
            } else {
                assert!(result.is_err(), "unexpected setup admission: {case}");
                assert_eq!(before, inventory(), "refused setup changed contents: {case}");
            }
            std::fs::remove_dir_all(&path).unwrap();
        }
        assert!(!root.join("outside").exists());
        std::fs::remove_dir(&root).unwrap();
    }
}

#[derive(Debug)]
pub(super) struct ReceiveNamespace {
    pub(super) destination: File,
    pub(super) artifacts: File,
    coordinator: File,
    directory: File,
    child: CString,
    generation: File,
    generation_name: CString,
    record_name: CString,
    directory_name: CString,
}

impl ReceiveNamespace {
    pub(super) fn acquire(destination: File, final_name: &CStr) -> io::Result<Self> {
        let coordinator = coordinator()?;
        // Serialize enrollment/retirement only. An active transfer never holds this gate.
        lock(&coordinator, libc::LOCK_EX)?;
        let key = directory_key(&destination)?;
        let generation_name = name(&format!("{key}.lock"))?;
        let generation = open_regular_child_no_follow(&coordinator, &generation_name,
            RegularFileAccess::Write, ReceiveFileCreation::OpenOrCreate)?;
        ReceiveOwnedArtifact::Payload.validate(&generation)?;
        sync_recv_regular_file(&generation)?;
        sync_recv_directory(&coordinator)?;
        lock(&generation, libc::LOCK_SH)?;
        let record_name = name(&format!("{key}.json"))?;
        let temporary = name(&format!("{key}.tmp"))?;
        // The enrollment gate excludes every record writer. A killed writer's
        // bounded temporary file is not committed authority and can be retired.
        retire_private_temporary(&coordinator, &temporary)?;
        let record = read_record(&coordinator, &record_name)?;
        let existing = record.as_ref().filter(|r| r.inode.is_some() && !r.retiring)
            .map(|r| record_directory(&destination, r));
        let (directory, directory_name) = match existing {
            Some(Ok(directory)) => {
                let record = record.as_ref()
                    .ok_or_else(|| io_invalid_input("receive namespace record is absent"))?;
                (directory, name(&record.name)?)
            }
            missing => {
                // A named container can be moved by the destination's owner. Never adopt a
                // replacement or create a parallel namespace while any old claim is live.
                lock(&generation, libc::LOCK_UN)?;
                if let Err(error) = lock(&generation, libc::LOCK_EX | libc::LOCK_NB) {
                    return Err(io::Error::new(error.kind(),
                        "receive namespace is unavailable while an existing generation is active"));
                }
                if let Some(Err(error)) = missing {
                    if !matches!(error.kind(), io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied)
                        && error.raw_os_error() != Some(libc::ELOOP)
                        && error.raw_os_error() != Some(libc::ENOTDIR) {
                        return Err(error);
                    }
                }
                let record = match record {
                    Some(mut record) if record.retiring => {
                        if !retire_directory(&coordinator, &record_name, &destination, &mut record)? {
                            return Err(refused("receive namespace retirement did not complete"));
                        }
                        None
                    }
                    record => record,
                };
                let mut record = match record {
                    Some(record) if record.inode.is_none() => record,
                    _ => {
                        let record = DirectoryRecord { version: 1,
                            name: format!(".rustdesk-receive-{}", crate::uuid::Uuid::new_v4().simple()),
                            inode: None, retiring: false };
                        // Publish and sync intent before creating any public entry.
                        write_record(&coordinator, &record_name, &temporary, &record)?;
                        record
                    }
                };
                let directory = prepare_directory(&destination, &record)?;
                let opened = unix_fstat(&directory)?;
                record.inode = Some(directory.metadata()?.ino());
                write_record(&coordinator, &record_name, &temporary, &record)?;
                // LOCK_EX -> LOCK_SH is not atomic. The enrollment gate excludes another
                // initializer throughout the conversion and the following identity replay.
                lock(&generation, libc::LOCK_SH)?;
                let replay = record_directory(&destination, &record)?;
                unix_require_same_object(&opened, &unix_fstat(&replay)?, "receive namespace replay")?;
                (directory, name(&record.name)?)
            }
        };
        let mut digest = Sha256::new();
        digest.update(b"rustdesk.receive.file.v1\0");
        digest.update(final_name.to_bytes());
        let child = name(&format!("{:x}", digest.finalize()))?;
        let artifacts = private_child(&directory, &child)?;
        // The caller keeps enrollment locked until its exact per-file lease is acquired.
        Ok(Self { destination, artifacts, coordinator, directory, child, generation, generation_name,
            record_name, directory_name })
    }

    pub(super) fn complete_enrollment(&self) -> io::Result<()> {
        lock(&self.coordinator, libc::LOCK_UN)
    }

    pub(super) fn retire_digest_preparation(&self) -> io::Result<()> {
        retire_private_temporary(&self.artifacts, &Self::artifact_name(".digest.tmp")?)
    }

    fn retire_generation(&self) -> io::Result<()> {
        // The enrollment gate remains held. Retired claims release their shared
        // membership even when another file still owns this namespace generation.
        // A retry through an unlinked old inode can only repeat the durability barrier.
        if self.generation.metadata()?.nlink() == 0 {
            return sync_recv_directory(&self.coordinator);
        }
        lock(&self.generation, libc::LOCK_UN)?;
        match lock(&self.generation, libc::LOCK_EX | libc::LOCK_NB) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
            Err(error) => return Err(error),
        }
        let result = (|| {
            ensure_recv_child_matches_open_file(&self.coordinator, &self.generation_name, &self.generation)?;
            if let Some(mut record) = read_record(&self.coordinator, &self.record_name)? {
                // A retry through a retired claim must preserve a later namespace.
                if record.name.as_bytes() == self.directory_name.as_bytes()
                    && record.inode == Some(self.directory.metadata()?.ino()) {
                    retire_directory(&self.coordinator, &self.record_name,
                        &self.destination, &mut record)?;
                }
            }
            remove_recv_child_at(&self.coordinator, &self.generation_name, &self.generation)?;
            sync_recv_directory(&self.coordinator)
        })();
        // A failed removal must not strand an exclusive lock in a completed claim
        // while a later enrollment holds the gate and waits for shared membership.
        let released = lock(&self.generation, libc::LOCK_UN);
        match (result, released) {
            (Ok(()), result) | (result, Ok(())) => result,
            (Err(error), Err(release)) => Err(io::Error::new(error.kind(),
                format!("{error}; receive generation lock release failed: {release}"))),
        }
    }

    pub(super) fn retire(&self, remove_lease: impl FnOnce() -> io::Result<()>) -> io::Result<()> {
        lock(&self.coordinator, libc::LOCK_EX)?;
        let result = (|| {
            remove_lease()?;
            // Removal may have succeeded before its parent barrier failed. Retry
            // that retained parent without touching a successor at the old name.
            if self.artifacts.metadata()?.nlink() == 0 {
                return sync_recv_directory(&self.directory);
            }
            // Resume inspection deliberately leaves a payload/digest pair in this directory.
            if !is_empty(&self.artifacts)? {
                return Ok(());
            }
            unix_require_same_object(&unix_fstat(&self.artifacts)?,
                &unix_fstatat_no_follow(self.directory.as_raw_fd(), &self.child)?, "receive file namespace")?;
            if unsafe { libc::unlinkat(self.directory.as_raw_fd(), self.child.as_ptr(), libc::AT_REMOVEDIR) } != 0 {
                return Err(io::Error::last_os_error());
            }
            sync_recv_directory(&self.directory)
        })().and_then(|()| self.retire_generation());
        let released = lock(&self.coordinator, libc::LOCK_UN);
        match (result, released) {
            (Ok(()), result) | (result, Ok(())) => result,
            (Err(error), Err(release)) => Err(io::Error::new(error.kind(),
                format!("{error}; receive enrollment gate release failed: {release}"))),
        }
    }

    pub(super) fn artifact_name(suffix: &str) -> io::Result<CString> {
        match suffix {
            ".download" => name("payload.download"),
            ".digest" => name("resume.digest"),
            ".digest.tmp" => name("resume.digest.tmp"),
            ".download.lock" => name("claim.download.lock"),
            _ => Err(io_invalid_input("unknown receive artifact role")),
        }
    }
}
