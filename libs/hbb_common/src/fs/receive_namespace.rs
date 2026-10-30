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
    inode: u64,
}

fn read_record(coordinator: &File, record_name: &CStr) -> io::Result<Option<DirectoryRecord>> {
    let file = match open_regular_child_no_follow(coordinator, record_name,
        RegularFileAccess::Read, ReceiveFileCreation::Existing) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    ReceiveOwnedArtifact::Payload.validate(&file)?;
    let mut bytes = Vec::new();
    file.take(257).read_to_end(&mut bytes)?;
    if bytes.len() > 256 { return Err(io_invalid_input("receive directory record is too large")); }
    let record: DirectoryRecord = serde_json::from_slice(&bytes)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let suffix = record.name.strip_prefix(".rustdesk-receive-")
        .ok_or_else(|| io_invalid_input("invalid receive directory record name"))?;
    if record.version != 1 || suffix.len() != 32 || !suffix.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(io_invalid_input("invalid receive directory record"));
    }
    Ok(Some(record))
}

fn record_directory(destination: &File, record: &DirectoryRecord) -> io::Result<File> {
    let directory = directory_at(destination, &name(&record.name)?)?;
    private_directory(&directory)?;
    let metadata = directory.metadata()?;
    if metadata.ino() != record.inode || metadata.dev() != destination.metadata()?.dev() {
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

fn write_record(coordinator: &File, record_name: &CStr, record: &DirectoryRecord) -> io::Result<()> {
    let temporary = name(&format!("{}.tmp", crate::uuid::Uuid::new_v4().simple()))?;
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

#[derive(Debug)]
pub(super) struct ReceiveNamespace {
    pub(super) destination: File,
    pub(super) artifacts: File,
    coordinator: File,
    directory: File,
    child: CString,
    _generation: File,
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
        let record = read_record(&coordinator, &record_name)?;
        let existing = record.as_ref().map(|r| record_directory(&destination, r));
        let directory = match existing {
            Some(Ok(directory)) => directory,
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
                let container = format!(".rustdesk-receive-{}", crate::uuid::Uuid::new_v4().simple());
                let container_name = name(&container)?;
                mkdir_at(&destination, &container_name)?;
                let directory = directory_at(&destination, &container_name)?;
                private_directory(&directory)?;
                // No pre-existing contents acquire receive-artifact authority.
                if !is_empty(&directory)? {
                    return Err(refused("new receive namespace is not empty"));
                }
                let opened = unix_fstat(&directory)?;
                unix_require_same_object(&opened,
                    &unix_fstatat_no_follow(destination.as_raw_fd(), &container_name)?, "receive namespace")?;
                let mut identity = open_regular_child_no_follow(&directory, &name("identity")?,
                    RegularFileAccess::Write, ReceiveFileCreation::CreateNew)?;
                ReceiveOwnedArtifact::Payload.validate(&identity)?;
                identity.write_all(container.as_bytes())?;
                sync_recv_regular_file(&identity)?;
                sync_recv_directory(&directory)?;
                sync_recv_directory(&destination)?;
                let record = DirectoryRecord { version: 1, name: container, inode: directory.metadata()?.ino() };
                write_record(&coordinator, &record_name, &record)?;
                // LOCK_EX -> LOCK_SH is not atomic. The enrollment gate excludes another
                // initializer throughout the conversion and the following identity replay.
                lock(&generation, libc::LOCK_SH)?;
                let replay = record_directory(&destination, &record)?;
                unix_require_same_object(&opened, &unix_fstat(&replay)?, "receive namespace replay")?;
                directory
            }
        };
        let mut digest = Sha256::new();
        digest.update(b"rustdesk.receive.file.v1\0");
        digest.update(final_name.to_bytes());
        let child = name(&format!("{:x}", digest.finalize()))?;
        let artifacts = private_child(&directory, &child)?;
        // The caller keeps enrollment locked until its exact per-file lease is acquired.
        Ok(Self { destination, artifacts, coordinator, directory, child, _generation: generation })
    }

    pub(super) fn complete_enrollment(&self) -> io::Result<()> {
        lock(&self.coordinator, libc::LOCK_UN)
    }

    pub(super) fn retire(&self, remove_lease: impl FnOnce() -> io::Result<()>) -> io::Result<()> {
        lock(&self.coordinator, libc::LOCK_EX)?;
        let result = (|| {
            remove_lease()?;
            if self.artifacts.metadata()?.nlink() == 0 { return Ok(()); }
            // Resume inspection deliberately leaves a payload/digest pair in this directory.
            if !is_empty(&self.artifacts)? {
                return Ok(());
            }
            unix_require_same_object(&unix_fstat(&self.artifacts)?,
                &unix_fstatat_no_follow(self.directory.as_raw_fd(), &self.child)?, "receive file namespace")?;
            if unsafe { libc::unlinkat(self.directory.as_raw_fd(), self.child.as_ptr(), libc::AT_REMOVEDIR) } != 0 {
                return Err(io::Error::last_os_error());
            }
            // Retain one namespace and two bounded coordination files per destination.
            // Removing the public container by name would reintroduce the unlink race.
            // Payloads, digests, leases and empty per-file directories are retired here.
            sync_recv_directory(&self.directory)
        })();
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
            ".download.lock" => name("claim.download.lock"),
            _ => Err(io_invalid_input("unknown receive artifact role")),
        }
    }
}
