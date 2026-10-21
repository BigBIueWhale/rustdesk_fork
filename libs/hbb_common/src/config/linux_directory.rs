use anyhow::{anyhow, Result};
use crate::{libc, sha2::{Digest, Sha256}};
use serde_derive::{Deserialize, Serialize};
use std::{
    convert::TryInto,
    ffi::{CStr, CString},
    fs::{File, Metadata},
    io::{self, Read, Seek, SeekFrom, Write},
    os::unix::{ffi::OsStrExt, fs::MetadataExt, io::{AsRawFd, FromRawFd, IntoRawFd}},
    path::{Component, Path},
};

type Identity = [u64; 2];
const MAX_RECORD: usize = 128 * 1024;
const MAX_JOURNAL: usize = 3 * (MAX_RECORD + 36);
const DOMAIN: &[u8] = b"rustdesk-config-directory-v1\0";

#[cfg(all(test, target_arch = "x86_64"))]
#[path = "directory_lease_tests.rs"]
mod lease_tests;

#[derive(Clone, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u8,
    parent: Identity,
    target: Vec<u8>,
    stage: String,
    tail: Vec<Vec<u8>>,
    // Reservation precedes mkdir; creation identity precedes descendants; selection precedes rename.
    root: Option<Identity>,
    selected: Option<Vec<Identity>>,
}

fn id(file: &File) -> io::Result<Identity> {
    let m = file.metadata()?;
    Ok([m.dev(), m.ino()])
}

fn component(bytes: &[u8]) -> Result<CString> {
    if bytes.is_empty() || bytes == b"." || bytes == b".." || bytes.contains(&b'/') {
        return Err(anyhow!("Invalid configuration directory component"));
    }
    Ok(CString::new(bytes)?)
}

fn dot() -> Result<&'static CStr> {
    Ok(CStr::from_bytes_with_nul(b".\0")?)
}

fn open_dir(parent: i32, name: &CStr, readable: bool) -> io::Result<File> {
    let fd = unsafe {
        libc::openat(parent, name.as_ptr(),
            (if readable { libc::O_RDONLY } else { libc::O_PATH })
                | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
    };
    if fd < 0 { Err(io::Error::last_os_error()) }
    else { Ok(unsafe { File::from_raw_fd(fd) }) }
}

fn optional_dir(parent: &File, name: &CStr, readable: bool) -> Result<Option<File>> {
    match open_dir(parent.as_raw_fd(), name, readable) {
        Ok(file) => Ok(Some(file)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

fn named(parent: &File, name: &CStr) -> io::Result<Option<libc::stat>> {
    let mut m = std::mem::MaybeUninit::<libc::stat>::uninit();
    let rc = unsafe {
        libc::fstatat(parent.as_raw_fd(), name.as_ptr(), m.as_mut_ptr(), libc::AT_SYMLINK_NOFOLLOW)
    };
    if rc == 0 { return Ok(Some(unsafe { m.assume_init() })); }
    let error = io::Error::last_os_error();
    if error.kind() == io::ErrorKind::NotFound { Ok(None) } else { Err(error) }
}

fn require_named(parent: &File, name: &CStr, file: &File) -> Result<()> {
    let opened = file.metadata()?;
    let m = named(parent, name)?.ok_or_else(|| anyhow!("Configuration directory entry disappeared"))?;
    if [m.st_dev as u64, m.st_ino as u64] != [opened.dev(), opened.ino()]
        || m.st_mode & libc::S_IFMT != opened.mode() & libc::S_IFMT
    {
        return Err(anyhow!("Configuration directory entry identity changed"));
    }
    Ok(())
}

fn private_directory(file: &File, device: u64) -> Result<Metadata> {
    let m = file.metadata()?;
    if !m.is_dir() || m.dev() != device || m.uid() != unsafe { libc::geteuid() }
        || m.mode() & 0o7777 != 0o700
    {
        return Err(anyhow!("Configuration staging directory metadata is unsafe"));
    }
    Ok(m)
}

fn descriptor_directory() -> Result<File> {
    let path = CString::new("/proc/thread-self/fd")?;
    let descriptors = open_dir(libc::AT_FDCWD, &path, true)?;
    let mut filesystem = std::mem::MaybeUninit::<libc::statfs>::uninit();
    if unsafe { libc::fstatfs(descriptors.as_raw_fd(), filesystem.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    if unsafe { filesystem.assume_init() }.f_type as u64 != libc::PROC_SUPER_MAGIC as u64 {
        return Err(anyhow!("Configuration directory descriptor path is not procfs"));
    }
    Ok(descriptors)
}

fn chmod_retained_directory(file: &File) -> Result<()> {
    let descriptors = descriptor_directory()?;
    let name = CString::new(file.as_raw_fd().to_string())?;
    let mut target = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstatat(descriptors.as_raw_fd(), name.as_ptr(), target.as_mut_ptr(), 0) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    let target = unsafe { target.assume_init() };
    let metadata = file.metadata()?;
    if !metadata.is_dir() || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o5077 != 0
        || [target.st_dev as u64, target.st_ino as u64] != [metadata.dev(), metadata.ino()]
    {
        return Err(anyhow!("Configuration directory descriptor identity changed"));
    }
    // The numeric entry is a kernel alias of our retained O_PATH descriptor.
    if unsafe { libc::fchmodat(descriptors.as_raw_fd(), name.as_ptr(), 0o700, 0) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    private_directory(file, metadata.dev())?;
    Ok(())
}

fn make_private(parent: &File, name: &CStr, device: u64) -> Result<File> {
    if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    let retained = open_dir(parent.as_raw_fd(), name, false)?;
    let m = retained.metadata()?;
    if !m.is_dir() || m.dev() != device || m.uid() != unsafe { libc::geteuid() }
        || m.mode() & 0o5077 != 0
    {
        return Err(anyhow!("New configuration directory metadata is unsafe"));
    }
    require_named(parent, name, &retained)?;
    let file = match open_dir(parent.as_raw_fd(), name, true) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied && m.mode() & 0o400 == 0 => {
            chmod_retained_directory(&retained)?;
            open_dir(retained.as_raw_fd(), dot()?, true)?
        }
        Err(error) => return Err(error.into()),
    };
    if id(&file)? != id(&retained)? {
        return Err(anyhow!("New configuration directory changed before permission update"));
    }
    if unsafe { libc::fchmod(file.as_raw_fd(), 0o700) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    private_directory(&file, device)?;
    require_named(parent, name, &file)?;
    Ok(file)
}

fn only_child(file: &File) -> Result<Option<Vec<u8>>> {
    let fd = open_dir(file.as_raw_fd(), dot()?, true)?.into_raw_fd();
    let stream = unsafe { libc::fdopendir(fd) };
    if stream.is_null() {
        let error = io::Error::last_os_error();
        drop(unsafe { File::from_raw_fd(fd) });
        return Err(error.into());
    }
    let result = (|| -> Result<Option<Vec<u8>>> {
        let mut child = None;
        loop {
            unsafe { *libc::__errno_location() = 0; }
            let entry = unsafe { libc::readdir(stream) };
            if entry.is_null() {
                let error = io::Error::last_os_error();
                if error.raw_os_error() != Some(0) { return Err(error.into()); }
                return Ok(child);
            }
            let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
            if name == b"." || name == b".." { continue; }
            if child.is_some() {
                return Err(anyhow!("Unexpected entry in private configuration directory"));
            }
            child = Some(name.to_vec());
        }
    })();
    let closed = unsafe { libc::closedir(stream) };
    if closed != 0 {
        let error = io::Error::last_os_error();
        return match result {
            Ok(_) => Err(error.into()),
            Err(first) => Err(anyhow!("{first}; directory close also failed: {error}")),
        };
    }
    result
}

fn private_chain(root: &File, record: &Record, complete: bool) -> Result<(File, Vec<Identity>)> {
    let mut current = open_dir(root.as_raw_fd(), dot()?, true)?;
    let mut identities = Vec::with_capacity(record.tail.len() + 1);
    private_directory(&current, record.parent[0])?;
    identities.push(id(&current)?);
    for bytes in &record.tail {
        match only_child(&current)? {
            None if !complete => return Ok((current, identities)),
            Some(child) if child.as_slice() == bytes.as_slice() => {}
            _ => return Err(anyhow!("Private configuration directory chain changed")),
        }
        let name = component(bytes)?;
        let next = open_dir(current.as_raw_fd(), &name, true)?;
        private_directory(&next, record.parent[0])?;
        require_named(&current, &name, &next)?;
        identities.push(id(&next)?);
        current = next;
    }
    if only_child(&current)?.is_some() {
        return Err(anyhow!("Private configuration directory is not empty"));
    }
    Ok((current, identities))
}

fn selected_chain(root: &File, record: &Record, private: bool) -> Result<()> {
    let expected = record.selected.as_ref().ok_or_else(|| anyhow!("Directory was not selected"))?;
    if private {
        let (_, actual) = private_chain(root, record, true)?;
        if &actual != expected {
            return Err(anyhow!("Selected private directory identities changed"));
        }
        return Ok(());
    }
    let mut current = open_dir(root.as_raw_fd(), dot()?, true)?;
    for (depth, expected_id) in expected.iter().enumerate() {
        private_directory(&current, record.parent[0])?;
        if id(&current)? != *expected_id {
            return Err(anyhow!("Selected public directory identity changed"));
        }
        if let Some(bytes) = record.tail.get(depth) {
            let name = component(bytes)?;
            let next = open_dir(current.as_raw_fd(), &name, true)?;
            require_named(&current, &name, &next)?;
            current = next;
        }
    }
    Ok(())
}

fn retire_empty_reservation(lease: &Lease, parent: &File, record: &Record, root: &File) -> Result<()> {
    let metadata = root.metadata()?;
    // Before fchmod, mkdir may leave only owner bits plus inherited set-group-ID.
    if !metadata.is_dir() || metadata.dev() != record.parent[0]
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o5077 != 0 || record.root.is_some() || record.selected.is_some()
    {
        return Err(anyhow!("Unrecorded directory reservation metadata is unsafe"));
    }
    let stage = CString::new(record.stage.as_bytes())?;
    let target = component(&record.target)?;
    lease.require_current(parent)?;
    require_named(parent, &stage, root)?;
    if named(parent, &target)?.is_some() {
        return Err(anyhow!("Unrecorded configuration directory left its private reservation"));
    }
    let namespace = parent.metadata()?;
    let uid = unsafe { libc::geteuid() };
    let private = namespace.uid() == uid && namespace.mode() & 0o022 == 0;
    let sticky = namespace.mode() & libc::S_ISVTX != 0
        && (namespace.uid() == uid || namespace.uid() == 0);
    if [namespace.dev(), namespace.ino()] != record.parent || !(private || sticky) {
        return Err(anyhow!("Unrecorded directory reservation has no protected namespace"));
    }
    // mkdir may precede fchmod/identity logging. The kernel permits only an empty
    // reservation to be removed; never read, normalize or adopt this directory.
    if unsafe { libc::unlinkat(parent.as_raw_fd(), stage.as_ptr(), libc::AT_REMOVEDIR) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    if root.metadata()?.nlink() != 0 {
        return Err(anyhow!("Retired directory reservation remains linked"));
    }
    Ok(())
}

fn retire_private(lease: &Lease, parent: &File, record: &Record, root: &File) -> Result<()> {
    if record.root != Some(id(root)?) {
        return Err(anyhow!("Unselected directory has no matching creation identity"));
    }
    let (mut current, identities) = private_chain(root, record, false)?;
    let stage = CString::new(record.stage.as_bytes())?;
    let target = component(&record.target)?;
    for depth in (0..identities.len()).rev() {
        lease.require_current(parent)?;
        require_named(parent, &stage, root)?;
        if named(parent, &target)?.is_some() {
            return Err(anyhow!("Unselected configuration directory left its private reservation"));
        }
        if id(&current)? != identities[depth] || only_child(&current)?.is_some() {
            return Err(anyhow!("Private directory changed before retirement"));
        }
        let upper = open_dir(current.as_raw_fd(), CStr::from_bytes_with_nul(b"..\0")?, true)?;
        let expected = if depth == 0 { record.parent } else { identities[depth - 1] };
        if id(&upper)? != expected {
            return Err(anyhow!("Private directory parent identity changed"));
        }
        let name = if depth == 0 { CString::new(record.stage.as_bytes())? }
            else { component(&record.tail[depth - 1])? };
        require_named(&upper, &name, &current)?;
        if unsafe { libc::unlinkat(upper.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) } != 0 {
            return Err(io::Error::last_os_error().into());
        }
        if current.metadata()?.nlink() != 0 {
            return Err(anyhow!("Retired private directory remains linked"));
        }
        current = upper;
    }
    if id(&current)? != id(parent)? {
        return Err(anyhow!("Configuration directory retirement left its parent"));
    }
    Ok(())
}

fn rename_private(parent: &File, stage: &CStr, target: &CStr) -> Result<()> {
    if unsafe {
        libc::syscall(libc::SYS_renameat2, parent.as_raw_fd(), stage.as_ptr(),
            parent.as_raw_fd(), target.as_ptr(), libc::RENAME_NOREPLACE)
    } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}

struct Lease {
    file: File,
    name: CString,
}

impl Lease {
    fn open(parent: &File, target: &[u8], create: bool) -> Result<Option<Self>> {
        let prefix = if target.first() == Some(&b'.') { "_" } else { "." };
        let mut hash = Sha256::new();
        hash.update(DOMAIN);
        hash.update(target);
        let name = CString::new(format!("{prefix}config-dir-lease.{:x}", hash.finalize()))?;
        let flags = libc::O_RDWR | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY;
        let metadata_flags = libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW;
        let mut fresh = false;
        let mut fd = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), metadata_flags) };
        if fd < 0 {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::NotFound { return Err(error.into()); }
            if !create { return Ok(None); }
            fd = unsafe {
                libc::openat(parent.as_raw_fd(), name.as_ptr(), flags | libc::O_CREAT | libc::O_EXCL, 0o600)
            };
            if fd < 0 {
                let error = io::Error::last_os_error();
                if error.kind() != io::ErrorKind::AlreadyExists { return Err(error.into()); }
                fd = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), metadata_flags) };
                if fd < 0 { return Err(io::Error::last_os_error().into()); }
            } else { fresh = true; }
        }
        let mut lease = Self { file: unsafe { File::from_raw_fd(fd) }, name };
        let metadata = lease.file.metadata()?;
        if !metadata.is_file() || metadata.uid() != unsafe { libc::geteuid() } || metadata.nlink() != 1 {
            return Err(anyhow!("Configuration directory lease is not an owned single-link file"));
        }
        if fresh && unsafe { libc::fchmod(fd, 0o600) } != 0 {
            return Err(io::Error::last_os_error().into());
        }
        if !fresh {
            lease.require_current(parent)?;
            let descriptors = descriptor_directory()?;
            let descriptor = CString::new(lease.file.as_raw_fd().to_string())?;
            // Only the admitted retained inode may acquire read/write journal authority.
            let fd = unsafe { libc::openat(
                descriptors.as_raw_fd(), descriptor.as_ptr(),
                libc::O_RDWR | libc::O_CLOEXEC | libc::O_NONBLOCK | libc::O_NOCTTY,
            ) };
            if fd < 0 { return Err(io::Error::last_os_error().into()); }
            let file = unsafe { File::from_raw_fd(fd) };
            if id(&file)? != id(&lease.file)? {
                return Err(anyhow!("Configuration directory lease changed during descriptor reopening"));
            }
            lease.file = file;
        }
        lease.require_current(parent)?;
        // Each traversal holds only one lease. Closing this file releases it on every outcome.
        let fd = lease.file.as_raw_fd();
        let started = std::time::Instant::now();
        let budget = std::time::Duration::from_secs(1);
        loop {
            if unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) } == 0 { break; }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::WouldBlock { return Err(error.into()); }
            let remaining = budget.saturating_sub(started.elapsed());
            if remaining.is_zero() {
                return Err(io::Error::new(io::ErrorKind::TimedOut,
                    "Configuration directory preparation is busy").into());
            }
            std::thread::sleep(remaining.min(std::time::Duration::from_millis(10)));
        }
        lease.require_current(parent)?;
        Ok(Some(lease))
    }

    fn require_current(&self, parent: &File) -> Result<()> {
        let metadata = self.file.metadata()?;
        if !metadata.is_file() || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.dev() != parent.metadata()?.dev()
            || metadata.nlink() != 1 || metadata.mode() & 0o7777 != 0o600
            || metadata.len() > MAX_JOURNAL as u64
        {
            return Err(anyhow!("Configuration directory lease metadata is unsafe"));
        }
        require_named(parent, &self.name, &self.file)
    }

    fn validate(record: &Record, parent: &File, target: &[u8]) -> Result<()> {
        if record.version != 1 || record.parent != id(parent)? || record.target.as_slice() != target {
            return Err(anyhow!("Configuration directory record has a different owner or target"));
        }
        component(&record.target)?;
        let prefix = if target.first() == Some(&b'.') { "_" } else { "." };
        let stem = format!("{prefix}config-dir-stage.");
        let suffix = record.stage.strip_prefix(&stem)
            .ok_or_else(|| anyhow!("Invalid private directory reservation"))?;
        let uuid = crate::uuid::Uuid::parse_str(suffix)
            .map_err(|_| anyhow!("Invalid private directory reservation"))?;
        if uuid.to_string() != suffix { return Err(anyhow!("Noncanonical directory reservation")); }
        let mut bytes = record.target.len();
        for name in &record.tail {
            component(name)?;
            bytes = bytes.checked_add(name.len() + 1).ok_or_else(|| anyhow!("Directory record overflow"))?;
            if bytes >= libc::PATH_MAX as usize { return Err(anyhow!("Directory record exceeds path bounds")); }
        }
        if let Some(selected) = &record.selected {
            if selected.len() != record.tail.len() + 1 || selected.first().copied() != record.root {
                return Err(anyhow!("Selected directory record has incoherent identities"));
            }
        }
        Ok(())
    }

    fn read(&mut self, parent: &File, target: &[u8]) -> Result<Option<Record>> {
        self.require_current(parent)?;
        self.file.seek(SeekFrom::Start(0))?;
        let mut bytes = Vec::new();
        (&mut self.file).take(MAX_JOURNAL as u64 + 1).read_to_end(&mut bytes)?;
        if bytes.len() > MAX_JOURNAL { return Err(anyhow!("Configuration directory journal exceeds bounds")); }
        let mut position = 0;
        let mut previous: Option<Record> = None;
        let mut count = 0;
        while position < bytes.len() {
            if count == 3 { return Err(anyhow!("Extra directory journal data")); }
            if bytes.len() - position < 4 { break; }
            let header: [u8; 4] = bytes[position..position + 4].try_into()
                .map_err(|_| anyhow!("Invalid directory journal header"))?;
            let length = u32::from_le_bytes(header) as usize;
            if length == 0 || length > MAX_RECORD { return Err(anyhow!("Invalid directory record length")); }
            let end = position + 4 + length + 32;
            if end > bytes.len() { break; }
            let body = &bytes[position + 4..position + 4 + length];
            let mut hash = Sha256::new();
            hash.update(DOMAIN); hash.update(header); hash.update(body);
            if hash.finalize().as_slice() != &bytes[end - 32..end] { break; }
            let record: Record = serde_json::from_slice(body)
                .map_err(|_| anyhow!("Invalid configuration directory publication record"))?;
            if serde_json::to_vec(&record)? != body {
                return Err(anyhow!("Noncanonical configuration directory record"));
            }
            Self::validate(&record, parent, target)?;
            match &previous {
                None if record.root.is_none() && record.selected.is_none() => {}
                Some(old) if count == 1 && old.root.is_none() && record.root.is_some()
                    && record.selected.is_none() => {
                    let mut expected = old.clone(); expected.root = record.root;
                    if expected != record { return Err(anyhow!("Directory creation binding changed")); }
                }
                Some(old) if count == 2 && old.root.is_some() && old.selected.is_none()
                    && record.selected.is_some() => {
                    let mut expected = old.clone(); expected.selected = record.selected.clone();
                    if expected != record { return Err(anyhow!("Directory selection binding changed")); }
                }
                _ => return Err(anyhow!("Invalid directory journal phase")),
            }
            previous = Some(record);
            count += 1;
            position = end;
        }
        if previous.is_none() && !bytes.is_empty() {
            return Err(anyhow!("Configuration directory journal has no valid reservation"));
        }
        if previous.as_ref().map(|r| r.selected.is_some()).unwrap_or(false) && position != bytes.len() {
            return Err(anyhow!("Selected directory journal has unexpected trailing data"));
        }
        self.require_current(parent)?;
        Ok(previous)
    }

    fn append(&mut self, parent: &File, record: &Record) -> Result<()> {
        self.require_current(parent)?;
        let body = serde_json::to_vec(record)?;
        if body.len() > MAX_RECORD { return Err(anyhow!("Configuration directory record exceeds bounds")); }
        if self.file.metadata()?.len() as usize > MAX_JOURNAL - body.len() - 36 {
            return Err(anyhow!("Configuration directory journal exceeds bounds"));
        }
        let length = (body.len() as u32).to_le_bytes();
        let mut hash = Sha256::new();
        hash.update(DOMAIN); hash.update(length); hash.update(&body);
        self.file.seek(SeekFrom::End(0))?;
        self.file.write_all(&length)?;
        self.file.write_all(&body)?;
        self.file.write_all(&hash.finalize())?;
        self.file.sync_all()?;
        self.require_current(parent)
    }

    fn clear(&mut self, parent: &File) -> Result<()> {
        self.require_current(parent)?;
        self.file.set_len(0)?;
        self.file.sync_all()?;
        self.require_current(parent)
    }

    fn recover(&mut self, parent: &File, target: &CStr) -> Result<()> {
        let record = match self.read(parent, target.to_bytes())? {
            Some(record) => record,
            None => return Ok(()),
        };
        self.file.sync_all()?;
        let sync_parent = open_dir(parent.as_raw_fd(), dot()?, true)?;
        let stage_name = CString::new(record.stage.as_bytes())?;
        let stage = optional_dir(parent, &stage_name, record.root.is_some())?;
        let public = optional_dir(parent, target, true)?;
        if record.selected.is_none() {
            if public.is_some() {
                return Err(anyhow!("Unselected configuration directory moved or target is occupied"));
            }
            if let Some(stage) = stage {
                if record.root.is_some() {
                    retire_private(self, &sync_parent, &record, &stage)?;
                } else {
                    retire_empty_reservation(self, &sync_parent, &record, &stage)?;
                }
            }
            sync_parent.sync_all()?;
            return self.clear(parent);
        }
        match (stage, public) {
            (Some(stage), None) => {
                selected_chain(&stage, &record, true)?;
                require_named(parent, &stage_name, &stage)?;
                rename_private(&sync_parent, &stage_name, target)?;
                sync_parent.sync_all()?;
                require_named(parent, target, &stage)?;
                selected_chain(&stage, &record, false)?;
            }
            (None, Some(public)) => {
                selected_chain(&public, &record, false)?;
                sync_parent.sync_all()?;
                require_named(parent, target, &public)?;
            }
            _ => return Err(anyhow!("Selected configuration directory topology is uncertain")),
        }
        if named(parent, &stage_name)?.is_some() {
            return Err(anyhow!("Private directory reservation remains after publication"));
        }
        self.clear(parent)
    }

    fn create(&mut self, parent: &File, target: &CStr, tail: &[Vec<u8>]) -> Result<()> {
        self.recover(parent, target)?;
        if named(parent, target)?.is_some() { return Ok(()); }
        let sync_parent = open_dir(parent.as_raw_fd(), dot()?, true)?;
        let prefix = if target.to_bytes().first() == Some(&b'.') { "_" } else { "." };
        let mut record = Record {
            version: 1, parent: id(parent)?, target: target.to_bytes().to_vec(),
            stage: format!("{prefix}config-dir-stage.{}", crate::uuid::Uuid::new_v4()),
            tail: tail.to_vec(), root: None, selected: None,
        };
        Self::validate(&record, parent, target.to_bytes())?;
        self.append(parent, &record)?;
        sync_parent.sync_all()?;
        let stage_name = CString::new(record.stage.as_bytes())?;
        let stage = match make_private(parent, &stage_name, record.parent[0]) {
            Ok(file) => file,
            Err(error) => {
                if error.downcast_ref::<io::Error>()
                    .map(|e| e.kind() == io::ErrorKind::AlreadyExists).unwrap_or(false)
                {
                    self.clear(parent)?;
                }
                return Err(error);
            }
        };
        record.root = Some(id(&stage)?);
        self.append(parent, &record)?;
        let mut identities = vec![id(&stage)?];
        let mut current = open_dir(stage.as_raw_fd(), dot()?, true)?;
        for bytes in tail {
            let name = component(bytes)?;
            let next = make_private(&current, &name, record.parent[0])?;
            next.sync_all()?;
            current.sync_all()?;
            identities.push(id(&next)?);
            current = next;
        }
        current.sync_all()?;
        stage.sync_all()?;
        sync_parent.sync_all()?;
        let (_, actual) = private_chain(&stage, &record, true)?;
        if actual != identities { return Err(anyhow!("Private directory chain changed before selection")); }
        record.selected = Some(identities);
        self.append(parent, &record)?;
        selected_chain(&stage, &record, true)?;
        require_named(parent, &stage_name, &stage)?;
        rename_private(&sync_parent, &stage_name, target)?;
        sync_parent.sync_all()?;
        require_named(parent, target, &stage)?;
        selected_chain(&stage, &record, false)?;
        if named(parent, &stage_name)?.is_some() {
            return Err(anyhow!("Directory staging name remains after publication"));
        }
        self.clear(parent)
    }
}

pub(super) fn open_parent(path: &Path) -> Result<File> {
    let parent_path = path.parent().ok_or_else(|| anyhow!("Configuration path has no parent"))?;
    let mut names = Vec::new();
    for value in parent_path.components() {
        match value {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(value) => { component(value.as_bytes())?; names.push(value.as_bytes().to_vec()); }
            _ => return Err(anyhow!("Unsupported configuration directory selector")),
        }
    }
    let start = CString::new(if parent_path.is_absolute() { "/" } else { "." })?;
    let mut parent = open_dir(libc::AT_FDCWD, &start, names.is_empty())?;
    for (index, bytes) in names.iter().enumerate() {
        let name = component(bytes)?;
        let mut lease = Lease::open(&parent, bytes, false)?;
        if let Some(lease) = &mut lease { lease.recover(&parent, &name)?; }
        let readable = index + 1 == names.len();
        match open_dir(parent.as_raw_fd(), &name, readable) {
            Ok(next) => parent = next,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let _sync_authority = open_dir(parent.as_raw_fd(), dot()?, true)?;
                let mut lease = match lease {
                    Some(lease) => lease,
                    None => Lease::open(&parent, bytes, true)?
                        .ok_or_else(|| anyhow!("Configuration directory lease disappeared"))?,
                };
                lease.create(&parent, &name, &names[index + 1..])?;
                parent = open_dir(parent.as_raw_fd(), &name, readable)?;
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(parent)
}
