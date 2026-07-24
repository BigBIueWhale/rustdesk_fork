use std::{
    collections::{HashMap, HashSet},
    fs,
    io::{self, Read, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    ops::{Deref, DerefMut},
    path::{Path, PathBuf},
    sync::{Mutex, RwLock},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::sync::OnceLock;

use anyhow::{anyhow, Result};
use rand::Rng;
use regex::Regex;
use serde as de;
use serde_derive::{Deserialize, Serialize};
use serde_json;
use sodiumoxide::base64;
#[cfg(any(target_os = "android", target_os = "ios"))]
use sodiumoxide::crypto::sign;

mod permanent_password;

pub use permanent_password::{
    compute_permanent_password_h1, decode_permanent_password_h1_from_storage,
    decode_preset_password_h1_from_storage, derive_cpace_prs,
    local_permanent_password_storage_is_usable_for_auth,
    preset_permanent_password_storage_is_usable_for_auth, ENCRYPT_MAX_LEN,
};
use permanent_password::{
    decode_permanent_password_h1_from_hashed_storage, decrypt_permanent_password_prs_storage,
    decrypt_permanent_password_str_or_original, derive_permanent_password_storages,
    encrypt_permanent_password_prs_storage, DEFAULT_SALT_LEN, PASSWORD_ENC_VERSION,
    PERMANENT_PASSWORD_H1_LEN,
};

use crate::{
    compress::{compress, decompress},
    log,
    password_security::{
        decrypt_str_or_original, decrypt_vec_or_original, encrypt_str_or_original,
        encrypt_vec_or_original, symmetric_crypt,
    },
};

pub const CONNECT_TIMEOUT: u64 = 18_000;
pub const READ_TIMEOUT: u64 = 18_000;
pub const COMPRESS_LEVEL: i32 = 3;

#[cfg(target_os = "macos")]
lazy_static::lazy_static! {
    pub static ref ORG: RwLock<String> = RwLock::new("com.carriez".to_owned());
}

#[cfg(any(target_os = "macos", test))]
#[derive(Clone, Debug, Eq, PartialEq)]
struct MacosServiceOwnedConfigRoot {
    home: PathBuf,
    path: PathBuf,
    log_path: PathBuf,
}

#[cfg(target_os = "macos")]
static MACOS_SERVICE_OWNED_CONFIG_ROOT: OnceLock<MacosServiceOwnedConfigRoot> = OnceLock::new();

#[cfg(any(target_os = "macos", test))]
fn macos_service_owned_config_root_from(
    home: &Path,
    organization: &str,
    app_name: &str,
) -> Result<MacosServiceOwnedConfigRoot> {
    if !home.is_absolute()
        || !home.components().all(|component| {
            matches!(
                component,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            )
        })
    {
        return Err(anyhow!("invalid macOS service-owned home directory"));
    }
    let identity_component_is_valid = |value: &str| {
        let mut components = Path::new(value).components();
        !value.is_empty()
            && !value
                .chars()
                .any(|character| character.is_control() || matches!(character, '/' | '\\'))
            && matches!(components.next(), Some(std::path::Component::Normal(_)))
            && components.next().is_none()
    };
    if !identity_component_is_valid(organization) || !identity_component_is_valid(app_name) {
        return Err(anyhow!("invalid macOS service-owned config identity"));
    }

    // Match directories-next 2.0's macOS project-name mapping while replacing
    // its ambient HOME base with the effective principal's passwd-owned home.
    let project_name = format!(
        "{}.{}",
        organization.replace(' ', "-"),
        app_name.replace(' ', "-")
    );
    let mut components = Path::new(&project_name).components();
    if !matches!(components.next(), Some(std::path::Component::Normal(_)))
        || components.next().is_some()
    {
        return Err(anyhow!("invalid macOS service-owned config project name"));
    }

    Ok(MacosServiceOwnedConfigRoot {
        home: home.to_path_buf(),
        path: home
            .join("Library")
            .join("Application Support")
            .join(project_name),
        log_path: home.join("Library").join("Logs").join(app_name),
    })
}

#[cfg(target_os = "macos")]
fn macos_service_owned_config_root() -> Option<&'static MacosServiceOwnedConfigRoot> {
    MACOS_SERVICE_OWNED_CONFIG_ROOT.get()
}

#[cfg(target_os = "linux")]
#[derive(Clone, Debug, Eq, PartialEq)]
struct LinuxServiceOwnedConfigRoot {
    home: PathBuf,
    path: PathBuf,
}

#[cfg(target_os = "linux")]
static LINUX_SERVICE_OWNED_CONFIG_ROOT: OnceLock<LinuxServiceOwnedConfigRoot> = OnceLock::new();

#[cfg(target_os = "linux")]
fn linux_service_owned_config_root_from(home: &Path, app_name: &str) -> Result<PathBuf> {
    if !home.is_absolute()
        || !home.components().all(|component| {
            matches!(
                component,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            )
        })
    {
        return Err(anyhow!("invalid Linux service-owned home directory"));
    }
    if app_name.is_empty()
        || app_name
            .chars()
            .any(|value| value.is_control() || matches!(value, '/' | '\\'))
    {
        return Err(anyhow!("invalid Linux service-owned config app name"));
    }
    // Match directories-next 2.0's Linux project-name mapping while replacing
    // its ambient HOME/XDG_CONFIG_HOME base with the passwd-owned home.
    let project_name = app_name
        .split_whitespace()
        .map(str::to_lowercase)
        .collect::<String>();
    let mut components = Path::new(&project_name).components();
    if !matches!(components.next(), Some(std::path::Component::Normal(_)))
        || components.next().is_some()
    {
        return Err(anyhow!("invalid Linux service-owned config project name"));
    }
    Ok(home.join(".config").join(project_name))
}

#[cfg(target_os = "linux")]
fn linux_service_owned_config_root() -> Option<&'static LinuxServiceOwnedConfigRoot> {
    LINUX_SERVICE_OWNED_CONFIG_ROOT.get()
}

#[cfg(any(windows, test))]
fn windows_service_owned_config_root_from(program_data: &Path, app_name: &str) -> Result<PathBuf> {
    if !program_data.is_absolute() || app_name.is_empty() {
        return Err(anyhow!("invalid Windows service-owned config root input"));
    }
    if app_name == "."
        || app_name == ".."
        || app_name.ends_with([' ', '.'])
        || app_name
            .chars()
            .any(|value| value.is_control() || r#"<>:"/\|?*"#.contains(value))
    {
        return Err(anyhow!("invalid Windows service-owned config app name"));
    }
    Ok(program_data.join(app_name).join("config"))
}

#[cfg(windows)]
mod windows_machine_config {
    use super::{config_temp_file_name, windows_config_acl, ConfigStoreFault};
    use anyhow::{anyhow, Result};
    use ntapi::ntioapi::{
        FileAttributeTagInformation, FileDispositionInformation, FileRenameInformation,
        NtCreateFile, NtFlushBuffersFile, NtQueryInformationFile, NtSetInformationFile,
        FILE_ATTRIBUTE_TAG_INFORMATION, FILE_CREATE, FILE_DIRECTORY_FILE,
        FILE_DISPOSITION_INFORMATION, FILE_NON_DIRECTORY_FILE, FILE_OPEN,
        FILE_OPEN_FOR_BACKUP_INTENT, FILE_OPEN_REPARSE_POINT, FILE_RENAME_INFORMATION,
        FILE_SYNCHRONOUS_IO_NONALERT, FILE_WRITE_THROUGH, IO_STATUS_BLOCK,
    };
    use std::{
        convert::TryFrom,
        ffi::OsStr,
        fs::File,
        io::{self, Read, Write},
        mem::{size_of, zeroed},
        os::windows::{
            ffi::OsStrExt,
            fs::OpenOptionsExt,
            io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle},
        },
        path::{Component, Path, PathBuf, Prefix},
        ptr::{copy_nonoverlapping, null_mut},
        sync::OnceLock,
    };
    use winapi::{
        shared::ntdef::{
            HANDLE, NTSTATUS, NT_SUCCESS, OBJECT_ATTRIBUTES, OBJ_CASE_INSENSITIVE, UNICODE_STRING,
        },
        um::{
            fileapi::{
                CreateFileW, FlushFileBuffers, GetVolumeInformationByHandleW,
                BY_HANDLE_FILE_INFORMATION, OPEN_EXISTING,
            },
            handleapi::INVALID_HANDLE_VALUE,
            winbase::{FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT},
            winnt::{
                DELETE, FILE_ADD_FILE, FILE_ADD_SUBDIRECTORY, FILE_ATTRIBUTE_NORMAL,
                FILE_ATTRIBUTE_REPARSE_POINT, FILE_DELETE_CHILD, FILE_GENERIC_READ,
                FILE_GENERIC_WRITE, FILE_LIST_DIRECTORY, FILE_PERSISTENT_ACLS,
                FILE_READ_ATTRIBUTES, FILE_READ_ONLY_VOLUME, FILE_SHARE_DELETE, FILE_SHARE_READ,
                FILE_SHARE_WRITE, FILE_TRAVERSE, FILE_WRITE_ATTRIBUTES, GENERIC_WRITE,
                READ_CONTROL, SYNCHRONIZE,
            },
        },
    };

    const SHARE_ALL: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
    const STATUS_OBJECT_NAME_NOT_FOUND: NTSTATUS = 0xC000_0034u32 as NTSTATUS;
    const STATUS_OBJECT_NAME_COLLISION: NTSTATUS = 0xC000_0035u32 as NTSTATUS;
    const STATUS_OBJECT_PATH_NOT_FOUND: NTSTATUS = 0xC000_003Au32 as NTSTATUS;

    pub(super) struct Root {
        path: PathBuf,
        handle: OwnedHandle,
        durability_volume: Option<OwnedHandle>,
        write_authority: bool,
        identity: FileIdentity,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct FileIdentity {
        volume: u32,
        index_high: u32,
        index_low: u32,
    }

    static ROOT: OnceLock<Root> = OnceLock::new();

    fn invalid(message: &'static str) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidInput, message)
    }

    fn nt_error(status: NTSTATUS) -> io::Error {
        if status == STATUS_OBJECT_NAME_NOT_FOUND || status == STATUS_OBJECT_PATH_NOT_FOUND {
            io::Error::from(io::ErrorKind::NotFound)
        } else if status == STATUS_OBJECT_NAME_COLLISION {
            io::Error::from(io::ErrorKind::AlreadyExists)
        } else {
            io::Error::new(
                io::ErrorKind::Other,
                format!("NTSTATUS 0x{:08x}", status as u32),
            )
        }
    }

    fn component_wide(value: &OsStr) -> io::Result<Vec<u16>> {
        let value = value.encode_wide().collect::<Vec<_>>();
        if value.is_empty() || value.iter().any(|value| matches!(*value, 0 | 47 | 58 | 92)) {
            return Err(invalid("invalid Windows machine-config path component"));
        }
        Ok(value)
    }

    fn decompose(path: &Path) -> io::Result<(u8, Vec<Vec<u16>>)> {
        let mut components = path.components();
        let drive = match components.next() {
            Some(Component::Prefix(prefix)) => match prefix.kind() {
                Prefix::Disk(drive) | Prefix::VerbatimDisk(drive) => drive,
                _ => return Err(invalid("machine config requires a local drive path")),
            },
            _ => return Err(invalid("machine config path is not absolute")),
        };
        if components.next() != Some(Component::RootDir) {
            return Err(invalid("machine config path is not rooted"));
        }
        let mut result = Vec::new();
        for component in components {
            match component {
                Component::Normal(value) => result.push(component_wide(value)?),
                Component::CurDir => {}
                _ => return Err(invalid("machine config path contains traversal")),
            }
        }
        Ok((drive, result))
    }

    fn open_volume_root(drive: u8) -> io::Result<OwnedHandle> {
        let path = format!(r"\\?\{}:\", drive as char);
        let access =
            FILE_LIST_DIRECTORY | FILE_TRAVERSE | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE;
        let file = std::fs::OpenOptions::new()
            .access_mode(access)
            .share_mode(SHARE_ALL)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)?;
        Ok(OwnedHandle::from(file))
    }

    fn open_durability_volume(drive: u8) -> io::Result<OwnedHandle> {
        let path = format!(r"\\.\{}:", drive as char)
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        let handle = unsafe {
            CreateFileW(
                path.as_ptr(),
                GENERIC_WRITE,
                SHARE_ALL,
                null_mut(),
                OPEN_EXISTING,
                0,
                null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        Ok(unsafe { OwnedHandle::from_raw_handle(handle as RawHandle) })
    }

    fn volume_information(handle: HANDLE) -> io::Result<(u32, u32)> {
        let mut serial = 0;
        let mut flags = 0;
        if unsafe {
            GetVolumeInformationByHandleW(
                handle,
                null_mut(),
                0,
                &mut serial,
                null_mut(),
                &mut flags,
                null_mut(),
                0,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok((serial, flags))
    }

    unsafe fn open_at(
        parent: HANDLE,
        name: &[u16],
        desired_access: u32,
        disposition: u32,
        options: u32,
    ) -> io::Result<OwnedHandle> {
        let name_bytes = name
            .len()
            .checked_mul(2)
            .filter(|length| *length <= u16::MAX as usize)
            .ok_or_else(|| invalid("machine config path component is too long"))?;
        let mut unicode = UNICODE_STRING {
            Length: name_bytes as u16,
            MaximumLength: name_bytes as u16,
            Buffer: name.as_ptr() as *mut u16,
        };
        let mut attributes: OBJECT_ATTRIBUTES = zeroed();
        attributes.Length = size_of::<OBJECT_ATTRIBUTES>() as u32;
        attributes.RootDirectory = parent;
        attributes.ObjectName = &mut unicode;
        attributes.Attributes = OBJ_CASE_INSENSITIVE;
        let mut handle: HANDLE = null_mut();
        let mut status_block: IO_STATUS_BLOCK = zeroed();
        let status = NtCreateFile(
            &mut handle,
            desired_access | SYNCHRONIZE | FILE_READ_ATTRIBUTES | READ_CONTROL,
            &mut attributes,
            &mut status_block,
            null_mut(),
            FILE_ATTRIBUTE_NORMAL,
            SHARE_ALL,
            disposition,
            options | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
            null_mut(),
            0,
        );
        if !NT_SUCCESS(status) {
            return Err(nt_error(status));
        }
        let handle = OwnedHandle::from_raw_handle(handle as RawHandle);
        let mut tag: FILE_ATTRIBUTE_TAG_INFORMATION = zeroed();
        let mut query_status: IO_STATUS_BLOCK = zeroed();
        let status = NtQueryInformationFile(
            handle.as_raw_handle() as HANDLE,
            &mut query_status,
            (&mut tag as *mut FILE_ATTRIBUTE_TAG_INFORMATION).cast(),
            size_of::<FILE_ATTRIBUTE_TAG_INFORMATION>() as u32,
            FileAttributeTagInformation,
        );
        if !NT_SUCCESS(status) || tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "machine config component is a reparse point or could not be proven ordinary",
            ));
        }
        Ok(handle)
    }

    fn directory_access(write_authority: bool) -> u32 {
        let mut access = FILE_LIST_DIRECTORY | FILE_TRAVERSE;
        if write_authority {
            access |=
                FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY | FILE_WRITE_ATTRIBUTES | FILE_DELETE_CHILD;
        }
        access
    }

    fn open_directory_at(
        parent: HANDLE,
        name: &[u16],
        write_authority: bool,
        create: bool,
    ) -> io::Result<OwnedHandle> {
        if create {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "machine config root descendants must be installer-provisioned",
            ));
        }
        unsafe {
            open_at(
                parent,
                name,
                directory_access(write_authority),
                FILE_OPEN,
                FILE_DIRECTORY_FILE | FILE_OPEN_FOR_BACKUP_INTENT,
            )
        }
    }

    fn identity(handle: HANDLE) -> io::Result<FileIdentity> {
        let mut information: BY_HANDLE_FILE_INFORMATION = unsafe { zeroed() };
        if unsafe { winapi::um::fileapi::GetFileInformationByHandle(handle, &mut information) } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(FileIdentity {
            volume: information.dwVolumeSerialNumber,
            index_high: information.nFileIndexHigh,
            index_low: information.nFileIndexLow,
        })
    }

    pub(super) fn initialize(path: PathBuf, write_authority: bool) -> Result<PathBuf> {
        let (drive, components) = decompose(&path)?;
        if components.is_empty() {
            return Err(anyhow!("machine config root has no directory components"));
        }
        let mut current = open_volume_root(drive)?;
        for (index, component) in components.iter().enumerate() {
            let final_root = index + 1 == components.len();
            current = open_directory_at(
                current.as_raw_handle() as HANDLE,
                component,
                write_authority && final_root,
                false,
            )?;
        }
        windows_config_acl::verify_machine_root_handle(current.as_raw_handle() as HANDLE)?;
        let root_identity = identity(current.as_raw_handle() as HANDLE)?;
        let (root_volume_serial, root_volume_flags) =
            volume_information(current.as_raw_handle() as HANDLE)?;
        if root_volume_serial != root_identity.volume
            || root_volume_flags & FILE_PERSISTENT_ACLS == 0
            || root_volume_flags & FILE_READ_ONLY_VOLUME != 0
        {
            return Err(anyhow!(
                "machine config root volume identity or persistent-ACL support is invalid"
            ));
        }
        let durability_volume = if write_authority {
            let volume = open_durability_volume(drive)?;
            let (volume_serial, volume_flags) =
                volume_information(volume.as_raw_handle() as HANDLE)?;
            if volume_serial != root_volume_serial
                || volume_flags & FILE_PERSISTENT_ACLS == 0
                || volume_flags & FILE_READ_ONLY_VOLUME != 0
            {
                return Err(anyhow!(
                    "machine config durability volume does not match the retained root"
                ));
            }
            Some(volume)
        } else {
            None
        };
        let root = Root {
            path: path.clone(),
            identity: root_identity,
            handle: current,
            durability_volume,
            write_authority,
        };
        match ROOT.set(root) {
            Ok(()) => Ok(path),
            Err(candidate) => {
                let Some(existing) = ROOT.get() else {
                    return Err(anyhow!("machine config root initialization was lost"));
                };
                if existing.path == candidate.path
                    && existing.identity == candidate.identity
                    && existing.write_authority == candidate.write_authority
                {
                    Ok(existing.path.clone())
                } else {
                    Err(anyhow!(
                        "machine config root was initialized inconsistently"
                    ))
                }
            }
        }
    }

    pub(super) fn root_path() -> Option<&'static Path> {
        ROOT.get().map(|root| root.path.as_path())
    }

    pub(super) fn contains(path: &Path) -> bool {
        root_path().is_some_and(|root| path.starts_with(root))
    }

    fn relative_components(path: &Path) -> io::Result<Vec<Vec<u16>>> {
        let root = ROOT
            .get()
            .ok_or_else(|| invalid("machine config root is not initialized"))?;
        let relative = path
            .strip_prefix(&root.path)
            .map_err(|_| invalid("machine config path escaped its root"))?;
        let mut result = Vec::new();
        for component in relative.components() {
            match component {
                Component::Normal(value) => result.push(component_wide(value)?),
                Component::CurDir => {}
                _ => return Err(invalid("machine config path contains traversal")),
            }
        }
        if result.is_empty() {
            return Err(invalid("machine config operation requires a child path"));
        }
        Ok(result)
    }

    fn with_parent<T>(
        path: &Path,
        write: bool,
        operation: impl FnOnce(HANDLE, &[u16]) -> io::Result<T>,
    ) -> io::Result<T> {
        let root = ROOT
            .get()
            .ok_or_else(|| invalid("machine config root is not initialized"))?;
        if write && !root.write_authority {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "service child has no machine-config disk authority",
            ));
        }
        let components = relative_components(path)?;
        let (file_name, directories) = components
            .split_last()
            .ok_or_else(|| invalid("machine config path has no file name"))?;
        let mut owned = Vec::new();
        let mut parent = root.handle.as_raw_handle() as HANDLE;
        for directory in directories {
            let handle = open_directory_at(parent, directory, write, false)?;
            verify_machine_child_handle(handle.as_raw_handle() as HANDLE, true)?;
            parent = handle.as_raw_handle() as HANDLE;
            owned.push(handle);
        }
        operation(parent, file_name)
    }

    fn verify_machine_child_handle(handle: HANDLE, expected_directory: bool) -> io::Result<()> {
        windows_config_acl::verify_machine_child_handle(handle, expected_directory).map_err(|err| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("machine config object trust validation failed: {err:#}"),
            )
        })
    }

    pub(super) fn read(path: &Path) -> io::Result<Vec<u8>> {
        with_parent(path, false, |parent, name| {
            let handle = unsafe {
                open_at(
                    parent,
                    name,
                    FILE_GENERIC_READ,
                    FILE_OPEN,
                    FILE_NON_DIRECTORY_FILE,
                )?
            };
            verify_machine_child_handle(handle.as_raw_handle() as HANDLE, false)?;
            let opened_identity = identity(handle.as_raw_handle() as HANDLE)?;
            let mut file = File::from(handle);
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes)?;
            if identity(file.as_raw_handle() as HANDLE)? != opened_identity {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "machine config file identity changed while open",
                ));
            }
            Ok(bytes)
        })
    }

    pub(super) fn preserve_corrupt(path: &Path) -> io::Result<()> {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| invalid("machine config file name is not UTF-8"))?;
        let backup_name = component_wide(OsStr::new(&format!("{file_name}.corrupt.{stamp}")))?;
        with_parent(path, true, |parent, name| {
            let handle = unsafe {
                open_at(
                    parent,
                    name,
                    DELETE | FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                    FILE_OPEN,
                    FILE_NON_DIRECTORY_FILE,
                )?
            };
            verify_machine_child_handle(handle.as_raw_handle() as HANDLE, false)?;
            unsafe {
                rename_at(
                    handle.as_raw_handle() as HANDLE,
                    parent,
                    &backup_name,
                    false,
                )?;
            }
            if flush_renamed_file(handle.as_raw_handle() as HANDLE).is_err()
                || flush_namespace_volume().is_err()
            {
                std::process::abort();
            }
            Ok(())
        })
    }

    unsafe fn mark_delete(handle: HANDLE) -> io::Result<()> {
        let mut information = FILE_DISPOSITION_INFORMATION { DeleteFileA: 1 };
        let mut status_block: IO_STATUS_BLOCK = zeroed();
        let status = NtSetInformationFile(
            handle,
            &mut status_block,
            (&mut information as *mut FILE_DISPOSITION_INFORMATION).cast(),
            size_of::<FILE_DISPOSITION_INFORMATION>() as u32,
            FileDispositionInformation,
        );
        if NT_SUCCESS(status) {
            Ok(())
        } else {
            Err(nt_error(status))
        }
    }

    unsafe fn rename_at(
        handle: HANDLE,
        parent: HANDLE,
        name: &[u16],
        replace: bool,
    ) -> io::Result<()> {
        let name_bytes = name
            .len()
            .checked_mul(2)
            .ok_or_else(|| invalid("machine config rename name is too long"))?;
        let name_bytes_u32 = u32::try_from(name_bytes)
            .map_err(|_| invalid("machine config rename name is too long"))?;
        let total = size_of::<FILE_RENAME_INFORMATION>()
            .checked_add(name_bytes)
            .ok_or_else(|| invalid("machine config rename buffer overflow"))?;
        let mut buffer = vec![0u64; (total + 7) / 8];
        let information = buffer.as_mut_ptr() as *mut FILE_RENAME_INFORMATION;
        (*information).ReplaceIfExists = u8::from(replace);
        (*information).RootDirectory = parent;
        (*information).FileNameLength = name_bytes_u32;
        copy_nonoverlapping(
            name.as_ptr(),
            (*information).FileName.as_mut_ptr(),
            name.len(),
        );
        let name_offset =
            ((*information).FileName.as_ptr() as usize).saturating_sub(information as usize);
        let length = name_offset
            .checked_add(name_bytes)
            .and_then(|length| u32::try_from(length).ok())
            .ok_or_else(|| invalid("machine config rename length overflow"))?;
        let mut status_block: IO_STATUS_BLOCK = zeroed();
        let status = NtSetInformationFile(
            handle,
            &mut status_block,
            information.cast(),
            length,
            FileRenameInformation,
        );
        if NT_SUCCESS(status) {
            Ok(())
        } else {
            Err(nt_error(status))
        }
    }

    fn flush_renamed_file(handle: HANDLE) -> io::Result<()> {
        let mut status_block: IO_STATUS_BLOCK = unsafe { zeroed() };
        let status = unsafe { NtFlushBuffersFile(handle, &mut status_block) };
        if NT_SUCCESS(status) {
            Ok(())
        } else {
            Err(nt_error(status))
        }
    }

    fn flush_namespace_volume() -> io::Result<()> {
        let root = ROOT
            .get()
            .ok_or_else(|| invalid("machine config root is not initialized"))?;
        let volume = root.durability_volume.as_ref().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "service child has no machine-config durability authority",
            )
        })?;
        if unsafe { FlushFileBuffers(volume.as_raw_handle() as HANDLE) } == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    pub(super) fn store(path: &Path, bytes: &[u8], fault: ConfigStoreFault) -> Result<()> {
        with_parent(path, true, |parent, final_name| {
            for attempt in 0..128 {
                let temporary_name = config_temp_file_name(path, attempt)
                    .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?;
                let temporary_name = component_wide(OsStr::new(&temporary_name))?;
                let handle = match unsafe {
                    open_at(
                        parent,
                        &temporary_name,
                        FILE_GENERIC_READ | FILE_GENERIC_WRITE | DELETE,
                        FILE_CREATE,
                        FILE_NON_DIRECTORY_FILE | FILE_WRITE_THROUGH,
                    )
                } {
                    Ok(handle) => handle,
                    Err(err) if err.kind() == io::ErrorKind::AlreadyExists => continue,
                    Err(err) => return Err(err),
                };
                verify_machine_child_handle(handle.as_raw_handle() as HANDLE, false)?;
                let opened_identity = identity(handle.as_raw_handle() as HANDLE)?;
                let mut file = File::from(handle);
                let precommit = (|| -> io::Result<()> {
                    file.write_all(bytes)?;
                    file.sync_all()?;
                    if fault == ConfigStoreFault::BeforeReplace {
                        return Err(io::Error::new(
                            io::ErrorKind::Other,
                            "injected machine config failure before replacement",
                        ));
                    }
                    if identity(file.as_raw_handle() as HANDLE)? != opened_identity {
                        return Err(io::Error::new(
                            io::ErrorKind::Other,
                            "machine config temporary file identity changed",
                        ));
                    }
                    Ok(())
                })();
                if let Err(err) = precommit {
                    let cleanup = unsafe { mark_delete(file.as_raw_handle() as HANDLE) };
                    return match cleanup {
                        Ok(()) => Err(err),
                        Err(cleanup) => Err(io::Error::new(
                            io::ErrorKind::Other,
                            format!("{err}; temporary cleanup failed: {cleanup}"),
                        )),
                    };
                }
                unsafe {
                    rename_at(file.as_raw_handle() as HANDLE, parent, final_name, true)?;
                }
                if fault == ConfigStoreFault::AfterReplace {
                    std::process::abort();
                }
                if flush_renamed_file(file.as_raw_handle() as HANDLE).is_err()
                    || flush_namespace_volume().is_err()
                {
                    std::process::abort();
                }
                if identity(file.as_raw_handle() as HANDLE)? != opened_identity {
                    std::process::abort();
                }
                return Ok(());
            }
            Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "could not allocate a machine config temporary file",
            ))
        })
        .map_err(Into::into)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn windows_service_owned_root_native_walk_requires_a_local_drive() {
            let (drive, components) = decompose(Path::new(r"C:\ProgramData\RustDesk\config"))
                .expect("fixed ProgramData path should decompose");
            assert_eq!(drive, b'C');
            assert_eq!(components.len(), 3);
            assert!(decompose(Path::new(r"\\server\share\RustDesk\config")).is_err());
        }
    }
}

fn advance_permanent_password_credential_generation(generation: &mut u64) {
    let Some(next) = generation.checked_add(1) else {
        log::error!(
            "Permanent-password credential generation exhausted; refusing ABA by terminating"
        );
        std::process::abort();
    };
    *generation = next;
}

type Size = (i32, i32, i32, i32);
type KeyPair = (Vec<u8>, Vec<u8>);

lazy_static::lazy_static! {
    static ref CONFIG: RwLock<Config> = RwLock::new(Config::load());
    static ref CONFIG2: RwLock<Config2> = RwLock::new(Config2::load());
    static ref LOCAL_CONFIG: RwLock<LocalConfig> = RwLock::new(LocalConfig::load());
    static ref STATUS: RwLock<Status> = RwLock::new(Status::load());
    // R-X4: EXE_RENDEZVOUS_SERVER (the exe-name license rendezvous server) removed.
    pub static ref APP_NAME: RwLock<String> = RwLock::new("RustDesk".to_owned());
    static ref KEY_PAIR: Mutex<Option<KeyPair>> = Default::default();
    static ref USER_DEFAULT_CONFIG: RwLock<(UserDefaultConfig, Instant)> = RwLock::new((UserDefaultConfig::load(), Instant::now()));
    pub static ref NEW_STORED_PEER_CONFIG: Mutex<HashSet<String>> = Default::default();
    pub static ref DEFAULT_SETTINGS: RwLock<HashMap<String, String>> = Default::default();
    pub static ref OVERWRITE_SETTINGS: RwLock<HashMap<String, String>> = Default::default();
    pub static ref DEFAULT_DISPLAY_SETTINGS: RwLock<HashMap<String, String>> = Default::default();
    pub static ref OVERWRITE_DISPLAY_SETTINGS: RwLock<HashMap<String, String>> = Default::default();
    pub static ref DEFAULT_LOCAL_SETTINGS: RwLock<HashMap<String, String>> = Default::default();
    pub static ref OVERWRITE_LOCAL_SETTINGS: RwLock<HashMap<String, String>> = Default::default();
    pub static ref HARD_SETTINGS: RwLock<HashMap<String, String>> = Default::default();
    pub static ref BUILTIN_SETTINGS: RwLock<HashMap<String, String>> = Default::default();
    static ref RUNTIME_PERMANENT_PASSWORD_PRS: RwLock<Option<String>> = RwLock::new(None);
    // This lock is the credential publication/authorization linearization point. Writers hold it
    // while publishing a changed persisted or runtime credential and advancing the generation;
    // a new session holds the read side while validating its captured generation and committing
    // its authorization state. Existing authorized sessions deliberately do not retain the lock.
    static ref PERMANENT_PASSWORD_CREDENTIAL_GENERATION: RwLock<u64> = RwLock::new(1);
}

#[cfg(target_os = "android")]
lazy_static::lazy_static! {
    pub static ref ANDROID_RUSTLS_PLATFORM_VERIFIER_INITIALIZED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
}

lazy_static::lazy_static! {
    pub static ref APP_DIR: RwLock<String> = Default::default();
}

#[cfg(any(target_os = "android", target_os = "ios"))]
lazy_static::lazy_static! {
    pub static ref APP_HOME_DIR: RwLock<String> = Default::default();
}

lazy_static::lazy_static! {
    pub static ref HELPER_URL: HashMap<&'static str, &'static str> = HashMap::new();
}

const PERMANENT_PASSWORD_STORAGE_SALT_CHARS: &[char] = &[
    '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k',
    'm', 'n', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
];

pub const RS_PUB_KEY: &str = "OeVuKk5nlHiXp+APNn0Y3pC1Iwpwn44JGqrQCsWqmBw=";

// Upstream's RELAY_PORT (21117) / WS_RENDEZVOUS_PORT (21118) / WS_RELAY_PORT (21119) are REMOVED:
// the rendezvous, relay, and WebSocket transports are excised. Only the pinned DIRECT_PORT
// listener remains.
// R-F4: the serverless direct-IP listener binds a SINGLE pinned compile-time
// constant. Deliberately a literal, NOT a rendezvous-port-plus-two derivation —
// that would silently shift the port (and desync the §10.4 CPace `CI` KAT,
// be16(21118)=527e) if the rendezvous port ever changed. Never a runtime option,
// env var, or config key (the direct-port config read is removed); an operator who
// needs a different port changes this constant and rebuilds (a build-time choice,
// never a runtime mode). It folds into the PAKE channel binding `CI` (R-P1).
pub const DIRECT_PORT: i32 = 21118;

#[inline]
pub fn is_service_ipc_postfix(postfix: &str) -> bool {
    matches!(postfix, "_service" | "_service_password")
        || cfg!(target_os = "linux") && postfix == "_service_credential"
}

// Keep Linux/macOS IPC parent directory rules in one place to avoid drift between
// `ipc_path()` and Unix `ipc_path_for_uid()`.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[inline]
fn ipc_parent_dir_for_uid(uid: u32, postfix: &str) -> String {
    let app_name = APP_NAME.read().unwrap().clone();
    if is_service_ipc_postfix(postfix) {
        format!("/tmp/{app_name}-service")
    } else {
        format!("/tmp/{app_name}-{uid}")
    }
}

macro_rules! serde_field_string {
    ($default_func:ident, $de_func:ident, $default_expr:expr) => {
        fn $default_func() -> String {
            $default_expr
        }

        fn $de_func<'de, D>(deserializer: D) -> Result<String, D::Error>
        where
            D: de::Deserializer<'de>,
        {
            let s: String =
                de::Deserialize::deserialize(deserializer).unwrap_or(Self::$default_func());
            if s.is_empty() {
                return Ok(Self::$default_func());
            }
            Ok(s)
        }
    };
}

macro_rules! serde_field_bool {
    ($struct_name: ident, $field_name: literal, $func: ident, $default: literal) => {
        #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
        pub struct $struct_name {
            #[serde(default = $default, rename = $field_name, deserialize_with = "deserialize_bool")]
            pub v: bool,
        }
        impl Default for $struct_name {
            fn default() -> Self {
                Self { v: Self::$func() }
            }
        }
        impl $struct_name {
            pub fn $func() -> bool {
                UserDefaultConfig::read($field_name) == "Y"
            }
        }
        impl Deref for $struct_name {
            type Target = bool;

            fn deref(&self) -> &Self::Target {
                &self.v
            }
        }
        impl DerefMut for $struct_name {
            fn deref_mut(&mut self) -> &mut Self::Target {
                &mut self.v
            }
        }
    };
}

#[derive(Debug, Default, Serialize, Deserialize, Clone, PartialEq)]
pub struct Config {
    #[serde(
        default,
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string"
    )]
    pub id: String, // use
    #[serde(default, deserialize_with = "deserialize_string")]
    enc_id: String, // store
    #[serde(default, deserialize_with = "deserialize_string")]
    password: String,
    // R-P1/R-S16: the permanent password's DERIVED CPace PRS at rest — the base64 of
    // Argon2id(NFC(password), fixed R-P1 salt): a memory-hard salted hash, NEVER the
    // plaintext — encrypted under the same machine-UUID wrapper as `password`. The
    // balanced CPace handshake reads it live on every connection (no cached PRS) and
    // feeds it to the PAKE verbatim. set_permanent_password writes it together with
    // `password`, which holds the SAME PRS's raw 32 bytes in the legacy hashed-storage
    // envelope; an empty password clears both, so the handshake fails closed (R-S9).
    #[serde(default, deserialize_with = "deserialize_string")]
    password_prs: String,
    #[serde(default, deserialize_with = "deserialize_string")]
    salt: String,
    #[serde(default, deserialize_with = "deserialize_keypair")]
    key_pair: KeyPair, // sk, pk
}

// more variable configs
#[derive(Debug, Default, Serialize, Deserialize, Clone, PartialEq)]
pub struct Config2 {
    #[serde(default, deserialize_with = "deserialize_hashmap_string_string")]
    pub options: HashMap<String, String>,
}

#[derive(Debug, Default, Serialize, Deserialize, Clone, PartialEq)]
pub struct Resolution {
    pub w: i32,
    pub h: i32,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct PeerConfig {
    #[serde(default, deserialize_with = "deserialize_vec_u8")]
    pub password: Vec<u8>,
    // R-S16 (viewer twin): the remote box's DERIVED CPace PRS — the base64 Argon2id
    // hash from `derive_cpace_prs`, a memory-hard salted hash, NEVER the plaintext —
    // encrypted at rest exactly like `password`. The viewer feeds it to the CPace
    // INITIATOR verbatim (never re-derived); it is the identical shared secret both
    // ends derive from the password, distinct from the fast SHA-256 h1 that `password`
    // caches. Empty until derived from the user-entered password at connect time; the
    // initiator fails closed (R-S9) on an empty PRS. Old peer configs without this
    // field deserialize to empty (`#[serde(default)]`).
    #[serde(default, deserialize_with = "deserialize_vec_u8")]
    pub password_prs: Vec<u8>,
    #[serde(default, deserialize_with = "deserialize_size")]
    pub size: Size,
    #[serde(default, deserialize_with = "deserialize_size")]
    pub size_ft: Size,
    #[serde(default, deserialize_with = "deserialize_size")]
    pub size_pf: Size,
    #[serde(
        default = "PeerConfig::default_view_style",
        deserialize_with = "PeerConfig::deserialize_view_style",
        skip_serializing_if = "String::is_empty"
    )]
    pub view_style: String,
    // Image scroll style, scrolledge, scrollbar or scroll auto
    #[serde(
        default = "PeerConfig::default_scroll_style",
        deserialize_with = "PeerConfig::deserialize_scroll_style",
        skip_serializing_if = "String::is_empty"
    )]
    pub scroll_style: String,
    #[serde(
        default = "PeerConfig::default_edge_scroll_edge_thickness",
        deserialize_with = "PeerConfig::deserialize_edge_scroll_edge_thickness"
    )]
    pub edge_scroll_edge_thickness: i32,
    #[serde(
        default = "PeerConfig::default_image_quality",
        deserialize_with = "PeerConfig::deserialize_image_quality",
        skip_serializing_if = "String::is_empty"
    )]
    pub image_quality: String,
    #[serde(
        default = "PeerConfig::default_custom_image_quality",
        deserialize_with = "PeerConfig::deserialize_custom_image_quality",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub custom_image_quality: Vec<i32>,
    #[serde(flatten)]
    pub show_remote_cursor: ShowRemoteCursor,
    #[serde(flatten)]
    pub lock_after_session_end: LockAfterSessionEnd,
    #[serde(flatten)]
    pub terminal_persistent: TerminalPersistent,
    #[serde(flatten)]
    pub privacy_mode: PrivacyMode,
    #[serde(flatten)]
    pub allow_swap_key: AllowSwapKey,
    #[serde(default, deserialize_with = "deserialize_vec_i32_string_i32")]
    pub port_forwards: Vec<(i32, String, i32)>,
    #[serde(flatten)]
    pub disable_audio: DisableAudio,
    #[serde(flatten)]
    pub disable_clipboard: DisableClipboard,
    #[serde(flatten)]
    pub enable_file_copy_paste: EnableFileCopyPaste,
    #[serde(flatten)]
    pub show_quality_monitor: ShowQualityMonitor,
    #[serde(flatten)]
    pub follow_remote_cursor: FollowRemoteCursor,
    #[serde(flatten)]
    pub follow_remote_window: FollowRemoteWindow,
    #[serde(
        default,
        deserialize_with = "deserialize_string",
        skip_serializing_if = "String::is_empty"
    )]
    pub keyboard_mode: String,
    #[serde(flatten)]
    pub view_only: ViewOnly,
    #[serde(flatten)]
    pub show_my_cursor: ShowMyCursor,
    #[serde(flatten)]
    pub sync_init_clipboard: SyncInitClipboard,
    // Mouse wheel or touchpad scroll mode
    #[serde(
        default = "PeerConfig::default_reverse_mouse_wheel",
        deserialize_with = "PeerConfig::deserialize_reverse_mouse_wheel",
        skip_serializing_if = "String::is_empty"
    )]
    pub reverse_mouse_wheel: String,
    #[serde(
        default = "PeerConfig::default_displays_as_individual_windows",
        deserialize_with = "PeerConfig::deserialize_displays_as_individual_windows",
        skip_serializing_if = "String::is_empty"
    )]
    pub displays_as_individual_windows: String,
    #[serde(
        default = "PeerConfig::default_use_all_my_displays_for_the_remote_session",
        deserialize_with = "PeerConfig::deserialize_use_all_my_displays_for_the_remote_session",
        skip_serializing_if = "String::is_empty"
    )]
    pub use_all_my_displays_for_the_remote_session: String,
    #[serde(
        rename = "trackpad-speed",
        default = "PeerConfig::default_trackpad_speed",
        deserialize_with = "PeerConfig::deserialize_trackpad_speed"
    )]
    pub trackpad_speed: i32,

    #[serde(
        default,
        deserialize_with = "deserialize_hashmap_resolutions",
        skip_serializing_if = "HashMap::is_empty"
    )]
    pub custom_resolutions: HashMap<String, Resolution>,

    // The other scalar value must before this
    #[serde(
        default,
        deserialize_with = "deserialize_hashmap_string_string",
        skip_serializing_if = "HashMap::is_empty"
    )]
    pub options: HashMap<String, String>, // not use delete to represent default values
    // Various data for flutter ui
    #[serde(default, deserialize_with = "deserialize_hashmap_string_string")]
    pub ui_flutter: HashMap<String, String>,
    #[serde(default)]
    pub info: PeerInfoSerde,
    #[serde(default)]
    pub transfer: TransferSerde,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PermanentPasswordPrsRead {
    Available(String),
    Empty,
    UndecryptableStorage,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PermanentPasswordCredentialSnapshot {
    prs: PermanentPasswordPrsRead,
    generation: u64,
}

impl PermanentPasswordCredentialSnapshot {
    pub fn into_parts(self) -> (PermanentPasswordPrsRead, u64) {
        (self.prs, self.generation)
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }
}

impl PermanentPasswordPrsRead {
    pub fn is_available(&self) -> bool {
        matches!(self, Self::Available(_))
    }
}

impl Default for PeerConfig {
    fn default() -> Self {
        Self {
            password: Default::default(),
            password_prs: Default::default(), // R-S16 viewer twin
            size: Default::default(),
            size_ft: Default::default(),
            size_pf: Default::default(),
            view_style: Self::default_view_style(),
            scroll_style: Self::default_scroll_style(),
            edge_scroll_edge_thickness: Self::default_edge_scroll_edge_thickness(),
            image_quality: Self::default_image_quality(),
            custom_image_quality: Self::default_custom_image_quality(),
            show_remote_cursor: Default::default(),
            lock_after_session_end: Default::default(),
            terminal_persistent: Default::default(),
            privacy_mode: Default::default(),
            allow_swap_key: Default::default(),
            port_forwards: Default::default(),
            disable_audio: Default::default(),
            disable_clipboard: Default::default(),
            enable_file_copy_paste: Default::default(),
            show_quality_monitor: Default::default(),
            follow_remote_cursor: Default::default(),
            follow_remote_window: Default::default(),
            keyboard_mode: Default::default(),
            view_only: Default::default(),
            show_my_cursor: Default::default(),
            reverse_mouse_wheel: Self::default_reverse_mouse_wheel(),
            displays_as_individual_windows: Self::default_displays_as_individual_windows(),
            use_all_my_displays_for_the_remote_session:
                Self::default_use_all_my_displays_for_the_remote_session(),
            trackpad_speed: Self::default_trackpad_speed(),
            custom_resolutions: Default::default(),
            options: Self::default_options(),
            ui_flutter: Default::default(),
            info: Default::default(),
            transfer: Default::default(),
            sync_init_clipboard: Default::default(),
        }
    }
}

#[derive(Debug, PartialEq, Default, Serialize, Deserialize, Clone)]
pub struct PeerInfoSerde {
    #[serde(default, deserialize_with = "deserialize_string")]
    pub username: String,
    #[serde(default, deserialize_with = "deserialize_string")]
    pub hostname: String,
    #[serde(default, deserialize_with = "deserialize_string")]
    pub platform: String,
}

/// R-S15: a keyed-but-hostile peer must not write unbounded or attacker-controlled strings into
/// the viewer's persistent PeerConfig via the in-session PeerInfo / BackNotification arms — these
/// survive R-S13 keying (keying authenticates the peer; it does not make a hostile-but-keyed
/// peer's payload trustworthy, Appendix C #19). Every peer-supplied config string is funnelled
/// through this bound: control characters are stripped (no TOML / terminal / UI-injection bytes
/// reach the on-disk config) and the length is clamped (no config-bloat DoS). The initiator-side
/// twin of the responder's R-S11 config-write gate.
pub fn bound_peer_config_string(s: &str) -> String {
    const MAX_PEER_CONFIG_STRING: usize = 256;
    s.chars()
        .filter(|c| !c.is_control())
        .take(MAX_PEER_CONFIG_STRING)
        .collect()
}

#[derive(Debug, Default, Serialize, Deserialize, Clone, PartialEq)]
pub struct TransferSerde {
    #[serde(default, deserialize_with = "deserialize_vec_string")]
    pub write_jobs: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_vec_string")]
    pub read_jobs: Vec<String>,
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn patch(path: PathBuf) -> PathBuf {
    if let Some(_tmp) = path.to_str() {
        #[cfg(target_os = "macos")]
        return _tmp.replace("Application Support", "Preferences").into();
        #[cfg(target_os = "linux")]
        {
            if _tmp == "/root" {
                if let Some(home) = crate::platform::linux::get_home_dir_trusted() {
                    return home;
                }
            }
        }
    }
    path
}

impl Config2 {
    fn load() -> Config2 {
        Config::load_::<Config2>("2")
    }

    pub fn file() -> PathBuf {
        Config::file_("2")
    }

    fn store(&self) {
        Config::store_(self, "2");
    }
}

fn keep_encrypted_storage_if_plaintext_unchanged(plain: &str, stored: &str) -> String {
    let (stored_plain, encrypted, _) = decrypt_str_or_original(stored, PASSWORD_ENC_VERSION);
    if encrypted && stored_plain == plain {
        return stored.to_owned();
    }
    encrypt_str_or_original(plain, PASSWORD_ENC_VERSION, ENCRYPT_MAX_LEN)
}

// F1: preserve a present-but-corrupt config for operator recovery instead of letting a
// fresh default overwrite it. Rename it aside to a timestamped `<name>.corrupt.<nanos>`
// sibling, harden the recovery file, then let callers create a fresh config at the vacated
// path. Repeated corruption events never clobber an earlier backup.
fn preserve_corrupt_config(file: &Path) {
    let ts = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let name = file
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("config");
    let mut backup = file.to_path_buf();
    backup.set_file_name(format!("{name}.corrupt.{ts}"));
    match fs::rename(file, &backup) {
        Ok(()) => {
            if let Err(err) = harden_preserved_config_file(&backup) {
                log::error!(
                    "Preserved corrupt config '{}' as '{}', but failed to harden recovery file: {err}",
                    file.display(),
                    backup.display()
                );
                return;
            }
            log::error!(
                "Preserved corrupt config '{}' as '{}' for recovery (original not overwritten)",
                file.display(),
                backup.display()
            );
        }
        Err(e) => log::error!(
            "Could not preserve corrupt config '{}' ({e}); leaving it in place — \
             Config::load refuses to overwrite a present config it read as default",
            file.display()
        ),
    }
}

#[cfg(unix)]
fn harden_preserved_config_file(path: &Path) -> Result<()> {
    use std::os::unix::{
        fs::{MetadataExt, OpenOptionsExt},
        io::AsRawFd,
    };

    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(crate::libc::O_CLOEXEC | crate::libc::O_NOFOLLOW)
        .open(path)
        .map_err(|err| {
            anyhow!(
                "Failed to open preserved config '{}' for hardening: {err}",
                path.display()
            )
        })?;
    let metadata = file.metadata().map_err(|err| {
        anyhow!(
            "Failed to inspect preserved config '{}': {err}",
            path.display()
        )
    })?;
    if !metadata.file_type().is_file() {
        return Err(anyhow!(
            "Preserved config '{}' is not a regular file",
            path.display()
        ));
    }
    if unsafe { crate::libc::fchmod(file.as_raw_fd(), 0o600 as crate::libc::mode_t) } != 0 {
        return Err(anyhow!(
            "Failed to set owner-only permissions on preserved config '{}': {}",
            path.display(),
            io::Error::last_os_error()
        ));
    }
    let mode = file
        .metadata()
        .map_err(|err| {
            anyhow!(
                "Failed to re-check preserved config '{}': {err}",
                path.display()
            )
        })?
        .mode()
        & 0o777;
    if mode != 0o600 {
        return Err(anyhow!(
            "Preserved config '{}' mode is {:o}, expected 600",
            path.display(),
            mode
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn harden_preserved_config_file(path: &Path) -> Result<()> {
    windows_config_acl::harden_config_file(path)
}

#[cfg(not(any(unix, windows)))]
fn harden_preserved_config_file(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(any(windows, test))]
fn windows_config_acl_sddl(user_sid: &str, inherit_to_children: bool) -> String {
    let inherit = if inherit_to_children { "OICI" } else { "" };
    let ace = |sid: &str| format!("(A;{inherit};FA;;;{sid})");
    if user_sid.eq_ignore_ascii_case("S-1-5-18") {
        format!("D:P{}", ace("SY"))
    } else {
        format!("D:P{}{}", ace("SY"), ace(user_sid))
    }
}

#[cfg(windows)]
mod windows_config_acl {
    use super::windows_config_acl_sddl;
    use anyhow::{anyhow, Result};
    use std::{
        fs,
        mem::{size_of, zeroed},
        os::windows::ffi::OsStrExt,
        path::Path,
        ptr,
    };
    use winapi::{
        shared::{
            minwindef::{DWORD, FALSE, HLOCAL, LPVOID},
            ntdef::{HANDLE, LPWSTR},
            sddl::{
                ConvertSecurityDescriptorToStringSecurityDescriptorW, ConvertSidToStringSidW,
                ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
            },
            winerror::ERROR_SUCCESS,
        },
        um::{
            accctrl::SE_FILE_OBJECT,
            aclapi::{GetNamedSecurityInfoW, GetSecurityInfo, SetNamedSecurityInfoW},
            errhandlingapi::GetLastError,
            fileapi::GetFileInformationByHandle,
            handleapi::CloseHandle,
            processthreadsapi::{GetCurrentProcess, OpenProcessToken},
            securitybaseapi::{
                GetAce, GetAclInformation, GetSecurityDescriptorControl, GetSecurityDescriptorDacl,
                GetTokenInformation, IsValidSid,
            },
            winbase::LocalFree,
            winnt::{
                AclSizeInformation, TokenUser, ACCESS_ALLOWED_ACE, ACCESS_ALLOWED_ACE_TYPE,
                ACE_HEADER, ACL_SIZE_INFORMATION, CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION,
                FILE_ALL_ACCESS, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
                OBJECT_INHERIT_ACE, OWNER_SECURITY_INFORMATION, PACL,
                PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
                SECURITY_DESCRIPTOR_CONTROL, SE_DACL_PROTECTED, SID_MAX_SUB_AUTHORITIES,
                SID_REVISION, TOKEN_QUERY, TOKEN_USER,
            },
        },
    };

    struct LocalFreeGuard(HLOCAL);

    impl Drop for LocalFreeGuard {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    let _ = LocalFree(self.0);
                }
            }
        }
    }

    struct HandleGuard(winapi::um::winnt::HANDLE);

    impl Drop for HandleGuard {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    CloseHandle(self.0);
                }
            }
        }
    }

    pub(super) fn prepare_config_path_for_load(path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            if parent.exists() {
                harden_path(parent, true)?;
                verify_hardened_path(parent, true)?;
            }
        }
        if path.exists() {
            harden_path(path, false)?;
            verify_hardened_path(path, false)?;
        }
        Ok(())
    }

    pub(super) fn prepare_config_path_for_store(path: &Path) -> Result<()> {
        let parent = path
            .parent()
            .ok_or_else(|| anyhow!("Config path '{}' has no parent directory", path.display()))?;
        fs::create_dir_all(parent).map_err(|err| {
            anyhow!(
                "Failed to create config directory '{}': {err}",
                parent.display()
            )
        })?;
        harden_path(parent, true)?;
        verify_hardened_path(parent, true)
    }

    pub(super) fn verify_machine_root_handle(handle: HANDLE) -> Result<()> {
        verify_machine_handle(handle, true, true)
    }

    pub(super) fn verify_machine_child_handle(
        handle: HANDLE,
        expected_directory: bool,
    ) -> Result<()> {
        verify_machine_handle(handle, expected_directory, false)
    }

    fn verify_machine_handle(
        handle: HANDLE,
        expected_directory: bool,
        require_protected_inheritable_dacl: bool,
    ) -> Result<()> {
        let mut information = unsafe { zeroed() };
        if unsafe { GetFileInformationByHandle(handle, &mut information) } == FALSE {
            return Err(anyhow!(
                "GetFileInformationByHandle failed for machine config object: win32_error={}",
                unsafe { GetLastError() }
            ));
        }
        let is_directory = information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0;
        if is_directory != expected_directory
            || information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        {
            return Err(anyhow!(
                "Machine config object type or reparse-point validation failed"
            ));
        }

        let mut owner: PSID = ptr::null_mut();
        let mut dacl: PACL = ptr::null_mut();
        let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
        let result = unsafe {
            GetSecurityInfo(
                handle,
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                ptr::null_mut(),
                &mut dacl,
                ptr::null_mut(),
                &mut descriptor,
            )
        };
        if result != ERROR_SUCCESS || descriptor.is_null() || owner.is_null() || dacl.is_null() {
            return Err(anyhow!(
                "GetSecurityInfo returned no authoritative machine config owner/DACL: win32_error={result}"
            ));
        }
        let _descriptor_guard = LocalFreeGuard(descriptor as HLOCAL);
        let owner = sid_to_string(owner)?;
        if !owner.eq_ignore_ascii_case("S-1-5-18") && !owner.eq_ignore_ascii_case("S-1-5-32-544") {
            return Err(anyhow!(
                "Machine config object owner is not SYSTEM or Administrators"
            ));
        }

        if require_protected_inheritable_dacl {
            let mut control: SECURITY_DESCRIPTOR_CONTROL = 0;
            let mut revision = 0;
            if unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) }
                == FALSE
                || control & SE_DACL_PROTECTED == 0
            {
                return Err(anyhow!("Machine config root DACL is not protected"));
            }
        }

        let mut acl_information: ACL_SIZE_INFORMATION = unsafe { zeroed() };
        if unsafe {
            GetAclInformation(
                dacl,
                (&mut acl_information as *mut ACL_SIZE_INFORMATION).cast(),
                size_of::<ACL_SIZE_INFORMATION>() as DWORD,
                AclSizeInformation,
            )
        } == FALSE
        {
            return Err(anyhow!(
                "GetAclInformation failed for machine config object: win32_error={}",
                unsafe { GetLastError() }
            ));
        }
        if acl_information.AceCount == 0 {
            return Err(anyhow!("Machine config object has an empty DACL"));
        }

        let mut system_full = false;
        let mut administrators_full = false;
        for index in 0..acl_information.AceCount {
            let mut raw_ace: LPVOID = ptr::null_mut();
            if unsafe { GetAce(dacl, index, &mut raw_ace) } == FALSE || raw_ace.is_null() {
                return Err(anyhow!(
                    "GetAce failed for machine config object: index={index}, win32_error={}",
                    unsafe { GetLastError() }
                ));
            }
            let header = unsafe { &*(raw_ace as *const ACE_HEADER) };
            let sid_offset = size_of::<ACCESS_ALLOWED_ACE>() - size_of::<DWORD>();
            let ace_size = usize::from(header.AceSize);
            if header.AceType != ACCESS_ALLOWED_ACE_TYPE || ace_size < sid_offset + 8 {
                return Err(anyhow!(
                    "Machine config DACL contains a non-basic allow ACE"
                ));
            }
            let ace = unsafe { &*(raw_ace as *const ACCESS_ALLOWED_ACE) };
            if ace.Mask & FILE_ALL_ACCESS != FILE_ALL_ACCESS {
                return Err(anyhow!(
                    "Machine config DACL contains a non-full-control ACE"
                ));
            }
            if require_protected_inheritable_dacl
                && ace.Header.AceFlags & (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE)
                    != (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE)
            {
                return Err(anyhow!(
                    "Machine config root DACL does not propagate to files and directories"
                ));
            }
            let sid_bytes = unsafe {
                std::slice::from_raw_parts(
                    (raw_ace as *const u8).add(sid_offset),
                    ace_size - sid_offset,
                )
            };
            let sub_authorities = usize::from(sid_bytes[1]);
            let sid_length = sub_authorities
                .checked_mul(size_of::<DWORD>())
                .and_then(|length| 8usize.checked_add(length))
                .ok_or_else(|| anyhow!("Machine config DACL SID length overflow"))?;
            if sid_bytes[0] != SID_REVISION
                || sub_authorities > usize::from(SID_MAX_SUB_AUTHORITIES)
                || sid_length > sid_bytes.len()
            {
                return Err(anyhow!("Machine config DACL contains a malformed SID"));
            }
            let sid: PSID = sid_bytes.as_ptr().cast_mut().cast();
            if unsafe { IsValidSid(sid) } == FALSE {
                return Err(anyhow!("Machine config DACL contains an invalid SID"));
            }
            match sid_to_string(sid)?.to_ascii_uppercase().as_str() {
                "S-1-5-18" => system_full = true,
                "S-1-5-32-544" => administrators_full = true,
                _ => {
                    return Err(anyhow!(
                        "Machine config DACL grants access to a lower principal"
                    ));
                }
            }
        }
        if !system_full || !administrators_full {
            return Err(anyhow!(
                "Machine config DACL does not grant full control to SYSTEM and Administrators"
            ));
        }
        Ok(())
    }

    pub(super) fn harden_config_file(path: &Path) -> Result<()> {
        harden_path(path, false)
    }

    pub(super) fn verify_config_file(path: &Path) -> Result<()> {
        verify_hardened_path(path, false)
    }

    fn harden_path(path: &Path, inherit_to_children: bool) -> Result<()> {
        let user_sid = current_user_sid_string()?;
        let sddl = windows_config_acl_sddl(&user_sid, inherit_to_children);
        let mut sd: PSECURITY_DESCRIPTOR = ptr::null_mut();
        let mut sddl_w = wide_null(&sddl);
        let converted = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl_w.as_mut_ptr(),
                SDDL_REVISION_1 as DWORD,
                &mut sd,
                ptr::null_mut(),
            )
        };
        if converted == FALSE || sd.is_null() {
            return Err(anyhow!(
                "ConvertStringSecurityDescriptorToSecurityDescriptorW failed for config ACL '{}': win32_error={}",
                path.display(),
                unsafe { GetLastError() }
            ));
        }
        let _sd_guard = LocalFreeGuard(sd as HLOCAL);

        let mut dacl_present = FALSE;
        let mut dacl_defaulted = FALSE;
        let mut dacl: PACL = ptr::null_mut();
        let got_dacl = unsafe {
            GetSecurityDescriptorDacl(sd, &mut dacl_present, &mut dacl, &mut dacl_defaulted)
        };
        if got_dacl == FALSE || dacl_present == FALSE || dacl.is_null() {
            return Err(anyhow!(
                "Converted config ACL has no DACL for '{}': win32_error={}",
                path.display(),
                unsafe { GetLastError() }
            ));
        }

        let mut path_w = wide_path(path);
        let result = unsafe {
            SetNamedSecurityInfoW(
                path_w.as_mut_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                dacl,
                ptr::null_mut(),
            )
        };
        if result != ERROR_SUCCESS {
            return Err(anyhow!(
                "SetNamedSecurityInfoW failed for config path '{}': win32_error={result}",
                path.display()
            ));
        }
        Ok(())
    }

    fn verify_hardened_path(path: &Path, inherit_to_children: bool) -> Result<()> {
        let mut path_w = wide_path(path);
        let mut sd: PSECURITY_DESCRIPTOR = ptr::null_mut();
        let result = unsafe {
            GetNamedSecurityInfoW(
                path_w.as_mut_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                &mut sd,
            )
        };
        if result != ERROR_SUCCESS || sd.is_null() {
            return Err(anyhow!(
                "GetNamedSecurityInfoW failed while verifying config ACL '{}': win32_error={result}",
                path.display()
            ));
        }
        let _sd_guard = LocalFreeGuard(sd as HLOCAL);
        let mut sddl_w: LPWSTR = ptr::null_mut();
        let converted = unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                sd,
                SDDL_REVISION_1 as DWORD,
                DACL_SECURITY_INFORMATION,
                &mut sddl_w,
                ptr::null_mut(),
            )
        };
        if converted == FALSE || sddl_w.is_null() {
            return Err(anyhow!(
                "Could not serialize config ACL for verification '{}': win32_error={}",
                path.display(),
                unsafe { GetLastError() }
            ));
        }
        let _sddl_guard = LocalFreeGuard(sddl_w as HLOCAL);
        let mut len = 0usize;
        while unsafe { *sddl_w.add(len) } != 0 {
            len += 1;
        }
        let actual = String::from_utf16(unsafe { std::slice::from_raw_parts(sddl_w, len) })?;
        let expected = windows_config_acl_sddl(&current_user_sid_string()?, inherit_to_children);
        if !actual.eq_ignore_ascii_case(&expected) {
            return Err(anyhow!(
                "Config ACL verification failed for '{}': expected '{}', got '{}'",
                path.display(),
                expected,
                actual
            ));
        }
        Ok(())
    }

    fn current_user_sid_string() -> Result<String> {
        let mut token = ptr::null_mut();
        let opened = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) };
        if opened == FALSE || token.is_null() {
            return Err(anyhow!(
                "OpenProcessToken failed while securing config ACL: win32_error={}",
                unsafe { GetLastError() }
            ));
        }
        let _token_guard = HandleGuard(token);

        let mut len: DWORD = 0;
        unsafe {
            GetTokenInformation(token, TokenUser, ptr::null_mut(), 0, &mut len);
        }
        if len == 0 {
            return Err(anyhow!(
                "GetTokenInformation(TokenUser) returned no buffer length while securing config ACL: win32_error={}",
                unsafe { GetLastError() }
            ));
        }

        let mut buf = vec![0u8; len as usize];
        let read = unsafe {
            GetTokenInformation(token, TokenUser, buf.as_mut_ptr() as LPVOID, len, &mut len)
        };
        if read == FALSE {
            return Err(anyhow!(
                "GetTokenInformation(TokenUser) failed while securing config ACL: win32_error={}",
                unsafe { GetLastError() }
            ));
        }

        let token_user = unsafe { &*(buf.as_ptr() as *const TOKEN_USER) };
        let sid = token_user.User.Sid;
        if sid.is_null() {
            return Err(anyhow!(
                "Current process token has no user SID while securing config ACL"
            ));
        }
        sid_to_string(sid)
    }

    pub(super) fn current_process_is_local_system() -> Result<bool> {
        Ok(current_user_sid_string()?.eq_ignore_ascii_case("S-1-5-18"))
    }

    fn sid_to_string(sid: PSID) -> Result<String> {
        let mut sid_w: LPWSTR = ptr::null_mut();
        let converted = unsafe { ConvertSidToStringSidW(sid, &mut sid_w) };
        if converted == FALSE || sid_w.is_null() {
            return Err(anyhow!(
                "ConvertSidToStringSidW failed while securing config ACL: win32_error={}",
                unsafe { GetLastError() }
            ));
        }
        let _sid_guard = LocalFreeGuard(sid_w as HLOCAL);
        let mut len = 0usize;
        while unsafe { *sid_w.add(len) } != 0 {
            len += 1;
        }
        let sid_slice = unsafe { std::slice::from_raw_parts(sid_w, len) };
        String::from_utf16(sid_slice)
            .map_err(|err| anyhow!("ConvertSidToStringSidW returned invalid UTF-16: {err}"))
    }

    fn wide_null(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn wide_path(path: &Path) -> Vec<u16> {
        path.as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ConfigLoadStatus {
    Loaded,
    NotFound,
    Corrupt,
    TransientError,
}

struct ConfigLoad<T> {
    value: T,
    status: ConfigLoadStatus,
}

impl<T> ConfigLoad<T> {
    fn new(value: T, status: ConfigLoadStatus) -> Self {
        Self { value, status }
    }

    fn into_value(self) -> T {
        self.value
    }
}

pub fn load_path<T: serde::Serialize + serde::de::DeserializeOwned + Default + std::fmt::Debug>(
    file: PathBuf,
) -> T {
    load_path_with_status(file).into_value()
}

fn load_path_with_status<
    T: serde::Serialize + serde::de::DeserializeOwned + Default + std::fmt::Debug,
>(
    file: PathBuf,
) -> ConfigLoad<T> {
    #[cfg(windows)]
    if windows_machine_config::contains(&file) {
        return match windows_machine_config::read(&file) {
            Ok(bytes) => match std::str::from_utf8(&bytes)
                .ok()
                .and_then(|value| toml::from_str(value).ok())
            {
                Some(config) => ConfigLoad::new(config, ConfigLoadStatus::Loaded),
                None => {
                    log::error!(
                        "Machine config '{}' is corrupt; preserving it and failing closed",
                        file.display()
                    );
                    if let Err(err) = windows_machine_config::preserve_corrupt(&file) {
                        log::error!(
                            "Could not preserve corrupt machine config '{}': {err}",
                            file.display()
                        );
                        ConfigLoad::new(T::default(), ConfigLoadStatus::TransientError)
                    } else {
                        ConfigLoad::new(T::default(), ConfigLoadStatus::Corrupt)
                    }
                }
            },
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                ConfigLoad::new(T::default(), ConfigLoadStatus::NotFound)
            }
            Err(err) => {
                log::error!(
                    "Machine config '{}' could not be read through its retained root: {err}",
                    file.display()
                );
                ConfigLoad::new(T::default(), ConfigLoadStatus::TransientError)
            }
        };
    }
    // A HIGH-blast-radius path: EVERY config load. Distinguish a genuine first run (no file)
    // from a PRESENT-but-corrupt file, and never silently reset+overwrite the latter — a
    // regenerated default stored back over it would discard the key_pair/permanent credential
    // (F1). confy stores via an atomic rename, so a present file is never a partial
    // application write; one that will not parse is a power-loss torn write or bit-rot.
    #[cfg(windows)]
    if let Err(err) = windows_config_acl::prepare_config_path_for_load(&file) {
        log::error!(
            "Config '{}' could not be secured before load: {err} - starting from defaults",
            file.display()
        );
        return ConfigLoad::new(T::default(), ConfigLoadStatus::TransientError);
    }

    match confy::load_path(&file) {
        Ok(config) => ConfigLoad::new(config, ConfigLoadStatus::Loaded),
        Err(err) => match &err {
            // Genuine first run: `File::open` returned NotFound — no file exists yet.
            confy::ConfyError::GeneralLoadError(e) if e.kind() == std::io::ErrorKind::NotFound => {
                ConfigLoad::new(T::default(), ConfigLoadStatus::NotFound)
            }
            // Read succeeded but the bytes will not parse: DEFINITE corruption (a valid
            // stored config always parses). Preserve the exact bytes for recovery so no
            // default+store can discard them, log loudly, and hand back a default so the
            // process comes up fail-closed. The vacated path lets later validated config
            // changes self-heal without touching the preserved corrupt bytes.
            confy::ConfyError::BadTomlData(_) => {
                log::error!(
                    "Config '{}' is present but unparseable (corruption): {err} — preserving \
                     it and starting from defaults (not overwriting)",
                    file.display()
                );
                preserve_corrupt_config(&file);
                ConfigLoad::new(T::default(), ConfigLoadStatus::Corrupt)
            }
            // Present but could not be read/opened THIS time (I/O or permission): this may be
            // a transient fault over intact bytes, so DO NOT move or destroy the file. Return
            // a default; the credential-bearing Config::load refuses to overwrite a present
            // file it read as default (below), so the loss is never finalized and it recovers on
            // the next successful load.
            _ => {
                log::error!(
                    "Config '{}' is present but could not be read: {err} — leaving it \
                     untouched and starting from defaults (not overwriting)",
                    file.display()
                );
                ConfigLoad::new(T::default(), ConfigLoadStatus::TransientError)
            }
        },
    }
}

#[inline]
pub fn store_path<T: serde::Serialize>(path: PathBuf, cfg: T) -> crate::ResultType<()> {
    let serialized = toml::to_string_pretty(&cfg)?;
    store_config_bytes_transaction(&path, serialized.as_bytes(), ConfigStoreFault::None)
}

fn load_raw_config_bytes(path: &Path) -> Result<Vec<u8>> {
    #[cfg(windows)]
    if windows_machine_config::contains(path) {
        return windows_machine_config::read(path).map_err(Into::into);
    }
    #[cfg(windows)]
    windows_config_acl::prepare_config_path_for_load(path)?;

    let mut file = fs::File::open(path)?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;
    Ok(data)
}

fn store_raw_config_bytes(path: PathBuf, data: &[u8]) -> Result<()> {
    store_config_bytes_transaction(&path, data, ConfigStoreFault::None)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConfigStoreFault {
    None,
    BeforeReplace,
    AfterReplace,
}

#[cfg(any(windows, test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReplacementFailureReconciliation {
    NewAuthoritative,
    NotNew,
}

#[cfg(any(windows, test))]
fn reconcile_replacement_failure(
    observed: Option<&[u8]>,
    intended: &[u8],
) -> ReplacementFailureReconciliation {
    if observed == Some(intended) {
        ReplacementFailureReconciliation::NewAuthoritative
    } else {
        ReplacementFailureReconciliation::NotNew
    }
}

fn config_temp_file_name(path: &Path, attempt: u32) -> Result<String> {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow!("Config path '{}' has no UTF-8 file name", path.display()))?;
    Ok(format!(
        ".{name}.tmp.{}.{}.{}",
        std::process::id(),
        stamp,
        attempt
    ))
}

#[cfg(unix)]
fn store_config_bytes_transaction(path: &Path, data: &[u8], fault: ConfigStoreFault) -> Result<()> {
    store_config_bytes_transaction_unix(path, data, fault, &|message| {
        log::error!("Fatal config durability failure after replacement: {message}");
        std::process::abort()
    })
}

#[cfg(unix)]
fn store_config_bytes_transaction_unix(
    path: &Path,
    data: &[u8],
    fault: ConfigStoreFault,
    fatal_after_replace: &dyn Fn(&str) -> Result<()>,
) -> Result<()> {
    use std::{
        ffi::{CStr, CString, OsStr},
        os::unix::{
            ffi::OsStrExt,
            io::{AsRawFd, FromRawFd},
        },
    };

    fn component(value: &OsStr, context: &str) -> Result<CString> {
        CString::new(value.as_bytes())
            .map_err(|err| anyhow!("Invalid {context} path component: {err}"))
    }

    fn open_parent(path: &Path) -> Result<fs::File> {
        let parent = path
            .parent()
            .ok_or_else(|| anyhow!("Config path '{}' has no parent directory", path.display()))?;
        let mut dir = fs::File::open(if parent.is_absolute() {
            Path::new("/")
        } else {
            Path::new(".")
        })?;
        for part in parent.components() {
            match part {
                std::path::Component::RootDir | std::path::Component::CurDir => {}
                std::path::Component::Normal(name) => {
                    let name = component(name, "config directory")?;
                    let made = unsafe {
                        crate::libc::mkdirat(
                            dir.as_raw_fd(),
                            name.as_ptr(),
                            0o700 as crate::libc::mode_t,
                        )
                    };
                    if made != 0 {
                        let err = io::Error::last_os_error();
                        if err.raw_os_error() != Some(crate::libc::EEXIST) {
                            return Err(anyhow!(
                                "Failed to create config directory component: {err}"
                            ));
                        }
                    }
                    let fd = unsafe {
                        crate::libc::openat(
                            dir.as_raw_fd(),
                            name.as_ptr(),
                            crate::libc::O_RDONLY
                                | crate::libc::O_DIRECTORY
                                | crate::libc::O_CLOEXEC
                                | crate::libc::O_NOFOLLOW,
                        )
                    };
                    if fd < 0 {
                        return Err(anyhow!(
                            "Failed to open config directory component without following links: {}",
                            io::Error::last_os_error()
                        ));
                    }
                    dir = unsafe { fs::File::from_raw_fd(fd) };
                }
                std::path::Component::ParentDir | std::path::Component::Prefix(_) => {
                    return Err(anyhow!(
                        "Config path '{}' contains an unsupported parent component",
                        path.display()
                    ));
                }
            }
        }
        Ok(dir)
    }

    fn verify_file(file: &fs::File, path: &Path) -> Result<()> {
        use std::os::unix::fs::MetadataExt;

        let metadata = file.metadata()?;
        if !metadata.file_type().is_file()
            || metadata.uid() != unsafe { crate::libc::geteuid() }
            || metadata.mode() & 0o777 != 0o600
            || metadata.nlink() != 1
        {
            return Err(anyhow!(
                "Config file '{}' failed regular-file/owner/mode/link verification",
                path.display()
            ));
        }
        Ok(())
    }

    fn sync_temp_file(file: &fs::File) -> Result<()> {
        file.sync_all()?;
        #[cfg(target_os = "macos")]
        if unsafe { crate::libc::fcntl(file.as_raw_fd(), crate::libc::F_FULLFSYNC) } != 0 {
            return Err(anyhow!(
                "F_FULLFSYNC failed for temporary config file: {}",
                io::Error::last_os_error()
            ));
        }
        Ok(())
    }

    fn unlink_temp(parent_fd: i32, name: &CStr) -> Result<()> {
        if unsafe { crate::libc::unlinkat(parent_fd, name.as_ptr(), 0) } == 0 {
            return Ok(());
        }
        let err = io::Error::last_os_error();
        if err.kind() == io::ErrorKind::NotFound {
            Ok(())
        } else {
            Err(anyhow!("Failed to remove temporary config file: {err}"))
        }
    }

    let parent = open_parent(path)?;
    let parent_fd = parent.as_raw_fd();
    let final_name = component(
        path.file_name()
            .ok_or_else(|| anyhow!("Config path '{}' has no file name", path.display()))?,
        "config file",
    )?;

    for attempt in 0..128 {
        let temp_name = CString::new(config_temp_file_name(path, attempt)?)?;
        let fd = unsafe {
            crate::libc::openat(
                parent_fd,
                temp_name.as_ptr(),
                crate::libc::O_WRONLY
                    | crate::libc::O_CREAT
                    | crate::libc::O_EXCL
                    | crate::libc::O_CLOEXEC
                    | crate::libc::O_NOFOLLOW,
                0o600 as crate::libc::c_uint,
            )
        };
        if fd < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::AlreadyExists {
                continue;
            }
            return Err(anyhow!("Failed to create temporary config file: {err}"));
        }
        let mut temp = unsafe { fs::File::from_raw_fd(fd) };
        let transaction = (|| -> Result<()> {
            if unsafe { crate::libc::fchmod(fd, 0o600 as crate::libc::mode_t) } != 0 {
                return Err(anyhow!(
                    "Failed to set temporary config permissions: {}",
                    io::Error::last_os_error()
                ));
            }
            verify_file(&temp, path)?;
            temp.write_all(data)?;
            sync_temp_file(&temp)?;
            if fault == ConfigStoreFault::BeforeReplace {
                return Err(anyhow!("injected config failure before replacement"));
            }
            if unsafe {
                crate::libc::renameat(
                    parent_fd,
                    temp_name.as_ptr(),
                    parent_fd,
                    final_name.as_ptr(),
                )
            } != 0
            {
                return Err(anyhow!(
                    "Failed to atomically replace config '{}': {}",
                    path.display(),
                    io::Error::last_os_error()
                ));
            }
            if fault == ConfigStoreFault::AfterReplace {
                return fatal_after_replace("injected failure before parent-directory sync");
            }
            let mut last_sync_error = None;
            for _ in 0..16 {
                match parent.sync_all() {
                    Ok(()) => return Ok(()),
                    Err(err) => {
                        last_sync_error = Some(err);
                        std::thread::sleep(Duration::from_millis(25));
                    }
                }
            }
            let message = format!(
                "could not sync parent directory for '{}' after replacement: {}",
                path.display(),
                last_sync_error
                    .map(|err| err.to_string())
                    .unwrap_or_else(|| "unknown sync failure".to_owned())
            );
            fatal_after_replace(&message)
        })();
        drop(temp);
        if let Err(error) = transaction {
            return match unlink_temp(parent_fd, &temp_name) {
                Ok(()) => Err(error),
                Err(cleanup) => Err(anyhow!("{error}; cleanup also failed: {cleanup}")),
            };
        }
        return Ok(());
    }
    Err(anyhow!(
        "Could not allocate a temporary config file for '{}'",
        path.display()
    ))
}

#[cfg(windows)]
fn store_config_bytes_transaction(path: &Path, data: &[u8], fault: ConfigStoreFault) -> Result<()> {
    use std::os::windows::{ffi::OsStrExt, fs::OpenOptionsExt};
    use winapi::um::{
        errhandlingapi::GetLastError,
        winbase::{
            MoveFileExW, FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAG_WRITE_THROUGH,
            MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
        },
    };

    if windows_machine_config::contains(path) {
        return windows_machine_config::store(path, data, fault);
    }
    windows_config_acl::prepare_config_path_for_store(path)?;
    for attempt in 0..128 {
        let temp_name = config_temp_file_name(path, attempt)?;
        let temp_path = path.with_file_name(temp_name);
        let mut temp = match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH)
            .open(&temp_path)
        {
            Ok(file) => file,
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(anyhow!("Failed to create temporary config file: {err}")),
        };
        let pre_replace = (|| -> Result<()> {
            windows_config_acl::harden_config_file(&temp_path)?;
            windows_config_acl::verify_config_file(&temp_path)?;
            temp.write_all(data)?;
            temp.sync_all()?;
            if fault == ConfigStoreFault::BeforeReplace {
                return Err(anyhow!("injected config failure before replacement"));
            }
            Ok(())
        })();
        drop(temp);
        if let Err(error) = pre_replace {
            return match fs::remove_file(&temp_path) {
                Ok(()) => Err(error),
                Err(cleanup) if cleanup.kind() == io::ErrorKind::NotFound => Err(error),
                Err(cleanup) => Err(anyhow!(
                    "{error}; temporary credential cleanup also failed: {cleanup}"
                )),
            };
        }

        let temp_w: Vec<u16> = temp_path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let path_w: Vec<u16> = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        if unsafe {
            MoveFileExW(
                temp_w.as_ptr(),
                path_w.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        } == 0
        {
            let error = unsafe { GetLastError() };
            match fs::remove_file(&temp_path) {
                Ok(()) => {
                    return Err(anyhow!(
                        "Failed to atomically replace config '{}': win32_error={error}",
                        path.display()
                    ));
                }
                Err(cleanup) if cleanup.kind() == io::ErrorKind::NotFound => {}
                Err(cleanup) => {
                    return Err(anyhow!(
                        "MoveFileExW failed and temporary config cleanup failed: win32_error={error}, cleanup={cleanup}"
                    ));
                }
            }

            // The source name was consumed despite the reported failure. Exact no-follow
            // readback determines whether the intended bytes became authoritative; inability to
            // read a definitive state is fatal because returning either Applied or failure would
            // be an unsupported durability claim.
            let observed = (|| -> Result<Vec<u8>> {
                let mut committed = fs::OpenOptions::new()
                    .read(true)
                    .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
                    .open(path)?;
                let mut observed = Vec::new();
                committed.read_to_end(&mut observed)?;
                Ok(observed)
            })();
            let observed = match observed {
                Ok(observed) => observed,
                Err(readback) => {
                    log::error!(
                        "MoveFileExW consumed the temporary config name but final-state readback failed; refusing an ambiguous mutation result: path='{}', win32_error={error}, readback={readback}",
                        path.display()
                    );
                    std::process::abort();
                }
            };
            if reconcile_replacement_failure(Some(&observed), data)
                == ReplacementFailureReconciliation::NewAuthoritative
            {
                log::error!(
                    "MoveFileExW reported failure after the new config became authoritative; refusing to continue without proven write-through durability: path='{}', win32_error={error}",
                    path.display()
                );
                std::process::abort();
            }
            return Err(anyhow!(
                "Failed to atomically replace config '{}': win32_error={error}",
                path.display()
            ));
        }
        // MOVEFILE_WRITE_THROUGH is the replacement durability barrier. The temp inode's DACL
        // and contents were verified and flushed before this call, so no fallible metadata or
        // readback step remains after the successful point of no return.
        let _ = fault;
        return Ok(());
    }
    Err(anyhow!(
        "Could not allocate a temporary config file for '{}'",
        path.display()
    ))
}

#[cfg(not(any(unix, windows)))]
fn store_config_bytes_transaction(path: &Path, data: &[u8], fault: ConfigStoreFault) -> Result<()> {
    if fault != ConfigStoreFault::None {
        return Err(anyhow!("config fault injection is unavailable"));
    }
    fs::write(path, data)?;
    Ok(())
}

fn encrypted_json_config_bytes(label: &str, json: String) -> Option<Vec<u8>> {
    let data = compress(json.as_bytes());
    let max_len = 64 * 1024 * 1024;
    if data.len() > max_len {
        log::error!("{label} data too large, {} > {}", data.len(), max_len);
        return None;
    }
    match symmetric_crypt(&data, true) {
        Ok(data) => Some(data),
        Err(_) => {
            log::error!("Failed to encrypt {label} data");
            None
        }
    }
}

fn load_encrypted_json_config<T: serde::de::DeserializeOwned>(
    path: &Path,
    label: &str,
) -> Result<Option<T>> {
    let data = match load_raw_config_bytes(path) {
        Ok(data) => data,
        Err(err) => {
            if is_not_found_error(&err) {
                return Ok(None);
            }
            return Err(anyhow!(
                "Failed to read {label} '{}': {err}",
                path.display()
            ));
        }
    };
    let data = match symmetric_crypt(&data, false) {
        Ok(data) => data,
        Err(_) => {
            return Err(anyhow!("Failed to decrypt {label} '{}'", path.display()));
        }
    };
    let data = decompress(&data);
    match serde_json::from_slice::<T>(&data) {
        Ok(value) => Ok(Some(value)),
        Err(err) => Err(anyhow!(
            "Failed to parse {label} '{}': {err}",
            path.display()
        )),
    }
}

fn is_not_found_error(err: &anyhow::Error) -> bool {
    err.downcast_ref::<io::Error>()
        .map_or(false, |err| err.kind() == io::ErrorKind::NotFound)
}

fn remove_raw_config_file(path: PathBuf, label: &str) {
    match fs::remove_file(&path) {
        Ok(()) => {}
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => log::error!("Failed to remove {label} '{}': {err}", path.display()),
    }
}

fn preserve_raw_config_file(path: &Path, label: &str) {
    if !path.exists() {
        return;
    }
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("raw_config");
    let mut backup = path.to_path_buf();
    backup.set_file_name(format!("{name}.corrupt.{stamp}"));
    match fs::rename(path, &backup) {
        Ok(()) => {
            if let Err(err) = harden_preserved_config_file(&backup) {
                log::error!(
                    "Preserved corrupt {label} '{}' as '{}', but failed to harden recovery file: {err}",
                    path.display(),
                    backup.display()
                );
                return;
            }

            log::error!(
                "Preserved corrupt {label} '{}' as '{}' for recovery",
                path.display(),
                backup.display()
            );
        }
        Err(err) => log::error!(
            "Could not preserve corrupt {label} '{}' for recovery: {err}",
            path.display()
        ),
    }
}

impl Config {
    fn load_<T: serde::Serialize + serde::de::DeserializeOwned + Default + std::fmt::Debug>(
        suffix: &str,
    ) -> T {
        let file = Self::file_(suffix);
        let cfg = load_path(file);
        if suffix.is_empty() {
            log::trace!("{:?}", cfg);
        }
        cfg
    }

    fn store_<T: serde::Serialize>(config: &T, suffix: &str) {
        let file = Self::file_(suffix);
        if let Err(err) = store_path(file, config) {
            log::error!("Failed to store {suffix} config: {err}");
        }
    }

    fn load() -> Config {
        let file = Self::file_("");
        let mut config = Config::load_::<Config>("");
        // F1: a stored Config always carries some persisted state. So a STILL-PRESENT file
        // that loads as an all-default Config is never a genuine first run (that has no file)
        // and never a parse corruption (load_path already renamed those aside, vacating the
        // path) — it is an empty power-loss torn write or a transient read failure. Never
        // store defaults OVER such a file while it still holds bytes.
        if config.is_empty() && file.exists() {
            let len = fs::metadata(&file).map(|m| m.len()).unwrap_or(0);
            if len == 0 {
                log::error!(
                    "Config '{}' is present but empty (power-loss torn write); the prior \
                     key_pair/credential is unrecoverable. Starting from a clean default — the \
                     box is fail-closed until you re-provision with --password",
                    file.display()
                );
                // fall through: later validated config changes may self-heal over the empty file
            } else {
                log::error!(
                    "Config '{}' is present ({len} bytes) but read as default (transient read \
                     failure); refusing to overwrite it. Coming up fail-closed on an \
                     unpersisted default — it recovers automatically once the file loads",
                    file.display()
                );
            }
        }
        if let Err(err) = Self::validate_or_decrypt_permanent_password_storage(&mut config) {
            log::error!("Failed to validate or decrypt permanent password storage: {err}");
        }
        let (id, encrypted, _) = decrypt_str_or_original(&config.enc_id, PASSWORD_ENC_VERSION);
        if encrypted {
            config.id = id;
        }
        config
    }

    fn validate_or_decrypt_permanent_password_storage(config: &mut Config) -> Result<()> {
        if config.password.is_empty() {
            return Ok(());
        }

        if config.password.starts_with(PASSWORD_ENC_VERSION) {
            let (plain, decrypted, not_well_formed) =
                decrypt_str_or_original(&config.password, PASSWORD_ENC_VERSION);
            if decrypted {
                config.password = plain;
                return Ok(());
            }
            // Undecryptable "00" storage. F3: `not_well_formed` (decrypt_str_or_original's 3rd
            // return, which on a non-empty value is `!is_encrypted`) is true exactly when the
            // value is NOT a well-formed `00` secretbox envelope (invalid base64 / shorter than
            // a MAC) — a definitively-MALFORMED payload that cannot decrypt under ANY
            // machine-UUID, so it is corruption, not a transient environment blip → clear
            // (unrecoverable, fail closed).
            if not_well_formed {
                return Err(anyhow!("Malformed legacy permanent password storage"));
            }
            // Otherwise it IS a well-formed `00` secretbox that merely failed to open — the
            // signature of a TRANSIENT machine-UUID read failure (macOS login window / Windows
            // shutdown — get_uuid, lib.rs). PRESERVE it: a coincident store() must not wipe a
            // possibly-valid credential on a blip. It fails closed at the CPace boundary
            // (the typed PRS read is unavailable) until the UUID reads again.
            return Ok(());
        }

        let (decrypted_storage, decrypted, _) =
            decrypt_permanent_password_str_or_original(&config.password);
        if decrypted {
            Self::ensure_permanent_password_hash_salt(config)?;
            if decode_permanent_password_h1_from_hashed_storage(&decrypted_storage).is_some() {
                return Ok(());
            }
            return Err(anyhow!("Invalid permanent password encrypted hash storage"));
        }

        Ok(())
    }

    fn ensure_permanent_password_hash_salt(config: &Config) -> Result<()> {
        if config.salt.is_empty() {
            return Err(anyhow!(
                "Permanent password hash storage requires a non-empty salt"
            ));
        }
        Ok(())
    }

    fn generate_permanent_password_storage_salt() -> String {
        let mut rng = rand::thread_rng();
        (0..DEFAULT_SALT_LEN)
            .map(|_| {
                PERMANENT_PASSWORD_STORAGE_SALT_CHARS
                    [rng.gen::<usize>() % PERMANENT_PASSWORD_STORAGE_SALT_CHARS.len()]
            })
            .collect()
    }

    fn ensure_permanent_password_salt(config: &mut Config) {
        if config.salt.is_empty() {
            config.salt = Self::generate_permanent_password_storage_salt();
        }
    }

    fn prepare_config_for_store(config: &mut Config) {
        match Self::validate_or_decrypt_permanent_password_storage(config) {
            Ok(_) => {}
            Err(err) => {
                // This path is for unrecoverable permanent-password storage, such as
                // hashed storage without its salt. Keep unrelated config writes working,
                // but handle future transient migration errors separately.
                log::error!(
                    "Clearing invalid permanent password storage before storing config: {err}"
                );
                // Clear ALL THREE credential forms together: dropping password/salt
                // but leaving config.password_prs would leave the CPace handshake authenticating with a
                // credential the box now reports as unset — a split-brain. Fail closed + consistent.
                config.password.clear();
                config.password_prs.clear();
                config.salt.clear();
            }
        }
    }

    fn store_result(&self) -> crate::ResultType<()> {
        let mut config = self.clone();
        Self::prepare_config_for_store(&mut config);
        if !config.password.is_empty()
            && decode_permanent_password_h1_from_storage(&config.password).is_none()
            // F4: never re-wrap a well-formed current-format `01…` credential in the legacy
            // `00` envelope. An UNDECRYPTABLE `01…` blob (a transient machine-UUID failure)
            // decodes to no h1 above, so without this guard it would fall into
            // keep_encrypted_storage_if_plaintext_unchanged and be spuriously double-wrapped as
            // `00(enc("01…"))` — cosmetic (it self-corrects on the next decryptable load, and
            // the credential fails closed regardless), but avoidable: a `01…`-shaped value is
            // already the current at-rest form and must be stored verbatim.
            && !config
                .password
                .starts_with(permanent_password::PERMANENT_PASSWORD_ENC_VERSION)
        {
            let stored = Config::load_::<Config>("");
            config.password =
                keep_encrypted_storage_if_plaintext_unchanged(&config.password, &stored.password);
        }
        if config.id.is_empty() {
            config.enc_id.clear();
        }
        config.id = "".to_owned();
        store_path(Self::file_(""), &config)
    }

    fn store(&self) {
        if let Err(err) = self.store_result() {
            log::error!("Failed to store config: {err}");
        }
    }

    pub fn file() -> PathBuf {
        Self::file_("")
    }

    fn file_(suffix: &str) -> PathBuf {
        let name = format!("{}{}", *APP_NAME.read().unwrap(), suffix);
        Config::with_extension(Self::path(name))
    }

    pub fn is_empty(&self) -> bool {
        self.id.is_empty()
            && self.enc_id.is_empty()
            && self.key_pair.0.is_empty()
            && self.password.is_empty()
            && self.password_prs.is_empty()
            && self.salt.is_empty()
    }

    /// Get the user's home directory for configuration purposes.
    ///
    /// # Security Note
    /// This function uses `dirs_next::home_dir()` which reads the `$HOME` environment
    /// variable on Unix systems. This is acceptable for user-space operations (config
    /// file storage, logging) where the user may intentionally redirect their home
    /// directory.
    ///
    /// **DO NOT use this function in privileged contexts** (e.g., code executed via
    /// `gtk_sudo` or system services running as root). On Linux, use
    /// `crate::platform::linux::get_home_dir_trusted()` for the real invoking user or
    /// `get_effective_home_dir_trusted()` for service-owned effective authority. Both
    /// bypass `$HOME` and query the system password database directly via `getpwuid`.
    ///
    /// Using `$HOME` in privileged contexts creates a confused-deputy vulnerability
    /// where an attacker can manipulate the environment variable to inject malicious
    /// paths into privileged operations.
    pub fn get_home() -> PathBuf {
        #[cfg(any(target_os = "android", target_os = "ios"))]
        return PathBuf::from(APP_HOME_DIR.read().unwrap().as_str());
        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        {
            #[cfg(target_os = "macos")]
            if let Some(root) = macos_service_owned_config_root() {
                return root.home.clone();
            }
            #[cfg(target_os = "linux")]
            if let Some(root) = linux_service_owned_config_root() {
                return root.home.clone();
            }
            if let Some(path) = dirs_next::home_dir() {
                patch(path)
            } else if let Ok(path) = std::env::current_dir() {
                path
            } else {
                std::env::temp_dir()
            }
        }
    }

    #[cfg(windows)]
    pub fn initialize_windows_service_owned_root(
        program_data: &Path,
        write_authority: bool,
    ) -> crate::ResultType<PathBuf> {
        if !windows_config_acl::current_process_is_local_system()? {
            return Err(anyhow!(
                "Windows service-owned config root requires the LocalSystem token"
            ));
        }
        let app_name = APP_NAME.read().unwrap().clone();
        let root = windows_service_owned_config_root_from(program_data, &app_name)?;
        windows_machine_config::initialize(root, write_authority)
    }

    #[cfg(target_os = "macos")]
    pub fn initialize_macos_service_owned_root(home: PathBuf) -> Result<PathBuf> {
        let organization = ORG.read().unwrap().clone();
        let app_name = APP_NAME.read().unwrap().clone();
        let candidate = macos_service_owned_config_root_from(&home, &organization, &app_name)?;
        match MACOS_SERVICE_OWNED_CONFIG_ROOT.set(candidate.clone()) {
            Ok(()) => Ok(candidate.path),
            Err(_) => {
                let existing = MACOS_SERVICE_OWNED_CONFIG_ROOT.get().ok_or_else(|| {
                    anyhow!("macOS service-owned config root initialization was lost")
                })?;
                if existing == &candidate {
                    Ok(existing.path.clone())
                } else {
                    Err(anyhow!(
                        "macOS service-owned config root was initialized inconsistently"
                    ))
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn initialize_linux_service_owned_root_from_home(home: PathBuf) -> Result<PathBuf> {
        let app_name = APP_NAME.read().unwrap().clone();
        let candidate = LinuxServiceOwnedConfigRoot {
            path: linux_service_owned_config_root_from(&home, &app_name)?,
            home,
        };
        match LINUX_SERVICE_OWNED_CONFIG_ROOT.set(candidate.clone()) {
            Ok(()) => Ok(candidate.path),
            Err(_) => {
                let existing = LINUX_SERVICE_OWNED_CONFIG_ROOT.get().ok_or_else(|| {
                    anyhow!("Linux service-owned config root initialization was lost")
                })?;
                if existing == &candidate {
                    Ok(existing.path.clone())
                } else {
                    Err(anyhow!(
                        "Linux service-owned config root was initialized inconsistently"
                    ))
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    pub fn initialize_linux_service_owned_root() -> Result<PathBuf> {
        let home = crate::platform::linux::get_effective_home_dir_trusted()
            .ok_or_else(|| anyhow!("Linux service-owned config home is unavailable"))?;
        Self::initialize_linux_service_owned_root_from_home(home)
    }

    pub fn path<P: AsRef<Path>>(p: P) -> PathBuf {
        #[cfg(any(target_os = "android", target_os = "ios"))]
        {
            let mut path: PathBuf = APP_DIR.read().unwrap().clone().into();
            path.push(p);
            return path;
        }
        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        {
            #[cfg(target_os = "macos")]
            if let Some(root) = macos_service_owned_config_root() {
                let mut path = root.path.clone();
                path.push(p);
                return path;
            }
            #[cfg(target_os = "linux")]
            if let Some(root) = linux_service_owned_config_root() {
                let mut path = root.path.clone();
                path.push(p);
                return path;
            }
            #[cfg(windows)]
            if let Some(root) = windows_machine_config::root_path() {
                let mut path = root.to_path_buf();
                path.push(p);
                return path;
            }
            #[cfg(not(target_os = "macos"))]
            let org = "".to_owned();
            #[cfg(target_os = "macos")]
            let org = ORG.read().unwrap().clone();
            // /var/root for root
            if let Some(project) =
                directories_next::ProjectDirs::from("", &org, &APP_NAME.read().unwrap())
            {
                let mut path = patch(project.config_dir().to_path_buf());
                path.push(p);
                return path;
            }
            "".into()
        }
    }

    /// Get the log directory path.
    ///
    /// # Security Note
    /// On macOS, this function uses `dirs_next::home_dir()` which reads the `$HOME`
    /// environment variable. On Linux/Android, it uses `Self::get_home()`.
    /// See [`Self::get_home()`] for security considerations regarding `$HOME` usage.
    #[allow(unreachable_code)]
    pub fn log_path() -> PathBuf {
        #[cfg(target_os = "macos")]
        {
            if let Some(root) = macos_service_owned_config_root() {
                return root.log_path.clone();
            }
            if let Some(path) = dirs_next::home_dir().as_mut() {
                path.push(format!("Library/Logs/{}", *APP_NAME.read().unwrap()));
                return path.clone();
            }
        }
        #[cfg(target_os = "linux")]
        {
            let mut path = Self::get_home();
            path.push(format!(".local/share/logs/{}", *APP_NAME.read().unwrap()));
            std::fs::create_dir_all(&path).ok();
            return path;
        }
        #[cfg(target_os = "android")]
        {
            let mut path = Self::get_home();
            path.push(format!("{}/Logs", *APP_NAME.read().unwrap()));
            std::fs::create_dir_all(&path).ok();
            return path;
        }
        if let Some(path) = Self::path("").parent() {
            let mut path: PathBuf = path.into();
            path.push("log");
            return path;
        }
        "".into()
    }

    pub fn ipc_path(postfix: &str) -> String {
        #[cfg(windows)]
        {
            // \\ServerName\pipe\PipeName
            // where ServerName is either the name of a remote computer or a period, to specify the local computer.
            // https://docs.microsoft.com/en-us/windows/win32/ipc/pipe-names
            format!(
                "\\\\.\\pipe\\{}\\query{}",
                *APP_NAME.read().unwrap(),
                postfix
            )
        }
        #[cfg(not(windows))]
        {
            #[cfg(target_os = "android")]
            use std::os::unix::fs::PermissionsExt;
            #[cfg(target_os = "android")]
            let mut path: PathBuf =
                format!("{}/{}", *APP_DIR.read().unwrap(), *APP_NAME.read().unwrap()).into();
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            let mut path: PathBuf = {
                let uid = unsafe { libc::geteuid() as u32 };
                ipc_parent_dir_for_uid(uid, postfix).into()
            };
            #[cfg(not(any(target_os = "android", target_os = "linux", target_os = "macos")))]
            let mut path: PathBuf = format!("/tmp/{}", *APP_NAME.read().unwrap()).into();
            // Android stores IPC sockets under app-controlled directories. Create the IPC parent
            // dir and enforce the expected mode here. On other Unix platforms, `ipc_path()` is
            // intentionally side-effect free (no mkdir/chmod); callers should enforce directory and
            // socket permissions at the IPC server boundary.
            #[cfg(target_os = "android")]
            {
                fs::create_dir_all(&path).ok();
                let path_mode = if is_service_ipc_postfix(postfix) {
                    0o0711
                } else {
                    0o0700
                };
                fs::set_permissions(&path, fs::Permissions::from_mode(path_mode)).ok();
            }
            path.push(format!("ipc{postfix}"));
            path.to_str().unwrap_or("").to_owned()
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub fn ipc_path_for_uid(uid: u32, postfix: &str) -> String {
        let parent = ipc_parent_dir_for_uid(uid, postfix);
        format!("{parent}/ipc{postfix}")
    }

    pub fn icon_path() -> PathBuf {
        let mut path = Self::path("icons");
        if fs::create_dir_all(&path).is_err() {
            path = std::env::temp_dir();
        }
        path
    }

    #[inline]
    pub fn get_any_listen_addr(is_ipv4: bool) -> SocketAddr {
        if is_ipv4 {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
        } else {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
        }
    }

    #[cfg(any(target_os = "android", target_os = "ios"))]
    pub fn get_key_pair() -> KeyPair {
        // lock here to make sure no gen_keypair more than once
        // no use of CONFIG directly here to ensure no recursive calling in Config::load because of password dec which calling this function
        let mut lock = KEY_PAIR.lock().unwrap();
        if let Some(p) = lock.as_ref() {
            return p.clone();
        }
        let mut config = Config::load_::<Config>("");
        if config.key_pair.0.is_empty() {
            log::info!("Generated mobile device-id keypair");
            let (pk, sk) = sign::gen_keypair();
            let key_pair = (sk.0.to_vec(), pk.0.into());
            config.key_pair = key_pair.clone();
            std::thread::spawn(|| {
                let mut config = CONFIG.write().unwrap();
                config.key_pair = key_pair;
                config.store();
            });
        }
        *lock = Some(config.key_pair.clone());
        config.key_pair
    }

    /// Get an existing legacy key pair without generating a new one.
    pub fn get_existing_key_pair() -> Option<KeyPair> {
        let mut lock = KEY_PAIR.lock().unwrap();
        if let Some(p) = lock.as_ref() {
            return Some(p.clone());
        }

        // IMPORTANT: this path is called while holding KEY_PAIR lock.
        // Config::load_ must remain a raw conf load/deserialize path and must never
        // call decrypt_* / symmetric_crypt (directly or indirectly), otherwise this
        // can re-enter key loading and deadlock.
        let config = Config::load_::<Config>("");
        if !config.key_pair.0.is_empty() {
            *lock = Some(config.key_pair.clone());
            Some(config.key_pair)
        } else {
            None
        }
    }

    #[cfg(test)]
    pub(crate) fn set_existing_key_pair_cache_for_test(key_pair: Option<(Vec<u8>, Vec<u8>)>) {
        *KEY_PAIR.lock().unwrap() = key_pair;
    }

    pub fn is_disable_change_permanent_password() -> bool {
        BUILTIN_SETTINGS
            .read()
            .unwrap()
            .get(keys::OPTION_DISABLE_CHANGE_PERMANENT_PASSWORD)
            .map(|v| v == "Y")
            .unwrap_or(false)
    }

    pub fn get_id() -> String {
        CONFIG.read().unwrap().id.clone()
    }

    pub fn get_id_or(b: String) -> String {
        let a = CONFIG.read().unwrap().id.clone();
        if a.is_empty() {
            b
        } else {
            a
        }
    }

    pub fn get_options() -> HashMap<String, String> {
        let mut res = DEFAULT_SETTINGS.read().unwrap().clone();
        res.extend(CONFIG2.read().unwrap().options.clone());
        res.extend(OVERWRITE_SETTINGS.read().unwrap().clone());
        overlay_pinned_settings(&mut res);
        res
    }

    #[inline]
    fn purify_options(v: &mut HashMap<String, String>) {
        v.retain(|k, v| is_option_can_save(&OVERWRITE_SETTINGS, k, &DEFAULT_SETTINGS, v));
    }

    pub fn set_options(mut v: HashMap<String, String>) {
        Self::purify_options(&mut v);
        let mut config = CONFIG2.write().unwrap();
        if config.options == v {
            return;
        }
        config.options = v;
        config.store();
    }

    pub fn get_option(k: &str) -> String {
        // R-S16(b): pin the read funnel. The controlled-side policy table is the
        // single source of truth — a pinned key returns its compile-time value
        // before any overwrite/stored/default lookup, so every config-driven
        // resolver (verification_method, approve_mode, option2bool("enable-*"),
        // the egress reads) returns the policy with no per-call-site edit. The
        // pin is UNCONDITIONAL (R-R2b): PINNED_SETTINGS is enforced on every build.
        if let Some(v) = pinned_setting(k) {
            return v.to_string();
        }
        get_or(
            &OVERWRITE_SETTINGS,
            &CONFIG2.read().unwrap().options,
            &DEFAULT_SETTINGS,
            k,
        )
        .unwrap_or_default()
    }

    pub fn get_bool_option(k: &str) -> bool {
        option2bool(k, &Self::get_option(k))
    }

    pub fn set_option(k: String, v: String) {
        if !is_option_can_save(&OVERWRITE_SETTINGS, &k, &DEFAULT_SETTINGS, &v) {
            let mut config = CONFIG2.write().unwrap();
            if config.options.remove(&k).is_some() {
                config.store();
            }
            return;
        }
        let mut config = CONFIG2.write().unwrap();
        let v2 = if v.is_empty() { None } else { Some(&v) };
        if v2 != config.options.get(&k) {
            if v2.is_none() {
                config.options.remove(&k);
            } else {
                config.options.insert(k, v);
            }
            config.store();
        }
    }

    /// Sets the local permanent password.
    ///
    /// Returns `true` when the password is accepted or already matches local durable
    /// storage. Returns `false` when changing the password is disabled or the new
    /// password cannot be prepared for storage.
    pub fn set_permanent_password(password: &str) -> bool {
        match Self::set_permanent_password_persisted(password) {
            Ok(accepted) => accepted,
            Err(err) => {
                log::error!("Failed to persist permanent password: {err}");
                false
            }
        }
    }

    pub fn set_permanent_password_persisted(password: &str) -> crate::ResultType<bool> {
        Self::set_permanent_password_with_store(password, Config::store_result)
    }

    fn set_permanent_password_with_store<F>(password: &str, persist: F) -> crate::ResultType<bool>
    where
        F: FnOnce(&Config) -> crate::ResultType<()>,
    {
        if Self::is_disable_change_permanent_password() {
            return Ok(false);
        }

        let mut generation = PERMANENT_PASSWORD_CREDENTIAL_GENERATION.write().unwrap();
        let old_effective_prs = Self::read_permanent_password_prs_unlocked();
        let mut config = CONFIG.write().unwrap();
        let mut next = config.clone();

        // R-P1: BOTH at-rest forms are the memory-hard PRS (Argon2id), never the
        // plaintext and never a fast SHA256 — `config.password` holds the PRS's raw 32
        // bytes in the legacy hashed-storage envelope (so the "is set" / load / sync
        // machinery is untouched), `config.password_prs` holds the base64 PRS string the
        // handshake reads live. Empty password clears both ⇒ no shared secret, fails
        // closed (R-S9).
        let (stored, prs) = if password.is_empty() {
            (String::new(), String::new())
        } else {
            // Keep config.salt non-empty so the hashed-storage envelope reads as
            // "salt-bound, usable for auth" (R-S9). The Argon2id salt itself is the fixed
            // domain-separation constant (R-P1), NOT config.salt — config.salt is now only
            // the hash-shaped-storage marker.
            Self::ensure_permanent_password_salt(&mut next);
            match derive_permanent_password_storages(password) {
                Some(pair) => pair,
                None => {
                    log::error!(
                        "Failed to derive the CPace PRS; refusing permanent password update"
                    );
                    return Ok(false);
                }
            }
        };
        next.password = stored;
        next.password_prs = prs;
        persist(&next)?;
        *config = next;
        drop(config);
        if Self::read_permanent_password_prs_unlocked() != old_effective_prs {
            advance_permanent_password_credential_generation(&mut generation);
        }
        Ok(true)
    }

    /// R-P1: the live CPace PRS — the memory-hard Argon2id hash (fixed salt)
    /// (base64), NOT the plaintext. Empty when no credential is stored — the handshake
    /// then has no shared secret and fails closed. Read fresh on every connection (no
    /// caching), so a `--password` change (R-D2) takes effect on the next handshake.
    /// The CPace layer applies NFC and the non-empty check (R-P1/R-S9); on this ASCII
    /// base64 string the NFC pass is a harmless no-op.
    pub fn read_permanent_password_prs() -> PermanentPasswordPrsRead {
        let _generation = PERMANENT_PASSWORD_CREDENTIAL_GENERATION.read().unwrap();
        Self::read_permanent_password_prs_unlocked()
    }

    fn read_permanent_password_prs_unlocked() -> PermanentPasswordPrsRead {
        if let Some(prs) = RUNTIME_PERMANENT_PASSWORD_PRS.read().unwrap().as_ref() {
            return if prs.is_empty() {
                PermanentPasswordPrsRead::Empty
            } else {
                PermanentPasswordPrsRead::Available(prs.clone())
            };
        }
        let storage = CONFIG.read().unwrap().password_prs.clone();
        if storage.is_empty() {
            return PermanentPasswordPrsRead::Empty;
        }
        match decrypt_permanent_password_prs_storage(&storage) {
            Some(prs) if !prs.is_empty() => PermanentPasswordPrsRead::Available(prs),
            Some(_) => PermanentPasswordPrsRead::Empty,
            None => PermanentPasswordPrsRead::UndecryptableStorage,
        }
    }

    pub fn read_permanent_password_credential_snapshot() -> PermanentPasswordCredentialSnapshot {
        let generation = PERMANENT_PASSWORD_CREDENTIAL_GENERATION.read().unwrap();
        PermanentPasswordCredentialSnapshot {
            prs: Self::read_permanent_password_prs_unlocked(),
            generation: *generation,
        }
    }

    /// Runs `authorize` only if `generation` is still current. The generation read lock remains
    /// held through the synchronous callback, making the callback's authorization transition and
    /// credential publication mutually exclusive.
    pub fn with_current_permanent_password_generation<T>(
        generation: u64,
        authorize: impl FnOnce() -> T,
    ) -> Option<T> {
        let current = PERMANENT_PASSWORD_CREDENTIAL_GENERATION.read().unwrap();
        if *current != generation {
            return None;
        }
        Some(authorize())
    }

    /// Returns the locally persisted permanent password storage and salt (NOT the hard/preset one).
    ///
    /// This function is side-effect free and returns a consistent snapshot under a single lock.
    pub fn get_local_permanent_password_storage_and_salt() -> (String, String) {
        let config = CONFIG.read().unwrap();
        (config.password.clone(), config.salt.clone())
    }

    /// Persist permanent password storage and salt from a daemon credential snapshot.
    pub fn set_permanent_password_storage_for_sync(
        storage: &str,
        salt: &str,
    ) -> crate::ResultType<bool> {
        Self::set_permanent_password_storage_for_sync_with_store(
            storage,
            salt,
            Config::store_result,
        )
    }

    fn set_permanent_password_storage_for_sync_with_store<F>(
        storage: &str,
        salt: &str,
        persist: F,
    ) -> crate::ResultType<bool>
    where
        F: FnOnce(&Config) -> crate::ResultType<()>,
    {
        let mut generation = PERMANENT_PASSWORD_CREDENTIAL_GENERATION.write().unwrap();
        let old_effective_prs = Self::read_permanent_password_prs_unlocked();
        let mut config = CONFIG.write().unwrap();
        let mut next = config.clone();
        if !Self::apply_permanent_password_storage_for_sync(&mut next, storage, salt)? {
            return Ok(false);
        }
        persist(&next)?;
        *config = next;
        drop(config);
        if Self::read_permanent_password_prs_unlocked() != old_effective_prs {
            advance_permanent_password_credential_generation(&mut generation);
        }
        Ok(true)
    }

    pub fn set_permanent_password_storage_for_runtime(
        storage: &str,
        salt: &str,
    ) -> crate::ResultType<bool> {
        let prs = Self::permanent_password_prs_from_storage(storage, salt)?;
        Self::set_permanent_password_prs_for_runtime(&prs)
    }

    /// Install a nonpersistent service-owned CPace PRS replica for this process.
    ///
    /// The replica is password-equivalent and therefore accepts only the canonical base64 form
    /// of exactly one PRS. It deliberately overrides every user-profile at-rest credential,
    /// including with an explicit empty value, without writing the replica back to that profile.
    pub fn set_permanent_password_prs_for_runtime(prs: &str) -> crate::ResultType<bool> {
        if !prs.is_empty() {
            let mut decoded = base64::decode(prs.as_bytes(), base64::Variant::Original)
                .map_err(|_| anyhow!("Invalid runtime permanent-password PRS encoding"))?;
            let mut canonical = base64::encode(&decoded, base64::Variant::Original);
            let valid = decoded.len() == PERMANENT_PASSWORD_H1_LEN && canonical == prs;
            sodiumoxide::utils::memzero(&mut decoded);
            sodiumoxide::utils::memzero(unsafe { canonical.as_mut_vec() });
            if !valid {
                return Err(anyhow!("Invalid runtime permanent-password PRS value"));
            }
        }
        let mut generation = PERMANENT_PASSWORD_CREDENTIAL_GENERATION.write().unwrap();
        let mut runtime_prs = RUNTIME_PERMANENT_PASSWORD_PRS.write().unwrap();
        if runtime_prs.as_deref() == Some(prs) {
            return Ok(false);
        }
        if let Some(previous) = runtime_prs.as_mut() {
            sodiumoxide::utils::memzero(unsafe { previous.as_mut_vec() });
        }
        *runtime_prs = Some(prs.to_owned());
        advance_permanent_password_credential_generation(&mut generation);
        Ok(true)
    }

    fn apply_permanent_password_storage_for_sync(
        config: &mut Config,
        storage: &str,
        salt: &str,
    ) -> Result<bool> {
        if storage.is_empty() {
            // A cleared credential must clear BOTH at-rest forms. Leaving config.password_prs set after
            // the storage is cleared would keep the CPace handshake authenticating with the just-cleared
            // password (the typed PRS reader reads password_prs, not password) — R-S9.
            if config.password.is_empty()
                && config.password_prs.is_empty()
                && (salt.is_empty() || config.salt == salt)
            {
                return Ok(false);
            }
            config.password.clear();
            config.password_prs.clear();
            if !salt.is_empty() {
                config.salt = salt.to_owned();
            }
            return Ok(true);
        }
        if salt.is_empty() {
            return Err(anyhow!(
                "Refusing to persist permanent password storage without salt"
            ));
        }
        let prs_string = Self::permanent_password_prs_from_storage(storage, salt)?;
        // R-S9: the service->user sync carries ONLY `storage` (config.password) + salt, never
        // config.password_prs. config.password and config.password_prs encode the SAME 32 PRS bytes,
        // so rebuild password_prs from the decoded bytes here. This keeps the two at-rest forms in step:
        // a synced set/rotate writes a fresh `password` and the matching password_prs together, so the
        // next --server restart reads a live PRS and listens (R-S9) with the current password. Rebuilding it
        // is what makes a set/rotate durable across restarts on the headless/root box (which has no
        // whole-config root<->user repair path).
        let Some(prs_storage) = encrypt_permanent_password_prs_storage(&prs_string) else {
            return Err(anyhow!(
                "Failed to rebuild the CPace PRS storage from the synced permanent password"
            ));
        };
        // Idempotent only when password + salt already match AND password_prs already decrypts to the
        // same PRS (the at-rest ciphertext uses a random nonce, so compare the decrypted PRS, not bytes).
        if config.password == storage
            && config.salt == salt
            && decrypt_permanent_password_prs_storage(&config.password_prs).as_deref()
                == Some(prs_string.as_str())
        {
            return Ok(false);
        }

        config.password = storage.to_owned();
        config.salt = salt.to_owned();
        config.password_prs = prs_storage;
        Ok(true)
    }

    fn permanent_password_prs_from_storage(storage: &str, salt: &str) -> Result<String> {
        if storage.is_empty() {
            return Ok(String::new());
        }
        if salt.is_empty() {
            return Err(anyhow!("Refusing permanent password storage without salt"));
        }
        let Some(raw) = decode_permanent_password_h1_from_storage(storage) else {
            log::error!("Rejecting non-current permanent password storage payload");
            return Err(anyhow!("Invalid permanent password storage payload"));
        };
        Ok(base64::encode(raw, base64::Variant::Original))
    }

    pub fn has_permanent_password() -> bool {
        if let Some(prs) = RUNTIME_PERMANENT_PASSWORD_PRS.read().unwrap().as_ref() {
            return !prs.is_empty();
        }
        let (local_storage, _local_salt) = Self::get_local_permanent_password_storage_and_salt();
        if !local_storage.is_empty() {
            // F2 (coherence): CPace keys from the LIVE PRS (read_permanent_password_prs →
            // config.password_prs), which is what the auth boundary actually consumes. Report a
            // LOCAL permanent password as "set" only when that PRS is present and decryptable,
            // so an undecryptable `01…` blob (e.g. a transient machine-UUID read failure) or a
            // password-set/prs-empty half-state — both of which refuse EVERY connection — do
            // NOT read as set. (Heal the SIGNAL, not the store: config.password is untouched.)
            return Self::read_permanent_password_prs().is_available();
        }
        Self::has_usable_preset_password()
    }

    fn has_usable_preset_password() -> bool {
        let (preset_storage, preset_salt) = Self::get_preset_password_storage_and_salt();
        preset_permanent_password_storage_is_usable_for_auth(&preset_storage, &preset_salt)
    }

    pub fn is_using_preset_password() -> bool {
        if RUNTIME_PERMANENT_PASSWORD_PRS.read().unwrap().is_some() {
            return false;
        }
        let (local_storage, _) = Self::get_local_permanent_password_storage_and_salt();
        local_storage.is_empty() && Self::has_usable_preset_password()
    }

    pub fn get_preset_password_storage_and_salt() -> (String, String) {
        let hard_settings = HARD_SETTINGS.read().unwrap();
        let storage = hard_settings.get("password").cloned().unwrap_or_default();
        let salt = hard_settings.get("salt").cloned().unwrap_or_default();
        (storage, salt)
    }

    pub fn get_effective_permanent_password_salt() -> String {
        let (local_storage, local_salt) = Self::get_local_permanent_password_storage_and_salt();
        if !local_storage.is_empty() {
            if local_permanent_password_storage_is_usable_for_auth(&local_storage, &local_salt) {
                return Self::get_salt();
            }
            return String::new();
        }
        let (preset_storage, preset_salt) = Self::get_preset_password_storage_and_salt();
        if !preset_salt.is_empty() {
            if preset_permanent_password_storage_is_usable_for_auth(&preset_storage, &preset_salt) {
                return preset_salt;
            }
            return String::new();
        }
        Self::get_salt()
    }

    pub fn has_local_permanent_password() -> bool {
        let (local_storage, local_salt) = Self::get_local_permanent_password_storage_and_salt();
        local_permanent_password_storage_is_usable_for_auth(&local_storage, &local_salt)
    }

    pub fn get_salt() -> String {
        CONFIG.read().unwrap().salt.clone()
    }

    pub fn ensure_loaded() {
        drop(CONFIG.read().unwrap());
    }

    fn with_extension(path: PathBuf) -> PathBuf {
        let ext = path.extension();
        if let Some(ext) = ext {
            let ext = format!("{}.toml", ext.to_string_lossy());
            path.with_extension(ext)
        } else {
            path.with_extension("toml")
        }
    }
}

const PEERS: &str = "peers";
const RETIRED_RDP_CREDENTIAL_OPTIONS: [&str; 2] = ["rdp_username", "rdp_password"];

fn remove_retired_rdp_credential_options(options: &mut HashMap<String, String>) -> bool {
    let original_len = options.len();
    options.retain(|key, _| !RETIRED_RDP_CREDENTIAL_OPTIONS.contains(&key.as_str()));
    options.len() != original_len
}

fn is_semantically_empty_peer_config(config: &PeerConfig) -> bool {
    config == &PeerConfig::default()
}

fn should_remove_empty_peer_config(status: ConfigLoadStatus, config: &PeerConfig) -> bool {
    matches!(status, ConfigLoadStatus::Loaded) && is_semantically_empty_peer_config(config)
}

impl PeerConfig {
    pub fn load(id: &str) -> PeerConfig {
        Self::load_with_status(id).into_value()
    }

    fn load_with_status(id: &str) -> ConfigLoad<PeerConfig> {
        Self::load_path_with_status(Self::path(id), Some(id))
    }

    fn load_path_with_status(
        path: PathBuf,
        stored_peer_id: Option<&str>,
    ) -> ConfigLoad<PeerConfig> {
        let _lock = CONFIG.read().unwrap();
        let loaded: ConfigLoad<PeerConfig> = load_path_with_status(path.clone());
        let mut config = loaded.value;
        let status = loaded.status;
        let mut store = false;
        let (password, _, store2) = decrypt_vec_or_original(&config.password, PASSWORD_ENC_VERSION);
        config.password = password;
        store = store || store2;
        // R-S16 (viewer twin): the DERIVED Argon2id CPace PRS, encrypted at rest like `password`.
        let (password_prs, _, store2) =
            decrypt_vec_or_original(&config.password_prs, PASSWORD_ENC_VERSION);
        config.password_prs = password_prs;
        store = store || store2;
        store = remove_retired_rdp_credential_options(&mut config.options) || store;
        if store {
            Self::store_path_(&path, &config);
            if let Some(id) = stored_peer_id {
                NEW_STORED_PEER_CONFIG.lock().unwrap().insert(id.to_owned());
            }
        }
        ConfigLoad::new(config, status)
    }

    pub fn store(&self, id: &str) {
        let _lock = CONFIG.read().unwrap();
        self.store_(id);
    }

    fn store_(&self, id: &str) {
        Self::store_path_(&Self::path(id), self);
        NEW_STORED_PEER_CONFIG.lock().unwrap().insert(id.to_owned());
    }

    fn store_path_(path: &Path, config: &PeerConfig) {
        let mut config = config.clone();
        config.password =
            encrypt_vec_or_original(&config.password, PASSWORD_ENC_VERSION, ENCRYPT_MAX_LEN);
        // R-S16 (viewer twin): the DERIVED Argon2id CPace PRS, encrypted at rest like `password`.
        config.password_prs =
            encrypt_vec_or_original(&config.password_prs, PASSWORD_ENC_VERSION, ENCRYPT_MAX_LEN);
        remove_retired_rdp_credential_options(&mut config.options);
        if let Err(err) = store_path(path.to_path_buf(), config) {
            log::error!("Failed to store config: {}", err);
        }
    }

    pub fn remove(id: &str) {
        fs::remove_file(Self::path(id)).ok();
    }

    fn path(id: &str) -> PathBuf {
        //If the id contains invalid chars, encode it
        let forbidden_paths = Regex::new(r".*[<>:/\\|\?\*].*");
        let path: PathBuf;
        if let Ok(forbidden_paths) = forbidden_paths {
            let id_encoded = if forbidden_paths.is_match(id) {
                "base64_".to_string() + base64::encode(id, base64::Variant::Original).as_str()
            } else {
                id.to_string()
            };
            path = [PEERS, id_encoded.as_str()].iter().collect();
        } else {
            log::warn!("Regex create failed: {:?}", forbidden_paths.err());
            // fallback for failing to create this regex.
            path = [PEERS, id.replace(":", "_").as_str()].iter().collect();
        }
        Config::with_extension(Config::path(path))
    }

    // The number of peers to load in the first round when showing the peers card list in the main window.
    // When there're too many peers, loading all of them at once will take a long time.
    // We can load them in two rouds, the first round loads the first 100 peers, and the second round loads the rest.
    // Then the UI will show the first 100 peers first, and the rest will be loaded and shown later.
    pub const BATCH_LOADING_COUNT: usize = 100;

    pub fn get_vec_id_modified_time_path(
        id_filters: &Option<Vec<String>>,
    ) -> Vec<(String, SystemTime, PathBuf)> {
        if let Ok(peers) = Config::path(PEERS).read_dir() {
            let mut vec_id_modified_time_path = peers
                .into_iter()
                .filter_map(|res| match res {
                    Ok(res) => {
                        let p = res.path();
                        if p.is_file()
                            && p.extension().map(|p| p.to_str().unwrap_or("")) == Some("toml")
                        {
                            Some(p)
                        } else {
                            None
                        }
                    }
                    _ => None,
                })
                .map(|p| {
                    let id = p
                        .file_stem()
                        .map(|p| p.to_str().unwrap_or(""))
                        .unwrap_or("")
                        .to_owned();

                    let id_decoded_string = if id.starts_with("base64_") && id.len() != 7 {
                        let id_decoded =
                            base64::decode(&id[7..], base64::Variant::Original).unwrap_or_default();
                        String::from_utf8_lossy(&id_decoded).as_ref().to_owned()
                    } else {
                        id
                    };
                    (id_decoded_string, p)
                })
                .filter(|(id, _)| {
                    let Some(filters) = id_filters else {
                        return true;
                    };
                    filters.contains(id)
                })
                .map(|(id, p)| {
                    let t = crate::get_modified_time(&p);
                    (id, t, p)
                })
                .collect::<Vec<_>>();
            vec_id_modified_time_path.sort_unstable_by(|a, b| b.1.cmp(&a.1));
            vec_id_modified_time_path
        } else {
            vec![]
        }
    }

    #[inline]
    async fn preload_file_async(path: PathBuf) {
        let _ = tokio::fs::File::open(path).await;
    }

    #[tokio::main(flavor = "current_thread")]
    async fn preload_peers_async() {
        let now = std::time::Instant::now();
        let vec_id_modified_time_path = Self::get_vec_id_modified_time_path(&None);
        let total_count = vec_id_modified_time_path.len();
        let mut futs = vec![];
        for (_, _, path) in vec_id_modified_time_path.into_iter() {
            futs.push(Self::preload_file_async(path));
            if futs.len() >= Self::BATCH_LOADING_COUNT {
                let first_load_start = std::time::Instant::now();
                futures::future::join_all(futs).await;
                if first_load_start.elapsed().as_millis() < 10 {
                    // No need to preload the rest if the first load is fast.
                    return;
                }
                futs = vec![];
            }
        }
        if !futs.is_empty() {
            futures::future::join_all(futs).await;
        }
        log::info!(
            "Preload peers done in {:?}, batch_count: {}, total: {}",
            now.elapsed(),
            Self::BATCH_LOADING_COUNT,
            total_count
        );
    }

    // We have to preload all peers in a background thread.
    // Because we find that opening files the first time after the system (Windows) booting will be very slow, up to 200~400ms.
    // The reason is that the Windows has "Microsoft Defender Antivirus Service" running in the background, which will scan the file when it's opened the first time.
    // So we have to preload all peers in a background thread to avoid the delay when opening the file the first time.
    // We can temporarily stop "Microsoft Defender Antivirus Service" or add the fold to the white list, to verify this. But don't do this in the release version.
    pub fn preload_peers() {
        std::thread::spawn(|| {
            Self::preload_peers_async();
        });
    }

    pub fn peers(id_filters: Option<Vec<String>>) -> Vec<(String, SystemTime, PeerConfig)> {
        let vec_id_modified_time_path = Self::get_vec_id_modified_time_path(&id_filters);
        Self::batch_peers(
            &vec_id_modified_time_path,
            0,
            Some(vec_id_modified_time_path.len()),
        )
        .0
    }

    pub fn batch_peers(
        all: &Vec<(String, SystemTime, PathBuf)>,
        from: usize,
        to: Option<usize>,
    ) -> (Vec<(String, SystemTime, PeerConfig)>, usize) {
        if from >= all.len() {
            return (vec![], 0);
        }

        let to = match to {
            Some(to) => to.min(all.len()),
            None => (from + Self::BATCH_LOADING_COUNT).min(all.len()),
        };

        // to <= from is unexpected, but we can just return an empty vec in this case.
        if to <= from {
            return (vec![], from);
        }

        let peers: Vec<_> = all[from..to]
            .iter()
            .filter_map(|(id, t, p)| {
                let loaded = PeerConfig::load_path_with_status(p.clone(), Some(id));
                let status = loaded.status;
                let c = loaded.value;
                if c.info.platform.is_empty() {
                    if should_remove_empty_peer_config(status, &c) {
                        fs::remove_file(p).ok();
                    }
                    return None;
                }
                Some((id.clone(), t.clone(), c))
            })
            .collect();
        (peers, to)
    }

    pub fn exists(id: &str) -> bool {
        Self::path(id).exists()
    }

    serde_field_string!(
        default_view_style,
        deserialize_view_style,
        UserDefaultConfig::read(keys::OPTION_VIEW_STYLE)
    );
    serde_field_string!(
        default_scroll_style,
        deserialize_scroll_style,
        UserDefaultConfig::read(keys::OPTION_SCROLL_STYLE)
    );
    serde_field_string!(
        default_image_quality,
        deserialize_image_quality,
        UserDefaultConfig::read(keys::OPTION_IMAGE_QUALITY)
    );
    serde_field_string!(
        default_reverse_mouse_wheel,
        deserialize_reverse_mouse_wheel,
        UserDefaultConfig::read(keys::OPTION_REVERSE_MOUSE_WHEEL)
    );
    serde_field_string!(
        default_displays_as_individual_windows,
        deserialize_displays_as_individual_windows,
        UserDefaultConfig::read(keys::OPTION_DISPLAYS_AS_INDIVIDUAL_WINDOWS)
    );
    serde_field_string!(
        default_use_all_my_displays_for_the_remote_session,
        deserialize_use_all_my_displays_for_the_remote_session,
        UserDefaultConfig::read(keys::OPTION_USE_ALL_MY_DISPLAYS_FOR_THE_REMOTE_SESSION)
    );

    fn default_custom_image_quality() -> Vec<i32> {
        let f: f64 = UserDefaultConfig::read(keys::OPTION_CUSTOM_IMAGE_QUALITY)
            .parse()
            .unwrap_or(50.0);
        vec![f as _]
    }

    fn deserialize_custom_image_quality<'de, D>(deserializer: D) -> Result<Vec<i32>, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let v: Vec<i32> = de::Deserialize::deserialize(deserializer)?;
        if v.len() == 1 && v[0] >= 10 && v[0] <= 0xFFF {
            Ok(v)
        } else {
            Ok(Self::default_custom_image_quality())
        }
    }

    fn default_options() -> HashMap<String, String> {
        let mut mp: HashMap<String, String> = Default::default();
        let _ = [
            keys::OPTION_CODEC_PREFERENCE,
            keys::OPTION_CUSTOM_FPS,
            keys::OPTION_ZOOM_CURSOR,
            keys::OPTION_I444,
            keys::OPTION_SWAP_LEFT_RIGHT_MOUSE,
            keys::OPTION_COLLAPSE_TOOLBAR,
        ]
        .map(|key| {
            mp.insert(key.to_owned(), UserDefaultConfig::read(key));
        });
        mp
    }

    fn default_trackpad_speed() -> i32 {
        UserDefaultConfig::read(keys::OPTION_TRACKPAD_SPEED)
            .parse()
            .unwrap_or(100)
    }

    fn deserialize_trackpad_speed<'de, D>(deserializer: D) -> Result<i32, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let v: i32 = de::Deserialize::deserialize(deserializer)?;
        if v >= 10 && v <= 1000 {
            Ok(v)
        } else {
            Ok(Self::default_trackpad_speed())
        }
    }

    fn default_edge_scroll_edge_thickness() -> i32 {
        UserDefaultConfig::read(keys::OPTION_EDGE_SCROLL_EDGE_THICKNESS)
            .parse()
            .unwrap_or(100)
    }

    fn deserialize_edge_scroll_edge_thickness<'de, D>(deserializer: D) -> Result<i32, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let v: i32 = de::Deserialize::deserialize(deserializer)?;
        if v >= 20 && v <= 150 {
            Ok(v)
        } else {
            Ok(Self::default_edge_scroll_edge_thickness())
        }
    }
}

serde_field_bool!(
    ShowRemoteCursor,
    "show_remote_cursor",
    default_show_remote_cursor,
    "ShowRemoteCursor::default_show_remote_cursor"
);
serde_field_bool!(
    FollowRemoteCursor,
    "follow_remote_cursor",
    default_follow_remote_cursor,
    "FollowRemoteCursor::default_follow_remote_cursor"
);

serde_field_bool!(
    FollowRemoteWindow,
    "follow_remote_window",
    default_follow_remote_window,
    "FollowRemoteWindow::default_follow_remote_window"
);
serde_field_bool!(
    ShowQualityMonitor,
    "show_quality_monitor",
    default_show_quality_monitor,
    "ShowQualityMonitor::default_show_quality_monitor"
);
serde_field_bool!(
    DisableAudio,
    "disable_audio",
    default_disable_audio,
    "DisableAudio::default_disable_audio"
);
serde_field_bool!(
    EnableFileCopyPaste,
    "enable-file-copy-paste",
    default_enable_file_copy_paste,
    "EnableFileCopyPaste::default_enable_file_copy_paste"
);
serde_field_bool!(
    DisableClipboard,
    "disable_clipboard",
    default_disable_clipboard,
    "DisableClipboard::default_disable_clipboard"
);
serde_field_bool!(
    LockAfterSessionEnd,
    "lock_after_session_end",
    default_lock_after_session_end,
    "LockAfterSessionEnd::default_lock_after_session_end"
);
serde_field_bool!(
    TerminalPersistent,
    "terminal-persistent",
    default_terminal_persistent,
    "TerminalPersistent::default_terminal_persistent"
);
serde_field_bool!(
    PrivacyMode,
    "privacy_mode",
    default_privacy_mode,
    "PrivacyMode::default_privacy_mode"
);

serde_field_bool!(
    AllowSwapKey,
    "allow_swap_key",
    default_allow_swap_key,
    "AllowSwapKey::default_allow_swap_key"
);

serde_field_bool!(
    ViewOnly,
    "view_only",
    default_view_only,
    "ViewOnly::default_view_only"
);

serde_field_bool!(
    ShowMyCursor,
    "show_my_cursor",
    default_show_my_cursor,
    "ShowMyCursor::default_show_my_cursor"
);

serde_field_bool!(
    SyncInitClipboard,
    "sync-init-clipboard",
    default_sync_init_clipboard,
    "SyncInitClipboard::default_sync_init_clipboard"
);

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct LocalConfig {
    #[serde(default, deserialize_with = "deserialize_string")]
    remote_id: String, // latest used one
    #[serde(default, deserialize_with = "deserialize_string")]
    kb_layout_type: String,
    #[serde(default, deserialize_with = "deserialize_size")]
    size: Size,
    #[serde(default, deserialize_with = "deserialize_vec_string")]
    pub fav: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_hashmap_string_string")]
    options: HashMap<String, String>,
    // Various data for flutter ui
    #[serde(default, deserialize_with = "deserialize_hashmap_string_string")]
    ui_flutter: HashMap<String, String>,
}

impl LocalConfig {
    fn load() -> LocalConfig {
        Config::load_::<LocalConfig>("_local")
    }

    fn store(&self) {
        Config::store_(self, "_local");
    }

    pub fn get_kb_layout_type() -> String {
        LOCAL_CONFIG.read().unwrap().kb_layout_type.clone()
    }

    pub fn set_kb_layout_type(kb_layout_type: String) {
        let mut config = LOCAL_CONFIG.write().unwrap();
        config.kb_layout_type = kb_layout_type;
        config.store();
    }

    pub fn get_size() -> Size {
        LOCAL_CONFIG.read().unwrap().size
    }

    pub fn set_size(x: i32, y: i32, w: i32, h: i32) {
        let mut config = LOCAL_CONFIG.write().unwrap();
        let size = (x, y, w, h);
        if size == config.size || size.2 < 300 || size.3 < 300 {
            return;
        }
        config.size = size;
        config.store();
    }

    pub fn set_remote_id(remote_id: &str) {
        let mut config = LOCAL_CONFIG.write().unwrap();
        if remote_id == config.remote_id {
            return;
        }
        config.remote_id = remote_id.into();
        config.store();
    }

    pub fn get_remote_id() -> String {
        LOCAL_CONFIG.read().unwrap().remote_id.clone()
    }

    pub fn set_fav(fav: Vec<String>) {
        let mut lock = LOCAL_CONFIG.write().unwrap();
        if lock.fav == fav {
            return;
        }
        lock.fav = fav;
        lock.store();
    }

    pub fn get_fav() -> Vec<String> {
        LOCAL_CONFIG.read().unwrap().fav.clone()
    }

    pub fn get_option(k: &str) -> String {
        get_or(
            &OVERWRITE_LOCAL_SETTINGS,
            &LOCAL_CONFIG.read().unwrap().options,
            &DEFAULT_LOCAL_SETTINGS,
            k,
        )
        .unwrap_or_default()
    }

    // Usually get_option should be used.
    pub fn get_option_from_file(k: &str) -> String {
        get_or(
            &OVERWRITE_LOCAL_SETTINGS,
            &Self::load().options,
            &DEFAULT_LOCAL_SETTINGS,
            k,
        )
        .unwrap_or_default()
    }

    pub fn get_bool_option(k: &str) -> bool {
        option2bool(k, &Self::get_option(k))
    }

    pub fn set_option(k: String, v: String) {
        if !is_option_can_save(&OVERWRITE_LOCAL_SETTINGS, &k, &DEFAULT_LOCAL_SETTINGS, &v) {
            let mut config = LOCAL_CONFIG.write().unwrap();
            if config.options.remove(&k).is_some() {
                config.store();
            }
            return;
        }
        let mut config = LOCAL_CONFIG.write().unwrap();
        // The custom client will explictly set "default" as the default language.
        let is_custom_client_default_lang = k == keys::OPTION_LANGUAGE && v == "default";
        if is_custom_client_default_lang {
            config.options.insert(k, "".to_owned());
            config.store();
            return;
        }
        let v2 = if v.is_empty() { None } else { Some(&v) };
        if v2 != config.options.get(&k) {
            if v2.is_none() {
                config.options.remove(&k);
            } else {
                config.options.insert(k, v);
            }
            config.store();
        }
    }

    pub fn get_flutter_option(k: &str) -> String {
        get_or(
            &OVERWRITE_LOCAL_SETTINGS,
            &LOCAL_CONFIG.read().unwrap().ui_flutter,
            &DEFAULT_LOCAL_SETTINGS,
            k,
        )
        .unwrap_or_default()
    }

    pub fn set_flutter_option(k: String, v: String) {
        let mut config = LOCAL_CONFIG.write().unwrap();
        let v2 = if v.is_empty() { None } else { Some(&v) };
        if v2 != config.ui_flutter.get(&k) {
            if v2.is_none() {
                config.ui_flutter.remove(&k);
            } else {
                config.ui_flutter.insert(k, v);
            }
            config.store();
        }
    }
}

// R-X5 / R-SV1 / R-D7a: LAN discovery is REMOVED. The `DiscoveryPeer` / `LanPeers` config types
// (the `_lan_peers` store that cached discovered MAC/ID/hostname/username/platform) are excised —
// the discovery listener/querier that populated them is gone (322aebb), the sciter Discovered-tab
// UI + ui_interface::get_lan_peers/remove_discovered are excised, and the flutter favorites merge
// no longer reads it. Nothing reads or writes `_lan_peers` anymore. (`deserialize_vec_discoverypeer`
// went with the struct.)

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct UserDefaultConfig {
    #[serde(default, deserialize_with = "deserialize_hashmap_string_string")]
    options: HashMap<String, String>,
}

impl UserDefaultConfig {
    fn read(key: &str) -> String {
        let mut cfg = USER_DEFAULT_CONFIG.write().unwrap();
        // we do so, because default config may changed in another process, but we don't sync it
        // but no need to read every time, give a small interval to avoid too many redundant read waste
        if cfg.1.elapsed() > Duration::from_secs(1) {
            *cfg = (Self::load(), Instant::now());
        }
        cfg.0.get(key)
    }

    pub fn load() -> UserDefaultConfig {
        Config::load_::<UserDefaultConfig>("_default")
    }

    #[inline]
    fn store(&self) {
        Config::store_(self, "_default");
    }

    pub fn get(&self, key: &str) -> String {
        match key {
            #[cfg(any(target_os = "android", target_os = "ios"))]
            keys::OPTION_VIEW_STYLE => self.get_string(key, "adaptive", vec!["original"]),
            #[cfg(not(any(target_os = "android", target_os = "ios")))]
            keys::OPTION_VIEW_STYLE => self.get_string(key, "original", vec!["adaptive"]),
            keys::OPTION_SCROLL_STYLE => {
                self.get_string(key, "scrollauto", vec!["scrolledge", "scrollbar"])
            }
            keys::OPTION_IMAGE_QUALITY => {
                self.get_string(key, "balanced", vec!["best", "low", "custom"])
            }
            keys::OPTION_CODEC_PREFERENCE => {
                self.get_string(key, "auto", vec!["vp8", "vp9", "h264", "h265"])
            }
            keys::OPTION_CUSTOM_IMAGE_QUALITY => self.get_num_string(key, 50.0, 10.0, 0xFFF as f64),
            keys::OPTION_CUSTOM_FPS => self.get_num_string(key, 30.0, 5.0, 120.0),
            keys::OPTION_ENABLE_FILE_COPY_PASTE => self.get_string(key, "Y", vec!["", "N"]),
            keys::OPTION_EDGE_SCROLL_EDGE_THICKNESS => self.get_num_string(key, 100, 20, 150),
            keys::OPTION_TRACKPAD_SPEED => self.get_num_string(key, 100, 10, 1000),
            _ => self
                .get_after(key)
                .map(|v| v.to_string())
                .unwrap_or_default(),
        }
    }

    pub fn set(&mut self, key: String, value: String) {
        if !is_option_can_save(
            &OVERWRITE_DISPLAY_SETTINGS,
            &key,
            &DEFAULT_DISPLAY_SETTINGS,
            &value,
        ) {
            if self.options.remove(&key).is_some() {
                self.store();
            }
            return;
        }
        if value.is_empty() {
            self.options.remove(&key);
        } else {
            self.options.insert(key, value);
        }
        self.store();
    }

    #[inline]
    fn get_string(&self, key: &str, default: &str, others: Vec<&str>) -> String {
        match self.get_after(key) {
            Some(option) => {
                if others.contains(&option.as_str()) {
                    option.to_owned()
                } else {
                    default.to_owned()
                }
            }
            None => default.to_owned(),
        }
    }

    #[inline]
    fn get_num_string<T>(&self, key: &str, default: T, min: T, max: T) -> String
    where
        T: ToString + std::str::FromStr + std::cmp::PartialOrd + std::marker::Copy,
    {
        match self.get_after(key) {
            Some(option) => {
                let v: T = option.parse().unwrap_or(default);
                if v >= min && v <= max {
                    v.to_string()
                } else {
                    default.to_string()
                }
            }
            None => default.to_string(),
        }
    }

    fn get_after(&self, k: &str) -> Option<String> {
        get_or(
            &OVERWRITE_DISPLAY_SETTINGS,
            &self.options,
            &DEFAULT_DISPLAY_SETTINGS,
            k,
        )
    }
}

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct AbPeer {
    #[serde(
        default,
        deserialize_with = "deserialize_string",
        skip_serializing_if = "String::is_empty"
    )]
    pub id: String,
    #[serde(
        default,
        deserialize_with = "deserialize_string",
        skip_serializing_if = "String::is_empty"
    )]
    pub hash: String,
    #[serde(
        default,
        deserialize_with = "deserialize_string",
        skip_serializing_if = "String::is_empty"
    )]
    pub username: String,
    #[serde(
        default,
        deserialize_with = "deserialize_string",
        skip_serializing_if = "String::is_empty"
    )]
    pub hostname: String,
    #[serde(
        default,
        deserialize_with = "deserialize_string",
        skip_serializing_if = "String::is_empty"
    )]
    pub platform: String,
    #[serde(
        default,
        deserialize_with = "deserialize_string",
        skip_serializing_if = "String::is_empty"
    )]
    pub alias: String,
    #[serde(default, deserialize_with = "deserialize_vec_string")]
    pub tags: Vec<String>,
}

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct AbEntry {
    #[serde(
        default,
        deserialize_with = "deserialize_string",
        skip_serializing_if = "String::is_empty"
    )]
    pub guid: String,
    #[serde(
        default,
        deserialize_with = "deserialize_string",
        skip_serializing_if = "String::is_empty"
    )]
    pub name: String,
    #[serde(default, deserialize_with = "deserialize_vec_abpeer")]
    pub peers: Vec<AbPeer>,
    #[serde(default, deserialize_with = "deserialize_vec_string")]
    pub tags: Vec<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_string",
        skip_serializing_if = "String::is_empty"
    )]
    pub tag_colors: String,
}

impl AbEntry {
    pub fn personal(&self) -> bool {
        self.name == "My address book" || self.name == "Legacy address book"
    }
}

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct Ab {
    #[serde(
        default,
        deserialize_with = "deserialize_string",
        skip_serializing_if = "String::is_empty"
    )]
    pub access_token: String,
    #[serde(default, deserialize_with = "deserialize_vec_abentry")]
    pub ab_entries: Vec<AbEntry>,
}

impl Ab {
    fn path() -> PathBuf {
        let filename = format!("{}_ab", APP_NAME.read().unwrap().clone());
        Config::path(filename)
    }

    pub fn store(json: String) {
        let Some(data) = encrypted_json_config_bytes("address book", json) else {
            return;
        };
        if let Err(err) = store_raw_config_bytes(Self::path(), &data) {
            log::error!("Failed to store address book: {err}");
        }
    }

    pub fn load() -> Ab {
        let path = Self::path();
        match load_encrypted_json_config::<Ab>(&path, "address book") {
            Ok(Some(ab)) => return ab,
            Ok(None) => {}
            Err(err) => {
                log::error!("{err}");
                preserve_raw_config_file(&path, "address book");
            }
        }
        Ab::default()
    }

    pub fn remove() {
        remove_raw_config_file(Self::path(), "address book");
    }
}

// use default value when field type is wrong
macro_rules! deserialize_default {
    ($func_name:ident, $return_type:ty) => {
        fn $func_name<'de, D>(deserializer: D) -> Result<$return_type, D::Error>
        where
            D: de::Deserializer<'de>,
        {
            Ok(de::Deserialize::deserialize(deserializer).unwrap_or_default())
        }
    };
}

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct GroupPeer {
    #[serde(
        default,
        deserialize_with = "deserialize_string",
        skip_serializing_if = "String::is_empty"
    )]
    pub id: String,
    #[serde(
        default,
        deserialize_with = "deserialize_string",
        skip_serializing_if = "String::is_empty"
    )]
    pub username: String,
    #[serde(
        default,
        deserialize_with = "deserialize_string",
        skip_serializing_if = "String::is_empty"
    )]
    pub hostname: String,
    #[serde(
        default,
        deserialize_with = "deserialize_string",
        skip_serializing_if = "String::is_empty"
    )]
    pub platform: String,
    #[serde(
        default,
        deserialize_with = "deserialize_string",
        skip_serializing_if = "String::is_empty"
    )]
    pub login_name: String,
}

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct GroupUser {
    #[serde(
        default,
        deserialize_with = "deserialize_string",
        skip_serializing_if = "String::is_empty"
    )]
    pub name: String,
    #[serde(
        default,
        deserialize_with = "deserialize_string",
        skip_serializing_if = "String::is_empty"
    )]
    pub display_name: String,
}

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct DeviceGroup {
    #[serde(
        default,
        deserialize_with = "deserialize_string",
        skip_serializing_if = "String::is_empty"
    )]
    pub name: String,
}

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct Group {
    #[serde(
        default,
        deserialize_with = "deserialize_string",
        skip_serializing_if = "String::is_empty"
    )]
    pub access_token: String,
    #[serde(default, deserialize_with = "deserialize_vec_groupuser")]
    pub users: Vec<GroupUser>,
    #[serde(default, deserialize_with = "deserialize_vec_grouppeer")]
    pub peers: Vec<GroupPeer>,
    #[serde(default, deserialize_with = "deserialize_vec_devicegroup")]
    pub device_groups: Vec<DeviceGroup>,
}

impl Group {
    fn path() -> PathBuf {
        let filename = format!("{}_group", APP_NAME.read().unwrap().clone());
        Config::path(filename)
    }

    pub fn store(json: String) {
        let Some(data) = encrypted_json_config_bytes("group", json) else {
            return;
        };
        if let Err(err) = store_raw_config_bytes(Self::path(), &data) {
            log::error!("Failed to store group: {err}");
        }
    }

    pub fn load() -> Self {
        let path = Self::path();
        match load_encrypted_json_config::<Self>(&path, "group") {
            Ok(Some(group)) => return group,
            Ok(None) => {}
            Err(err) => {
                log::error!("{err}");
                preserve_raw_config_file(&path, "group");
            }
        }
        Self::default()
    }

    pub fn remove() {
        remove_raw_config_file(Self::path(), "group");
    }
}

deserialize_default!(deserialize_string, String);
deserialize_default!(deserialize_bool, bool);
deserialize_default!(deserialize_vec_u8, Vec<u8>);
deserialize_default!(deserialize_vec_string, Vec<String>);
deserialize_default!(deserialize_vec_i32_string_i32, Vec<(i32, String, i32)>);
deserialize_default!(deserialize_vec_abpeer, Vec<AbPeer>);
deserialize_default!(deserialize_vec_abentry, Vec<AbEntry>);
deserialize_default!(deserialize_vec_groupuser, Vec<GroupUser>);
deserialize_default!(deserialize_vec_grouppeer, Vec<GroupPeer>);
deserialize_default!(deserialize_vec_devicegroup, Vec<DeviceGroup>);
deserialize_default!(deserialize_keypair, KeyPair);
deserialize_default!(deserialize_size, Size);
deserialize_default!(deserialize_hashmap_string_string, HashMap<String, String>);
deserialize_default!(deserialize_hashmap_resolutions, HashMap<String, Resolution>);

#[inline]
fn get_or(
    a: &RwLock<HashMap<String, String>>,
    b: &HashMap<String, String>,
    c: &RwLock<HashMap<String, String>>,
    k: &str,
) -> Option<String> {
    a.read()
        .unwrap()
        .get(k)
        .or(b.get(k))
        .or(c.read().unwrap().get(k))
        .cloned()
}

/// R-S16(b)/(c): the pinned value for `k`, if it is in the compile-time policy
/// table ([`keys::PINNED_SETTINGS`]). `None` when `k` is not a pinned key (the
/// table itself is unconditional and non-empty on every build — R-R2b).
#[inline]
fn pinned_setting(k: &str) -> Option<&'static str> {
    keys::PINNED_SETTINGS
        .iter()
        .find(|(key, _)| *key == k)
        .map(|(_, v)| *v)
}

#[inline]
fn overlay_pinned_settings(options: &mut HashMap<String, String>) {
    for &(key, value) in keys::PINNED_SETTINGS {
        options.insert(key.to_owned(), value.to_owned());
    }
}

#[inline]
fn is_option_can_save(
    overwrite: &RwLock<HashMap<String, String>>,
    k: &str,
    defaults: &RwLock<HashMap<String, String>>,
    v: &str,
) -> bool {
    // R-S16(c): pin the write funnel. A pinned policy key is never writable — by
    // a local set, an IPC Options write (R-S11), or a server-pushed config
    // merge (R-X3) — so the persisted file cannot shadow or disable the
    // compile-time policy. The callers already drop-and-purge it from the file.
    // Pinned keys are Config server-settings keys only, so the LocalConfig /
    // DisplaySettings callers of this shared guard are unaffected (no collision).
    if pinned_setting(k).is_some() {
        return false;
    }
    if overwrite.read().unwrap().contains_key(k)
        || defaults.read().unwrap().get(k).map_or(false, |x| x == v)
    {
        return false;
    }
    true
}

#[inline]
pub fn is_incoming_only() -> bool {
    HARD_SETTINGS
        .read()
        .unwrap()
        .get("conn-type")
        .map_or(false, |x| x == ("incoming"))
}

#[inline]
pub fn is_outgoing_only() -> bool {
    HARD_SETTINGS
        .read()
        .unwrap()
        .get("conn-type")
        .map_or(false, |x| x == ("outgoing"))
}

#[inline]
fn is_some_hard_opton(name: &str) -> bool {
    HARD_SETTINGS
        .read()
        .unwrap()
        .get(name)
        .map_or(false, |x| x == ("Y"))
}

#[inline]
pub fn is_disable_tcp_listen() -> bool {
    is_some_hard_opton("disable-tcp-listen")
}

#[inline]
pub fn is_disable_settings() -> bool {
    is_some_hard_opton("disable-settings")
}

// R-G4 / R-SV6 (§19): `is_disable_ab` / `is_disable_account` removed with the excised account /
// address-book / group front-end (their only callers were the deleted flutter FFI resolvers).

#[inline]
// This function must be kept the same as the one in flutter and sciter code.
// flutter: flutter/lib/common.dart -> option2bool()
// sciter: Does not have the function, but it should be kept the same.
pub fn option2bool(option: &str, value: &str) -> bool {
    if option.starts_with("enable-") {
        value != "N"
    } else if option.starts_with("allow-") || option == "stop-service" {
        value == "Y"
    } else {
        value != "N"
    }
}

// `use_ws()` and `allow_insecure_tls_fallback()` are absent (R-G4/§8): the WebSocket and proxy
// transports are excised, including the alternate TLS connector that consumed the fallback.
// Their retired option names stay pinned `N` so stale stored values cannot reappear through broad
// option reads.

pub mod keys {
    pub const OPTION_VIEW_ONLY: &str = "view_only";
    pub const OPTION_SHOW_MONITORS_TOOLBAR: &str = "show_monitors_toolbar";
    pub const OPTION_COLLAPSE_TOOLBAR: &str = "collapse_toolbar";
    pub const OPTION_SHOW_REMOTE_CURSOR: &str = "show_remote_cursor";
    pub const OPTION_FOLLOW_REMOTE_CURSOR: &str = "follow_remote_cursor";
    pub const OPTION_FOLLOW_REMOTE_WINDOW: &str = "follow_remote_window";
    pub const OPTION_ZOOM_CURSOR: &str = "zoom-cursor";
    pub const OPTION_SHOW_QUALITY_MONITOR: &str = "show_quality_monitor";
    pub const OPTION_DISABLE_AUDIO: &str = "disable_audio";
    pub const OPTION_ENABLE_FILE_COPY_PASTE: &str = "enable-file-copy-paste";
    pub const OPTION_DISABLE_CLIPBOARD: &str = "disable_clipboard";
    pub const OPTION_LOCK_AFTER_SESSION_END: &str = "lock_after_session_end";
    pub const OPTION_PRIVACY_MODE: &str = "privacy_mode";
    pub const OPTION_TOUCH_MODE: &str = "touch-mode";
    pub const OPTION_I444: &str = "i444";
    pub const OPTION_REVERSE_MOUSE_WHEEL: &str = "reverse_mouse_wheel";
    pub const OPTION_SWAP_LEFT_RIGHT_MOUSE: &str = "swap-left-right-mouse";
    pub const OPTION_DISPLAYS_AS_INDIVIDUAL_WINDOWS: &str = "displays_as_individual_windows";
    pub const OPTION_USE_ALL_MY_DISPLAYS_FOR_THE_REMOTE_SESSION: &str =
        "use_all_my_displays_for_the_remote_session";
    pub const OPTION_VIEW_STYLE: &str = "view_style";
    pub const OPTION_SCROLL_STYLE: &str = "scroll_style";
    pub const OPTION_EDGE_SCROLL_EDGE_THICKNESS: &str = "edge-scroll-edge-thickness";
    pub const OPTION_IMAGE_QUALITY: &str = "image_quality";
    pub const OPTION_CUSTOM_IMAGE_QUALITY: &str = "custom_image_quality";
    pub const OPTION_CUSTOM_FPS: &str = "custom-fps";
    pub const OPTION_CODEC_PREFERENCE: &str = "codec-preference";
    pub const OPTION_SYNC_INIT_CLIPBOARD: &str = "sync-init-clipboard";
    pub const OPTION_THEME: &str = "theme";
    pub const OPTION_LANGUAGE: &str = "lang";
    pub const OPTION_REMOTE_MENUBAR_DRAG_LEFT: &str = "remote-menubar-drag-left";
    pub const OPTION_REMOTE_MENUBAR_DRAG_RIGHT: &str = "remote-menubar-drag-right";
    pub const OPTION_HIDE_AB_TAGS_PANEL: &str = "hideAbTagsPanel";
    pub const OPTION_ENABLE_CONFIRM_CLOSING_TABS: &str = "enable-confirm-closing-tabs";
    pub const OPTION_ENABLE_OPEN_NEW_CONNECTIONS_IN_TABS: &str =
        "enable-open-new-connections-in-tabs";
    pub const OPTION_TEXTURE_RENDER: &str = "use-texture-render";
    pub const OPTION_ALLOW_D3D_RENDER: &str = "allow-d3d-render";
    // R-G4 / R-SV3 / R-X1 / §18: OPTION_ENABLE_CHECK_UPDATE ("enable-check-update") and
    // OPTION_ALLOW_AUTO_UPDATE ("allow-auto-update") are removed — the version-check (R-SV3)
    // and the fetch-and-run updater (R-X1) are excised, so no key gates a removed feature.
    // The latter is also dropped from KEYS_SETTINGS below (no longer DEFAULT/OVERWRITE-settable).
    pub const OPTION_SYNC_AB_WITH_RECENT_SESSIONS: &str = "sync-ab-with-recent-sessions";
    pub const OPTION_SYNC_AB_TAGS: &str = "sync-ab-tags";
    pub const OPTION_FILTER_AB_BY_INTERSECTION: &str = "filter-ab-by-intersection";
    pub const OPTION_ACCESS_MODE: &str = "access-mode";
    pub const OPTION_ENABLE_KEYBOARD: &str = "enable-keyboard";
    pub const OPTION_ENABLE_CLIPBOARD: &str = "enable-clipboard";
    pub const OPTION_ENABLE_FILE_TRANSFER: &str = "enable-file-transfer";
    pub const OPTION_ENABLE_CAMERA: &str = "enable-camera";
    pub const OPTION_ENABLE_TERMINAL: &str = "enable-terminal";
    pub const OPTION_TERMINAL_PERSISTENT: &str = "terminal-persistent";
    pub const OPTION_ENABLE_AUDIO: &str = "enable-audio";
    pub const OPTION_ENABLE_TUNNEL: &str = "enable-tunnel";
    pub const OPTION_ENABLE_REMOTE_RESTART: &str = "enable-remote-restart";
    pub const OPTION_ENABLE_RECORD_SESSION: &str = "enable-record-session";
    pub const OPTION_ENABLE_BLOCK_INPUT: &str = "enable-block-input";
    pub const OPTION_ENABLE_PRIVACY_MODE: &str = "enable-privacy-mode";
    pub const OPTION_ENABLE_VIRTUAL_DISPLAY: &str = "enable-virtual-display";
    pub const OPTION_ENABLE_PERM_CHANGE_IN_ACCEPT_WINDOW: &str =
        "enable-perm-change-in-accept-window";
    pub const OPTION_ALLOW_AUTO_DISCONNECT: &str = "allow-auto-disconnect";
    pub const OPTION_AUTO_DISCONNECT_TIMEOUT: &str = "auto-disconnect-timeout";
    pub const OPTION_ALLOW_ONLY_CONN_WINDOW_OPEN: &str = "allow-only-conn-window-open";
    pub const OPTION_ALLOW_AUTO_RECORD_INCOMING: &str = "allow-auto-record-incoming";
    pub const OPTION_ALLOW_AUTO_RECORD_OUTGOING: &str = "allow-auto-record-outgoing";
    pub const OPTION_VIDEO_SAVE_DIRECTORY: &str = "video-save-directory";
    pub const OPTION_ENABLE_ABR: &str = "enable-abr";
    pub const OPTION_ALLOW_REMOVE_WALLPAPER: &str = "allow-remove-wallpaper";
    pub const OPTION_ALLOW_ALWAYS_SOFTWARE_RENDER: &str = "allow-always-software-render";
    pub const OPTION_ALLOW_LINUX_HEADLESS: &str = "allow-linux-headless";
    pub const OPTION_ENABLE_HWCODEC: &str = "enable-hwcodec";
    pub const OPTION_APPROVE_MODE: &str = "approve-mode";
    pub const OPTION_VERIFICATION_METHOD: &str = "verification-method";
    pub const OPTION_CUSTOM_RENDEZVOUS_SERVER: &str = "custom-rendezvous-server";
    pub const OPTION_API_SERVER: &str = "api-server";
    pub const OPTION_KEY: &str = "key";
    pub const OPTION_ALLOW_WEBSOCKET: &str = "allow-websocket";
    pub const OPTION_PRESET_ADDRESS_BOOK_NAME: &str = "preset-address-book-name";
    pub const OPTION_PRESET_ADDRESS_BOOK_TAG: &str = "preset-address-book-tag";
    pub const OPTION_PRESET_ADDRESS_BOOK_ALIAS: &str = "preset-address-book-alias";
    pub const OPTION_PRESET_ADDRESS_BOOK_PASSWORD: &str = "preset-address-book-password";
    pub const OPTION_PRESET_ADDRESS_BOOK_NOTE: &str = "preset-address-book-note";
    pub const OPTION_PRESET_DEVICE_USERNAME: &str = "preset-device-username";
    pub const OPTION_PRESET_DEVICE_NAME: &str = "preset-device-name";
    pub const OPTION_PRESET_NOTE: &str = "preset-note";
    pub const OPTION_ENABLE_DIRECTX_CAPTURE: &str = "enable-directx-capture";
    pub const OPTION_ENABLE_ANDROID_SOFTWARE_ENCODING_HALF_SCALE: &str =
        "enable-android-software-encoding-half-scale";
    pub const OPTION_TRACKPAD_SPEED: &str = "trackpad-speed";
    pub const OPTION_RELAY_SERVER: &str = "relay-server";
    /// Maximum number of files allowed during a single file transfer request.
    ///
    /// Key: `file-transfer-max-files`.
    /// Unit: number of files (not bytes).
    ///
    /// Behaviour:
    /// - If set to a positive integer N, at most N files are allowed.
    /// - If set to 0, a safe built-in default is used (see DEFAULT_MAX_VALIDATED_FILES).
    /// - If unset, negative, or non-integer, the same safe built-in default is used.
    pub const OPTION_FILE_TRANSFER_MAX_FILES: &str = "file-transfer-max-files";
    pub const OPTION_ALLOW_INSECURE_TLS_FALLBACK: &str = "allow-insecure-tls-fallback";
    pub const OPTION_SHOW_VIRTUAL_MOUSE: &str = "show-virtual-mouse";
    // joystick is the virtual mouse.
    // So `OPTION_SHOW_VIRTUAL_MOUSE` should also be set if `OPTION_SHOW_VIRTUAL_JOYSTICK` is set.
    pub const OPTION_SHOW_VIRTUAL_JOYSTICK: &str = "show-virtual-joystick";
    pub const OPTION_ENABLE_FLUTTER_HTTP_ON_RUST: &str = "enable-flutter-http-on-rust";
    pub const OPTION_ALLOW_ASK_FOR_NOTE: &str = "allow-ask-for-note";

    // built-in options
    pub const OPTION_DISPLAY_NAME: &str = "display-name";
    pub const OPTION_AVATAR: &str = "avatar";
    pub const OPTION_PRESET_DEVICE_GROUP_NAME: &str = "preset-device-group-name";
    pub const OPTION_PRESET_USERNAME: &str = "preset-user-name";
    pub const OPTION_PRESET_STRATEGY_NAME: &str = "preset-strategy-name";
    pub const OPTION_REMOVE_PRESET_PASSWORD_WARNING: &str = "remove-preset-password-warning";
    pub const OPTION_HIDE_SECURITY_SETTINGS: &str = "hide-security-settings";
    pub const OPTION_HIDE_NETWORK_SETTINGS: &str = "hide-network-settings";
    pub const OPTION_HIDE_SERVER_SETTINGS: &str = "hide-server-settings";
    pub const OPTION_HIDE_PROXY_SETTINGS: &str = "hide-proxy-settings";
    pub const OPTION_HIDE_WEBSOCKET_SETTINGS: &str = "hide-websocket-settings";
    pub const OPTION_HIDE_STOP_SERVICE: &str = "hide-stop-service";
    pub const OPTION_ALLOW_COMMAND_LINE_SETTINGS_WHEN_SETTINGS_DISABLED: &str =
        "allow-command-line-settings-when-settings-disabled";

    pub const OPTION_HIDE_USERNAME_ON_CARD: &str = "hide-username-on-card";
    pub const OPTION_HIDE_HELP_CARDS: &str = "hide-help-cards";
    pub const OPTION_DEFAULT_CONNECT_PASSWORD: &str = "default-connect-password";
    pub const OPTION_HIDE_TRAY: &str = "hide-tray";
    pub const OPTION_ONE_WAY_CLIPBOARD_REDIRECTION: &str = "one-way-clipboard-redirection";
    pub const OPTION_ALLOW_LOGON_SCREEN_PASSWORD: &str = "allow-logon-screen-password";
    pub const OPTION_ALLOW_DEEP_LINK_PASSWORD: &str = "allow-deep-link-password";
    pub const OPTION_ALLOW_DEEP_LINK_SERVER_SETTINGS: &str = "allow-deep-link-server-settings";
    pub const OPTION_ONE_WAY_FILE_TRANSFER: &str = "one-way-file-transfer";
    pub const OPTION_USE_RAW_TCP_FOR_API: &str = "use-raw-tcp-for-api";
    pub const OPTION_HIDE_POWERED_BY_ME: &str = "hide-powered-by-me";
    pub const OPTION_MAIN_WINDOW_ALWAYS_ON_TOP: &str = "main-window-always-on-top";
    pub const OPTION_DISABLE_CHANGE_PERMANENT_PASSWORD: &str = "disable-change-permanent-password";

    // flutter local options
    pub const OPTION_FLUTTER_REMOTE_MENUBAR_STATE: &str = "remoteMenubarState";
    pub const OPTION_FLUTTER_PEER_SORTING: &str = "peer-sorting";
    pub const OPTION_FLUTTER_PEER_TAB_INDEX: &str = "peer-tab-index";
    pub const OPTION_FLUTTER_PEER_TAB_ORDER: &str = "peer-tab-order";
    pub const OPTION_FLUTTER_PEER_TAB_VISIBLE: &str = "peer-tab-visible";
    pub const OPTION_FLUTTER_PEER_CARD_UI_TYLE: &str = "peer-card-ui-type";
    pub const OPTION_FLUTTER_CURRENT_AB_NAME: &str = "current-ab-name";

    // android floating window options
    pub const OPTION_DISABLE_FLOATING_WINDOW: &str = "disable-floating-window";
    pub const OPTION_FLOATING_WINDOW_SIZE: &str = "floating-window-size";
    pub const OPTION_FLOATING_WINDOW_UNTOUCHABLE: &str = "floating-window-untouchable";
    pub const OPTION_FLOATING_WINDOW_TRANSPARENCY: &str = "floating-window-transparency";
    pub const OPTION_FLOATING_WINDOW_SVG: &str = "floating-window-svg";

    // android keep screen on
    pub const OPTION_KEEP_SCREEN_ON: &str = "keep-screen-on";

    // Server-side: keep host system awake during incoming sessions (Security setting)
    pub const OPTION_KEEP_AWAKE_DURING_INCOMING_SESSIONS: &str =
        "keep-awake-during-incoming-sessions";

    // Client-side: keep client system awake during outgoing sessions (General setting)
    pub const OPTION_KEEP_AWAKE_DURING_OUTGOING_SESSIONS: &str =
        "keep-awake-during-outgoing-sessions";

    pub const OPTION_DISABLE_GROUP_PANEL: &str = "disable-group-panel";
    pub const OPTION_DISABLE_DISCOVERY_PANEL: &str = "disable-discovery-panel";
    pub const OPTION_PRE_ELEVATE_SERVICE: &str = "pre-elevate-service";

    // Retired proxy option names remain pinned empty so stale stored or signed-custom values cannot
    // surface through whole-map option reads. There is no proxy transport or structured proxy store.
    pub const OPTION_PROXY_URL: &str = "proxy-url";
    pub const OPTION_PROXY_USERNAME: &str = "proxy-username";
    pub const OPTION_PROXY_PASSWORD: &str = "proxy-password";

    // DEFAULT_DISPLAY_SETTINGS, OVERWRITE_DISPLAY_SETTINGS
    pub const KEYS_DISPLAY_SETTINGS: &[&str] = &[
        OPTION_VIEW_ONLY,
        OPTION_SHOW_MONITORS_TOOLBAR,
        OPTION_COLLAPSE_TOOLBAR,
        OPTION_SHOW_REMOTE_CURSOR,
        OPTION_FOLLOW_REMOTE_CURSOR,
        OPTION_FOLLOW_REMOTE_WINDOW,
        OPTION_ZOOM_CURSOR,
        OPTION_SHOW_QUALITY_MONITOR,
        OPTION_DISABLE_AUDIO,
        OPTION_ENABLE_FILE_COPY_PASTE,
        OPTION_DISABLE_CLIPBOARD,
        OPTION_LOCK_AFTER_SESSION_END,
        OPTION_PRIVACY_MODE,
        OPTION_TOUCH_MODE,
        OPTION_I444,
        OPTION_REVERSE_MOUSE_WHEEL,
        OPTION_SWAP_LEFT_RIGHT_MOUSE,
        OPTION_DISPLAYS_AS_INDIVIDUAL_WINDOWS,
        OPTION_USE_ALL_MY_DISPLAYS_FOR_THE_REMOTE_SESSION,
        OPTION_VIEW_STYLE,
        OPTION_TERMINAL_PERSISTENT,
        OPTION_SCROLL_STYLE,
        OPTION_EDGE_SCROLL_EDGE_THICKNESS,
        OPTION_IMAGE_QUALITY,
        OPTION_CUSTOM_IMAGE_QUALITY,
        OPTION_CUSTOM_FPS,
        OPTION_CODEC_PREFERENCE,
        OPTION_SYNC_INIT_CLIPBOARD,
        OPTION_TRACKPAD_SPEED,
    ];
    // DEFAULT_LOCAL_SETTINGS, OVERWRITE_LOCAL_SETTINGS
    pub const KEYS_LOCAL_SETTINGS: &[&str] = &[
        OPTION_THEME,
        OPTION_LANGUAGE,
        OPTION_ENABLE_CONFIRM_CLOSING_TABS,
        OPTION_ENABLE_OPEN_NEW_CONNECTIONS_IN_TABS,
        OPTION_TEXTURE_RENDER,
        OPTION_ALLOW_D3D_RENDER,
        OPTION_SYNC_AB_WITH_RECENT_SESSIONS,
        OPTION_SYNC_AB_TAGS,
        OPTION_FILTER_AB_BY_INTERSECTION,
        OPTION_REMOTE_MENUBAR_DRAG_LEFT,
        OPTION_REMOTE_MENUBAR_DRAG_RIGHT,
        OPTION_HIDE_AB_TAGS_PANEL,
        OPTION_FLUTTER_REMOTE_MENUBAR_STATE,
        OPTION_FLUTTER_PEER_SORTING,
        OPTION_FLUTTER_PEER_TAB_INDEX,
        OPTION_FLUTTER_PEER_TAB_ORDER,
        OPTION_FLUTTER_PEER_TAB_VISIBLE,
        OPTION_FLUTTER_PEER_CARD_UI_TYLE,
        OPTION_FLUTTER_CURRENT_AB_NAME,
        OPTION_DISABLE_FLOATING_WINDOW,
        OPTION_FLOATING_WINDOW_SIZE,
        OPTION_FLOATING_WINDOW_UNTOUCHABLE,
        OPTION_FLOATING_WINDOW_TRANSPARENCY,
        OPTION_FLOATING_WINDOW_SVG,
        OPTION_KEEP_SCREEN_ON,
        // Client-side: keep client system awake during outgoing sessions (General setting)
        OPTION_KEEP_AWAKE_DURING_OUTGOING_SESSIONS,
        OPTION_DISABLE_GROUP_PANEL,
        OPTION_DISABLE_DISCOVERY_PANEL,
        OPTION_PRE_ELEVATE_SERVICE,
        OPTION_ALLOW_AUTO_RECORD_OUTGOING,
        OPTION_VIDEO_SAVE_DIRECTORY,
        OPTION_TOUCH_MODE,
        OPTION_SHOW_VIRTUAL_MOUSE,
        OPTION_SHOW_VIRTUAL_JOYSTICK,
        OPTION_ENABLE_FLUTTER_HTTP_ON_RUST,
        OPTION_ALLOW_ASK_FOR_NOTE,
    ];
    // DEFAULT_SETTINGS, OVERWRITE_SETTINGS
    pub const KEYS_SETTINGS: &[&str] = &[
        OPTION_ACCESS_MODE,
        OPTION_ENABLE_KEYBOARD,
        OPTION_ENABLE_CLIPBOARD,
        OPTION_ENABLE_FILE_TRANSFER,
        OPTION_ENABLE_CAMERA,
        OPTION_ENABLE_TERMINAL,
        OPTION_ENABLE_AUDIO,
        OPTION_ENABLE_TUNNEL,
        OPTION_ENABLE_REMOTE_RESTART,
        OPTION_ENABLE_RECORD_SESSION,
        OPTION_ENABLE_BLOCK_INPUT,
        OPTION_ENABLE_PRIVACY_MODE,
        OPTION_ENABLE_VIRTUAL_DISPLAY,
        OPTION_ALLOW_AUTO_DISCONNECT,
        OPTION_AUTO_DISCONNECT_TIMEOUT,
        OPTION_ALLOW_ONLY_CONN_WINDOW_OPEN,
        OPTION_ALLOW_AUTO_RECORD_INCOMING,
        OPTION_ENABLE_ABR,
        OPTION_ALLOW_REMOVE_WALLPAPER,
        OPTION_ALLOW_ALWAYS_SOFTWARE_RENDER,
        OPTION_ALLOW_LINUX_HEADLESS,
        OPTION_ENABLE_HWCODEC,
        OPTION_APPROVE_MODE,
        OPTION_VERIFICATION_METHOD,
        OPTION_PROXY_URL,
        OPTION_PROXY_USERNAME,
        OPTION_PROXY_PASSWORD,
        OPTION_CUSTOM_RENDEZVOUS_SERVER,
        OPTION_API_SERVER,
        OPTION_KEY,
        OPTION_ALLOW_WEBSOCKET,
        OPTION_PRESET_ADDRESS_BOOK_NAME,
        OPTION_PRESET_ADDRESS_BOOK_TAG,
        OPTION_PRESET_ADDRESS_BOOK_ALIAS,
        OPTION_PRESET_ADDRESS_BOOK_PASSWORD,
        OPTION_PRESET_ADDRESS_BOOK_NOTE,
        OPTION_PRESET_DEVICE_USERNAME,
        OPTION_PRESET_DEVICE_NAME,
        OPTION_PRESET_NOTE,
        OPTION_ENABLE_DIRECTX_CAPTURE,
        OPTION_ENABLE_ANDROID_SOFTWARE_ENCODING_HALF_SCALE,
        OPTION_RELAY_SERVER,
        OPTION_ALLOW_INSECURE_TLS_FALLBACK,
        OPTION_KEEP_AWAKE_DURING_INCOMING_SESSIONS,
        // R-G4/R-X1: OPTION_ALLOW_AUTO_UPDATE removed (the updater is excised — nothing to set).
    ];

    /// R-S16(a): the controlled side's entire security policy, pinned at compile
    /// time — one auditable source of truth. `Config::get_option` returns these
    /// verbatim (R-S16(b)) and `is_option_can_save` rejects any write to them
    /// (R-S16(c)), so no key here can be defaulted-permissive or written back on
    /// — by a local process, an IPC `Options` write, or a server-pushed config
    /// merge. Pins only `Config` server-settings keys; the
    /// parallel `LocalConfig` viewer-UI map is untouched.
    ///
    /// UNCONDITIONAL: this table is the controlled-side security policy on every
    /// shipped artifact, never behind a feature flag (spec R-S16(a), R-R2b). An
    /// operator who needs a different policy edits this table and rebuilds (the
    /// R-F4 build-time-choice discipline) — never a runtime knob.
    pub const PINNED_SETTINGS: &[(&str, &str)] = &[
        // Credential & approval: the CPace PRS is the permanent password; no
        // one-time-password path, no silent click-to-accept (R-S16, R-X7).
        (OPTION_VERIFICATION_METHOD, "use-permanent-password"),
        (OPTION_APPROVE_MODE, "password"),
        // FULL ACCESS is the ONE pinned mode (R-D8/R-X8/R-F1). The CPace-authenticated peer is the
        // sovereign OWNER who holds the password (on the §17 box that password is also the OS/sudo
        // login) — §2 explicitly does NOT confine a password-knower, and the bar is SSH (one auth →
        // a full shell + port-forwarding). Denying the owner capabilities is theater (keyboard + the
        // shared sudo password already reach a root shell, a tunnel, a reboot), so every capability is
        // GRANTED — except enable-virtual-display (a native display-DRIVER surface, R-T0/#2b, below).
        // Still defensive: post-CPace (owner-only), funnel-pinned (no runtime flip — a
        // password-knower can neither widen nor narrow it, R-S16), and the genuinely-separate
        // SECOND-OS-CREDENTIAL path stays excised (Windows LogonUserW / Linux os_login->PAM, R-X14/
        // R-S18; the Linux terminal is a plain root PTY, so granting it adds no second credential).
        (OPTION_ACCESS_MODE, "full"),
        (OPTION_ENABLE_KEYBOARD, "Y"),
        (OPTION_ENABLE_CLIPBOARD, "Y"),
        (OPTION_ENABLE_FILE_TRANSFER, "Y"),
        (OPTION_ENABLE_AUDIO, "Y"),
        (OPTION_ENABLE_CAMERA, "Y"),
        (OPTION_ENABLE_TERMINAL, "Y"),
        (OPTION_ENABLE_TUNNEL, "Y"),
        (OPTION_ENABLE_REMOTE_RESTART, "Y"),
        (OPTION_ENABLE_RECORD_SESSION, "Y"),
        (OPTION_ENABLE_BLOCK_INPUT, "Y"),
        (OPTION_ENABLE_PRIVACY_MODE, "Y"),
        // The ONE exception to full access (R-T0/Appendix C #2b): enable-virtual-display drives a
        // native display-DRIVER API (Windows IddCx; the native-code surface the fork minimizes). It is
        // NOT control the owner reaches another way, and a no-op on the §17 headless Xvfb box — so it
        // stays OFF as defense-in-depth on the native-driver surface.
        (OPTION_ENABLE_VIRTUAL_DISPLAY, "N"),
        // No TOTP, no Telegram-bot push (R-X7, R-D6); trusted-devices is fully excised, not just pinned.
        ("2fa", ""),
        ("bot", ""),
        // Egress-silent: no rendezvous / relay / api / proxy (R-D6). The structured
        // SOCKS accessors are pinned inert below; these option pins close the string map.
        (OPTION_API_SERVER, ""),
        (OPTION_CUSTOM_RENDEZVOUS_SERVER, ""),
        (OPTION_RELAY_SERVER, ""),
        (OPTION_PROXY_URL, ""),
        (OPTION_PROXY_USERNAME, ""),
        (OPTION_PROXY_PASSWORD, ""),
        // The trust anchor is the baked RS_PUB_KEY; no stored override exists.
        (OPTION_KEY, ""),
        // Transport / fallback hardening (R-D6, R-X14).
        (OPTION_ALLOW_WEBSOCKET, "N"),
        (OPTION_ALLOW_INSECURE_TLS_FALLBACK, "N"),
        (OPTION_ALLOW_LINUX_HEADLESS, "N"),
        // Service un-killable by a local write (R-X9); never self-DoS a headless box.
        ("stop-service", "N"),
        (OPTION_ALLOW_ONLY_CONN_WINDOW_OPEN, ""),
    ];

    // BUILDIN_SETTINGS
    pub const KEYS_BUILDIN_SETTINGS: &[&str] = &[
        OPTION_DISPLAY_NAME,
        OPTION_AVATAR,
        OPTION_PRESET_DEVICE_GROUP_NAME,
        OPTION_PRESET_USERNAME,
        OPTION_PRESET_STRATEGY_NAME,
        OPTION_REMOVE_PRESET_PASSWORD_WARNING,
        OPTION_HIDE_SECURITY_SETTINGS,
        OPTION_HIDE_NETWORK_SETTINGS,
        OPTION_HIDE_SERVER_SETTINGS,
        OPTION_HIDE_PROXY_SETTINGS,
        OPTION_HIDE_WEBSOCKET_SETTINGS,
        OPTION_HIDE_STOP_SERVICE,
        OPTION_HIDE_USERNAME_ON_CARD,
        OPTION_HIDE_HELP_CARDS,
        OPTION_DEFAULT_CONNECT_PASSWORD,
        OPTION_HIDE_TRAY,
        OPTION_ONE_WAY_CLIPBOARD_REDIRECTION,
        OPTION_ALLOW_LOGON_SCREEN_PASSWORD,
        OPTION_ALLOW_DEEP_LINK_PASSWORD,
        OPTION_ALLOW_DEEP_LINK_SERVER_SETTINGS,
        OPTION_ONE_WAY_FILE_TRANSFER,
        OPTION_HIDE_POWERED_BY_ME,
        OPTION_MAIN_WINDOW_ALWAYS_ON_TOP,
        OPTION_FILE_TRANSFER_MAX_FILES,
        OPTION_DISABLE_CHANGE_PERMANENT_PASSWORD,
        OPTION_USE_RAW_TCP_FOR_API,
        OPTION_ENABLE_PERM_CHANGE_IN_ACCEPT_WINDOW,
        OPTION_ALLOW_COMMAND_LINE_SETTINGS_WHEN_SETTINGS_DISABLED,
    ];
}

pub fn common_load<
    T: serde::Serialize + serde::de::DeserializeOwned + Default + std::fmt::Debug,
>(
    suffix: &str,
) -> T {
    Config::load_::<T>(suffix)
}

pub fn common_store<T: serde::Serialize>(config: &T, suffix: &str) {
    Config::store_(config, suffix);
}

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct Status {
    #[serde(default, deserialize_with = "deserialize_hashmap_string_string")]
    values: HashMap<String, String>,
}

impl Status {
    fn load() -> Status {
        Config::load_::<Status>("_status")
    }

    fn store(&self) {
        Config::store_(self, "_status");
    }

    pub fn get(k: &str) -> String {
        STATUS
            .read()
            .unwrap()
            .values
            .get(k)
            .cloned()
            .unwrap_or_default()
    }

    pub fn set(k: &str, v: String) {
        if Self::get(k) == v {
            return;
        }

        let mut st = STATUS.write().unwrap();
        st.values.insert(k.to_owned(), v);
        st.store();
    }
}

#[cfg(test)]
mod tests {
    use super::{
        permanent_password::{
            encode_permanent_password_encrypted_storage_from_h1, PERMANENT_PASSWORD_ENC_VERSION,
        },
        *,
    };

    #[test]
    fn sync_rebuilds_password_prs_from_storage() {
        // R-S9: a credential snapshot may carry only (storage, salt), never
        // password_prs, so the apply path rebuilds password_prs from the storage envelope (both encode
        // the SAME 32 PRS bytes). This keeps the box listening with a live PRS (R-S9) and
        // authenticating the current password after a restart. This exercises the
        // private sync-apply on a LOCAL Config (no global state), so it is hermetic and parallel-safe.
        let (storage, prs_storage) =
            derive_permanent_password_storages("correct horse battery staple").unwrap();
        let salt = "sync-salt"; // the sync requires a non-empty salt
        let mut config = Config::default();
        assert!(config.password_prs.is_empty(), "a fresh config has no PRS");

        // apply the daemon credential snapshot payload (storage + salt only):
        let changed =
            Config::apply_permanent_password_storage_for_sync(&mut config, &storage, salt).unwrap();
        assert!(changed, "a new credential is a change");
        assert!(
            !config.password_prs.is_empty(),
            "the sync MUST rebuild password_prs from the storage, not leave it empty"
        );
        assert_eq!(
            decrypt_permanent_password_prs_storage(&config.password_prs),
            decrypt_permanent_password_prs_storage(&prs_storage),
            "the rebuilt PRS must equal the credential's real live PRS"
        );

        // the sibling fix: clearing (empty storage) must clear password_prs too, else the box keeps
        // authenticating the just-cleared credential.
        let cleared =
            Config::apply_permanent_password_storage_for_sync(&mut config, "", salt).unwrap();
        assert!(cleared);
        assert!(
            config.password_prs.is_empty(),
            "clearing the credential must clear password_prs (not leave it live)"
        );
    }

    #[test]
    fn direct_only_password_config_is_not_empty() {
        let (password, password_prs) =
            derive_permanent_password_storages("direct-only password").unwrap();
        let config = Config {
            password,
            password_prs,
            salt: "direct-only-salt".to_owned(),
            ..Default::default()
        };

        assert!(config.id.is_empty());
        assert!(config.enc_id.is_empty());
        assert!(config.key_pair.0.is_empty());
        assert!(!config.is_empty());
    }

    #[test]
    fn config2_ignores_retired_network_state_and_never_serializes_it() {
        let legacy = r#"
rendezvous_server = "legacy.example:21116"
nat_type = 2
serial = 42

[socks]
proxy = "127.0.0.1:1080"
username = "legacy-user"
password = "legacy-secret"

[options]
unrelated = "preserved"
"#;

        let config: Config2 = toml::from_str(legacy).unwrap();
        assert_eq!(
            config.options.get("unrelated").map(String::as_str),
            Some("preserved")
        );

        let serialized = toml::to_string(&config).unwrap();
        assert!(!serialized.contains("socks"));
        assert!(!serialized.contains("127.0.0.1:1080"));
        assert!(!serialized.contains("legacy-user"));
        assert!(!serialized.contains("legacy-secret"));
        assert!(!serialized.contains("rendezvous_server"));
        assert!(!serialized.contains("legacy.example:21116"));
        assert!(!serialized.contains("nat_type"));
        assert!(!serialized.contains("serial"));
    }

    #[test]
    fn runtime_password_snapshot_does_not_persist() {
        let _lock = CONFIG_STATE_TEST_LOCK.lock().unwrap();
        let file = Config::file_("");
        let _file_guard = ConfigFileRestoreGuard::new(file.clone());
        fs::remove_file(&file).ok();
        let _state_guard = ConfigStateTestGuard::new(Config::default(), HashMap::new());
        let (storage, prs_storage) =
            derive_permanent_password_storages("runtime snapshot password").unwrap();

        assert!(
            Config::set_permanent_password_storage_for_runtime(&storage, "runtime-salt").unwrap()
        );
        assert_eq!(
            Config::read_permanent_password_prs(),
            PermanentPasswordPrsRead::Available(
                decrypt_permanent_password_prs_storage(&prs_storage).unwrap()
            )
        );
        let config = CONFIG.read().unwrap();
        assert!(config.password.is_empty());
        assert!(config.password_prs.is_empty());
        drop(config);
        let durable_config = CONFIG.read().unwrap().clone();
        durable_config.store();
        let saved_config: Config = load_path(file);
        assert!(saved_config.password.is_empty());
        assert!(saved_config.password_prs.is_empty());
    }

    #[test]
    fn runtime_password_prs_replica_is_canonical_nonpersistent_and_can_clear() {
        let _lock = CONFIG_STATE_TEST_LOCK.lock().unwrap();
        let file = Config::file_("");
        let _file_guard = ConfigFileRestoreGuard::new(file.clone());
        fs::remove_file(&file).ok();
        let _state_guard = ConfigStateTestGuard::new(Config::default(), HashMap::new());
        assert!(Config::set_permanent_password_persisted("stale user-profile password").unwrap());
        let durable = {
            let config = CONFIG.read().unwrap();
            (config.password.clone(), config.password_prs.clone())
        };
        assert!(!durable.0.is_empty());
        assert!(!durable.1.is_empty());
        let prs = base64::encode(
            &[0x5au8; PERMANENT_PASSWORD_H1_LEN],
            base64::Variant::Original,
        );

        assert!(Config::set_permanent_password_prs_for_runtime(&prs).unwrap());
        assert_eq!(
            Config::read_permanent_password_prs(),
            PermanentPasswordPrsRead::Available(prs.clone())
        );
        assert!(!Config::set_permanent_password_prs_for_runtime(&prs).unwrap());
        for invalid in [
            "not-base64",
            "YQ==",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ] {
            assert!(Config::set_permanent_password_prs_for_runtime(invalid).is_err());
            assert_eq!(
                Config::read_permanent_password_prs(),
                PermanentPasswordPrsRead::Available(prs.clone())
            );
        }

        assert!(Config::set_permanent_password_prs_for_runtime("").unwrap());
        assert!(matches!(
            Config::read_permanent_password_prs(),
            PermanentPasswordPrsRead::Empty
        ));
        let config = CONFIG.read().unwrap();
        assert_eq!(
            (config.password.clone(), config.password_prs.clone()),
            durable
        );
        drop(config);
        let durable_config = CONFIG.read().unwrap().clone();
        durable_config.store();
        let saved_config: Config = load_path(file);
        assert_eq!((saved_config.password, saved_config.password_prs), durable);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn config_patch_root_home_uses_passwd_home() {
        let expected = crate::platform::linux::get_home_dir_trusted()
            .unwrap_or_else(|| PathBuf::from("/root"));
        let patched = patch(PathBuf::from("/root"));

        assert_eq!(patched, expected);
    }

    #[test]
    fn r_s11e52_macos_service_owned_paths_ignore_ambient_home() {
        let root =
            macos_service_owned_config_root_from(Path::new("/var/root"), "com.carriez", "RustDesk")
                .unwrap();

        assert_eq!(root.home, Path::new("/var/root"));
        assert_eq!(
            root.path,
            Path::new("/var/root/Library/Application Support/com.carriez.RustDesk")
        );
        assert_eq!(root.log_path, Path::new("/var/root/Library/Logs/RustDesk"));
        assert!(macos_service_owned_config_root_from(
            Path::new("relative/root"),
            "com.carriez",
            "RustDesk"
        )
        .is_err());
        assert!(macos_service_owned_config_root_from(
            Path::new("/var/root"),
            "com.carriez",
            "../RustDesk"
        )
        .is_err());
        assert!(
            macos_service_owned_config_root_from(Path::new("/var/root"), "com.carriez", "..")
                .is_err()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_service_owned_config_root_derivation_is_explicit() {
        let home = Path::new("/srv/service-home");
        assert_eq!(
            linux_service_owned_config_root_from(home, "RustDesk").unwrap(),
            home.join(".config/rustdesk")
        );
        assert!(linux_service_owned_config_root_from(Path::new("relative"), "RustDesk").is_err());
        assert!(linux_service_owned_config_root_from(home, "../bad").is_err());
        assert!(linux_service_owned_config_root_from(home, "bad\\name").is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_service_owned_config_root_ignores_ambient_home_and_xdg() {
        const TEST_NAME: &str =
            "config::tests::linux_service_owned_config_root_ignores_ambient_home_and_xdg";
        const ROLE_ENV: &str = "RUSTDESK_TEST_SERVICE_CONFIG_ROOT_ROLE";
        const AMBIENT_HOME: &str = "/tmp/rustdesk-attacker-selected-home";
        const AMBIENT_XDG: &str = "/tmp/rustdesk-attacker-selected-xdg";

        if std::env::var_os(ROLE_ENV).as_deref() == Some(std::ffi::OsStr::new("worker")) {
            let trusted_home = PathBuf::from("/srv/service-home");
            let expected_root =
                linux_service_owned_config_root_from(&trusted_home, &APP_NAME.read().unwrap())
                    .unwrap();
            assert_eq!(
                std::env::var_os("HOME").as_deref(),
                Some(std::ffi::OsStr::new(AMBIENT_HOME))
            );
            assert_eq!(
                std::env::var_os("XDG_CONFIG_HOME").as_deref(),
                Some(std::ffi::OsStr::new(AMBIENT_XDG))
            );

            assert_eq!(
                Config::initialize_linux_service_owned_root_from_home(trusted_home.clone())
                    .unwrap(),
                expected_root
            );
            assert_eq!(
                Config::initialize_linux_service_owned_root_from_home(trusted_home.clone())
                    .unwrap(),
                expected_root
            );
            assert!(
                Config::initialize_linux_service_owned_root_from_home(PathBuf::from(
                    "/srv/different-service-home"
                ))
                .is_err()
            );
            assert_eq!(Config::get_home(), trusted_home);
            assert_eq!(
                Config::path("authority-probe"),
                expected_root.join("authority-probe")
            );
            assert!(!Config::path("authority-probe").starts_with(AMBIENT_HOME));
            assert!(!Config::path("authority-probe").starts_with(AMBIENT_XDG));
            return;
        }

        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST_NAME, "--nocapture"])
            .env(ROLE_ENV, "worker")
            .env("HOME", AMBIENT_HOME)
            .env("XDG_CONFIG_HOME", AMBIENT_XDG)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "service-owned config-root worker failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    static CONFIG_STATE_TEST_LOCK: Mutex<()> = Mutex::new(());

    struct ConfigStateTestGuard {
        original_config: Config,
        original_hard_settings: HashMap<String, String>,
        original_runtime_prs: Option<String>,
    }

    struct ConfigFileRestoreGuard {
        path: PathBuf,
        original_content: Option<Vec<u8>>,
    }

    impl ConfigStateTestGuard {
        fn new(config: Config, hard_settings: HashMap<String, String>) -> Self {
            let mut generation = PERMANENT_PASSWORD_CREDENTIAL_GENERATION.write().unwrap();
            let original_config = CONFIG.read().unwrap().clone();
            let original_hard_settings = HARD_SETTINGS.read().unwrap().clone();
            let original_runtime_prs = RUNTIME_PERMANENT_PASSWORD_PRS.read().unwrap().clone();
            *CONFIG.write().unwrap() = config;
            *HARD_SETTINGS.write().unwrap() = hard_settings;
            *RUNTIME_PERMANENT_PASSWORD_PRS.write().unwrap() = None;
            advance_permanent_password_credential_generation(&mut generation);
            Self {
                original_config,
                original_hard_settings,
                original_runtime_prs,
            }
        }
    }

    impl Drop for ConfigStateTestGuard {
        fn drop(&mut self) {
            let mut generation = PERMANENT_PASSWORD_CREDENTIAL_GENERATION.write().unwrap();
            *CONFIG.write().unwrap() = self.original_config.clone();
            *HARD_SETTINGS.write().unwrap() = self.original_hard_settings.clone();
            *RUNTIME_PERMANENT_PASSWORD_PRS.write().unwrap() = self.original_runtime_prs.clone();
            advance_permanent_password_credential_generation(&mut generation);
        }
    }

    impl ConfigFileRestoreGuard {
        fn new(path: PathBuf) -> Self {
            let original_content = fs::read(&path).ok();
            Self {
                path,
                original_content,
            }
        }
    }

    impl Drop for ConfigFileRestoreGuard {
        fn drop(&mut self) {
            if let Some(content) = &self.original_content {
                if let Some(parent) = self.path.parent() {
                    fs::create_dir_all(parent).ok();
                }
                fs::write(&self.path, content).ok();
            } else {
                fs::remove_file(&self.path).ok();
            }
        }
    }

    fn with_config_and_hard_settings<R>(
        config: Config,
        hard_settings: HashMap<String, String>,
        test: impl FnOnce() -> R,
    ) -> R {
        let _guard = CONFIG_STATE_TEST_LOCK.lock().unwrap();
        let _state_guard = ConfigStateTestGuard::new(config, hard_settings);
        test()
    }

    #[test]
    fn test_serialize() {
        let cfg: Config = Default::default();
        let res = toml::to_string_pretty(&cfg);
        assert!(res.is_ok());
        let cfg: PeerConfig = Default::default();
        let res = toml::to_string_pretty(&cfg);
        assert!(res.is_ok());
    }

    #[test]
    fn test_hbbs_00_hashed_preset_password_storage_matches_plain_with_salt() {
        let salt = "salt123";
        let h1 = compute_permanent_password_h1("p@ssw0rd", salt);
        let storage = "00".to_owned() + &base64::encode(h1, base64::Variant::Original);
        let hard_settings = HashMap::from([
            ("password".to_owned(), storage),
            ("salt".to_owned(), salt.to_owned()),
        ]);

        with_config_and_hard_settings(Config::default(), hard_settings, || {
            assert!(Config::has_permanent_password());
            assert!(Config::has_usable_preset_password());
            assert!(Config::is_using_preset_password());
            assert_eq!(Config::get_effective_permanent_password_salt(), salt);
        });
    }

    #[test]
    fn test_legacy_plain_preset_password_with_00_hash_shape_without_salt_keeps_old_behavior() {
        let h1 = compute_permanent_password_h1("p@ssw0rd", "salt123");
        let storage = "00".to_owned() + &base64::encode(h1, base64::Variant::Original);
        let hard_settings = HashMap::from([("password".to_owned(), storage.clone())]);

        let mut config = Config::default();
        config.salt = "local1".to_owned();

        with_config_and_hard_settings(config, hard_settings, || {
            assert!(Config::has_permanent_password());
            assert!(Config::has_usable_preset_password());
            assert!(Config::is_using_preset_password());
            assert_eq!(Config::get_effective_permanent_password_salt(), "local1");
        });
    }

    #[test]
    fn test_local_hashed_permanent_password_without_salt_is_not_reported_as_set() {
        let h1 = compute_permanent_password_h1("p@ssw0rd", "salt123");
        let mut config = Config::default();
        config.password = encode_permanent_password_encrypted_storage_from_h1(&h1).unwrap();

        with_config_and_hard_settings(config, HashMap::new(), || {
            assert!(!Config::has_permanent_password());
            assert!(!Config::has_local_permanent_password());
            assert!(!Config::is_using_preset_password());
        });
    }

    #[test]
    fn test_invalid_local_hashed_password_does_not_generate_effective_salt() {
        let h1 = compute_permanent_password_h1("p@ssw0rd", "salt123");
        let mut config = Config::default();
        config.password = encode_permanent_password_encrypted_storage_from_h1(&h1).unwrap();

        with_config_and_hard_settings(config, HashMap::new(), || {
            assert_eq!(Config::get_effective_permanent_password_salt(), "");
            assert_eq!(
                Config::get_local_permanent_password_storage_and_salt().1,
                ""
            );
        });
    }

    #[test]
    fn test_legacy_plain_preset_password_uses_local_salt_for_challenge() {
        let mut config = Config::default();
        config.salt = "local1".to_owned();
        let hard_settings = HashMap::from([("password".to_owned(), "legacy-password".to_owned())]);

        with_config_and_hard_settings(config, hard_settings, || {
            assert_eq!(Config::get_effective_permanent_password_salt(), "local1");
            assert!(Config::has_permanent_password());
            assert!(Config::is_using_preset_password());
        });
    }

    #[test]
    fn test_set_permanent_password_persists_when_value_matches_preset() {
        let _lock = CONFIG_STATE_TEST_LOCK.lock().unwrap();
        let file = Config::file_("");
        let _file_guard = ConfigFileRestoreGuard::new(file.clone());
        fs::remove_file(&file).ok();
        let salt = "preset-salt";
        let h1 = compute_permanent_password_h1("p@ssw0rd", salt);
        let preset_storage = "00".to_owned() + &base64::encode(h1, base64::Variant::Original);
        let hard_settings = HashMap::from([
            ("password".to_owned(), preset_storage),
            ("salt".to_owned(), salt.to_owned()),
        ]);
        let _state_guard = ConfigStateTestGuard::new(Config::default(), hard_settings);

        assert!(Config::is_using_preset_password());
        assert!(Config::set_permanent_password("p@ssw0rd"));
        assert!(Config::has_local_permanent_password());
        assert!(!Config::is_using_preset_password());
        let saved_config: Config = load_path(file);
        assert!(!saved_config.password.is_empty());
        assert!(!saved_config.password_prs.is_empty());
        assert_eq!(saved_config.salt.len(), DEFAULT_SALT_LEN);
        assert!(saved_config
            .salt
            .chars()
            .all(|c| PERMANENT_PASSWORD_STORAGE_SALT_CHARS.contains(&c)));
    }

    #[test]
    fn test_set_permanent_password_does_not_publish_unpersisted_state() {
        with_config_and_hard_settings(Config::default(), HashMap::new(), || {
            let result = Config::set_permanent_password_with_store("new-password", |_| {
                Err(anyhow!("injected persistence failure"))
            });
            assert!(result.is_err());
            let config = CONFIG.read().unwrap();
            assert!(config.password.is_empty());
            assert!(config.password_prs.is_empty());
            assert!(config.salt.is_empty());
        });
    }

    #[test]
    fn test_permanent_password_sync_does_not_publish_unpersisted_state() {
        let (storage, _) = derive_permanent_password_storages("new-password").unwrap();
        with_config_and_hard_settings(Config::default(), HashMap::new(), || {
            let result = Config::set_permanent_password_storage_for_sync_with_store(
                &storage,
                "sync-salt",
                |_| Err(anyhow!("injected persistence failure")),
            );
            assert!(result.is_err());
            let config = CONFIG.read().unwrap();
            assert!(config.password.is_empty());
            assert!(config.password_prs.is_empty());
            assert!(config.salt.is_empty());
        });
    }

    #[cfg(unix)]
    #[test]
    fn config_transaction_faults_preserve_precommit_and_make_postcommit_fatal() {
        use std::{
            os::unix::fs::PermissionsExt,
            sync::atomic::{AtomicBool, Ordering},
        };

        let directory = std::env::temp_dir().join(format!(
            "rustdesk-config-transaction-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.join("credential.toml");

        store_config_bytes_transaction(&path, b"old", ConfigStoreFault::None).unwrap();
        let before = store_config_bytes_transaction_unix(
            &path,
            b"new-before",
            ConfigStoreFault::BeforeReplace,
            &|_| panic!("pre-replacement failure must not be fatal"),
        );
        assert!(before.is_err());
        assert_eq!(fs::read(&path).unwrap(), b"old");

        let fatal = AtomicBool::new(false);
        let after = store_config_bytes_transaction_unix(
            &path,
            b"new-after",
            ConfigStoreFault::AfterReplace,
            &|_| {
                fatal.store(true, Ordering::Release);
                Err(anyhow!("simulated process-fatal durability outcome"))
            },
        );
        assert!(after.is_err());
        assert!(fatal.load(Ordering::Acquire));
        assert_eq!(fs::read(&path).unwrap(), b"new-after");
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );

        fs::remove_file(&path).unwrap();
        fs::remove_dir(&directory).unwrap();
    }

    #[test]
    fn replacement_failure_readback_reconciliation_requires_exact_bytes() {
        assert_eq!(
            reconcile_replacement_failure(Some(b"new"), b"new"),
            ReplacementFailureReconciliation::NewAuthoritative
        );
        assert_eq!(
            reconcile_replacement_failure(Some(b"old"), b"new"),
            ReplacementFailureReconciliation::NotNew
        );
        assert_eq!(
            reconcile_replacement_failure(None, b"new"),
            ReplacementFailureReconciliation::NotNew
        );
    }

    #[cfg(unix)]
    #[test]
    fn config_transaction_rejects_symlink_parent_and_replaces_final_link_itself() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let directory = std::env::temp_dir().join(format!(
            "rustdesk-config-nofollow-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        let real = directory.join("real");
        fs::create_dir_all(&real).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&real, fs::Permissions::from_mode(0o700)).unwrap();
        let linked_parent = directory.join("linked-parent");
        symlink(&real, &linked_parent).unwrap();
        assert!(store_config_bytes_transaction(
            &linked_parent.join("config.toml"),
            b"blocked",
            ConfigStoreFault::None,
        )
        .is_err());
        assert!(!real.join("config.toml").exists());

        let victim = directory.join("victim");
        fs::write(&victim, b"victim").unwrap();
        let final_path = real.join("config.toml");
        symlink(&victim, &final_path).unwrap();
        store_config_bytes_transaction(&final_path, b"committed", ConfigStoreFault::None).unwrap();
        assert_eq!(fs::read(&victim).unwrap(), b"victim");
        assert_eq!(fs::read(&final_path).unwrap(), b"committed");
        assert!(!fs::symlink_metadata(&final_path)
            .unwrap()
            .file_type()
            .is_symlink());

        fs::remove_dir_all(&directory).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn windows_precommit_failure_removes_credential_temp_file() {
        let directory = std::env::temp_dir().join(format!(
            "rustdesk-config-windows-cleanup-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        fs::create_dir(&directory).unwrap();
        let path = directory.join("credential.toml");
        assert!(store_config_bytes_transaction(
            &path,
            b"new-credential",
            ConfigStoreFault::BeforeReplace,
        )
        .is_err());
        assert!(!path.exists());
        assert_eq!(fs::read_dir(&directory).unwrap().count(), 0);
        fs::remove_dir(&directory).unwrap();
    }

    #[test]
    fn credential_generation_linearizes_authorization_before_rotation() {
        use std::sync::{
            atomic::{AtomicBool, Ordering},
            Arc, Barrier,
        };

        with_config_and_hard_settings(Config::default(), HashMap::new(), || {
            let old_storage =
                encode_permanent_password_encrypted_storage_from_h1(&[1u8; 32]).unwrap();
            let new_storage =
                encode_permanent_password_encrypted_storage_from_h1(&[2u8; 32]).unwrap();
            Config::set_permanent_password_storage_for_runtime(&old_storage, "salt").unwrap();
            let generation = Config::read_permanent_password_credential_snapshot().generation();

            let gate = Arc::new(Barrier::new(2));
            let authorized = Arc::new(AtomicBool::new(false));
            let auth_gate = Arc::clone(&gate);
            let auth_flag = Arc::clone(&authorized);
            let authorization = std::thread::spawn(move || {
                Config::with_current_permanent_password_generation(generation, || {
                    auth_gate.wait();
                    auth_gate.wait();
                    auth_flag.store(true, Ordering::Release);
                })
            });

            gate.wait();
            let rotation_done = Arc::new(AtomicBool::new(false));
            let rotation_flag = Arc::clone(&rotation_done);
            let rotation = std::thread::spawn(move || {
                Config::set_permanent_password_storage_for_runtime(&new_storage, "salt").unwrap();
                rotation_flag.store(true, Ordering::Release);
            });
            std::thread::sleep(Duration::from_millis(50));
            assert!(!rotation_done.load(Ordering::Acquire));
            gate.wait();

            assert!(authorization.join().unwrap().is_some());
            rotation.join().unwrap();
            assert!(authorized.load(Ordering::Acquire));
            assert!(rotation_done.load(Ordering::Acquire));
            assert!(
                Config::with_current_permanent_password_generation(generation, || ()).is_none()
            );
        });
    }

    #[test]
    fn windows_service_owned_root_derivation_is_explicit() {
        #[cfg(windows)]
        let program_data = Path::new(r"C:\ProgramData");
        #[cfg(not(windows))]
        let program_data = Path::new("/ProgramData");
        let root = windows_service_owned_config_root_from(program_data, "RustDesk").unwrap();
        assert_eq!(root, program_data.join("RustDesk").join("config"));
        assert!(windows_service_owned_config_root_from(program_data, "../bad").is_err());
        assert!(windows_service_owned_config_root_from(Path::new("relative"), "RustDesk").is_err());
    }

    #[test]
    fn test_malformed_preset_password_with_salt_is_not_usable() {
        for storage in ["01secret", "00not-a-valid-hash"] {
            let hard_settings = HashMap::from([
                ("password".to_owned(), storage.to_owned()),
                ("salt".to_owned(), "preset-salt".to_owned()),
            ]);

            with_config_and_hard_settings(Config::default(), hard_settings, || {
                assert_eq!(Config::get_effective_permanent_password_salt(), "");
                assert_eq!(
                    Config::get_local_permanent_password_storage_and_salt().1,
                    ""
                );
                assert!(!Config::has_permanent_password());
                assert!(!Config::is_using_preset_password());
            });
        }
    }

    #[test]
    fn test_validate_or_decrypt_keeps_plaintext_permanent_password_unchanged() {
        let mut cfg = Config::default();
        cfg.password = "p@ssw0rd".to_owned();
        cfg.salt = "".to_owned();
        Config::validate_or_decrypt_permanent_password_storage(&mut cfg).unwrap();
        assert_eq!(cfg.password, "p@ssw0rd");
        assert!(cfg.salt.is_empty());
    }

    #[test]
    fn test_validate_or_decrypt_decrypts_00_permanent_password_without_forcing_store() {
        let mut cfg = Config::default();
        let legacy_storage =
            encrypt_str_or_original("legacy-secret", PASSWORD_ENC_VERSION, ENCRYPT_MAX_LEN);
        cfg.password = legacy_storage;
        cfg.salt = "".to_owned();
        Config::validate_or_decrypt_permanent_password_storage(&mut cfg).unwrap();
        assert_eq!(cfg.password, "legacy-secret");
        assert!(cfg.salt.is_empty());
    }

    #[test]
    fn test_validate_or_decrypt_preserves_undecryptable_wellformed_00_storage() {
        // F3: a WELL-FORMED legacy `00` secretbox that fails to open is INDISTINGUISHABLE from a
        // transient machine-UUID read failure (macOS login window / Windows shutdown), so it MUST
        // be PRESERVED, never rejected — a store() coincident with such a blip must not
        // permanently wipe a possibly-valid credential. (Bit-rot lands here too, but preserving
        // an already-dead `00` is harmless: the fork authenticates from config.password_prs, and
        // an undecryptable credential still fails closed at the CPace boundary.)
        let legacy_storage =
            encrypt_str_or_original("legacy-secret", PASSWORD_ENC_VERSION, ENCRYPT_MAX_LEN);
        let mut payload = base64::decode(
            &legacy_storage.as_bytes()[PASSWORD_ENC_VERSION.len()..],
            base64::Variant::Original,
        )
        .unwrap();
        *payload.last_mut().unwrap() ^= 1; // flip a MAC bit: still well-formed, won't open

        let mut cfg = Config::default();
        cfg.password =
            PASSWORD_ENC_VERSION.to_owned() + &base64::encode(payload, base64::Variant::Original);
        cfg.salt = "salt123".to_owned();
        let original_password = cfg.password.clone();

        assert!(Config::validate_or_decrypt_permanent_password_storage(&mut cfg).is_ok());
        assert_eq!(
            cfg.password, original_password,
            "well-formed 00 blob preserved verbatim"
        );
        assert_eq!(cfg.salt, "salt123");
    }

    #[test]
    fn test_validate_or_decrypt_clears_malformed_00_storage() {
        // F3 complement: a `00`-prefixed value that is NOT a well-formed secretbox (decoded
        // payload shorter than a MAC) cannot decrypt under ANY machine-UUID, so it is definite
        // corruption, not a transient blip — rejected (→ cleared, fail closed).
        let mut cfg = Config::default();
        cfg.password =
            PASSWORD_ENC_VERSION.to_owned() + &base64::encode(b"short", base64::Variant::Original);
        cfg.salt = "salt123".to_owned();

        assert!(Config::validate_or_decrypt_permanent_password_storage(&mut cfg).is_err());
    }

    #[test]
    fn test_prepare_config_for_store_preserves_transient_00_credential() {
        // F3 end-to-end: prepare_config_for_store runs on EVERY store(); it must NOT clear a
        // well-formed-but-undecryptable `00` credential, else a store() (e.g. saving an unrelated
        // option) coincident with a transient machine-UUID failure would permanently wipe the
        // password, salt AND prs.
        let legacy_storage =
            encrypt_str_or_original("legacy-secret", PASSWORD_ENC_VERSION, ENCRYPT_MAX_LEN);
        let mut payload = base64::decode(
            &legacy_storage.as_bytes()[PASSWORD_ENC_VERSION.len()..],
            base64::Variant::Original,
        )
        .unwrap();
        *payload.last_mut().unwrap() ^= 1;
        let mut cfg = Config::default();
        cfg.password =
            PASSWORD_ENC_VERSION.to_owned() + &base64::encode(payload, base64::Variant::Original);
        cfg.salt = "salt123".to_owned();
        cfg.password_prs = "some-prs-storage".to_owned();
        let (p, s, prs) = (
            cfg.password.clone(),
            cfg.salt.clone(),
            cfg.password_prs.clone(),
        );

        Config::prepare_config_for_store(&mut cfg);

        assert_eq!(
            cfg.password, p,
            "a transient 00 credential must be preserved"
        );
        assert_eq!(cfg.salt, s);
        assert_eq!(
            cfg.password_prs, prs,
            "prs must not be wiped on a transient blip"
        );
    }

    #[test]
    fn test_prepare_config_for_store_clears_malformed_00_credential() {
        // F3 complement, end-to-end: a definitely-malformed (unrecoverable) `00` is cleared —
        // all three credential forms together (fail closed, no split-brain).
        let mut cfg = Config::default();
        cfg.password =
            PASSWORD_ENC_VERSION.to_owned() + &base64::encode(b"short", base64::Variant::Original);
        cfg.salt = "salt123".to_owned();
        cfg.password_prs = "some-prs-storage".to_owned();

        Config::prepare_config_for_store(&mut cfg);

        assert!(cfg.password.is_empty());
        assert!(cfg.salt.is_empty());
        assert!(cfg.password_prs.is_empty());
    }

    #[test]
    fn test_has_permanent_password_reflects_live_prs_not_stale_storage() {
        // F2 (coherence): `has_permanent_password` (the UI/IPC "is a permanent password set"
        // signal) MUST track the value the CPace auth boundary actually keys from — the live PRS
        // (config.password_prs) — not config.password. A password-set/prs-empty half-state (and an
        // undecryptable `01…` blob) refuses EVERY connection, so it must read as NOT set.
        let (storage, prs_storage) =
            derive_permanent_password_storages("correct horse battery staple").unwrap();

        // Fully provisioned: both at-rest forms present and decryptable → reads as set.
        let mut provisioned = Config::default();
        provisioned.password = storage.clone();
        provisioned.password_prs = prs_storage;
        provisioned.salt = "salt123".to_owned();
        with_config_and_hard_settings(provisioned, HashMap::new(), || {
            assert!(matches!(
                Config::read_permanent_password_prs(),
                PermanentPasswordPrsRead::Available(_)
            ));
            assert!(Config::has_permanent_password());
        });

        // Half-state: config.password present (and it decodes as a valid hash), but PRS empty —
        // the OLD storage-only signal reported "set" while the box refused every connection.
        let mut half = Config::default();
        half.password = storage;
        half.salt = "salt123".to_owned();
        with_config_and_hard_settings(half, HashMap::new(), || {
            assert_eq!(
                Config::read_permanent_password_prs(),
                PermanentPasswordPrsRead::Empty
            );
            assert!(!Config::has_permanent_password());
        });

        // Undecryptable current-format blob (transient machine-UUID failure): storage present but
        // neither form decrypts → reads as NOT set, and recovers to set once the UUID reads again.
        let mut opaque = Config::default();
        opaque.password = "01AAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned();
        opaque.password_prs = "01AAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned();
        opaque.salt = "salt123".to_owned();
        with_config_and_hard_settings(opaque, HashMap::new(), || {
            assert_eq!(
                Config::read_permanent_password_prs(),
                PermanentPasswordPrsRead::UndecryptableStorage
            );
            assert!(!Config::has_permanent_password());
        });
    }

    #[test]
    fn test_get_id_is_side_effect_free() {
        let mut config = Config::default();
        config.id.clear();
        config.enc_id.clear();

        with_config_and_hard_settings(config, HashMap::new(), || {
            assert_eq!(Config::get_id(), "");
            assert!(CONFIG.read().unwrap().id.is_empty());
        });
    }

    #[test]
    fn test_load_does_not_generate_id_for_empty_config() {
        let _lock = CONFIG_STATE_TEST_LOCK.lock().unwrap();
        let file = Config::file_("");
        let _file_guard = ConfigFileRestoreGuard::new(file.clone());
        fs::remove_file(&file).ok();

        let loaded = Config::load();

        assert!(loaded.id.is_empty());
        assert!(loaded.enc_id.is_empty());
        assert!(
            !file.exists(),
            "loading a fresh config must not store a generated ID"
        );
    }

    #[test]
    fn test_store_clears_empty_id_storage() {
        let _lock = CONFIG_STATE_TEST_LOCK.lock().unwrap();
        let file = Config::file_("");
        let _file_guard = ConfigFileRestoreGuard::new(file);
        let mut cfg = Config::default();
        cfg.enc_id = encrypt_str_or_original("123456789", PASSWORD_ENC_VERSION, ENCRYPT_MAX_LEN);

        cfg.store();

        let raw = Config::load_::<Config>("");
        assert!(raw.id.is_empty());
        assert!(raw.enc_id.is_empty());
    }

    #[test]
    fn test_get_salt_is_side_effect_free() {
        with_config_and_hard_settings(Config::default(), HashMap::new(), || {
            assert_eq!(Config::get_salt(), "");
            assert!(CONFIG.read().unwrap().salt.is_empty());
        });
    }

    #[test]
    fn test_load_reads_legacy_plaintext_id_without_storing() {
        let _lock = CONFIG_STATE_TEST_LOCK.lock().unwrap();
        let file = Config::file_("");
        let _file_guard = ConfigFileRestoreGuard::new(file);
        let mut raw = Config::default();
        raw.id = "123456789".to_owned();
        Config::store_(&raw, "");

        let loaded = Config::load();

        assert_eq!(loaded.id, "123456789");
        let stored = Config::load_::<Config>("");
        assert_eq!(stored.id, "123456789");
        assert!(stored.enc_id.is_empty());
    }

    fn unique_tmp_dir(tag: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let ts = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!(
            "rustdesk-loadpath-{tag}-{}-{ts}-{n}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[cfg(unix)]
    #[test]
    fn store_path_writes_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = unique_tmp_dir("mode600");
        let file = dir.join("config.toml");
        store_path(file.clone(), Config2::default()).unwrap();

        let mode = fs::metadata(&file).unwrap().permissions().mode() & 0o777;
        fs::remove_dir_all(&dir).ok();
        assert_eq!(mode, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn store_raw_config_bytes_writes_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = unique_tmp_dir("raw-mode600");
        let file = dir.join("raw");
        store_raw_config_bytes(file.clone(), b"secret").unwrap();

        let mode = fs::metadata(&file).unwrap().permissions().mode() & 0o777;
        let data = load_raw_config_bytes(&file).unwrap();
        fs::remove_dir_all(&dir).ok();
        assert_eq!(mode, 0o600);
        assert_eq!(data, b"secret");
    }

    #[test]
    fn store_raw_config_bytes_replaces_existing_file() {
        let dir = unique_tmp_dir("raw-replace");
        let file = dir.join("raw");
        store_raw_config_bytes(file.clone(), b"old").unwrap();
        store_raw_config_bytes(file.clone(), b"new").unwrap();

        let data = load_raw_config_bytes(&file).unwrap();
        fs::remove_dir_all(&dir).ok();
        assert_eq!(data, b"new");
    }

    #[test]
    fn raw_encrypted_json_load_failure_preserves_payload_for_recovery() {
        #[cfg(unix)]
        use std::os::unix::fs::PermissionsExt;

        let dir = unique_tmp_dir("raw-corrupt");
        let file = dir.join("ab");
        let corrupt_json = symmetric_crypt(&compress(b"not-json"), true).unwrap();
        store_raw_config_bytes(file.clone(), &corrupt_json).unwrap();
        #[cfg(unix)]
        fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();

        let err = load_encrypted_json_config::<Ab>(&file, "address book").unwrap_err();
        assert!(err.to_string().contains("Failed to parse address book"));
        preserve_raw_config_file(&file, "address book");

        assert!(!file.exists());
        let backups: Vec<PathBuf> = fs::read_dir(&dir)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .filter(|entry| {
                entry
                    .file_name()
                    .and_then(|name| name.to_str())
                    .map(|name| name.starts_with("ab.corrupt."))
                    .unwrap_or(false)
            })
            .collect();
        assert_eq!(backups.len(), 1);
        #[cfg(unix)]
        {
            let mode = fs::metadata(&backups[0]).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn windows_config_acl_sddl_is_protected_owner_system_only() {
        let user_sid = "S-1-5-21-1-2-3-1001";
        assert_eq!(
            windows_config_acl_sddl(user_sid, false),
            "D:P(A;;FA;;;SY)(A;;FA;;;S-1-5-21-1-2-3-1001)"
        );
        assert_eq!(
            windows_config_acl_sddl(user_sid, true),
            "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;S-1-5-21-1-2-3-1001)"
        );
        assert_eq!(
            windows_config_acl_sddl("S-1-5-18", true),
            "D:P(A;OICI;FA;;;SY)"
        );
    }

    #[test]
    fn test_load_path_first_run_returns_default_without_creating_file() {
        // F1: a NON-existent file is a genuine first run → default, and NOTHING is created.
        let dir = unique_tmp_dir("firstrun");
        let file = dir.join("absent.toml");
        let loaded: ConfigLoad<Config2> = load_path_with_status(file.clone());
        assert_eq!(loaded.value, Config2::default());
        assert_eq!(loaded.status, ConfigLoadStatus::NotFound);
        assert!(
            !file.exists(),
            "load_path must not create a file on first run"
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_load_path_valid_file_loads_unchanged() {
        // F1: a valid config round-trips unchanged (the happy path is untouched).
        let dir = unique_tmp_dir("valid");
        let file = dir.join("valid.toml");
        let mut original = Config2::default();
        original.options.insert("k".to_owned(), "v".to_owned());
        store_path(file.clone(), original.clone()).unwrap();
        let loaded: ConfigLoad<Config2> = load_path_with_status(file.clone());
        assert_eq!(loaded.value, original);
        assert_eq!(loaded.status, ConfigLoadStatus::Loaded);
        assert!(file.exists());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_load_path_present_but_corrupt_is_preserved_not_overwritten() {
        #[cfg(unix)]
        use std::os::unix::fs::PermissionsExt;

        // F1: a PRESENT-but-unparseable file is corruption → a fail-closed default is returned,
        // the exact corrupt bytes are PRESERVED aside for recovery, and the original path is
        // never overwritten by a default (it is vacated for a clean self-heal instead).
        let dir = unique_tmp_dir("corrupt");
        let file = dir.join("corrupt.toml");
        let corrupt_bytes = b"= = = this is not valid toml [[[".to_vec();
        fs::write(&file, &corrupt_bytes).unwrap();
        #[cfg(unix)]
        fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();

        let loaded: ConfigLoad<Config2> = load_path_with_status(file.clone());
        assert_eq!(
            loaded.value,
            Config2::default(),
            "a corrupt load yields a fail-closed default"
        );
        assert_eq!(loaded.status, ConfigLoadStatus::Corrupt);
        assert!(
            !file.exists(),
            "the corrupt file must be moved aside, not left in place to be overwritten"
        );
        let backup = fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok().map(|e| e.path()))
            .find(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .map(|n| n.contains(".corrupt."))
                    .unwrap_or(false)
            })
            .expect("a `.corrupt.<ts>` backup of the exact bytes must exist");
        assert_eq!(
            fs::read(&backup).unwrap(),
            corrupt_bytes,
            "the corrupt bytes are preserved verbatim for operator recovery"
        );
        #[cfg(unix)]
        {
            let mode = fs::metadata(&backup).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn preserved_config_hardening_rejects_symlink_targets() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let dir = unique_tmp_dir("recovery-symlink");
        let target = dir.join("target");
        let link = dir.join("link");
        fs::write(&target, b"secret").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o644)).unwrap();
        symlink(&target, &link).unwrap();

        assert!(harden_preserved_config_file(&link).is_err());
        let mode = fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        fs::remove_dir_all(&dir).ok();
        assert_eq!(mode, 0o644);
    }

    #[test]
    fn test_load_path_present_but_unreadable_is_transient_not_stale() {
        let dir = unique_tmp_dir("transient-read");
        let file = dir.join("peer.toml");
        fs::create_dir(&file).unwrap();

        let loaded: ConfigLoad<Config2> = load_path_with_status(file.clone());
        assert_eq!(loaded.value, Config2::default());
        assert_eq!(loaded.status, ConfigLoadStatus::TransientError);
        assert!(
            file.exists(),
            "a transient read failure must leave the original path available for recovery"
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn empty_peer_cleanup_requires_loaded_semantically_empty_config() {
        let empty = PeerConfig::default();
        assert!(should_remove_empty_peer_config(
            ConfigLoadStatus::Loaded,
            &empty
        ));
        assert!(!should_remove_empty_peer_config(
            ConfigLoadStatus::NotFound,
            &empty
        ));
        assert!(!should_remove_empty_peer_config(
            ConfigLoadStatus::Corrupt,
            &empty
        ));
        assert!(!should_remove_empty_peer_config(
            ConfigLoadStatus::TransientError,
            &empty
        ));

        let mut with_peer_prs = PeerConfig::default();
        with_peer_prs.password_prs = b"connect-equivalent".to_vec();
        assert!(!should_remove_empty_peer_config(
            ConfigLoadStatus::Loaded,
            &with_peer_prs
        ));
    }

    #[test]
    fn peer_store_drops_retired_rdp_credential_options() {
        let dir = unique_tmp_dir("rdp-credential-store");
        let file = dir.join("peer.toml");
        let mut config = PeerConfig::default();
        config
            .options
            .insert("rdp_username".to_owned(), "account".to_owned());
        config
            .options
            .insert("rdp_password".to_owned(), "secret".to_owned());
        config
            .options
            .insert("rdp_port".to_owned(), "3390".to_owned());

        PeerConfig::store_path_(&file, &config);

        let stored: PeerConfig = load_path(file);
        assert!(!stored.options.contains_key("rdp_username"));
        assert!(!stored.options.contains_key("rdp_password"));
        assert_eq!(
            stored.options.get("rdp_port").map(String::as_str),
            Some("3390")
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn peer_load_removes_and_rewrites_legacy_rdp_credential_options() {
        let dir = unique_tmp_dir("rdp-credential-load");
        let file = dir.join("peer.toml");
        let mut legacy = PeerConfig::default();
        legacy
            .options
            .insert("rdp_username".to_owned(), "account".to_owned());
        legacy
            .options
            .insert("rdp_password".to_owned(), "secret".to_owned());
        legacy
            .options
            .insert("rdp_port".to_owned(), "3390".to_owned());
        store_path(file.clone(), legacy).unwrap();

        let loaded = PeerConfig::load_path_with_status(file.clone(), None);
        assert_eq!(loaded.status, ConfigLoadStatus::Loaded);
        assert!(!loaded.value.options.contains_key("rdp_username"));
        assert!(!loaded.value.options.contains_key("rdp_password"));
        assert_eq!(
            loaded.value.options.get("rdp_port").map(String::as_str),
            Some("3390")
        );

        let rewritten: PeerConfig = load_path(file);
        assert!(!rewritten.options.contains_key("rdp_username"));
        assert!(!rewritten.options.contains_key("rdp_password"));
        assert_eq!(
            rewritten.options.get("rdp_port").map(String::as_str),
            Some("3390")
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn peer_cleanup_decision_is_bound_to_the_enumerated_path() {
        let _lock = CONFIG_STATE_TEST_LOCK.lock().unwrap();
        let id = "r_s11b4d_alias_cleanup";
        let canonical_path = PeerConfig::path(id);
        let _canonical_guard = ConfigFileRestoreGuard::new(canonical_path.clone());
        if let Some(parent) = canonical_path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        store_path(canonical_path, PeerConfig::default()).unwrap();

        let alias_dir = unique_tmp_dir("peer-alias-cleanup");
        let alias_path = alias_dir.join(format!(
            "base64_{}.toml",
            base64::encode(id, base64::Variant::Original)
        ));
        let mut alias_config = PeerConfig::default();
        alias_config.password_prs = b"connect-equivalent".to_vec();
        store_path(alias_path.clone(), alias_config).unwrap();

        let all = vec![(id.to_owned(), SystemTime::UNIX_EPOCH, alias_path.clone())];
        let (peers, next) = PeerConfig::batch_peers(&all, 0, None);

        assert!(peers.is_empty());
        assert_eq!(next, 1);
        assert!(
            alias_path.exists(),
            "peer cleanup must not delete an enumerated file based on a different canonical path load"
        );
        fs::remove_dir_all(&alias_dir).ok();
    }

    #[test]
    fn test_store_does_not_double_wrap_current_format_credential() {
        // F4: a well-formed but currently-undecryptable `01…` credential (a transient machine-UUID
        // failure) is already the current at-rest form and MUST be stored VERBATIM — never
        // re-wrapped in the legacy `00` envelope. Inspect the RAW on-disk storage
        // (Config::load_ does not decrypt) right after store(); it must be unchanged.
        let _lock = CONFIG_STATE_TEST_LOCK.lock().unwrap();
        let _file_guard = ConfigFileRestoreGuard::new(Config::file_(""));
        let opaque = "01AAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(); // 01-prefixed, non-decryptable
        let mut cfg = Config::default();
        cfg.id = "123456789".to_owned();
        cfg.password = opaque.clone();
        cfg.salt = "salt123".to_owned();
        cfg.store();
        let raw = Config::load_::<Config>("");
        assert_eq!(
            raw.password, opaque,
            "a 01-format credential must be stored verbatim (no spurious 00 double-wrap)"
        );
    }

    #[test]
    fn test_validate_or_decrypt_rejects_encrypted_hashed_permanent_password_without_salt() {
        let mut cfg = Config::default();
        let h1 = compute_permanent_password_h1("p@ssw0rd", "salt123");
        cfg.password = encode_permanent_password_encrypted_storage_from_h1(&h1).unwrap();
        let original_password = cfg.password.clone();

        assert!(Config::validate_or_decrypt_permanent_password_storage(&mut cfg).is_err());
        assert_eq!(cfg.password, original_password);
        assert!(cfg.salt.is_empty());
    }

    #[test]
    fn test_store_preserves_existing_enc_id() {
        let _lock = CONFIG_STATE_TEST_LOCK.lock().unwrap();
        let _file_guard = ConfigFileRestoreGuard::new(Config::file_(""));
        let mut cfg = Config::default();
        cfg.id = "123456789".to_owned();
        cfg.enc_id = encrypt_str_or_original(&cfg.id, PASSWORD_ENC_VERSION, ENCRYPT_MAX_LEN);
        let original_enc_id = cfg.enc_id.clone();

        cfg.store();

        let raw = Config::load_::<Config>("");
        assert!(raw.id.is_empty());
        assert_eq!(raw.enc_id, original_enc_id);
        assert_eq!(Config::load().id, "123456789");
    }

    #[test]
    fn test_store_does_not_rewrite_existing_enc_id() {
        let _lock = CONFIG_STATE_TEST_LOCK.lock().unwrap();
        let _file_guard = ConfigFileRestoreGuard::new(Config::file_(""));
        let original_id = "123456789";
        let updated_id = "987654321";
        let mut cfg = Config::default();
        cfg.id = updated_id.to_owned();
        let original_enc_id =
            encrypt_str_or_original(original_id, PASSWORD_ENC_VERSION, ENCRYPT_MAX_LEN);
        cfg.enc_id = original_enc_id.clone();

        cfg.store();

        let stored = Config::load_::<Config>("").enc_id;
        let (stored_id, encrypted, _) = decrypt_str_or_original(&stored, PASSWORD_ENC_VERSION);
        assert_eq!(stored, original_enc_id);
        assert!(encrypted);
        assert_eq!(stored_id, original_id);
        assert_eq!(Config::load().id, original_id);
    }

    #[test]
    fn test_validate_or_decrypt_keeps_plaintext_permanent_password_with_current_prefix_and_long_base64(
    ) {
        let mut cfg = Config::default();
        let plain = "01".to_owned() + &base64::encode([42u8; 24], base64::Variant::Original);
        cfg.password = plain.clone();
        cfg.salt = "".to_owned();

        Config::validate_or_decrypt_permanent_password_storage(&mut cfg).unwrap();
        assert_eq!(cfg.password, plain);
        assert!(cfg.salt.is_empty());
    }

    #[test]
    fn test_permanent_password_sync_treats_same_encrypted_hash_as_unchanged() {
        // R-S9 idempotency — the complement of sync_rebuilds_password_prs_from_storage:
        // re-syncing the credential already at rest is a no-op (returns `false` = unchanged),
        // so the daemon does not needlessly rewrite the config. config.password (the
        // encrypted-hash storage envelope) and config.password_prs (the live CPace PRS) are
        // the two at-rest forms of the SAME 32 PRS bytes and are always written together, so
        // the real steady state has BOTH present and consistent — that is what "unchanged"
        // requires. (Were password_prs missing or stale, the sync would instead REBUILD it
        // from the storage and report a change.) The at-rest ciphertext carries a random
        // nonce (symmetric_crypt), so the unchanged decision compares the DECRYPTED PRS, never
        // the unstable ciphertext bytes — this pins that.
        let (storage, prs_storage) = derive_permanent_password_storages("p@ssw0rd").unwrap();
        let salt = "salt123";
        let mut cfg = Config::default();
        cfg.password = storage.clone();
        cfg.password_prs = prs_storage;
        cfg.salt = salt.to_owned();

        assert!(
            !Config::apply_permanent_password_storage_for_sync(&mut cfg, &storage, salt).unwrap(),
            "re-syncing the identical already-stored credential must be a no-op (unchanged)"
        );
    }

    #[test]
    fn test_permanent_password_sync_stores_incoming_encrypted_hash_when_local_empty() {
        let salt = "salt123";
        let h1 = compute_permanent_password_h1("p@ssw0rd", salt);
        let incoming = encode_permanent_password_encrypted_storage_from_h1(&h1).unwrap();
        let mut cfg = Config::default();

        assert!(
            Config::apply_permanent_password_storage_for_sync(&mut cfg, &incoming, salt).unwrap()
        );
        assert_eq!(cfg.password, incoming);
        assert_eq!(cfg.salt, salt);
    }

    #[test]
    fn test_permanent_password_sync_rejects_non_current_storage_payloads() {
        let invalid_payload = vec![42u8; sodiumoxide::crypto::secretbox::MACBYTES + 1];
        let invalid_storage = PERMANENT_PASSWORD_ENC_VERSION.to_owned()
            + &base64::encode(invalid_payload, base64::Variant::Original);
        let encrypted_legacy_plaintext =
            encrypt_str_or_original("legacy-secret", PASSWORD_ENC_VERSION, ENCRYPT_MAX_LEN);

        let encrypted = crate::password_security::symmetric_crypt(b"not-a-hash", true).unwrap();
        let encrypted_non_hash = PERMANENT_PASSWORD_ENC_VERSION.to_owned()
            + &base64::encode(encrypted, base64::Variant::Original);
        for storage in [
            "00secret",
            &encrypted_legacy_plaintext,
            &invalid_storage,
            "01invalid",
            &encrypted_non_hash,
        ] {
            let mut cfg = Config::default();
            assert!(Config::apply_permanent_password_storage_for_sync(
                &mut cfg, storage, "salt123"
            )
            .is_err());
            assert!(cfg.password.is_empty());
            assert!(cfg.salt.is_empty());
        }

        let mut cfg = Config::default();
        cfg.password = invalid_storage.clone();
        cfg.salt = "salt123".to_owned();
        assert!(Config::apply_permanent_password_storage_for_sync(
            &mut cfg,
            &invalid_storage,
            "salt123"
        )
        .is_err());
        assert_eq!(cfg.password, invalid_storage);
        assert_eq!(cfg.salt, "salt123");
    }

    #[test]
    fn test_permanent_password_sync_rejects_non_empty_storage_without_salt() {
        let mut cfg = Config::default();
        let h1 = compute_permanent_password_h1("p@ssw0rd", "salt123");
        let incoming = encode_permanent_password_encrypted_storage_from_h1(&h1).unwrap();

        assert!(
            Config::apply_permanent_password_storage_for_sync(&mut cfg, &incoming, "").is_err()
        );
        assert!(cfg.password.is_empty());
        assert!(cfg.salt.is_empty());
    }

    #[test]
    fn test_permanent_password_sync_empty_storage_clears_existing_password() {
        let salt = "salt123";
        let h1 = compute_permanent_password_h1("p@ssw0rd", salt);
        let mut cfg = Config::default();
        cfg.password = encode_permanent_password_encrypted_storage_from_h1(&h1).unwrap();
        cfg.salt = salt.to_owned();

        assert!(Config::apply_permanent_password_storage_for_sync(&mut cfg, "", "").unwrap());
        assert!(cfg.password.is_empty());
        assert_eq!(cfg.salt, salt);
    }

    #[test]
    fn test_permanent_password_sync_empty_storage_uses_incoming_salt() {
        let old_salt = "old-salt";
        let h1 = compute_permanent_password_h1("p@ssw0rd", old_salt);
        let mut cfg = Config::default();
        cfg.password = encode_permanent_password_encrypted_storage_from_h1(&h1).unwrap();
        cfg.salt = old_salt.to_owned();

        assert!(
            Config::apply_permanent_password_storage_for_sync(&mut cfg, "", "new-salt").unwrap()
        );
        assert!(cfg.password.is_empty());
        assert_eq!(cfg.salt, "new-salt");
    }

    #[test]
    fn test_overwrite_settings() {
        DEFAULT_SETTINGS
            .write()
            .unwrap()
            .insert("b".to_string(), "a".to_string());
        DEFAULT_SETTINGS
            .write()
            .unwrap()
            .insert("c".to_string(), "a".to_string());
        CONFIG2
            .write()
            .unwrap()
            .options
            .insert("a".to_string(), "b".to_string());
        CONFIG2
            .write()
            .unwrap()
            .options
            .insert("b".to_string(), "b".to_string());
        OVERWRITE_SETTINGS
            .write()
            .unwrap()
            .insert("b".to_string(), "c".to_string());
        OVERWRITE_SETTINGS
            .write()
            .unwrap()
            .insert("c".to_string(), "f".to_string());
        OVERWRITE_SETTINGS
            .write()
            .unwrap()
            .insert("d".to_string(), "c".to_string());
        let mut res: HashMap<String, String> = Default::default();
        res.insert("b".to_owned(), "c".to_string());
        res.insert("d".to_owned(), "c".to_string());
        res.insert("c".to_owned(), "a".to_string());
        Config::purify_options(&mut res);
        assert!(res.len() == 0);
        res.insert("b".to_owned(), "c".to_string());
        res.insert("d".to_owned(), "c".to_string());
        res.insert("c".to_owned(), "a".to_string());
        res.insert("f".to_owned(), "a".to_string());
        Config::purify_options(&mut res);
        assert!(res.len() == 1);
        res.insert("b".to_owned(), "c".to_string());
        res.insert("d".to_owned(), "c".to_string());
        res.insert("c".to_owned(), "a".to_string());
        res.insert("f".to_owned(), "a".to_string());
        res.insert("e".to_owned(), "d".to_string());
        Config::purify_options(&mut res);
        assert!(res.len() == 2);
        res.insert("b".to_owned(), "c".to_string());
        res.insert("d".to_owned(), "c".to_string());
        res.insert("c".to_owned(), "a".to_string());
        res.insert("f".to_owned(), "a".to_string());
        res.insert("c".to_owned(), "d".to_string());
        res.insert("d".to_owned(), "cc".to_string());
        Config::purify_options(&mut res);
        DEFAULT_SETTINGS
            .write()
            .unwrap()
            .insert("f".to_string(), "c".to_string());
        Config::purify_options(&mut res);
        assert!(res.len() == 2);
        DEFAULT_SETTINGS
            .write()
            .unwrap()
            .insert("f".to_string(), "a".to_string());
        Config::purify_options(&mut res);
        assert!(res.len() == 1);
        let res = Config::get_options();
        assert!(res["a"] == "b");
        assert!(res["c"] == "f");
        assert!(res["b"] == "c");
        assert!(res["d"] == "c");
        assert!(Config::get_option("a") == "b");
        assert!(Config::get_option("c") == "f");
        assert!(Config::get_option("b") == "c");
        assert!(Config::get_option("d") == "c");
        DEFAULT_SETTINGS.write().unwrap().clear();
        OVERWRITE_SETTINGS.write().unwrap().clear();
        CONFIG2.write().unwrap().options.clear();

        DEFAULT_LOCAL_SETTINGS
            .write()
            .unwrap()
            .insert("b".to_string(), "a".to_string());
        DEFAULT_LOCAL_SETTINGS
            .write()
            .unwrap()
            .insert("c".to_string(), "a".to_string());
        LOCAL_CONFIG
            .write()
            .unwrap()
            .options
            .insert("a".to_string(), "b".to_string());
        LOCAL_CONFIG
            .write()
            .unwrap()
            .options
            .insert("b".to_string(), "b".to_string());
        OVERWRITE_LOCAL_SETTINGS
            .write()
            .unwrap()
            .insert("b".to_string(), "c".to_string());
        OVERWRITE_LOCAL_SETTINGS
            .write()
            .unwrap()
            .insert("d".to_string(), "c".to_string());
        assert!(LocalConfig::get_option("a") == "b");
        assert!(LocalConfig::get_option("c") == "a");
        assert!(LocalConfig::get_option("b") == "c");
        assert!(LocalConfig::get_option("d") == "c");
        DEFAULT_LOCAL_SETTINGS.write().unwrap().clear();
        OVERWRITE_LOCAL_SETTINGS.write().unwrap().clear();
        LOCAL_CONFIG.write().unwrap().options.clear();

        DEFAULT_DISPLAY_SETTINGS
            .write()
            .unwrap()
            .insert("b".to_string(), "a".to_string());
        DEFAULT_DISPLAY_SETTINGS
            .write()
            .unwrap()
            .insert("c".to_string(), "a".to_string());
        USER_DEFAULT_CONFIG
            .write()
            .unwrap()
            .0
            .options
            .insert("a".to_string(), "b".to_string());
        USER_DEFAULT_CONFIG
            .write()
            .unwrap()
            .0
            .options
            .insert("b".to_string(), "b".to_string());
        OVERWRITE_DISPLAY_SETTINGS
            .write()
            .unwrap()
            .insert("b".to_string(), "c".to_string());
        OVERWRITE_DISPLAY_SETTINGS
            .write()
            .unwrap()
            .insert("d".to_string(), "c".to_string());
        assert!(UserDefaultConfig::read("a") == "b");
        assert!(UserDefaultConfig::read("c") == "a");
        assert!(UserDefaultConfig::read("b") == "c");
        assert!(UserDefaultConfig::read("d") == "c");
        DEFAULT_DISPLAY_SETTINGS.write().unwrap().clear();
        OVERWRITE_DISPLAY_SETTINGS.write().unwrap().clear();
        LOCAL_CONFIG.write().unwrap().options.clear();
    }

    #[test]
    fn test_config_deserialize() {
        let wrong_type_str = r#"
        id = true
        enc_id = []
        password = 1
        salt = "123456"
        key_pair = {}
        "#;
        let cfg = toml::from_str::<Config>(wrong_type_str);
        assert_eq!(
            cfg,
            Ok(Config {
                salt: "123456".to_string(),
                ..Default::default()
            })
        );

        let wrong_field_str = r#"
        hello = "world"
        salt = "abc"
        "#;
        let cfg = toml::from_str::<Config>(wrong_field_str);
        assert_eq!(
            cfg,
            Ok(Config {
                salt: "abc".to_string(),
                ..Default::default()
            })
        );
    }

    #[test]
    fn test_peer_config_deserialize() {
        let default_peer_config = toml::from_str::<PeerConfig>("").unwrap();
        // test custom_resolution
        {
            let wrong_type_str = r#"
            view_style = "adaptive"
            scroll_style = "scrollbar"
            custom_resolutions = true
            "#;
            let mut cfg_to_compare = default_peer_config.clone();
            cfg_to_compare.view_style = "adaptive".to_string();
            cfg_to_compare.scroll_style = "scrollbar".to_string();
            let cfg = toml::from_str::<PeerConfig>(wrong_type_str);
            assert_eq!(cfg, Ok(cfg_to_compare), "Failed to test wrong_type_str");

            let wrong_type_str = r#"
            view_style = "adaptive"
            scroll_style = "scrollbar"
            [custom_resolutions.0]
            w = "1920"
            h = 1080
            "#;
            let mut cfg_to_compare = default_peer_config.clone();
            cfg_to_compare.view_style = "adaptive".to_string();
            cfg_to_compare.scroll_style = "scrollbar".to_string();
            let cfg = toml::from_str::<PeerConfig>(wrong_type_str);
            assert_eq!(cfg, Ok(cfg_to_compare), "Failed to test wrong_type_str");

            let wrong_field_str = r#"
            [custom_resolutions.0]
            w = 1920
            h = 1080
            hello = "world"
            [ui_flutter]
            "#;
            let mut cfg_to_compare = default_peer_config.clone();
            cfg_to_compare.custom_resolutions =
                HashMap::from([("0".to_string(), Resolution { w: 1920, h: 1080 })]);
            let cfg = toml::from_str::<PeerConfig>(wrong_field_str);
            assert_eq!(cfg, Ok(cfg_to_compare), "Failed to test wrong_field_str");
        }
    }

    #[test]
    fn test_store_load() {
        let peerconfig_id = "123456789";
        let cfg: PeerConfig = Default::default();
        cfg.store(&peerconfig_id);
        assert_eq!(PeerConfig::load(&peerconfig_id), cfg);

        #[cfg(not(windows))]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                // ignore file type information by masking with 0o777 (see https://stackoverflow.com/a/50045872)
                fs::metadata(PeerConfig::path(&peerconfig_id))
                    .expect("reading metadata failed")
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }

    #[test]
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn test_service_ipc_path_is_shared_across_uids() {
        const ROOT_UID: u32 = 0;
        const USER_UID: u32 = 1000;

        #[cfg(target_os = "linux")]
        let service_postfixes = ["_service", "_service_password", "_service_credential"];
        #[cfg(target_os = "macos")]
        let service_postfixes = ["_service", "_service_password"];

        for postfix in service_postfixes {
            assert!(is_service_ipc_postfix(postfix));
            let path_root = Config::ipc_path_for_uid(ROOT_UID, postfix);
            let path_user = Config::ipc_path_for_uid(USER_UID, postfix);
            assert_eq!(path_root, path_user);

            let app_name = APP_NAME.read().unwrap().clone();
            assert!(
                path_root.starts_with(&format!("/tmp/{app_name}-service/")),
                "unexpected service ipc path: {}",
                path_root
            );
        }

        let non_service_root = Config::ipc_path_for_uid(ROOT_UID, "");
        let non_service_user = Config::ipc_path_for_uid(USER_UID, "");
        assert_ne!(non_service_root, non_service_user);

        assert!(!is_service_ipc_postfix("_password"));
        let password_root = Config::ipc_path_for_uid(ROOT_UID, "_password");
        let password_user = Config::ipc_path_for_uid(USER_UID, "_password");
        assert_ne!(password_root, password_user);
    }
}
