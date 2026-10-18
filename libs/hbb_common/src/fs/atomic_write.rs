use std::{ffi::OsStr, io, path::Path};

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn destination(path: &Path) -> io::Result<(&Path, &OsStr)> {
    let name = path.file_name().ok_or_else(|| invalid("output path has no file name"))?;
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        if path.as_os_str().as_bytes().rsplit(|&b| b == b'/').next() != Some(name.as_bytes()) {
            return Err(invalid("output path must end with its file name"));
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        let original: Vec<_> = path.as_os_str().encode_wide().collect();
        let filename: Vec<_> = name.encode_wide().collect();
        if original.rsplit(|&c| c == b'/' as u16 || c == b'\\' as u16).next()
            != Some(filename.as_slice())
            || filename.last().is_some_and(|&c| c == b'.' as u16 || c == b' ' as u16)
        {
            return Err(invalid("output path must end with a Windows file name"));
        }
    }
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    Ok((parent, name))
}

fn temporary_name() -> io::Result<String> {
    use crate::rand::RngCore;
    let mut nonce = [0u8; 16];
    crate::rand::rngs::OsRng.try_fill_bytes(&mut nonce)
        .map_err(|error| io::Error::new(io::ErrorKind::Other, error))?;
    Ok(format!(".rustdesk-save-{}.tmp", crate::uuid::Uuid::from_bytes(nonce).simple()))
}

fn complete(primary: io::Result<()>, cleanup: io::Result<()>) -> io::Result<()> {
    match (primary, cleanup) {
        (Ok(()), result) | (result, Ok(())) => result,
        (Err(error), Err(cleanup)) => Err(io::Error::new(
            error.kind(),
            format!("{error}; temporary output cleanup failed: {cleanup}"),
        )),
    }
}

fn visible_error(error: io::Error) -> io::Error {
    io::Error::new(error.kind(), format!("output is visible, but publication finality is uncertain: {error}"))
}

/// Publish a complete user-selected output by replacing its directory entry.
/// The caller owns action authority. Directory links resolve only when acquiring the parent;
/// every subsequent operation uses that retained directory. Existing destination data is never
/// opened for writing. A publication error can have an uncertain outcome and is never retried.
pub fn write_user_file_atomically(path: &Path, data: &[u8]) -> io::Result<()> {
    let (parent, name) = destination(path)?;
    #[cfg(unix)]
    { unix::PendingOutput::create(parent, name)?.save(data) }
    #[cfg(windows)]
    { windows::PendingOutput::create(parent, name)?.save(data) }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (parent, name, data);
        Err(io::Error::new(io::ErrorKind::Unsupported, "atomic output is unavailable on this platform"))
    }
}

#[cfg(unix)]
mod unix {
    use super::*;
    use crate::libc;
    use std::{
        ffi::CString,
        fs::{File, OpenOptions},
        io::Write,
        os::unix::{ffi::OsStrExt, fs::OpenOptionsExt, io::{AsRawFd, FromRawFd}},
    };

    pub(super) struct PendingOutput {
        parent: File,
        temporary: CString,
        destination: CString,
        file: File,
        published: bool,
    }

    impl PendingOutput {
        pub(super) fn create(parent: &Path, name: &OsStr) -> io::Result<Self> {
            let destination = CString::new(name.as_bytes())
                .map_err(|_| invalid("output file name contains NUL"))?;
            let temporary = CString::new(temporary_name()?)
                .map_err(|_| invalid("temporary output name contains NUL"))?;
            if temporary == destination {
                return Err(invalid("temporary output name collides with its destination"));
            }
            let parent = OpenOptions::new().read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NONBLOCK | libc::O_NOCTTY)
                .open(parent)?;
            let fd = unsafe {
                libc::openat(
                    parent.as_raw_fd(), temporary.as_ptr(),
                    libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW
                        | libc::O_CLOEXEC | libc::O_NONBLOCK | libc::O_NOCTTY,
                    0o600 as libc::c_uint,
                )
            };
            if fd < 0 { return Err(io::Error::last_os_error()); }
            // Retain creation authority before any fallible metadata check.
            let file = unsafe { File::from_raw_fd(fd) };
            Ok(Self { parent, temporary, destination, file, published: false })
        }

        fn source_identity(&self) -> io::Result<libc::stat> {
            let opened = super::super::unix_fstat(&self.file)?;
            if !super::super::stat_is_regular(&opened) || opened.st_nlink != 1 {
                return Err(invalid("temporary output must be a regular file with one link"));
            }
            let named = super::super::unix_fstatat_no_follow(self.parent.as_raw_fd(), &self.temporary)?;
            super::super::unix_require_same_object(&opened, &named, "temporary output")?;
            Ok(opened)
        }

        fn write_and_publish(&mut self, data: &[u8]) -> io::Result<()> {
            let opened = self.source_identity()?;
            match super::super::unix_fstatat_no_follow(self.parent.as_raw_fd(), &self.destination) {
                Ok(target) if super::super::unix_same_object(&opened, &target) => {
                    return Err(invalid("temporary output aliases its destination"));
                }
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
            self.file.write_all(data)?;
            super::super::sync_recv_regular_file(&self.file)?;
            let opened = self.source_identity()?;
            if unsafe {
                libc::renameat(self.parent.as_raw_fd(), self.temporary.as_ptr(),
                    self.parent.as_raw_fd(), self.destination.as_ptr())
            } != 0 {
                let error = io::Error::last_os_error();
                return Err(io::Error::new(error.kind(), format!("output publication outcome is uncertain: {error}")));
            }
            self.published = true;
            let named = super::super::unix_fstatat_no_follow(self.parent.as_raw_fd(), &self.destination)
                .map_err(visible_error)?;
            super::super::unix_require_same_object(&opened, &named, "published output")
                .map_err(visible_error)?;
            super::super::sync_recv_directory(&self.parent).map_err(visible_error)?;
            #[cfg(any(target_os = "macos", target_os = "ios"))]
            super::super::sync_recv_regular_file(&self.file).map_err(visible_error)?;
            Ok(())
        }

        fn retire_unpublished(&self) -> io::Result<()> {
            if super::super::unix_fstat(&self.file)?.st_nlink == 0 {
                return super::super::sync_recv_directory(&self.parent);
            }
            self.source_identity()?;
            if unsafe { libc::unlinkat(self.parent.as_raw_fd(), self.temporary.as_ptr(), 0) } != 0 {
                return Err(io::Error::last_os_error());
            }
            if super::super::unix_fstat(&self.file)?.st_nlink != 0 {
                return Err(invalid("temporary output retirement is uncertain"));
            }
            super::super::sync_recv_directory(&self.parent)
        }

        fn finish(self, result: io::Result<()>) -> io::Result<()> {
            let cleanup = if self.published { Ok(()) } else { self.retire_unpublished() };
            complete(result, cleanup)
        }

        pub(super) fn save(mut self, data: &[u8]) -> io::Result<()> {
            let result = self.write_and_publish(data);
            self.finish(result)
        }
    }

    #[cfg(all(test, target_os = "linux"))]
    mod tests {
        use super::*;
        use std::{os::unix::fs::{symlink, MetadataExt}, path::PathBuf};

        struct Fixture(PathBuf);
        impl Fixture {
            fn new() -> Self {
                let path = std::env::temp_dir().join(format!("atomic-output-{}", crate::uuid::Uuid::new_v4()));
                std::fs::create_dir(&path).unwrap();
                Self(path)
            }
        }
        impl Drop for Fixture {
            fn drop(&mut self) { std::fs::remove_dir_all(&self.0).unwrap(); }
        }

        #[test]
        fn retained_parent_cannot_be_redirected_by_a_replaced_path() {
            let fixture = Fixture::new();
            let chosen = fixture.0.join("chosen");
            let moved = fixture.0.join("retained");
            let decoy = fixture.0.join("decoy");
            std::fs::create_dir(&chosen).unwrap();
            std::fs::create_dir(&decoy).unwrap();
            std::fs::write(chosen.join("image.png"), b"original").unwrap();
            std::fs::write(decoy.join("image.png"), b"decoy").unwrap();
            let pending = PendingOutput::create(&chosen, OsStr::new("image.png")).unwrap();
            std::fs::rename(&chosen, &moved).unwrap();
            symlink(&decoy, &chosen).unwrap();
            pending.save(b"new image").unwrap();
            assert_eq!(std::fs::read(moved.join("image.png")).unwrap(), b"new image");
            assert_eq!(std::fs::read(decoy.join("image.png")).unwrap(), b"decoy");
            assert_eq!(std::fs::read_dir(&moved).unwrap().count(), 1);
        }

        #[test]
        fn replaced_temporary_name_is_refused_without_removing_foreign_data() {
            let fixture = Fixture::new();
            let selected = fixture.0.join("image.png");
            std::fs::write(&selected, b"original").unwrap();
            let pending = PendingOutput::create(&fixture.0, OsStr::new("image.png")).unwrap();
            let temporary = fixture.0.join(OsStr::from_bytes(pending.temporary.as_bytes()));
            let moved = fixture.0.join("moved");
            std::fs::rename(&temporary, &moved).unwrap();
            std::fs::write(&temporary, b"foreign").unwrap();
            assert!(pending.save(b"must not be written").is_err());
            assert_eq!(std::fs::read(&selected).unwrap(), b"original");
            assert_eq!(std::fs::read(&temporary).unwrap(), b"foreign");
            assert!(std::fs::read(&moved).unwrap().is_empty());
        }

        #[test]
        fn failed_publication_preserves_directory_and_cleans_temporary_file() {
            let fixture = Fixture::new();
            let selected = fixture.0.join("directory");
            std::fs::create_dir(&selected).unwrap();
            std::fs::write(selected.join("sentinel"), b"untouched").unwrap();
            assert!(write_user_file_atomically(&selected, b"new image").is_err());
            assert_eq!(std::fs::read(selected.join("sentinel")).unwrap(), b"untouched");
            assert_eq!(std::fs::read_dir(&fixture.0).unwrap().count(), 1);
        }

        #[test]
        fn normal_paths_and_directory_links_preserve_bytes_and_requested_mode() {
            let fixture = Fixture::new();
            let linked = fixture.0.join("linked");
            symlink(&fixture.0, &linked).unwrap();
            let filename = OsStr::from_bytes(b"image-\xff.png");
            let selected = linked.join(filename);
            write_user_file_atomically(&selected, b"first").unwrap();
            write_user_file_atomically(&selected, b"replacement").unwrap();
            assert_eq!(std::fs::read(&selected).unwrap(), b"replacement");
            assert_eq!(std::fs::metadata(&selected).unwrap().mode() & 0o077, 0);
            assert_eq!(std::fs::read_dir(&fixture.0).unwrap().count(), 2);
            assert!(write_user_file_atomically(&selected.join(""), b"bad").is_err());
            assert_eq!(std::fs::read(&selected).unwrap(), b"replacement");
            let depth = std::env::current_dir().unwrap().components()
                .filter(|c| matches!(c, std::path::Component::Normal(_))).count();
            let relative = PathBuf::from("../".repeat(depth))
                .join(fixture.0.strip_prefix("/").unwrap()).join("relative.png");
            write_user_file_atomically(&relative, b"relative").unwrap();
            assert_eq!(std::fs::read(fixture.0.join("relative.png")).unwrap(), b"relative");
            assert_eq!(std::fs::read_dir(&fixture.0).unwrap().count(), 3);
        }

        #[test]
        fn late_error_never_removes_a_published_file() {
            let fixture = Fixture::new();
            let selected = fixture.0.join("image.png");
            std::fs::write(&selected, b"original").unwrap();
            let mut pending = PendingOutput::create(&fixture.0, OsStr::new("image.png")).unwrap();
            pending.write_and_publish(b"published").unwrap();
            assert!(pending.finish(Err(io::Error::new(io::ErrorKind::Other, "injected late failure"))).is_err());
            assert_eq!(std::fs::read(&selected).unwrap(), b"published");
            assert_eq!(std::fs::read_dir(&fixture.0).unwrap().count(), 1);
        }
    }
}

#[cfg(windows)]
mod windows {
    use super::*;
    use super::super::nt_nofollow;
    use ntapi::ntioapi::{FILE_CREATE, FILE_NON_DIRECTORY_FILE, FILE_OPEN};
    use std::{
        fs::{File, OpenOptions},
        io::Write,
        os::windows::{ffi::OsStrExt, fs::OpenOptionsExt, io::AsRawHandle},
    };
    use winapi::{
        shared::ntdef::HANDLE,
        um::{
            fileapi::{GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION},
            winbase::FILE_FLAG_BACKUP_SEMANTICS,
            winnt::{
                DELETE, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
                FILE_GENERIC_WRITE, FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ,
                FILE_SHARE_WRITE, FILE_TRAVERSE, SYNCHRONIZE,
            },
        },
    };

    const SHARE_ALL: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;

    fn file_name(name: &OsStr) -> io::Result<Vec<u16>> {
        let wide: Vec<u16> = name.encode_wide().collect();
        if wide.is_empty() || wide.iter().any(|&c| c == 0 || c == b'/' as u16 || c == b'\\' as u16 || c == b':' as u16) {
            return Err(invalid("output requires one ordinary file name"));
        }
        let mut stem: Vec<_> = wide.iter().copied().take_while(|&c| c != b'.' as u16)
            .map(|c| if (b'a' as u16..=b'z' as u16).contains(&c) { c - 32 } else { c })
            .collect();
        while stem.last() == Some(&(b' ' as u16)) { stem.pop(); }
        let reserved = ["CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"]
            .iter().any(|s| stem.iter().copied().eq(s.encode_utf16()));
        let device_port = stem.len() == 4
            && ["COM", "LPT"].iter().any(|s| stem[..3].iter().copied().eq(s.encode_utf16()))
            && matches!(stem[3], 49..=57 | 178 | 179 | 185);
        if reserved || device_port {
            return Err(invalid("output file name is a reserved Windows device"));
        }
        Ok(wide)
    }

    pub(super) struct PendingOutput {
        parent: File,
        destination: Vec<u16>,
        file: File,
        published: bool,
    }

    impl PendingOutput {
        pub(super) fn create(parent: &Path, name: &OsStr) -> io::Result<Self> {
            let destination = file_name(name)?;
            let temporary = file_name(OsStr::new(&temporary_name()?))?;
            if temporary == destination {
                return Err(invalid("temporary output name collides with its destination"));
            }
            let parent = OpenOptions::new()
                .access_mode(FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | FILE_TRAVERSE | SYNCHRONIZE)
                .share_mode(SHARE_ALL)
                .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
                .open(parent)?;
            if !parent.metadata()?.is_dir() {
                return Err(invalid("output parent is not a directory"));
            }
            let owned = unsafe {
                nt_nofollow::nt_open_at_raw(
                    parent.as_raw_handle() as HANDLE, &temporary,
                    FILE_GENERIC_WRITE | DELETE, FILE_CREATE, FILE_NON_DIRECTORY_FILE, 0,
                )?
            };
            Ok(Self { parent, destination, file: File::from(owned), published: false })
        }

        fn validate_source(&self) -> io::Result<()> {
            let attributes = unsafe { nt_nofollow::nt_attributes(self.file.as_raw_handle() as HANDLE)? };
            if attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
                return Err(invalid("temporary output is not a regular file"));
            }
            let mut information: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
            if unsafe { GetFileInformationByHandle(self.file.as_raw_handle() as HANDLE, &mut information) } == 0 {
                return Err(io::Error::last_os_error());
            }
            if information.nNumberOfLinks != 1 {
                return Err(invalid("temporary output must have one filesystem link"));
            }
            Ok(())
        }

        fn write_and_publish(&mut self, data: &[u8]) -> io::Result<()> {
            self.validate_source()?;
            let target = unsafe {
                nt_nofollow::nt_open_at_raw(
                    self.parent.as_raw_handle() as HANDLE, &self.destination,
                    FILE_READ_ATTRIBUTES, FILE_OPEN, FILE_NON_DIRECTORY_FILE, SHARE_ALL,
                )
            };
            match target {
                Ok(target) => {
                    if nt_nofollow::nt_file_identity(target.as_raw_handle() as HANDLE)?
                        == nt_nofollow::nt_file_identity(self.file.as_raw_handle() as HANDLE)?
                    {
                        return Err(invalid("temporary output aliases its destination"));
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
            self.file.write_all(data)?;
            self.file.sync_all()?;
            self.validate_source()?;
            unsafe {
                nt_nofollow::nt_rename_at(
                    self.file.as_raw_handle() as HANDLE, self.parent.as_raw_handle() as HANDLE,
                    &self.destination, true,
                ).map_err(|error| io::Error::new(error.kind(),
                    format!("output publication outcome is uncertain: {error}")))?
            };
            self.published = true;
            self.file.sync_all().map_err(visible_error)
        }

        pub(super) fn save(mut self, data: &[u8]) -> io::Result<()> {
            let result = self.write_and_publish(data);
            let cleanup = if self.published { Ok(()) }
                else { nt_nofollow::delete_open_recv_file(&self.file) };
            complete(result, cleanup)
        }
    }
}
