#[cfg(windows)]
use std::os::windows::prelude::*;
use std::{
    fmt::{Debug, Display},
    io::Cursor,
    path::{Path, PathBuf},
    sync::atomic::{AtomicI32, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde_derive::{Deserialize, Serialize};
use serde_json::json;
use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt, BufStream as TokioBufStream},
};

use crate::{anyhow::anyhow, bail, get_version_number, message_proto::*, ResultType, Stream};
// https://doc.rust-lang.org/std/os/windows/fs/trait.MetadataExt.html
use crate::{
    compress::{compress, peer_decompress},
    config::Config,
};

static NEXT_JOB_ID: AtomicI32 = AtomicI32::new(1);

pub const DEFAULT_FILE_TRANSFER_MAX_FILES: usize = 10_000;
pub const MAX_FILE_ENUM_DIRS: usize = DEFAULT_FILE_TRANSFER_MAX_FILES;
pub const MAX_FILE_ENUM_DEPTH: usize = 64;
pub const MAX_FILE_ENUM_SERIALIZED_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_ACTIVE_FILE_TRANSFER_READ_JOBS_PER_CONN: usize = 32;
pub const MAX_ACTIVE_FILE_TRANSFER_WRITE_JOBS_PER_CONN: usize = 32;
const FILE_ENUMERATION_BUDGET_EXCEEDED: &str = "file enumeration budget exceeded";

#[derive(Clone, Copy, Debug)]
pub struct FileEnumerationBudget {
    pub max_entries: usize,
    pub max_dirs: usize,
    pub max_depth: usize,
    pub max_serialized_bytes: usize,
}

impl FileEnumerationBudget {
    pub fn for_max_entries(max_entries: usize) -> Self {
        let max_entries = max_entries.max(1);
        Self {
            max_entries,
            max_dirs: MAX_FILE_ENUM_DIRS.min(max_entries).max(1),
            max_depth: MAX_FILE_ENUM_DEPTH,
            max_serialized_bytes: MAX_FILE_ENUM_SERIALIZED_BYTES,
        }
    }

    fn unbounded_for_local_use() -> Self {
        Self {
            max_entries: usize::MAX,
            max_dirs: usize::MAX,
            max_depth: usize::MAX,
            max_serialized_bytes: usize::MAX,
        }
    }
}

#[derive(Default)]
struct FileEnumerationUsage {
    entries: usize,
    dirs: usize,
    approx_serialized_bytes: usize,
}

impl FileEnumerationUsage {
    fn enter_dir(&mut self, depth: usize, budget: FileEnumerationBudget) -> ResultType<()> {
        if depth > budget.max_depth {
            bail!(
                "{}: depth {} exceeds limit {}",
                FILE_ENUMERATION_BUDGET_EXCEEDED,
                depth,
                budget.max_depth
            );
        }
        if self.dirs >= budget.max_dirs {
            bail!(
                "{}: directories exceed limit {}",
                FILE_ENUMERATION_BUDGET_EXCEEDED,
                budget.max_dirs
            );
        }
        self.dirs += 1;
        Ok(())
    }

    fn push_entry(&mut self, name: &str, budget: FileEnumerationBudget) -> ResultType<()> {
        if self.entries >= budget.max_entries {
            bail!(
                "{}: entries exceed limit {}",
                FILE_ENUMERATION_BUDGET_EXCEEDED,
                budget.max_entries
            );
        }
        let entry_bytes = 128usize.saturating_add(name.len());
        let next_bytes = self
            .approx_serialized_bytes
            .checked_add(entry_bytes)
            .ok_or_else(|| anyhow!("file enumeration budget byte counter overflow"))?;
        if next_bytes > budget.max_serialized_bytes {
            bail!(
                "{}: approx serialized bytes {} exceed limit {}",
                FILE_ENUMERATION_BUDGET_EXCEEDED,
                next_bytes,
                budget.max_serialized_bytes
            );
        }
        self.entries += 1;
        self.approx_serialized_bytes = next_bytes;
        Ok(())
    }
}

fn is_file_enumeration_budget_error(err: &anyhow::Error) -> bool {
    err.to_string().contains(FILE_ENUMERATION_BUDGET_EXCEEDED)
}

pub fn get_next_job_id() -> i32 {
    NEXT_JOB_ID.fetch_add(1, Ordering::SeqCst)
}

pub fn update_next_job_id(id: i32) {
    NEXT_JOB_ID.store(id, Ordering::SeqCst);
}

pub fn read_dir(path: &Path, include_hidden: bool) -> ResultType<FileDirectory> {
    read_dir_with_budget(
        path,
        include_hidden,
        FileEnumerationBudget::unbounded_for_local_use(),
    )
}

pub fn read_dir_with_budget(
    path: &Path,
    include_hidden: bool,
    budget: FileEnumerationBudget,
) -> ResultType<FileDirectory> {
    let mut usage = FileEnumerationUsage::default();
    read_dir_with_usage(path, include_hidden, budget, &mut usage, 0)
}

fn read_dir_with_usage(
    path: &Path,
    include_hidden: bool,
    budget: FileEnumerationBudget,
    usage: &mut FileEnumerationUsage,
    depth: usize,
) -> ResultType<FileDirectory> {
    usage.enter_dir(depth, budget)?;
    let mut dir = FileDirectory {
        path: get_string(path),
        ..Default::default()
    };
    #[cfg(windows)]
    if "/" == &get_string(path) {
        let drives = unsafe { winapi::um::fileapi::GetLogicalDrives() };
        for i in 0..32 {
            if drives & (1 << i) != 0 {
                let name = format!(
                    "{}:",
                    std::char::from_u32('A' as u32 + i as u32).unwrap_or('A')
                );
                usage.push_entry(&name, budget)?;
                dir.entries.push(FileEntry {
                    name,
                    entry_type: FileType::DirDrive.into(),
                    ..Default::default()
                });
            }
        }
        return Ok(dir);
    }
    for entry in path.read_dir()?.flatten() {
        let p = entry.path();
        let name = p
            .file_name()
            .map(|p| p.to_str().unwrap_or(""))
            .unwrap_or("")
            .to_owned();
        if name.is_empty() {
            continue;
        }
        let mut is_hidden = false;
        let meta;
        if let Ok(tmp) = std::fs::symlink_metadata(&p) {
            meta = tmp;
        } else {
            continue;
        }
        // docs.microsoft.com/en-us/windows/win32/fileio/file-attribute-constants
        #[cfg(windows)]
        if meta.file_attributes() & 0x2 != 0 {
            is_hidden = true;
        }
        #[cfg(not(windows))]
        if name.find('.').unwrap_or(usize::MAX) == 0 {
            is_hidden = true;
        }
        if is_hidden && !include_hidden {
            continue;
        }
        let (entry_type, size) = {
            if p.is_dir() {
                if meta.file_type().is_symlink() {
                    (FileType::DirLink.into(), 0)
                } else {
                    (FileType::Dir.into(), 0)
                }
            } else if meta.file_type().is_symlink() {
                (FileType::FileLink.into(), 0)
            } else {
                (FileType::File.into(), meta.len())
            }
        };
        let modified_time = meta
            .modified()
            .map(|x| {
                x.duration_since(std::time::SystemTime::UNIX_EPOCH)
                    .map(|x| x.as_secs())
                    .unwrap_or(0)
            })
            .unwrap_or(0);
        let name = get_file_name(&p);
        usage.push_entry(&name, budget)?;
        dir.entries.push(FileEntry {
            name,
            entry_type,
            is_hidden,
            size,
            modified_time,
            ..Default::default()
        });
    }
    Ok(dir)
}

#[inline]
pub fn get_file_name(p: &Path) -> String {
    p.file_name()
        .map(|p| p.to_str().unwrap_or(""))
        .unwrap_or("")
        .to_owned()
}

#[inline]
pub fn get_string(path: &Path) -> String {
    path.to_str().unwrap_or("").to_owned()
}

#[inline]
pub fn get_path(path: &str) -> PathBuf {
    Path::new(path).to_path_buf()
}

#[inline]
pub fn get_home_as_string() -> String {
    get_string(&Config::get_home())
}

fn read_dir_recursive(
    path: &Path,
    prefix: &Path,
    include_hidden: bool,
) -> ResultType<Vec<FileEntry>> {
    read_dir_recursive_with_budget(
        path,
        prefix,
        include_hidden,
        FileEnumerationBudget::unbounded_for_local_use(),
        &mut FileEnumerationUsage::default(),
        0,
    )
}

fn read_dir_recursive_with_budget(
    path: &Path,
    prefix: &Path,
    include_hidden: bool,
    budget: FileEnumerationBudget,
    usage: &mut FileEnumerationUsage,
    depth: usize,
) -> ResultType<Vec<FileEntry>> {
    let mut files = Vec::new();
    if path.is_dir() {
        // to-do: symbol link handling, cp the link rather than the content
        // to-do: file mode, for unix
        let fd = read_dir_with_usage(path, include_hidden, budget, usage, depth)?;
        for entry in fd.entries.iter() {
            match entry.entry_type.enum_value() {
                Ok(FileType::File) => {
                    let mut entry = entry.clone();
                    entry.name = get_string(&prefix.join(entry.name));
                    files.push(entry);
                }
                Ok(FileType::Dir) => {
                    let child_depth = depth
                        .checked_add(1)
                        .ok_or_else(|| anyhow!("file enumeration depth counter overflow"))?;
                    match read_dir_recursive_with_budget(
                        &path.join(&entry.name),
                        &prefix.join(&entry.name),
                        include_hidden,
                        budget,
                        usage,
                        child_depth,
                    ) {
                        Ok(mut tmp) => {
                            for entry in tmp.drain(0..) {
                                files.push(entry);
                            }
                        }
                        Err(err) => {
                            if is_file_enumeration_budget_error(&err) {
                                return Err(err);
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        Ok(files)
    } else if path.is_file() {
        usage.push_entry(&get_file_name(path), budget)?;
        let (size, modified_time) = if let Ok(meta) = std::fs::metadata(path) {
            (
                meta.len(),
                meta.modified()
                    .map(|x| {
                        x.duration_since(std::time::SystemTime::UNIX_EPOCH)
                            .map(|x| x.as_secs())
                            .unwrap_or(0)
                    })
                    .unwrap_or(0),
            )
        } else {
            (0, 0)
        };
        files.push(FileEntry {
            entry_type: FileType::File.into(),
            size,
            modified_time,
            ..Default::default()
        });
        Ok(files)
    } else {
        bail!("Not exists");
    }
}

pub fn get_recursive_files(path: &str, include_hidden: bool) -> ResultType<Vec<FileEntry>> {
    read_dir_recursive(&get_path(path), &get_path(""), include_hidden)
}

pub fn get_recursive_files_with_budget(
    path: &str,
    include_hidden: bool,
    budget: FileEnumerationBudget,
) -> ResultType<Vec<FileEntry>> {
    let mut usage = FileEnumerationUsage::default();
    read_dir_recursive_with_budget(
        &get_path(path),
        &get_path(""),
        include_hidden,
        budget,
        &mut usage,
        0,
    )
}

fn read_empty_dirs_recursive(
    path: &Path,
    prefix: &Path,
    include_hidden: bool,
) -> ResultType<Vec<FileDirectory>> {
    read_empty_dirs_recursive_with_budget(
        path,
        prefix,
        include_hidden,
        FileEnumerationBudget::unbounded_for_local_use(),
        &mut FileEnumerationUsage::default(),
        0,
    )
}

fn read_empty_dirs_recursive_with_budget(
    path: &Path,
    prefix: &Path,
    include_hidden: bool,
    budget: FileEnumerationBudget,
    usage: &mut FileEnumerationUsage,
    depth: usize,
) -> ResultType<Vec<FileDirectory>> {
    let mut dirs = Vec::new();
    if path.is_dir() {
        // to-do: symbol link handling, cp the link rather than the content
        // to-do: file mode, for unix
        let fd = read_dir_with_usage(path, include_hidden, budget, usage, depth)?;
        if fd.entries.is_empty() {
            dirs.push(fd);
        } else {
            for entry in fd.entries.iter() {
                match entry.entry_type.enum_value() {
                    Ok(FileType::Dir) => {
                        let child_depth = depth
                            .checked_add(1)
                            .ok_or_else(|| anyhow!("file enumeration depth counter overflow"))?;
                        match read_empty_dirs_recursive_with_budget(
                            &path.join(&entry.name),
                            &prefix.join(&entry.name),
                            include_hidden,
                            budget,
                            usage,
                            child_depth,
                        ) {
                            Ok(mut tmp) => {
                                for entry in tmp.drain(0..) {
                                    dirs.push(entry);
                                }
                            }
                            Err(err) => {
                                if is_file_enumeration_budget_error(&err) {
                                    return Err(err);
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        Ok(dirs)
    } else if path.is_file() {
        Ok(dirs)
    } else {
        bail!("Not exists");
    }
}

pub fn get_empty_dirs_recursive(
    path: &str,
    include_hidden: bool,
) -> ResultType<Vec<FileDirectory>> {
    read_empty_dirs_recursive(&get_path(path), &get_path(""), include_hidden)
}

pub fn get_empty_dirs_recursive_with_budget(
    path: &str,
    include_hidden: bool,
    budget: FileEnumerationBudget,
) -> ResultType<Vec<FileDirectory>> {
    let mut usage = FileEnumerationUsage::default();
    read_empty_dirs_recursive_with_budget(
        &get_path(path),
        &get_path(""),
        include_hidden,
        budget,
        &mut usage,
        0,
    )
}

#[inline]
pub fn is_file_exists(file_path: &str) -> bool {
    return Path::new(file_path).exists();
}

#[inline]
pub fn can_enable_overwrite_detection(version: i64) -> bool {
    version >= get_version_number("1.1.10")
}

#[repr(i32)]
#[derive(Copy, Clone, Serialize, Debug, PartialEq)]
pub enum JobType {
    Generic = 0,
    Printer = 1,
}

impl Default for JobType {
    fn default() -> Self {
        JobType::Generic
    }
}

impl From<JobType> for file_transfer_send_request::FileType {
    fn from(t: JobType) -> Self {
        match t {
            JobType::Generic => file_transfer_send_request::FileType::Generic,
            JobType::Printer => file_transfer_send_request::FileType::Printer,
        }
    }
}

impl From<i32> for JobType {
    fn from(value: i32) -> Self {
        match value {
            0 => JobType::Generic,
            1 => JobType::Printer,
            _ => JobType::Generic,
        }
    }
}

impl Into<i32> for JobType {
    fn into(self) -> i32 {
        self as i32
    }
}

impl JobType {
    pub fn from_proto(t: ::protobuf::EnumOrUnknown<file_transfer_send_request::FileType>) -> Self {
        match t.enum_value() {
            Ok(file_transfer_send_request::FileType::Generic) => JobType::Generic,
            Ok(file_transfer_send_request::FileType::Printer) => JobType::Printer,
            _ => JobType::Generic,
        }
    }
}

#[derive(Debug)]
pub enum DataSource {
    FilePath(PathBuf),
    MemoryCursor(Cursor<Vec<u8>>),
}

impl Default for DataSource {
    fn default() -> Self {
        DataSource::FilePath(PathBuf::new())
    }
}

impl serde::Serialize for DataSource {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            DataSource::FilePath(p) => serializer.serialize_str(p.to_str().unwrap_or("")),
            DataSource::MemoryCursor(_) => serializer.serialize_str(""),
        }
    }
}

impl Display for DataSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DataSource::FilePath(p) => write!(f, "File: {}", p.to_string_lossy().to_string()),
            DataSource::MemoryCursor(_) => write!(f, "Bytes"),
        }
    }
}

impl DataSource {
    fn to_meta(&self) -> String {
        match self {
            DataSource::FilePath(p) => p.to_string_lossy().to_string(),
            DataSource::MemoryCursor(_) => "".to_string(),
        }
    }
}

enum DataStream {
    FileStream(File),
    BufStream(TokioBufStream<Cursor<Vec<u8>>>),
}

impl Debug for DataStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DataStream::FileStream(fs) => write!(f, "{:?}", fs),
            DataStream::BufStream(_) => write!(f, "BufStream"),
        }
    }
}

impl DataStream {
    async fn write_all(&mut self, buf: &[u8]) -> ResultType<()> {
        match self {
            DataStream::FileStream(fs) => fs.write_all(buf).await?,
            DataStream::BufStream(bs) => bs.write_all(buf).await?,
        }
        Ok(())
    }

    async fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            DataStream::FileStream(fs) => fs.read(buf).await,
            DataStream::BufStream(bs) => bs.read(buf).await,
        }
    }
}

#[derive(Default, Serialize, Deserialize, Debug)]
pub struct FileDigest {
    pub size: u64,
    pub modified: u64,
}

#[derive(Default, Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct TransferJob {
    pub id: i32,
    pub r#type: JobType,
    pub remote: String,
    pub data_source: DataSource,
    pub show_hidden: bool,
    pub is_remote: bool,
    pub is_last_job: bool,
    pub is_resume: bool,
    pub file_num: i32,
    #[serde(skip_serializing)]
    files: Vec<FileEntry>,
    pub conn_id: i32, // server only

    #[serde(skip_serializing)]
    data_stream: Option<DataStream>,
    pub total_size: u64,
    finished_size: u64,
    transferred: u64,
    enable_overwrite_detection: bool,
    file_confirmed: bool,
    // indicating the last file is skipped
    file_skipped: bool,
    file_is_waiting: bool,
    default_overwrite_strategy: Option<bool>,
    #[serde(skip_serializing)]
    digest: FileDigest,
}

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct TransferJobMeta {
    #[serde(default)]
    pub id: i32,
    #[serde(default)]
    pub remote: String,
    #[serde(default)]
    pub to: String,
    #[serde(default)]
    pub show_hidden: bool,
    #[serde(default)]
    pub file_num: i32,
    #[serde(default)]
    pub is_remote: bool,
}

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct RemoveJobMeta {
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub is_remote: bool,
    #[serde(default)]
    pub no_confirm: bool,
}

#[inline]
fn get_ext(name: &str) -> &str {
    if let Some(i) = name.rfind('.') {
        return &name[i + 1..];
    }
    ""
}

#[inline]
fn is_compressed_file(name: &str) -> bool {
    let compressed_exts = ["xz", "gz", "zip", "7z", "rar", "bz2", "tgz", "png", "jpg"];
    let ext = get_ext(name);
    compressed_exts.contains(&ext)
}

pub fn validate_file_name_no_traversal(name: &str) -> ResultType<()> {
    if name.bytes().any(|b| b == 0) {
        bail!("file name contains null bytes");
    }
    let has_traversal = name
        .split(|c: char| c == '/' || (cfg!(windows) && c == '\\'))
        .filter(|s| !s.is_empty())
        .any(|s| s == "..");
    if has_traversal {
        bail!("path traversal detected in file name");
    }
    #[cfg(windows)]
    {
        if name.len() >= 2 {
            let bytes = name.as_bytes();
            if bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
                bail!("absolute path detected in file name");
            }
        }
        if name.starts_with('/') || name.starts_with('\\') {
            bail!("absolute path detected in file name");
        }
    }
    #[cfg(not(windows))]
    if name.starts_with('/') {
        bail!("absolute path detected in file name");
    }
    Ok(())
}

fn validate_transfer_file_names(files: &[FileEntry]) -> ResultType<()> {
    // Single-file transfer may use an empty relative name, because
    // the destination file path is carried by transfer metadata.
    if files.len() == 1 && files.first().map_or(false, |f| f.name.is_empty()) {
        return Ok(());
    }
    for file in files {
        if file.name.is_empty() {
            bail!("empty file name in multi-file transfer");
        }
        validate_file_name_no_traversal(&file.name)?;
    }
    Ok(())
}

pub fn validate_transfer_file_list(
    base: Option<&PathBuf>,
    files: &[FileEntry],
    max_files: usize,
) -> ResultType<()> {
    if files.len() > max_files {
        bail!(
            "file transfer rejected: too many files ({} files exceeds limit of {})",
            files.len(),
            max_files
        );
    }
    validate_transfer_file_names(files)?;
    if let Some(base) = base {
        for file in files {
            validate_no_symlink_components(base, &file.name)?;
        }
    }
    Ok(())
}

#[inline]
fn validate_fs_path_argument(path: &str, arg_name: &str) -> ResultType<()> {
    if path.is_empty() {
        bail!("{arg_name} cannot be empty");
    }
    if path.bytes().any(|b| b == 0) {
        bail!("{arg_name} contains null bytes");
    }
    Ok(())
}

fn validate_no_symlink_components(base: &PathBuf, name: &str) -> ResultType<()> {
    if name.is_empty() {
        return Ok(());
    }
    let mut current = base.clone();
    for component in Path::new(name).components() {
        match component {
            std::path::Component::Normal(seg) => {
                current.push(seg);
                match std::fs::symlink_metadata(&current) {
                    Ok(meta) => {
                        if meta.file_type().is_symlink() {
                            bail!("symlink path component is not allowed");
                        }
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                        // Component does not exist yet, continue best-effort validation.
                    }
                    Err(err) => {
                        bail!(
                            "failed to validate path component '{}': {}",
                            current.display(),
                            err
                        );
                    }
                }
            }
            std::path::Component::CurDir => {}
            _ => {
                bail!("invalid file name component");
            }
        }
    }
    Ok(())
}

fn join_validated_path(base: &PathBuf, name: &str) -> ResultType<PathBuf> {
    validate_file_name_no_traversal(name)?;
    validate_no_symlink_components(base, name)?;
    Ok(TransferJob::join(base, name))
}

fn recv_sidecar_path(path: &Path, suffix: &str) -> PathBuf {
    PathBuf::from(format!("{}{}", get_string(path), suffix))
}

#[cfg(unix)]
fn io_invalid_input(message: impl Into<String>) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, message.into())
}

#[cfg(unix)]
fn cstring_from_os_str(
    value: &std::ffi::OsStr,
    context: &str,
) -> std::io::Result<std::ffi::CString> {
    use std::os::unix::ffi::OsStrExt;
    std::ffi::CString::new(value.as_bytes()).map_err(|err| {
        io_invalid_input(format!(
            "invalid {context} path component contains NUL: {err}"
        ))
    })
}

#[cfg(unix)]
fn cstring_file_name(path: &Path) -> std::io::Result<std::ffi::CString> {
    let name = path
        .file_name()
        .ok_or_else(|| io_invalid_input(format!("path has no file name: {}", path.display())))?;
    cstring_from_os_str(name, "file-transfer")
}

#[cfg(unix)]
fn open_parent_dir_no_follow(
    parent: &Path,
    create_missing: bool,
) -> std::io::Result<std::fs::File> {
    use std::os::unix::io::{AsRawFd, FromRawFd};

    let mut dir = if parent.is_absolute() {
        std::fs::File::open(Path::new("/"))?
    } else {
        std::fs::File::open(Path::new("."))?
    };

    for component in parent.components() {
        match component {
            std::path::Component::RootDir | std::path::Component::CurDir => {}
            std::path::Component::Normal(name) => {
                let name_c = cstring_from_os_str(name, "file-transfer parent")?;
                if create_missing {
                    let rc = unsafe {
                        crate::libc::mkdirat(
                            dir.as_raw_fd(),
                            name_c.as_ptr(),
                            0o777 as crate::libc::mode_t,
                        )
                    };
                    if rc != 0 {
                        let err = std::io::Error::last_os_error();
                        if err.raw_os_error() != Some(crate::libc::EEXIST) {
                            return Err(err);
                        }
                    }
                }

                let fd = unsafe {
                    crate::libc::openat(
                        dir.as_raw_fd(),
                        name_c.as_ptr(),
                        crate::libc::O_RDONLY
                            | crate::libc::O_DIRECTORY
                            | crate::libc::O_CLOEXEC
                            | crate::libc::O_NOFOLLOW,
                    )
                };
                if fd < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                dir = unsafe { std::fs::File::from_raw_fd(fd) };
            }
            std::path::Component::ParentDir => {
                return Err(io_invalid_input(format!(
                    "parent traversal is not allowed in receive path: {}",
                    parent.display()
                )));
            }
            std::path::Component::Prefix(_) => {
                return Err(io_invalid_input(format!(
                    "unsupported path prefix in receive path: {}",
                    parent.display()
                )));
            }
        }
    }

    Ok(dir)
}

#[cfg(unix)]
fn stat_is_regular(stat: &crate::libc::stat) -> bool {
    (stat.st_mode & (crate::libc::S_IFMT as crate::libc::mode_t))
        == (crate::libc::S_IFREG as crate::libc::mode_t)
}

#[cfg(unix)]
fn fstatat_regular_no_follow(
    parent_fd: i32,
    name: &std::ffi::CStr,
) -> std::io::Result<Option<crate::libc::stat>> {
    let mut stat: crate::libc::stat = unsafe { std::mem::zeroed() };
    let rc = unsafe {
        crate::libc::fstatat(
            parent_fd,
            name.as_ptr(),
            &mut stat,
            crate::libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        if err.kind() == std::io::ErrorKind::NotFound {
            return Ok(None);
        }
        return Err(err);
    }
    if !stat_is_regular(&stat) {
        return Err(io_invalid_input("receive target is not a regular file"));
    }
    Ok(Some(stat))
}

#[cfg(unix)]
fn open_regular_child_no_follow(
    parent_fd: i32,
    name: &std::ffi::CStr,
    flags: i32,
    mode: crate::libc::mode_t,
) -> std::io::Result<std::fs::File> {
    use std::os::unix::io::FromRawFd;

    let _ = fstatat_regular_no_follow(parent_fd, name)?;
    let fd = unsafe {
        crate::libc::openat(parent_fd, name.as_ptr(), flags, mode as crate::libc::c_uint)
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let file = unsafe { std::fs::File::from_raw_fd(fd) };
    let mut stat: crate::libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { crate::libc::fstat(fd, &mut stat) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    if !stat_is_regular(&stat) {
        return Err(io_invalid_input(
            "opened receive target is not a regular file",
        ));
    }
    Ok(file)
}

#[cfg(unix)]
fn open_existing_regular_no_follow(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::io::AsRawFd;

    let parent = open_parent_dir_no_follow(path.parent().unwrap_or_else(|| Path::new(".")), false)?;
    let name = cstring_file_name(path)?;
    let flags = crate::libc::O_RDONLY
        | crate::libc::O_CLOEXEC
        | crate::libc::O_NOFOLLOW
        | crate::libc::O_NONBLOCK
        | crate::libc::O_NOCTTY;
    open_regular_child_no_follow(parent.as_raw_fd(), &name, flags, 0)
}

/// R-S8 / R-A5: open a file-transfer RECEIVE-write target with NO-FOLLOW semantics across the
/// whole parent path, not just the final component. The Unix path creates/opens every parent
/// directory via `mkdirat`/`openat(O_DIRECTORY|O_NOFOLLOW)` and then opens the target with
/// `openat(O_NOFOLLOW)`, rejecting symlinks, FIFOs, devices, and other non-regular targets. This
/// closes the intermediate-directory race documented in HARDENING_STATUS: a local user cannot swap a
/// parent directory for a symlink between validation and root's write.
///
/// Windows keeps the standard reparse-point no-follow flag; the Windows artifact path is validated
/// by its own build VM, while the Unix handle-walk is behavior-tested in this repository.
fn open_recv_write_no_follow_std(path: &Path, truncate: bool) -> std::io::Result<std::fs::File> {
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;

        let parent =
            open_parent_dir_no_follow(path.parent().unwrap_or_else(|| Path::new(".")), true)?;
        let name = cstring_file_name(path)?;
        let mut flags = crate::libc::O_WRONLY
            | crate::libc::O_CREAT
            | crate::libc::O_CLOEXEC
            | crate::libc::O_NOFOLLOW
            | crate::libc::O_NONBLOCK
            | crate::libc::O_NOCTTY;
        if truncate {
            flags |= crate::libc::O_TRUNC;
        }
        open_regular_child_no_follow(parent.as_raw_fd(), &name, flags, 0o666)
    }

    #[cfg(not(unix))]
    {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(truncate);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
            opts.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        }
        opts.open(path)
    }
}

/// Async wrapper over [`open_recv_write_no_follow_std`] for the tokio receive-write path (R-S8).
async fn open_recv_write_no_follow(path: &Path, truncate: bool) -> ResultType<File> {
    Ok(File::from_std(open_recv_write_no_follow_std(
        path, truncate,
    )?))
}

#[cfg(unix)]
fn unlink_recv_child_no_follow(parent_fd: i32, name: &std::ffi::CStr) -> std::io::Result<()> {
    let rc = unsafe { crate::libc::unlinkat(parent_fd, name.as_ptr(), 0) };
    if rc == 0 {
        return Ok(());
    }
    let err = std::io::Error::last_os_error();
    if err.kind() == std::io::ErrorKind::NotFound {
        Ok(())
    } else {
        Err(err)
    }
}

fn remove_recv_write_artifacts_no_follow(path: &Path) {
    let digest_path = recv_sidecar_path(path, ".digest");
    let download_path = recv_sidecar_path(path, ".download");
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        let Ok(parent) =
            open_parent_dir_no_follow(path.parent().unwrap_or_else(|| Path::new(".")), false)
        else {
            return;
        };
        if let Ok(download_name) = cstring_file_name(&download_path) {
            let _ = unlink_recv_child_no_follow(parent.as_raw_fd(), &download_name);
        }
        if let Ok(digest_name) = cstring_file_name(&digest_path) {
            let _ = unlink_recv_child_no_follow(parent.as_raw_fd(), &digest_name);
        }
    }
    #[cfg(not(unix))]
    {
        std::fs::remove_file(download_path).ok();
        std::fs::remove_file(digest_path).ok();
    }
}

fn finish_recv_write_no_follow(path: &Path, modified_time: u64) -> std::io::Result<()> {
    let mtime = filetime::FileTime::from_unix_time(modified_time as _, 0);
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;

        let parent =
            open_parent_dir_no_follow(path.parent().unwrap_or_else(|| Path::new(".")), false)?;
        let final_name = cstring_file_name(path)?;
        let download_name = cstring_file_name(&recv_sidecar_path(path, ".download"))?;
        let digest_name = cstring_file_name(&recv_sidecar_path(path, ".digest"))?;
        let _ = unlink_recv_child_no_follow(parent.as_raw_fd(), &digest_name);
        if unsafe {
            crate::libc::renameat(
                parent.as_raw_fd(),
                download_name.as_ptr(),
                parent.as_raw_fd(),
                final_name.as_ptr(),
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error());
        }
        let final_file = open_existing_regular_no_follow(path)?;
        filetime::set_file_handle_times(&final_file, None, Some(mtime))?;
        return Ok(());
    }

    #[cfg(not(unix))]
    {
        let download_path = recv_sidecar_path(path, ".download");
        let digest_path = recv_sidecar_path(path, ".digest");
        std::fs::remove_file(digest_path).ok();
        std::fs::rename(download_path, path)?;
        filetime::set_file_mtime(path, mtime)?;
        Ok(())
    }
}

fn read_recv_sidecar_to_string_no_follow(path: &Path, max_bytes: u64) -> std::io::Result<String> {
    #[cfg(unix)]
    {
        use std::io::Read;
        let file = open_existing_regular_no_follow(path)?;
        let mut reader = file.take(max_bytes.saturating_add(1));
        let mut content = String::new();
        reader.read_to_string(&mut content)?;
        if content.len() as u64 > max_bytes {
            return Err(io_invalid_input("receive sidecar is too large"));
        }
        return Ok(content);
    }

    #[cfg(not(unix))]
    {
        std::fs::read_to_string(path)
    }
}

impl TransferJob {
    #[allow(clippy::too_many_arguments)]
    pub fn new_write(
        id: i32,
        r#type: JobType,
        remote: String,
        data_source: DataSource,
        file_num: i32,
        show_hidden: bool,
        is_remote: bool,
        enable_overwrite_detection: bool,
    ) -> Self {
        log::info!("new write {}", data_source);
        Self {
            id,
            r#type,
            remote,
            data_source,
            file_num,
            show_hidden,
            is_remote,
            files: Vec::new(),
            total_size: 0,
            enable_overwrite_detection,
            ..Default::default()
        }
    }

    pub fn with_files(mut self, files: Vec<FileEntry>) -> ResultType<Self> {
        self.set_files(files)?;
        Ok(self)
    }

    pub fn new_read(
        id: i32,
        r#type: JobType,
        remote: String,
        data_source: DataSource,
        file_num: i32,
        show_hidden: bool,
        is_remote: bool,
        enable_overwrite_detection: bool,
    ) -> ResultType<Self> {
        Self::new_read_with_budget(
            id,
            r#type,
            remote,
            data_source,
            file_num,
            show_hidden,
            is_remote,
            enable_overwrite_detection,
            FileEnumerationBudget::unbounded_for_local_use(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_read_with_budget(
        id: i32,
        r#type: JobType,
        remote: String,
        data_source: DataSource,
        file_num: i32,
        show_hidden: bool,
        is_remote: bool,
        enable_overwrite_detection: bool,
        budget: FileEnumerationBudget,
    ) -> ResultType<Self> {
        log::info!("new read {}", data_source);
        let (files, total_size) = match &data_source {
            DataSource::FilePath(p) => {
                let p = p.to_str().ok_or(anyhow!("Invalid path"))?;
                let files = get_recursive_files_with_budget(p, show_hidden, budget)?;
                let total_size = files.iter().map(|x| x.size).sum();
                (files, total_size)
            }
            DataSource::MemoryCursor(c) => (Vec::new(), c.get_ref().len() as u64),
        };
        Ok(Self {
            id,
            r#type,
            remote,
            data_source,
            file_num,
            show_hidden,
            is_remote,
            files,
            total_size,
            enable_overwrite_detection,
            ..Default::default()
        })
    }

    pub async fn get_buf_data(self) -> ResultType<Option<Vec<u8>>> {
        match self.data_stream {
            Some(DataStream::BufStream(mut bs)) => {
                bs.flush().await?;
                Ok(Some(bs.into_inner().into_inner()))
            }
            _ => Ok(None),
        }
    }

    #[inline]
    pub fn files(&self) -> &Vec<FileEntry> {
        &self.files
    }

    #[inline]
    pub fn set_files(&mut self, files: Vec<FileEntry>) -> ResultType<()> {
        self.set_files_with_limit(files, usize::MAX)
    }

    #[inline]
    pub fn set_files_with_limit(
        &mut self,
        files: Vec<FileEntry>,
        max_files: usize,
    ) -> ResultType<()> {
        let base = match &self.data_source {
            DataSource::FilePath(base) => Some(base),
            DataSource::MemoryCursor(_) => None,
        };
        validate_transfer_file_list(base, &files, max_files)?;
        self.total_size = files.iter().map(|x| x.size).sum();
        self.files = files;
        Ok(())
    }

    #[inline]
    pub fn set_digest(&mut self, size: u64, modified: u64) {
        self.digest.size = size;
        self.digest.modified = modified;
    }

    #[inline]
    pub fn id(&self) -> i32 {
        self.id
    }

    #[inline]
    pub fn total_size(&self) -> u64 {
        self.total_size
    }

    #[inline]
    pub fn finished_size(&self) -> u64 {
        self.finished_size
    }

    #[inline]
    pub fn transferred(&self) -> u64 {
        self.transferred
    }

    #[inline]
    pub fn file_num(&self) -> i32 {
        self.file_num
    }

    fn resolve_entry_path(&self, base: &PathBuf, name: &str) -> Option<PathBuf> {
        if self.r#type == JobType::Generic {
            match join_validated_path(base, name) {
                Ok(path) => Some(path),
                Err(err) => {
                    log::error!("Invalid file name in transfer job {}: {}", self.id, err);
                    None
                }
            }
        } else {
            Some(Self::join(base, name))
        }
    }

    pub fn modify_time(&self) {
        if self.r#type == JobType::Printer {
            return;
        }
        if let DataSource::FilePath(p) = &self.data_source {
            let file_num = self.file_num as usize;
            if file_num < self.files.len() {
                let entry = &self.files[file_num];
                let Some(path) = self.resolve_entry_path(p, &entry.name) else {
                    return;
                };
                if let Err(err) = finish_recv_write_no_follow(&path, entry.modified_time) {
                    if err.kind() == std::io::ErrorKind::NotFound {
                        return;
                    }
                    log::warn!(
                        "Failed to finish receive-write target {}: {}",
                        path.display(),
                        err
                    );
                }
            }
        }
    }

    pub fn remove_download_file(&self) {
        if self.r#type == JobType::Printer {
            return;
        }
        if let DataSource::FilePath(p) = &self.data_source {
            let file_num = self.file_num as usize;
            if file_num < self.files.len() {
                let entry = &self.files[file_num];
                let Some(path) = self.resolve_entry_path(p, &entry.name) else {
                    return;
                };
                remove_recv_write_artifacts_no_follow(&path);
            }
        }
    }

    #[inline]
    pub fn set_finished_size_on_resume(&mut self) {
        if self.is_resume && self.file_num > 0 {
            let finished_size: u64 = self
                .files
                .iter()
                .take(self.file_num as usize)
                .map(|file| file.size)
                .sum();
            self.finished_size = finished_size;
        }
    }

    pub async fn write(&mut self, block: FileTransferBlock) -> ResultType<()> {
        if block.id != self.id {
            bail!("Wrong id");
        }
        match &self.data_source {
            DataSource::FilePath(p) => {
                let file_num = block.file_num as usize;
                if file_num >= self.files.len() {
                    bail!("Wrong file number");
                }
                if file_num != self.file_num as usize || self.data_stream.is_none() {
                    let had_file_stream =
                        matches!(self.data_stream, Some(DataStream::FileStream(_)));
                    if let Some(DataStream::FileStream(file)) = self.data_stream.as_mut() {
                        file.sync_all().await?;
                    }
                    if had_file_stream {
                        self.modify_time();
                    }
                    self.file_num = block.file_num;
                    let entry = &self.files[file_num];
                    let (path, digest_path) = if self.r#type == JobType::Printer {
                        (p.to_string_lossy().to_string(), None)
                    } else {
                        let path = join_validated_path(p, &entry.name)?;
                        let file_path = get_string(&path);
                        (
                            format!("{}.download", &file_path),
                            Some(format!("{}.digest", &file_path)),
                        )
                    };
                    // R-S8/R-A5: no-follow parent walk + no-follow regular-file open. On Unix this
                    // creates/opens every parent via mkdirat/openat(O_NOFOLLOW) before opening the
                    // `.download` target, so neither intermediate symlink swaps nor final symlinks can
                    // redirect the write.
                    self.data_stream = Some(DataStream::FileStream(
                        open_recv_write_no_follow(Path::new(&path), true).await?,
                    ));
                    if let Some(dp) = digest_path.as_ref() {
                        // R-S8: the digest sidecar is a write too — no-follow it for the same reason.
                        if let Ok(mut f) = open_recv_write_no_follow_std(Path::new(dp), true) {
                            use std::io::Write;
                            let _ = f.write_all(json!(self.digest).to_string().as_bytes());
                        }
                    }
                }
            }
            DataSource::MemoryCursor(c) => {
                if self.data_stream.is_none() {
                    self.data_stream = Some(DataStream::BufStream(TokioBufStream::new(c.clone())));
                }
            }
        }
        if block.compressed {
            let tmp = peer_decompress(&block.data);
            self.data_stream
                .as_mut()
                .ok_or(anyhow!("data stream is None"))?
                .write_all(&tmp)
                .await?;
            self.finished_size += tmp.len() as u64;
        } else {
            self.data_stream
                .as_mut()
                .ok_or(anyhow!("file is None"))?
                .write_all(&block.data)
                .await?;
            self.finished_size += block.data.len() as u64;
        }
        self.transferred += block.data.len() as u64;
        Ok(())
    }

    #[inline]
    pub fn join(p: &PathBuf, name: &str) -> PathBuf {
        if name.is_empty() {
            p.clone()
        } else {
            p.join(name)
        }
    }

    /// Open the data stream for the current file.
    /// Returns Ok(true) if job is done, Ok(false) otherwise.
    async fn open_data_stream(&mut self) -> ResultType<bool> {
        let file_num = self.file_num as usize;
        match &mut self.data_source {
            DataSource::FilePath(p) => {
                if file_num >= self.files.len() {
                    // job done
                    self.data_stream.take();
                    return Ok(true);
                };
                if self.data_stream.is_none() {
                    match File::open(Self::join(p, &self.files[file_num].name)).await {
                        Ok(file) => {
                            self.data_stream = Some(DataStream::FileStream(file));
                            self.file_confirmed = false;
                            self.file_is_waiting = false;
                        }
                        // On open error, behave the same as validation failure: advance
                        // to next file and return the error.
                        Err(err) => {
                            self.file_num += 1;
                            self.file_confirmed = false;
                            self.file_is_waiting = false;
                            return Err(err.into());
                        }
                    }
                }
            }
            DataSource::MemoryCursor(c) => {
                if self.data_stream.is_none() {
                    let mut t = std::io::Cursor::new(Vec::new());
                    std::mem::swap(&mut t, c);
                    self.data_stream = Some(DataStream::BufStream(TokioBufStream::new(t)));
                }
            }
        }
        Ok(false)
    }

    /// Get current file's digest (last_modified, file_size) for overwrite detection.
    async fn get_current_digest(&self) -> ResultType<(u64, u64)> {
        let meta = match self.data_stream.as_ref().ok_or(anyhow!("file is None"))? {
            DataStream::FileStream(file) => file.metadata().await?,
            DataStream::BufStream(_) => bail!("No digest for buf stream"),
        };
        let last_modified = meta
            .modified()?
            .duration_since(SystemTime::UNIX_EPOCH)?
            .as_secs();
        Ok((last_modified, meta.len()))
    }

    async fn init_data_stream(&mut self, stream: &mut crate::Stream) -> ResultType<()> {
        if self.open_data_stream().await? {
            return Ok(());
        }
        if self.r#type == JobType::Generic
            && self.enable_overwrite_detection
            && !self.file_confirmed()
            && !self.file_is_waiting()
        {
            self.send_current_digest(stream).await?;
            self.set_file_is_waiting(true);
        }
        Ok(())
    }

    /// Initialize data stream for CM (Connection Manager) scenario.
    /// Returns digest info (last_modified, file_size) if overwrite detection is enabled,
    /// so caller can send it via IPC instead of network stream.
    /// Returns Ok(None) if job is done or already initialized.
    pub async fn init_data_stream_for_cm(&mut self) -> ResultType<Option<(u64, u64)>> {
        if self.open_data_stream().await? {
            return Ok(None);
        }
        // For overwrite detection, return digest info instead of sending via stream
        if self.r#type == JobType::Generic
            && self.enable_overwrite_detection
            && !self.file_confirmed()
            && !self.file_is_waiting()
        {
            let digest = self.get_current_digest().await?;
            self.set_file_is_waiting(true);
            return Ok(Some(digest));
        }
        Ok(None)
    }

    pub async fn read(&mut self) -> ResultType<Option<FileTransferBlock>> {
        if self.r#type == JobType::Generic {
            if self.enable_overwrite_detection && !self.file_confirmed() {
                return Ok(None);
            }
        }

        let file_num = self.file_num as usize;
        let name = match &self.data_source {
            DataSource::FilePath(p) => {
                if file_num >= self.files.len() {
                    self.data_stream.take();
                    return Ok(None);
                };
                if self.files.len() == 1 && self.files[file_num].name.is_empty() {
                    p.file_name()
                        .map(|p| p.to_str().unwrap_or(""))
                        .unwrap_or("")
                } else {
                    &self.files[file_num].name
                }
            }
            DataSource::MemoryCursor(..) => "",
        };
        const BUF_SIZE: usize = 128 * 1024;
        let mut buf: Vec<u8> = vec![0; BUF_SIZE];
        let mut compressed = false;
        let mut offset: usize = 0;
        loop {
            match self
                .data_stream
                .as_mut()
                .ok_or(anyhow!("data stream is None"))?
                .read(&mut buf[offset..])
                .await
            {
                Err(err) => {
                    self.file_num += 1;
                    self.data_stream = None;
                    self.file_confirmed = false;
                    self.file_is_waiting = false;
                    return Err(err.into());
                }
                Ok(n) => {
                    offset += n;
                    if n == 0 || offset == BUF_SIZE {
                        break;
                    }
                }
            }
        }
        unsafe { buf.set_len(offset) };
        if offset == 0 {
            if matches!(self.data_source, DataSource::MemoryCursor(_)) {
                self.data_stream.take();
                return Ok(None);
            }
            self.file_num += 1;
            self.data_stream = None;
            self.file_confirmed = false;
            self.file_is_waiting = false;
        } else {
            self.finished_size += offset as u64;
            if matches!(self.data_source, DataSource::FilePath(_)) && !is_compressed_file(name) {
                let tmp = compress(&buf);
                if tmp.len() < buf.len() {
                    buf = tmp;
                    compressed = true;
                }
            }
            self.transferred += buf.len() as u64;
        }
        Ok(Some(FileTransferBlock {
            id: self.id,
            file_num: file_num as _,
            data: buf.into(),
            compressed,
            ..Default::default()
        }))
    }

    // Only for generic job and file stream
    async fn send_current_digest(&mut self, stream: &mut Stream) -> ResultType<()> {
        let (last_modified, file_size) = self.get_current_digest().await?;
        let mut msg = Message::new();
        let mut resp = FileResponse::new();
        resp.set_digest(FileTransferDigest {
            id: self.id,
            file_num: self.file_num,
            last_modified,
            file_size,
            is_resume: self.is_resume,
            ..Default::default()
        });
        msg.set_file_response(resp);
        stream.send(&msg).await?;
        log::info!(
            "id: {}, file_num: {}, digest message is sent. waiting for confirm. msg: {:?}",
            self.id,
            self.file_num,
            msg
        );
        Ok(())
    }

    pub fn set_overwrite_strategy(&mut self, overwrite_strategy: Option<bool>) {
        self.default_overwrite_strategy = overwrite_strategy;
    }

    pub fn default_overwrite_strategy(&self) -> Option<bool> {
        self.default_overwrite_strategy
    }

    pub fn set_file_confirmed(&mut self, file_confirmed: bool) {
        log::info!("id: {}, file_confirmed: {}", self.id, file_confirmed);
        self.file_confirmed = file_confirmed;
        self.file_skipped = false;
    }

    pub fn set_file_is_waiting(&mut self, file_is_waiting: bool) {
        self.file_is_waiting = file_is_waiting;
    }

    #[inline]
    pub fn file_is_waiting(&self) -> bool {
        self.file_is_waiting
    }

    #[inline]
    pub fn file_confirmed(&self) -> bool {
        self.file_confirmed
    }

    /// Indicating whether the last file is skipped
    #[inline]
    pub fn file_skipped(&self) -> bool {
        self.file_skipped
    }

    /// Indicating whether the whole task is skipped
    #[inline]
    pub fn job_skipped(&self) -> bool {
        self.file_skipped() && self.files.len() == 1
    }

    /// Check whether the job is completed after `read` returns `None`
    /// This is a helper function which gives additional lifecycle when the job reads `None`.
    /// If returns `true`, it means we can delete the job automatically. `False` otherwise.
    ///
    /// [`Note`]
    /// Conditions:
    /// 1. Files are not waiting for confirmation by peers.
    #[inline]
    pub fn job_completed(&self) -> bool {
        // has no error, Condition 2
        !self.enable_overwrite_detection || (!self.file_confirmed && !self.file_is_waiting)
    }

    /// Get job error message, useful for getting status when job had finished
    pub fn job_error(&self) -> Option<String> {
        if self.job_skipped() {
            return Some("skipped".to_string());
        }
        None
    }

    pub fn set_file_skipped(&mut self) -> bool {
        log::debug!("skip file {} in job {}", self.file_num, self.id);
        self.data_stream.take();
        self.set_file_confirmed(false);
        self.set_file_is_waiting(false);
        self.file_num += 1;
        self.file_skipped = true;
        true
    }

    async fn set_stream_offset(&mut self, file_num: usize, offset: u64) {
        if let DataSource::FilePath(p) = &self.data_source {
            let entry = &self.files[file_num];
            let Some(path) = self.resolve_entry_path(p, &entry.name) else {
                return;
            };
            let file_path = get_string(&path);
            let download_path = format!("{}.download", &file_path);
            let digest_path = format!("{}.digest", &file_path);

            let mut f = if Path::new(&download_path).exists() && Path::new(&digest_path).exists() {
                // If both download and digest files exist, seek (writer) to the offset
                // R-S8/R-A5: no-follow parent walk + reopen of the resume target (truncate=false
                // keeps the partial download); a symlink swapped in here fails rather than
                // redirecting the write.
                match open_recv_write_no_follow(Path::new(&download_path), false).await {
                    Ok(f) => f,
                    Err(e) => {
                        log::warn!("Failed to open file {}: {}", download_path, e);
                        return;
                    }
                }
            } else if Path::new(&file_path).exists() {
                // If `file_path` exists, seek (reader) to the offset
                match File::open(&file_path).await {
                    Ok(f) => f,
                    Err(e) => {
                        log::warn!("Failed to open file {}: {}", file_path, e);
                        return;
                    }
                }
            } else {
                log::warn!(
                    "File {} not found, cannot seek to offset {}",
                    file_path,
                    offset
                );
                return;
            };
            if f.seek(std::io::SeekFrom::Start(offset)).await.is_ok() {
                self.data_stream = Some(DataStream::FileStream(f));
                self.transferred += offset;
                self.finished_size += offset;
            }
        }
    }

    pub async fn confirm(&mut self, r: &FileTransferSendConfirmRequest) -> bool {
        if self.file_num() != r.file_num {
            // This branch will always be hit if:
            // 1. `confirm()` is called in `ui_cm_interface.rs`
            // 2. Not resuming
            //
            // It is ok. Because `confirm()` in `ui_cm_interface.rs` is only used for resuming.
            log::info!("file num truncated, ignoring");
        } else {
            match r.union {
                Some(file_transfer_send_confirm_request::Union::Skip(s)) => {
                    if s {
                        self.set_file_skipped();
                    } else {
                        self.set_file_confirmed(true);
                    }
                }
                Some(file_transfer_send_confirm_request::Union::OffsetBlk(offset)) => {
                    self.set_file_confirmed(true);
                    // If offset is greater than 0, we need to seek to the offset
                    if offset > 0 {
                        self.set_stream_offset(r.file_num as usize, offset as u64)
                            .await;
                    }
                }
                _ => {}
            }
        }
        true
    }

    #[inline]
    pub fn gen_meta(&self) -> TransferJobMeta {
        TransferJobMeta {
            id: self.id,
            remote: self.remote.to_string(),
            to: self.data_source.to_meta(),
            file_num: self.file_num,
            show_hidden: self.show_hidden,
            is_remote: self.is_remote,
        }
    }
}

#[inline]
pub fn new_error<T: std::string::ToString>(id: i32, err: T, file_num: i32) -> Message {
    let mut resp = FileResponse::new();
    resp.set_error(FileTransferError {
        id,
        error: err.to_string(),
        file_num,
        ..Default::default()
    });
    let mut msg_out = Message::new();
    msg_out.set_file_response(resp);
    msg_out
}

#[inline]
pub fn new_dir(id: i32, path: String, files: Vec<FileEntry>) -> Message {
    let mut resp = FileResponse::new();
    resp.set_dir(FileDirectory {
        id,
        path,
        entries: files,
        ..Default::default()
    });
    let mut msg_out = Message::new();
    msg_out.set_file_response(resp);
    msg_out
}

#[inline]
pub fn new_block(block: FileTransferBlock) -> Message {
    let mut resp = FileResponse::new();
    resp.set_block(block);
    let mut msg_out = Message::new();
    msg_out.set_file_response(resp);
    msg_out
}

#[inline]
pub fn new_send_confirm(r: FileTransferSendConfirmRequest) -> Message {
    let mut msg_out = Message::new();
    let mut action = FileAction::new();
    action.set_send_confirm(r);
    msg_out.set_file_action(action);
    msg_out
}

#[inline]
pub fn new_receive(
    id: i32,
    path: String,
    file_num: i32,
    files: Vec<FileEntry>,
    total_size: u64,
) -> Message {
    let mut action = FileAction::new();
    action.set_receive(FileTransferReceiveRequest {
        id,
        path,
        files,
        file_num,
        total_size,
        ..Default::default()
    });
    let mut msg_out = Message::new();
    msg_out.set_file_action(action);
    msg_out
}

#[inline]
pub fn new_send(
    id: i32,
    r#type: JobType,
    path: String,
    file_num: i32,
    include_hidden: bool,
) -> Message {
    log::info!("new send: {}, id: {}", path, id);
    let mut action = FileAction::new();
    let t: file_transfer_send_request::FileType = r#type.into();
    action.set_send(FileTransferSendRequest {
        id,
        path,
        include_hidden,
        file_num,
        file_type: t.into(),
        ..Default::default()
    });
    let mut msg_out = Message::new();
    msg_out.set_file_action(action);
    msg_out
}

#[inline]
pub fn new_done(id: i32, file_num: i32) -> Message {
    let mut resp = FileResponse::new();
    resp.set_done(FileTransferDone {
        id,
        file_num,
        ..Default::default()
    });
    let mut msg_out = Message::new();
    msg_out.set_file_response(resp);
    msg_out
}

#[inline]
pub fn remove_job(id: i32, jobs: &mut Vec<TransferJob>) -> Option<TransferJob> {
    jobs.iter()
        .position(|x| x.id() == id)
        .map(|index| jobs.remove(index))
}

#[inline]
pub fn get_job(id: i32, jobs: &mut [TransferJob]) -> Option<&mut TransferJob> {
    jobs.iter_mut().find(|x| x.id() == id)
}

#[inline]
pub fn get_job_immutable(id: i32, jobs: &[TransferJob]) -> Option<&TransferJob> {
    jobs.iter().find(|x| x.id() == id)
}

async fn init_jobs(jobs: &mut Vec<TransferJob>, stream: &mut crate::Stream) -> ResultType<()> {
    for job in jobs.iter_mut() {
        if job.is_last_job {
            continue;
        }
        if let Err(err) = job.init_data_stream(stream).await {
            stream
                .send(&new_error(job.id(), err, job.file_num()))
                .await?;
        }
    }
    Ok(())
}

pub async fn handle_read_jobs(
    jobs: &mut Vec<TransferJob>,
    stream: &mut crate::Stream,
) -> ResultType<String> {
    init_jobs(jobs, stream).await?;

    let mut job_log = Default::default();
    let mut finished = Vec::new();
    for job in jobs.iter_mut() {
        if job.is_last_job {
            continue;
        }
        match job.read().await {
            Err(err) => {
                stream
                    .send(&new_error(job.id(), err, job.file_num()))
                    .await?;
            }
            Ok(Some(block)) => {
                stream.send(&new_block(block)).await?;
            }
            Ok(None) => {
                if job.job_completed() {
                    job_log = serialize_transfer_job(job, true, false, "");
                    finished.push(job.id());
                    match job.job_error() {
                        Some(err) => {
                            job_log = serialize_transfer_job(job, false, false, &err);
                            stream
                                .send(&new_error(job.id(), err, job.file_num()))
                                .await?
                        }
                        None => stream.send(&new_done(job.id(), job.file_num())).await?,
                    }
                } else {
                    // waiting confirmation.
                }
            }
        }
        // Break to handle jobs one by one.
        break;
    }
    for id in finished {
        let _ = remove_job(id, jobs);
    }
    Ok(job_log)
}

pub fn remove_all_empty_dir(path: &Path) -> ResultType<()> {
    let fd = read_dir(path, true)?;
    for entry in fd.entries.iter() {
        match entry.entry_type.enum_value() {
            Ok(FileType::Dir) => {
                remove_all_empty_dir(&path.join(&entry.name)).ok();
            }
            Ok(FileType::DirLink) | Ok(FileType::FileLink) => {
                std::fs::remove_file(path.join(&entry.name)).ok();
            }
            _ => {}
        }
    }
    std::fs::remove_dir(path).ok();
    Ok(())
}

#[inline]
pub fn remove_file(file: &str) -> ResultType<()> {
    validate_fs_path_argument(file, "file path")?;
    std::fs::remove_file(get_path(file))?;
    Ok(())
}

#[inline]
pub fn create_dir(dir: &str) -> ResultType<()> {
    validate_fs_path_argument(dir, "directory path")?;
    std::fs::create_dir_all(get_path(dir))?;
    Ok(())
}

#[inline]
pub fn rename_file(path: &str, new_name: &str) -> ResultType<()> {
    validate_fs_path_argument(path, "path")?;
    if new_name.is_empty() {
        bail!("new file name cannot be empty");
    }
    validate_file_name_no_traversal(new_name)?;
    let path = std::path::Path::new(&path);
    if path.exists() {
        let dir = path
            .parent()
            .ok_or(anyhow!("Parent directoy of {path:?} not exists"))?;
        let new_path = dir.join(&new_name);
        std::fs::rename(&path, &new_path)?;
        Ok(())
    } else {
        bail!("{path:?} not exists");
    }
}

#[inline]
pub fn transform_windows_path(entries: &mut Vec<FileEntry>) {
    for entry in entries {
        entry.name = entry.name.replace('\\', "/");
    }
}

pub enum DigestCheckResult {
    IsSame,
    NeedConfirm(FileTransferDigest),
    NoSuchFile,
}

#[inline]
pub fn is_write_need_confirmation(
    is_resume: bool,
    file_path: &str,
    digest: &FileTransferDigest,
) -> ResultType<DigestCheckResult> {
    let path = Path::new(file_path);
    let digest_file = format!("{}.digest", file_path);
    let download_file = format!("{}.download", file_path);
    if is_resume && Path::new(&digest_file).exists() && Path::new(&download_file).exists() {
        // If the digest file exists, it means the file was transferred before.
        // We can use the digest file to check whether the file is the same.
        if let Ok(content) = read_recv_sidecar_to_string_no_follow(Path::new(&digest_file), 4096) {
            if let Ok(local_digest) = serde_json::from_str::<FileDigest>(&content) {
                let is_identical = local_digest.modified == digest.last_modified
                    && local_digest.size == digest.file_size;
                if is_identical {
                    if let Ok(download_metadata) = std::fs::metadata(download_file) {
                        // Get the file size of the local file
                        // Only send confirmation if the file is not empty.
                        let transferred_size = download_metadata.len();
                        if transferred_size > 0 {
                            return Ok(DigestCheckResult::NeedConfirm(FileTransferDigest {
                                id: digest.id,
                                file_num: digest.file_num,
                                last_modified: digest.last_modified,
                                file_size: digest.file_size,
                                is_identical,
                                transferred_size,
                                ..Default::default()
                            }));
                        }
                    }
                }
            }
        }
    }

    if path.exists() && path.is_file() {
        let metadata = std::fs::metadata(path)?;
        let modified_time = metadata.modified()?;
        let remote_mt = Duration::from_secs(digest.last_modified);
        let local_mt = modified_time.duration_since(UNIX_EPOCH)?;
        // [Note]
        // We decide to give the decision whether to override the existing file to users,
        // which obey the behavior of the file manager in our system.
        let mut is_identical = false;
        if remote_mt == local_mt && digest.file_size == metadata.len() {
            is_identical = true;
        }
        Ok(DigestCheckResult::NeedConfirm(FileTransferDigest {
            id: digest.id,
            file_num: digest.file_num,
            last_modified: local_mt.as_secs(),
            file_size: metadata.len(),
            is_identical,
            ..Default::default()
        }))
    } else {
        // If the file does not exist, or the digest file and download file do not exist, we return NoSuchFile.
        Ok(DigestCheckResult::NoSuchFile)
    }
}

pub fn serialize_transfer_jobs(jobs: &[TransferJob]) -> String {
    let mut v = vec![];
    for job in jobs {
        let value = serde_json::to_value(job).unwrap_or_default();
        v.push(value);
    }
    serde_json::to_string(&v).unwrap_or_default()
}

pub fn serialize_transfer_job(job: &TransferJob, done: bool, cancel: bool, error: &str) -> String {
    let mut value = serde_json::to_value(job).unwrap_or_default();
    value["done"] = json!(done);
    value["cancel"] = json!(cancel);
    value["error"] = json!(error);
    serde_json::to_string(&value).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestTempDir {
        path: PathBuf,
    }

    impl TestTempDir {
        fn new(prefix: &str) -> Self {
            Self {
                path: unique_temp_dir(prefix),
            }
        }

        fn join(&self, path: &str) -> PathBuf {
            self.path.join(path)
        }
    }

    impl Drop for TestTempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    fn unique_temp_dir(prefix: &str) -> PathBuf {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        std::env::temp_dir().join(format!("{}_{}_{}", prefix, std::process::id(), timestamp))
    }

    fn new_file_entry(name: &str) -> FileEntry {
        let mut entry = FileEntry::new();
        entry.name = name.to_string();
        entry
    }

    // R-S8/R-A5: the receive-write open MUST refuse a symlink final component (the symlink TOCTOU),
    // so a local user racing a symlink swap cannot redirect the (root, on the §17 box) write to an
    // arbitrary file. This tests the no-follow open DIRECTLY — robust to the race timing.
    #[test]
    #[cfg(unix)]
    fn recv_write_no_follow_refuses_symlink_target() {
        let tmp = TestTempDir::new("rustdesk_nofollow_sym");
        let dl = tmp.join("downloads");
        std::fs::create_dir_all(&dl).expect("create downloads");
        let secret = tmp.join("secret.txt");
        std::fs::write(&secret, b"DO-NOT-OVERWRITE").expect("write secret");
        // a local attacker swaps the receive target for a symlink to the secret (after path validation)
        let target = dl.join("incoming.download");
        std::os::unix::fs::symlink(&secret, &target).expect("create symlink");
        // the no-follow open MUST fail (ELOOP) — never follow into `secret`
        let res = open_recv_write_no_follow_std(&target, true);
        assert!(
            res.is_err(),
            "O_NOFOLLOW must refuse a symlink final component"
        );
        // and the secret is untouched (the open failed before any truncate-through-the-symlink)
        assert_eq!(
            std::fs::read(&secret).expect("read secret"),
            b"DO-NOT-OVERWRITE",
            "the no-follow open must not have truncated the symlink target"
        );
    }

    // R-S8: the no-follow open MUST still allow a legitimate (fresh or existing-regular) target, so
    // the hardening never breaks a real transfer (only a symlink final component is refused).
    #[test]
    fn recv_write_no_follow_allows_regular_target() {
        let tmp = TestTempDir::new("rustdesk_nofollow_ok");
        let dl = tmp.join("downloads");
        std::fs::create_dir_all(&dl).expect("create downloads");
        let target = dl.join("incoming.download");
        let target_s = target.to_str().expect("utf8 path");
        // a fresh target opens
        assert!(
            open_recv_write_no_follow_std(&target, true).is_ok(),
            "no-follow open must allow a fresh regular target"
        );
        assert!(target.exists());
        // an existing regular target re-opens (truncate) — a re-download is not blocked
        assert!(
            open_recv_write_no_follow_std(Path::new(target_s), true).is_ok(),
            "no-follow open must allow an existing regular target"
        );
    }

    #[test]
    #[cfg(unix)]
    fn recv_write_no_follow_refuses_symlink_parent_component() {
        let tmp = TestTempDir::new("rustdesk_nofollow_parent");
        let downloads = tmp.join("downloads");
        let outside = tmp.join("outside");
        std::fs::create_dir_all(&downloads).expect("create downloads");
        std::fs::create_dir_all(&outside).expect("create outside");

        let link = downloads.join("link");
        std::os::unix::fs::symlink(&outside, &link).expect("create symlink parent");
        let target = link.join("incoming.download");

        let res = open_recv_write_no_follow_std(&target, true);
        assert!(
            res.is_err(),
            "openat parent walk must refuse symlink intermediate components"
        );
        assert!(
            !outside.join("incoming.download").exists(),
            "symlink parent must not redirect the receive write outside the destination tree"
        );
    }

    #[test]
    #[cfg(unix)]
    fn recv_finish_renameat_replaces_symlink_final_without_touching_target() {
        let tmp = TestTempDir::new("rustdesk_finish_renameat");
        let downloads = tmp.join("downloads");
        std::fs::create_dir_all(&downloads).expect("create downloads");
        let secret = tmp.join("secret.txt");
        std::fs::write(&secret, b"DO-NOT-OVERWRITE").expect("write secret");

        let final_path = downloads.join("incoming.txt");
        let download_path = recv_sidecar_path(&final_path, ".download");
        std::fs::write(&download_path, b"payload").expect("write download");
        std::os::unix::fs::symlink(&secret, &final_path).expect("create symlink final");

        finish_recv_write_no_follow(&final_path, 1).expect("finish receive write");

        assert_eq!(
            std::fs::read(&secret).expect("read secret"),
            b"DO-NOT-OVERWRITE",
            "renameat finalization must replace the symlink itself, not truncate its target"
        );
        assert_eq!(
            std::fs::read(&final_path).expect("read final"),
            b"payload",
            "final path should contain the received payload"
        );
    }

    #[test]
    #[cfg(unix)]
    fn recv_digest_read_no_follow_refuses_symlink_sidecar() {
        let tmp = TestTempDir::new("rustdesk_digest_nofollow");
        let downloads = tmp.join("downloads");
        std::fs::create_dir_all(&downloads).expect("create downloads");
        let secret = tmp.join("secret.json");
        std::fs::write(&secret, b"{\"size\":1,\"modified\":1}").expect("write secret");

        let digest = downloads.join("incoming.txt.digest");
        std::os::unix::fs::symlink(&secret, &digest).expect("create digest symlink");

        let res = read_recv_sidecar_to_string_no_follow(&digest, 4096);
        assert!(
            res.is_err(),
            "resume digest reads must not follow a symlink sidecar"
        );
    }

    fn new_validation_job(id: i32) -> TransferJob {
        TransferJob::new_write(
            id,
            JobType::Generic,
            "/fake/remote".to_string(),
            DataSource::FilePath(std::env::temp_dir().join(format!("rustdesk_validation_{id}"))),
            0,
            false,
            true,
            false,
        )
    }

    fn new_write_job(id: i32, download_dir: PathBuf, name: &str) -> ResultType<TransferJob> {
        let job = TransferJob::new_write(
            id,
            JobType::Generic,
            "/fake/remote".to_string(),
            DataSource::FilePath(download_dir),
            0,
            false,
            true,
            false,
        )
        .with_files(vec![new_file_entry(name)])?;
        Ok(job)
    }

    fn assert_err_contains(err: anyhow::Error, expected: &str) {
        assert!(
            err.to_string().contains(expected),
            "expected error containing '{}', got: {}",
            expected,
            err
        );
    }

    #[test]
    fn budgeted_read_dir_rejects_too_many_entries_before_returning_vector() {
        let tmp = TestTempDir::new("rustdesk_budgeted_read_dir");
        std::fs::create_dir_all(&tmp.path).expect("create temp dir");
        std::fs::write(tmp.join("one.txt"), b"1").expect("write one");
        std::fs::write(tmp.join("two.txt"), b"2").expect("write two");
        std::fs::write(tmp.join("three.txt"), b"3").expect("write three");

        let err = read_dir_with_budget(
            &tmp.path,
            true,
            FileEnumerationBudget {
                max_entries: 2,
                max_dirs: 1,
                max_depth: 1,
                max_serialized_bytes: MAX_FILE_ENUM_SERIALIZED_BYTES,
            },
        )
        .expect_err("third entry must trip the budget during directory read");
        assert_err_contains(err, "entries exceed limit");
    }

    #[test]
    fn budgeted_recursive_listing_rejects_excessive_depth() {
        let tmp = TestTempDir::new("rustdesk_budgeted_recursive_depth");
        let nested = tmp.join("a").join("b");
        std::fs::create_dir_all(&nested).expect("create nested dirs");
        std::fs::write(nested.join("leaf.txt"), b"leaf").expect("write leaf");

        let err = get_recursive_files_with_budget(
            &tmp.path.to_string_lossy(),
            true,
            FileEnumerationBudget {
                max_entries: 16,
                max_dirs: 16,
                max_depth: 1,
                max_serialized_bytes: MAX_FILE_ENUM_SERIALIZED_BYTES,
            },
        )
        .expect_err("depth-two traversal must trip the recursive budget");
        assert_err_contains(err, "depth 2 exceeds limit 1");
    }

    #[test]
    fn path_traversal_e2e_write_rejects_relative_escape() {
        let tmp_root = TestTempDir::new("rustdesk_e2e_relative");
        let downloads = tmp_root.join("downloads");
        std::fs::create_dir_all(&downloads).expect("create downloads dir");

        let err = new_write_job(1, downloads, "../traversal_proof.txt")
            .expect_err("relative path traversal must be rejected");
        assert_err_contains(err, "path traversal");
        assert!(!tmp_root.join("traversal_proof.txt").exists());
    }

    #[test]
    fn path_traversal_e2e_write_rejects_absolute_path() {
        let tmp_root = TestTempDir::new("rustdesk_e2e_absolute");
        let downloads = tmp_root.join("downloads");
        let absolute_target = tmp_root.join("fake_ssh").join("authorized_keys");
        std::fs::create_dir_all(&downloads).expect("create downloads dir");

        let err = new_write_job(2, downloads, &absolute_target.to_string_lossy())
            .expect_err("absolute path must be rejected");
        assert_err_contains(err, "absolute path");
        assert!(!absolute_target.exists());
    }

    #[test]
    #[cfg_attr(windows, ignore = "requires symlink privilege to create test symlink")]
    fn path_traversal_e2e_write_rejects_symlink_escape() {
        let tmp_root = TestTempDir::new("rustdesk_e2e_symlink");
        let downloads = tmp_root.join("downloads");
        let outside = tmp_root.join("outside");
        let escaped_target = outside.join("escape.txt");
        std::fs::create_dir_all(&downloads).expect("create downloads dir");
        std::fs::create_dir_all(&outside).expect("create outside dir");

        let symlink_path = downloads.join("link");
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            symlink(&outside, &symlink_path).expect("create symlink for test");
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::symlink_dir;
            symlink_dir(&outside, &symlink_path).expect("create directory symlink for test");
        }

        let err = new_write_job(3, downloads, "link/escape.txt")
            .expect_err("symlink traversal must be rejected");
        assert_err_contains(err, "symlink");
        assert!(!escaped_target.exists());
    }

    #[test]
    fn set_files_allows_single_empty_name_for_single_file_transfer() {
        let mut job = new_validation_job(101);
        assert!(job.set_files(vec![new_file_entry("")]).is_ok());
    }

    #[test]
    fn set_files_rejects_empty_name_in_multi_file_transfer() {
        let mut job = new_validation_job(102);
        let err = job
            .set_files(vec![new_file_entry(""), new_file_entry("ok.txt")])
            .expect_err("empty name in multi-file transfer must be rejected");
        assert_err_contains(err, "empty file name");
    }

    #[test]
    fn set_files_rejects_null_byte_name() {
        let mut job = new_validation_job(103);
        let err = job
            .set_files(vec![new_file_entry("bad\0name.txt")])
            .expect_err("null byte in file name must be rejected");
        assert_err_contains(err, "null bytes");
    }

    #[test]
    fn set_files_rejects_mixed_entries_when_one_is_traversal() {
        let mut job = new_validation_job(104);
        let err = job
            .set_files(vec![
                new_file_entry("safe/file.txt"),
                new_file_entry("../../escape.txt"),
            ])
            .expect_err("any traversal entry must reject the full file list");
        assert_err_contains(err, "path traversal");
    }

    #[cfg(windows)]
    #[test]
    fn set_files_rejects_unc_absolute_path() {
        let mut job = new_validation_job(105);
        let err = job
            .set_files(vec![new_file_entry("\\\\server\\share\\payload.txt")])
            .expect_err("UNC absolute path must be rejected");
        assert_err_contains(err, "absolute path");
    }

    #[cfg(not(windows))]
    #[test]
    fn set_files_allows_backslash_prefixed_name_on_unix() {
        let mut job = new_validation_job(105);
        assert!(job
            .set_files(vec![new_file_entry("\\\\server\\share\\payload.txt")])
            .is_ok());
    }

    #[test]
    fn remove_file_rejects_empty_path() {
        let err = remove_file("").expect_err("empty file path must be rejected");
        assert_err_contains(err, "cannot be empty");
    }

    #[test]
    fn remove_file_rejects_null_byte_path() {
        let err = remove_file("bad\0path").expect_err("null byte path must be rejected");
        assert_err_contains(err, "null bytes");
    }

    #[test]
    fn create_dir_rejects_empty_path() {
        let err = create_dir("").expect_err("empty directory path must be rejected");
        assert_err_contains(err, "cannot be empty");
    }

    #[test]
    fn create_dir_rejects_null_byte_path() {
        let err = create_dir("bad\0path").expect_err("null byte path must be rejected");
        assert_err_contains(err, "null bytes");
    }

    #[test]
    fn rename_file_rejects_invalid_new_name() {
        let tmp_root = TestTempDir::new("rustdesk_rename_invalid");
        let src = tmp_root.join("source.txt");
        std::fs::create_dir_all(&tmp_root.path).expect("create temp dir");
        std::fs::write(&src, b"content").expect("create source file");

        let src_str = src.to_string_lossy().to_string();

        let err_empty =
            rename_file(&src_str, "").expect_err("empty new file name must be rejected");
        assert_err_contains(err_empty, "cannot be empty");

        let err_traversal = rename_file(&src_str, "../escape.txt")
            .expect_err("traversal new file name must be rejected");
        assert_err_contains(err_traversal, "path traversal");

        let err_null = rename_file(&src_str, "bad\0name.txt")
            .expect_err("null byte in new file name must be rejected");
        assert_err_contains(err_null, "null bytes");

        #[cfg(windows)]
        {
            let err_abs = rename_file(&src_str, "C:\\Windows\\Temp\\payload.txt")
                .expect_err("absolute new file name must be rejected");
            assert_err_contains(err_abs, "absolute path");
        }
        #[cfg(not(windows))]
        {
            let err_abs = rename_file(&src_str, "/tmp/payload.txt")
                .expect_err("absolute new file name must be rejected");
            assert_err_contains(err_abs, "absolute path");
        }
    }

    #[test]
    fn rename_file_accepts_valid_new_name() {
        let tmp_root = TestTempDir::new("rustdesk_rename_ok");
        let src = tmp_root.join("rename_src.txt");
        let dst = tmp_root.join("renamed.txt");
        std::fs::create_dir_all(&tmp_root.path).expect("create temp dir");
        std::fs::write(&src, b"content").expect("create source file");

        let src_str = src.to_string_lossy().to_string();
        rename_file(&src_str, "renamed.txt").expect("rename should succeed");

        assert!(!src.exists());
        assert!(dst.exists());
    }

    #[cfg(windows)]
    #[test]
    fn set_files_rejects_windows_drive_absolute_path() {
        let mut job = new_validation_job(106);
        let err = job
            .set_files(vec![new_file_entry("C:\\Windows\\Temp\\payload.txt")])
            .expect_err("drive-letter absolute path must be rejected");
        assert_err_contains(err, "absolute path");
    }

    #[cfg(windows)]
    #[test]
    fn set_files_rejects_windows_verbatim_drive_absolute_path() {
        let mut job = new_validation_job(1061);
        let err = job
            .set_files(vec![new_file_entry(r"\\?\C:\Windows\Temp\x.txt")])
            .expect_err("verbatim drive absolute path must be rejected");
        assert_err_contains(err, "absolute path");
    }
}
