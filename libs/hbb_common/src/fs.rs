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
    compress::{compress, try_decompress},
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

fn checked_file_total_size(files: &[FileEntry]) -> ResultType<u64> {
    files.iter().try_fold(0u64, |total, file| {
        total
            .checked_add(file.size)
            .ok_or_else(|| anyhow!("file-transfer total size overflow"))
    })
}

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
    // BR-13: the `Printer` job type is excised with the remote-printer capability (a native
    // print-DRIVER surface, the class the fork minimizes — cf. enable-virtual-display). File
    // transfer keeps its one generic job type.
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
        }
    }
}

impl From<i32> for JobType {
    fn from(value: i32) -> Self {
        match value {
            0 => JobType::Generic,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TransferRole {
    Send,
    Receive,
}

impl Default for TransferRole {
    fn default() -> Self {
        Self::Send
    }
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

#[derive(Clone, Copy, Default, Eq, PartialEq, Serialize, Deserialize, Debug)]
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
    role: TransferRole,
    #[serde(skip_serializing)]
    data_stream: Option<DataStream>,
    #[serde(skip_serializing)]
    receive_write_claim: Option<ReceiveWriteClaim>,
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

/// True if `meta` is a symlink (all platforms) or — on Windows — any reparse point. `is_symlink()`
/// on Windows is true only for `IO_REPARSE_TAG_SYMLINK` and MISSES NTFS **junctions**
/// (`IO_REPARSE_TAG_MOUNT_POINT`), so this also tests `file_attributes() &
/// FILE_ATTRIBUTE_REPARSE_POINT` — the same junction-inclusive primitive used by
/// `src/platform/windows/acl.rs::is_reparse_point`. This is defense-in-depth atop the handle-
/// relative no-follow walk (that walk is the real R-S8 fix; a stat like this is a separate syscall
/// from the open and so TOCTOU-prone on its own — hence not the sole guard).
fn is_symlink_or_reparse_point(meta: &std::fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return true;
        }
    }
    meta.file_type().is_symlink()
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
                        if is_symlink_or_reparse_point(&meta) {
                            bail!(
                                "symlink or reparse-point (junction) path component is not allowed"
                            );
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
                let mut created = false;
                if create_missing {
                    let rc = unsafe {
                        crate::libc::mkdirat(
                            dir.as_raw_fd(),
                            name_c.as_ptr(),
                            0o777 as crate::libc::mode_t,
                        )
                    };
                    if rc == 0 {
                        created = true;
                    } else {
                        let err = std::io::Error::last_os_error();
                        if err.raw_os_error() != Some(crate::libc::EEXIST) {
                            return Err(err);
                        }
                    }
                }

                // A successful mkdirat publishes a new entry in `dir`. Persist that entry before
                // descending into it, otherwise a later file fsync cannot make a newly created
                // ancestor survive a crash. Existing directories need no creation barrier here.
                if created {
                    sync_recv_directory(&dir)?;
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

fn sync_recv_regular_file(file: &std::fs::File) -> std::io::Result<()> {
    file.sync_all()?;

    // Darwin's fsync only pushes host caches to the drive. F_FULLFSYNC additionally asks the
    // device to flush its own volatile cache. Keep this as one mandatory path rather than a
    // best-effort fallback: a filesystem that cannot provide the requested barrier must fail the
    // transaction instead of reporting durable completion.
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        use std::os::unix::io::AsRawFd;

        if unsafe {
            crate::libc::fcntl(
                file.as_raw_fd(),
                crate::libc::F_FULLFSYNC,
                0 as crate::libc::c_int,
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error());
        }
    }

    Ok(())
}

#[cfg(unix)]
fn sync_recv_directory(directory: &std::fs::File) -> std::io::Result<()> {
    directory.sync_all()
}

#[cfg(unix)]
fn sync_recv_parent_no_follow(path: &Path) -> std::io::Result<()> {
    let parent = open_parent_dir_no_follow(path.parent().unwrap_or_else(|| Path::new(".")), false)?;
    sync_recv_directory(&parent)
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

/// R-S8 / R-A5 — the WINDOWS equivalent of the Unix `openat(O_NOFOLLOW)` receive-write walk.
///
/// Win32 `CreateFileW` re-resolves the whole path from its string on every call, so a per-component
/// `CreateFileW(FILE_FLAG_OPEN_REPARSE_POINT)` still *follows* a junction / mount-point / symlink
/// planted on a **parent** directory between validation and write — the intermediate-directory
/// TOCTOU. The only user-mode primitive that opens a child *relative to a parent directory handle*
/// (the real `openat` analogue) is the NT layer: `NtCreateFile` with
/// `OBJECT_ATTRIBUTES{ RootDirectory = parent_handle, ObjectName = <bare component> }`. This module
/// opens the volume root once (Win32, backup-semantics + open-reparse-point — the analogue of the
/// Unix walk's `/` anchor), then walks each `Normal` component with `NtCreateFile` no-follow
/// (`FILE_OPEN_REPARSE_POINT | FILE_DIRECTORY_FILE`), fail-closed **rejecting** any component whose
/// handle reports `FILE_ATTRIBUTE_REPARSE_POINT` (catches NTFS **junctions**, `IO_REPARSE_TAG_
/// MOUNT_POINT`, *and* symlinks — the junctions that a plain `is_symlink()` misses). The final
/// target is opened relative to the walked parent handle and finalized handle-relative
/// (`NtSetInformationFile(FileRenameInformation, RootDirectory = parent)`), so no step ever
/// re-resolves a parent by path. This mirrors the Unix `open_parent_dir_no_follow` walk exactly and
/// closes the same intermediate-directory race on Windows; it is behavior-tested against a planted
/// NTFS junction in the `#[cfg(windows)]` tests below (validated in the §12.2 Windows build VM).
#[cfg(windows)]
mod nt_nofollow {
    use std::ffi::OsStr;
    use std::io;
    use std::mem::{size_of, zeroed};
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use std::path::{Component, Path, Prefix};
    use std::ptr::{copy_nonoverlapping, null_mut};

    use ntapi::ntioapi::{
        FileAttributeTagInformation, FileDispositionInformation, FileRenameInformation,
        NtCreateFile, NtQueryInformationFile, NtSetInformationFile, FILE_ATTRIBUTE_TAG_INFORMATION,
        FILE_DIRECTORY_FILE, FILE_DISPOSITION_INFORMATION, FILE_NON_DIRECTORY_FILE, FILE_OPEN,
        FILE_OPEN_FOR_BACKUP_INTENT, FILE_OPEN_IF, FILE_OPEN_REPARSE_POINT,
        FILE_RENAME_INFORMATION, FILE_SYNCHRONOUS_IO_NONALERT, IO_STATUS_BLOCK,
    };
    use winapi::shared::ntdef::{
        HANDLE, NTSTATUS, NT_SUCCESS, OBJECT_ATTRIBUTES, OBJ_CASE_INSENSITIVE, UNICODE_STRING,
    };
    use winapi::um::winbase::{FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT};
    use winapi::um::winnt::{
        DELETE, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT, FILE_GENERIC_READ,
        FILE_GENERIC_WRITE, FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE,
        FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TRAVERSE, FILE_WRITE_ATTRIBUTES, SYNCHRONIZE,
    };

    const SHARE_ALL: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
    // STATUS codes mapped to io::ErrorKind::NotFound so a missing artifact is a no-op (ENOENT twin).
    const STATUS_OBJECT_NAME_NOT_FOUND: NTSTATUS = 0xC000_0034u32 as NTSTATUS;
    const STATUS_OBJECT_PATH_NOT_FOUND: NTSTATUS = 0xC000_003Au32 as NTSTATUS;

    fn invalid(msg: &'static str) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidInput, msg)
    }

    fn nt_err(status: NTSTATUS) -> io::Error {
        if status == STATUS_OBJECT_NAME_NOT_FOUND || status == STATUS_OBJECT_PATH_NOT_FOUND {
            io::Error::from(io::ErrorKind::NotFound)
        } else {
            io::Error::new(
                io::ErrorKind::Other,
                format!("NTSTATUS 0x{:08x}", status as u32),
            )
        }
    }

    /// A `Normal` path component -> UTF-16, rejecting NUL / separators / drive-colon (defense in
    /// depth; `Path::components()` never yields these in a `Normal`, but the receive path is peer-
    /// influenced so we validate anyway).
    fn component_wide(os: &OsStr) -> io::Result<Vec<u16>> {
        let w: Vec<u16> = os.encode_wide().collect();
        if w.is_empty() {
            return Err(invalid("empty path component"));
        }
        if w.iter()
            .any(|&c| c == 0 || c == b'\\' as u16 || c == b'/' as u16 || c == b':' as u16)
        {
            return Err(invalid("illegal character in path component"));
        }
        Ok(w)
    }

    fn file_name_wide(path: &Path) -> io::Result<Vec<u16>> {
        component_wide(
            path.file_name()
                .ok_or_else(|| invalid("receive path has no file name"))?,
        )
    }

    fn parent_dir(path: &Path) -> io::Result<&Path> {
        path.parent()
            .ok_or_else(|| invalid("receive path has no parent directory"))
    }

    /// The core reparse-safe, handle-relative open — the `openat(O_NOFOLLOW)` analogue. `parent` is
    /// a directory HANDLE; `name` a bare component (UTF-16, not NUL-terminated). ALWAYS no-follow
    /// (`FILE_OPEN_REPARSE_POINT`) + synchronous, and ALWAYS fail-closed if the opened object is a
    /// reparse point (junction or symlink) — verified on the exact handle just opened, so there is
    /// no re-open and no window.
    unsafe fn nt_open_at(
        parent: HANDLE,
        name: &[u16],
        desired_access: u32,
        disposition: u32,
        create_options: u32,
    ) -> io::Result<OwnedHandle> {
        let nbytes = name
            .len()
            .checked_mul(2)
            .filter(|n| *n <= u16::MAX as usize)
            .ok_or_else(|| invalid("path component too long"))?;
        // `ustr`, `oa` (and the `name` slice) must all outlive the NtCreateFile call.
        let mut ustr = UNICODE_STRING {
            Length: nbytes as u16,        // bytes, not chars; no NUL counted
            MaximumLength: nbytes as u16, // bytes
            Buffer: name.as_ptr() as *mut u16,
        };
        let mut oa: OBJECT_ATTRIBUTES = zeroed();
        oa.Length = size_of::<OBJECT_ATTRIBUTES>() as u32;
        oa.RootDirectory = parent; // the openat anchor: resolve relative to this handle
        oa.ObjectName = &mut ustr;
        oa.Attributes = OBJ_CASE_INSENSITIVE; // Windows-native case handling

        let mut handle: HANDLE = null_mut();
        let mut iosb: IO_STATUS_BLOCK = zeroed();
        let status = NtCreateFile(
            &mut handle,
            // SYNCHRONIZE is mandatory with FILE_SYNCHRONOUS_IO_NONALERT; FILE_READ_ATTRIBUTES is
            // needed for the reparse query below (matches the cap-std reference).
            desired_access | SYNCHRONIZE | FILE_READ_ATTRIBUTES,
            &mut oa,
            &mut iosb,
            null_mut(),
            FILE_ATTRIBUTE_NORMAL,
            SHARE_ALL,
            disposition,
            create_options | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
            null_mut(),
            0,
        );
        if !NT_SUCCESS(status) {
            return Err(nt_err(status));
        }
        // Own the handle immediately so every error path closes it (no leak, no double-close).
        let owned = OwnedHandle::from_raw_handle(handle as _);

        let mut tag: FILE_ATTRIBUTE_TAG_INFORMATION = zeroed();
        let mut iosb2: IO_STATUS_BLOCK = zeroed();
        let st = NtQueryInformationFile(
            handle,
            &mut iosb2,
            (&mut tag as *mut FILE_ATTRIBUTE_TAG_INFORMATION).cast(),
            size_of::<FILE_ATTRIBUTE_TAG_INFORMATION>() as u32,
            FileAttributeTagInformation,
        );
        if !NT_SUCCESS(st) {
            // Fail closed: if we cannot prove it is NOT a reparse point, refuse.
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "R-S8: could not verify reparse status of receive-path component; refusing",
            ));
        }
        if tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "R-S8: reparse-point (NTFS junction or symlink) receive-path component is not allowed",
            ));
        }
        Ok(owned)
    }

    /// Open one intermediate directory component no-follow. Directories forbid generic rights — use
    /// list/traverse (+ read-attributes/SYNCHRONIZE added by `nt_open_at`). `create` mirrors the
    /// Unix walk's `mkdirat` (FILE_OPEN_IF creates the dir if absent).
    fn open_dir_at(parent: HANDLE, name: &[u16], create: bool) -> io::Result<OwnedHandle> {
        unsafe {
            nt_open_at(
                parent,
                name,
                FILE_LIST_DIRECTORY | FILE_TRAVERSE,
                if create { FILE_OPEN_IF } else { FILE_OPEN },
                FILE_DIRECTORY_FILE | FILE_OPEN_FOR_BACKUP_INTENT,
            )
        }
    }

    /// Open the volume root (`\\?\C:\`) as the walk anchor — the Windows analogue of the Unix walk's
    /// `/` root. Backup-semantics opens the directory; open-reparse-point keeps it no-follow.
    fn open_root_anchor(drive: u8) -> io::Result<OwnedHandle> {
        let root = format!(r"\\?\{}:\", drive as char);
        let f = std::fs::OpenOptions::new()
            .access_mode(FILE_LIST_DIRECTORY | FILE_TRAVERSE | FILE_READ_ATTRIBUTES | SYNCHRONIZE)
            .share_mode(SHARE_ALL)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&root)?;
        Ok(OwnedHandle::from(f))
    }

    /// Split an ABSOLUTE local path into (drive-letter, [Normal components]); reject `..`, non-disk
    /// prefixes (UNC / device namespace), and relative paths — fail-closed, since the receive base
    /// is always a local absolute drive path.
    fn decompose(path: &Path) -> io::Result<(u8, Vec<Vec<u16>>)> {
        let mut it = path.components();
        let drive = match it.next() {
            Some(Component::Prefix(p)) => match p.kind() {
                Prefix::Disk(d) | Prefix::VerbatimDisk(d) => d,
                _ => return Err(invalid("unsupported path prefix in receive path")),
            },
            _ => return Err(invalid("receive path is not an absolute drive path")),
        };
        match it.next() {
            Some(Component::RootDir) => {}
            _ => return Err(invalid("receive path is not rooted")),
        }
        let mut comps = Vec::new();
        for c in it {
            match c {
                Component::Normal(os) => comps.push(component_wide(os)?),
                Component::CurDir => {}
                Component::ParentDir => {
                    return Err(invalid("parent traversal is not allowed in receive path"))
                }
                Component::RootDir => {}
                Component::Prefix(_) => {
                    return Err(invalid("unexpected path prefix in receive path"))
                }
            }
        }
        Ok((drive, comps))
    }

    /// Walk to the parent directory handle reparse-safely (mirrors `open_parent_dir_no_follow`).
    /// Each reassignment keeps the previous handle alive across the `NtCreateFile` that consumes it.
    fn walk_to_parent(parent_path: &Path, create_missing: bool) -> io::Result<OwnedHandle> {
        let (drive, comps) = decompose(parent_path)?;
        let mut cur = open_root_anchor(drive)?;
        for name in &comps {
            cur = open_dir_at(cur.as_raw_handle() as HANDLE, name, create_missing)?;
        }
        Ok(cur)
    }

    unsafe fn nt_set_dispose_delete(handle: HANDLE) -> io::Result<()> {
        // ntapi 0.4 spells the field `DeleteFileA` (a naming artifact); it is the BOOLEAN DeleteFile.
        let mut info = FILE_DISPOSITION_INFORMATION { DeleteFileA: 1 };
        let mut iosb: IO_STATUS_BLOCK = zeroed();
        let st = NtSetInformationFile(
            handle,
            &mut iosb,
            (&mut info as *mut FILE_DISPOSITION_INFORMATION).cast(),
            size_of::<FILE_DISPOSITION_INFORMATION>() as u32,
            FileDispositionInformation,
        );
        if NT_SUCCESS(st) {
            Ok(())
        } else {
            Err(nt_err(st))
        }
    }

    /// Handle-relative rename via `NtSetInformationFile(FileRenameInformation)` — the `renameat`
    /// analogue. `target` is the source file handle (needs DELETE); `new_parent` the directory the
    /// new name is relative to; `new_name` a bare component. Replaces the destination *name* (never
    /// follows a symlink at the destination), matching Unix `renameat`.
    unsafe fn nt_rename_at(
        target: HANDLE,
        new_parent: HANDLE,
        new_name: &[u16],
        replace: bool,
    ) -> io::Result<()> {
        let name_bytes = new_name.len() * 2;
        let total = size_of::<FILE_RENAME_INFORMATION>() + name_bytes;
        // Vec<u64> guarantees the 8-byte alignment the embedded HANDLE requires.
        let mut buf = vec![0u64; (total + 7) / 8];
        let p = buf.as_mut_ptr() as *mut FILE_RENAME_INFORMATION;
        (*p).ReplaceIfExists = u8::from(replace);
        (*p).RootDirectory = new_parent;
        (*p).FileNameLength = name_bytes as u32;
        copy_nonoverlapping(
            new_name.as_ptr(),
            (*p).FileName.as_mut_ptr(),
            new_name.len(),
        );
        // Length = offset_of(FileName) + name bytes (the true header size; avoids trailing padding).
        let name_off = ((*p).FileName.as_ptr() as usize) - (p as usize);
        let length = (name_off + name_bytes) as u32;
        let mut iosb: IO_STATUS_BLOCK = zeroed();
        let st = NtSetInformationFile(target, &mut iosb, p.cast(), length, FileRenameInformation);
        if NT_SUCCESS(st) {
            Ok(())
        } else {
            Err(nt_err(st))
        }
    }

    // ---- crate-facing entry points (called by the `#[cfg(windows)]` branches of the receive path) ----

    /// R-S8/R-A5: open a receive-WRITE target reparse-safely (parent walk + no-follow child open).
    /// Uses FILE_OPEN_IF (never OVERWRITE_IF), so a reparse-point final component is rejected before
    /// the caller validates ownership/link authority and explicitly truncates the admitted handle.
    pub(super) fn open_recv_write(
        path: &Path,
        create_file: bool,
        create_parent: bool,
        readable: bool,
    ) -> io::Result<std::fs::File> {
        let parent = walk_to_parent(parent_dir(path)?, create_parent)?;
        let name = file_name_wide(path)?;
        let mut access = FILE_GENERIC_WRITE | DELETE | FILE_WRITE_ATTRIBUTES;
        if readable {
            access |= FILE_GENERIC_READ;
        }
        let owned = unsafe {
            nt_open_at(
                parent.as_raw_handle() as HANDLE,
                &name,
                access,
                if create_file { FILE_OPEN_IF } else { FILE_OPEN },
                FILE_NON_DIRECTORY_FILE,
            )?
        };
        Ok(std::fs::File::from(owned))
    }

    pub(super) fn delete_open_recv_file(file: &std::fs::File) -> io::Result<()> {
        unsafe { nt_set_dispose_delete(file.as_raw_handle() as HANDLE) }
    }

    pub(super) fn ensure_recv_path_matches_open_file(
        path: &Path,
        file: &std::fs::File,
    ) -> io::Result<()> {
        use winapi::um::fileapi::{GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION};

        fn identity(handle: HANDLE) -> io::Result<(u32, u32, u32)> {
            let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { zeroed() };
            if unsafe { GetFileInformationByHandle(handle, &mut info) } == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok((
                info.dwVolumeSerialNumber,
                info.nFileIndexHigh,
                info.nFileIndexLow,
            ))
        }

        let parent = walk_to_parent(parent_dir(path)?, false)?;
        let name = file_name_wide(path)?;
        let named = unsafe {
            nt_open_at(
                parent.as_raw_handle() as HANDLE,
                &name,
                FILE_READ_ATTRIBUTES,
                FILE_OPEN,
                FILE_NON_DIRECTORY_FILE,
            )?
        };
        if identity(named.as_raw_handle() as HANDLE)? != identity(file.as_raw_handle() as HANDLE)? {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "receive artifact generation changed while its lease was held",
            ));
        }
        Ok(())
    }

    pub(super) fn validate_recv_file_authority(file: &std::fs::File) -> io::Result<()> {
        use winapi::um::fileapi::{GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION};

        let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { zeroed() };
        if unsafe { GetFileInformationByHandle(file.as_raw_handle() as HANDLE, &mut info) } == 0 {
            return Err(io::Error::last_os_error());
        }
        if info.nNumberOfLinks != 1 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "receive artifact must have exactly one filesystem link",
            ));
        }
        Ok(())
    }

    /// R-S8/R-A5: finalize the receive write handle-relative — set the mtime on the admitted
    /// `.download` handle, discard the exact digest handle, and rename that SAME download handle
    /// onto the final name via `NtSetInformationFile(FileRenameInformation,
    /// RootDirectory=parent)`. A second flush through that exact renamed handle follows; failure
    /// there is explicitly reported as visible-but-durability-uncertain. Mirrors the Unix
    /// `renameat` finalize.
    pub(super) fn finish_recv_write(
        final_path: &Path,
        download_file: &std::fs::File,
        digest_file: &std::fs::File,
        mtime: filetime::FileTime,
        published: &mut bool,
    ) -> io::Result<()> {
        let parent = walk_to_parent(parent_dir(final_path)?, false)?;
        let ph = parent.as_raw_handle() as HANDLE;
        let final_name = file_name_wide(final_path)?;
        // Both handles were opened only after the caller acquired the destination lease. Delete the
        // exact digest object before publication, then make the exact admitted download handle the
        // final name. Any later flush failure is a distinct visible-but-uncertain outcome.
        filetime::set_file_handle_times(download_file, None, Some(mtime))?;
        super::sync_recv_regular_file(download_file)?;
        delete_open_recv_file(digest_file)?;
        unsafe {
            nt_rename_at(
                download_file.as_raw_handle() as HANDLE,
                ph,
                &final_name,
                true,
            )?
        };
        *published = true;
        // Flush again through the exact now-renamed handle. A failure is post-publication and must
        // be surfaced as outcome-uncertain, never as a claim that the destination stayed absent.
        super::sync_recv_regular_file(download_file)
            .map_err(super::visible_receive_commit_durability_error)?;
        Ok(())
    }

    /// R-S8/R-A5: read a receive sidecar (resume digest) handle-relative + no-follow, size-bounded.
    pub(super) fn read_recv_sidecar(path: &Path, max_bytes: u64) -> io::Result<String> {
        use std::io::Read;
        let parent = walk_to_parent(parent_dir(path)?, false)?;
        let name = file_name_wide(path)?;
        let owned = unsafe {
            nt_open_at(
                parent.as_raw_handle() as HANDLE,
                &name,
                FILE_GENERIC_READ,
                FILE_OPEN,
                FILE_NON_DIRECTORY_FILE,
            )?
        };
        let file = std::fs::File::from(owned);
        let mut reader = file.take(max_bytes.saturating_add(1));
        let mut content = String::new();
        reader.read_to_string(&mut content)?;
        if content.len() as u64 > max_bytes {
            return Err(invalid("receive sidecar is too large"));
        }
        Ok(content)
    }
}

/// R-S8 / R-A5: open a file-transfer RECEIVE-write target with NO-FOLLOW semantics across the
/// whole parent path, not just the final component. When parent creation is authorized, the Unix
/// path creates/opens every parent directory via `mkdirat`/`openat(O_DIRECTORY|O_NOFOLLOW)`; resume
/// and confirmation use the same walk without creation. The target opens with `openat(O_NOFOLLOW)`,
/// rejecting symlinks, FIFOs, devices, and other non-regular targets. Windows performs the identical
/// create-or-open walk with `NtCreateFile` + `OBJECT_ATTRIBUTES.RootDirectory` (see the
/// `nt_nofollow` module above), rejecting NTFS junctions and symlinks on every component. Both close
/// the intermediate-directory race documented in HARDENING_STATUS: a local user cannot swap a
/// parent directory for a reparse point between validation and the peer's write.
fn open_recv_file_no_follow_std(
    path: &Path,
    truncate: bool,
    create_file: bool,
    create_parent: bool,
    readable: bool,
) -> std::io::Result<std::fs::File> {
    let file = {
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;

            let parent = open_parent_dir_no_follow(
                path.parent().unwrap_or_else(|| Path::new(".")),
                create_parent,
            )?;
            let name = cstring_file_name(path)?;
            let mut flags = (if readable {
                crate::libc::O_RDWR
            } else {
                crate::libc::O_WRONLY
            }) | crate::libc::O_CLOEXEC
                | crate::libc::O_NOFOLLOW
                | crate::libc::O_NONBLOCK
                | crate::libc::O_NOCTTY;
            if create_file {
                flags |= crate::libc::O_CREAT;
            }
            open_regular_child_no_follow(parent.as_raw_fd(), &name, flags, 0o600)
        }

        #[cfg(windows)]
        {
            nt_nofollow::open_recv_write(path, create_file, create_parent, readable)
        }

        #[cfg(all(not(unix), not(windows)))]
        {
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true)
                .read(readable)
                .create(create_file)
                .truncate(false);
            opts.open(path)
        }
    }?;
    validate_recv_file_authority(&file)?;
    if truncate {
        file.set_len(0)?;
    }
    Ok(file)
}

fn validate_recv_file_authority(file: &std::fs::File) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        let metadata = file.metadata()?;
        if metadata.uid() != unsafe { crate::libc::geteuid() as u32 } {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "receive artifact is not owned by the receiving process identity",
            ));
        }
        if metadata.nlink() != 1 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "receive artifact must have exactly one filesystem link",
            ));
        }
        return Ok(());
    }

    #[cfg(windows)]
    {
        nt_nofollow::validate_recv_file_authority(file)
    }

    #[cfg(all(not(unix), not(windows)))]
    {
        let _ = file;
        Ok(())
    }
}

#[cfg(test)]
fn open_recv_write_no_follow_std(path: &Path, truncate: bool) -> std::io::Result<std::fs::File> {
    open_recv_file_no_follow_std(path, truncate, true, true, false)
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

#[cfg(any(unix, windows))]
fn ensure_recv_path_matches_open_file(path: &Path, file: &std::fs::File) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::{fs::MetadataExt, io::AsRawFd};

        let parent =
            open_parent_dir_no_follow(path.parent().unwrap_or_else(|| Path::new(".")), false)?;
        let name = cstring_file_name(path)?;
        let named = fstatat_regular_no_follow(parent.as_raw_fd(), &name)?
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound))?;
        let opened = file.metadata()?;
        if named.st_dev as u64 != opened.dev() || named.st_ino as u64 != opened.ino() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "receive artifact generation changed while its lease was held",
            ));
        }
        return Ok(());
    }

    #[cfg(windows)]
    {
        nt_nofollow::ensure_recv_path_matches_open_file(path, file)
    }
}

fn remove_open_recv_file_no_follow(path: &Path, file: &std::fs::File) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;

        ensure_recv_path_matches_open_file(path, file)?;
        let parent =
            open_parent_dir_no_follow(path.parent().unwrap_or_else(|| Path::new(".")), false)?;
        let name = cstring_file_name(path)?;
        return unlink_recv_child_no_follow(parent.as_raw_fd(), &name);
    }

    #[cfg(windows)]
    {
        let _ = path;
        return nt_nofollow::delete_open_recv_file(file);
    }

    #[cfg(all(not(unix), not(windows)))]
    {
        let _ = file;
        std::fs::remove_file(path)
    }
}

fn remove_receive_artifacts_and_sync_parent(
    final_path: &Path,
    artifacts: &[(&Path, &std::fs::File)],
) -> std::io::Result<()> {
    let mut first_error = None;
    for (path, file) in artifacts {
        if let Err(error) = remove_open_recv_file_no_follow(path, file) {
            if first_error.is_none() {
                first_error = Some(error);
            } else {
                log::warn!(
                    "additional receive cleanup failure for {}: {}",
                    path.display(),
                    error
                );
            }
        }
    }

    // Persist every namespace removal that did succeed, even when another exact artifact could
    // not be removed. Only a fully successful barrier permits retirement of the stable lock name.
    #[cfg(unix)]
    if let Err(error) = sync_recv_parent_no_follow(final_path) {
        if first_error.is_none() {
            first_error = Some(error);
        } else {
            log::warn!(
                "additional receive cleanup directory synchronization failure for {}: {}",
                final_path.display(),
                error
            );
        }
    }
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    if let Some((_, file)) = artifacts.first() {
        if let Err(error) = sync_recv_regular_file(file) {
            if first_error.is_none() {
                first_error = Some(error);
            } else {
                log::warn!(
                    "additional receive cleanup full-storage synchronization failure for {}: {}",
                    final_path.display(),
                    error
                );
            }
        }
    }

    match first_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

fn visible_receive_commit_durability_error(error: std::io::Error) -> std::io::Error {
    std::io::Error::new(
        error.kind(),
        format!(
            "received file is visible, but commit durability is uncertain because the final namespace synchronization failed: {error}"
        ),
    )
}

fn finish_recv_write_no_follow(
    path: &Path,
    download_file: &std::fs::File,
    digest_file: &std::fs::File,
    modified_time: u64,
    published: &mut bool,
) -> std::io::Result<()> {
    if *published {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "receive generation is already published",
        ));
    }
    let mtime = filetime::FileTime::from_unix_time(modified_time as _, 0);
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;

        let parent =
            open_parent_dir_no_follow(path.parent().unwrap_or_else(|| Path::new(".")), false)?;
        let final_name = cstring_file_name(path)?;
        let download_path = recv_sidecar_path(path, ".download");
        let download_name = cstring_file_name(&download_path)?;
        filetime::set_file_handle_times(&download_file, None, Some(mtime))?;
        sync_recv_regular_file(download_file)?;
        ensure_recv_path_matches_open_file(&download_path, download_file)?;
        remove_open_recv_file_no_follow(&recv_sidecar_path(path, ".digest"), digest_file)?;
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
        *published = true;
        // File-data synchronization does not persist the containing directory entry. The rename
        // is already visible if this barrier fails, so return an explicit outcome-uncertain error
        // rather than pretending the publication did not happen.
        sync_recv_directory(&parent).map_err(visible_receive_commit_durability_error)?;
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        sync_recv_regular_file(download_file).map_err(visible_receive_commit_durability_error)?;
        return Ok(());
    }

    #[cfg(windows)]
    {
        nt_nofollow::finish_recv_write(path, download_file, digest_file, mtime, published)
    }

    #[cfg(all(not(unix), not(windows)))]
    {
        let download_path = recv_sidecar_path(path, ".download");
        let digest_path = recv_sidecar_path(path, ".digest");
        filetime::set_file_handle_times(download_file, None, Some(mtime))?;
        sync_recv_regular_file(download_file)?;
        remove_open_recv_file_no_follow(&digest_path, digest_file)?;
        std::fs::rename(download_path, path)?;
        *published = true;
        sync_recv_regular_file(download_file).map_err(visible_receive_commit_durability_error)?;
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

    #[cfg(windows)]
    {
        nt_nofollow::read_recv_sidecar(path, max_bytes)
    }

    #[cfg(all(not(unix), not(windows)))]
    {
        let _ = max_bytes;
        std::fs::read_to_string(path)
    }
}

fn acquire_receive_path_lock(file: &std::fs::File) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;

        if unsafe {
            crate::libc::flock(
                file.as_raw_fd(),
                crate::libc::LOCK_EX | crate::libc::LOCK_NB,
            )
        } == 0
        {
            return Ok(());
        }
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(crate::libc::EWOULDBLOCK)
            || err.raw_os_error() == Some(crate::libc::EAGAIN)
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "another receive job owns this destination",
            ));
        }
        return Err(err);
    }

    #[cfg(windows)]
    {
        use std::{mem::zeroed, os::windows::io::AsRawHandle};
        use winapi::um::{
            fileapi::LockFileEx,
            minwinbase::OVERLAPPED,
            winbase::{LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY},
            winnt::HANDLE,
        };

        let mut overlapped: OVERLAPPED = unsafe { zeroed() };
        if unsafe {
            LockFileEx(
                file.as_raw_handle() as HANDLE,
                LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
                0,
                u32::MAX,
                u32::MAX,
                &mut overlapped,
            )
        } != 0
        {
            return Ok(());
        }
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(winapi::shared::winerror::ERROR_LOCK_VIOLATION as i32) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "another receive job owns this destination",
            ));
        }
        return Err(err);
    }

    #[cfg(all(not(unix), not(windows)))]
    {
        let _ = file;
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "receive destination leases are unsupported on this platform",
        ))
    }
}

fn release_receive_path_lock(file: &std::fs::File) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;

        if unsafe { crate::libc::flock(file.as_raw_fd(), crate::libc::LOCK_UN) } == 0 {
            return Ok(());
        }
        return Err(std::io::Error::last_os_error());
    }

    #[cfg(windows)]
    {
        use std::{mem::zeroed, os::windows::io::AsRawHandle};
        use winapi::um::{fileapi::UnlockFileEx, minwinbase::OVERLAPPED, winnt::HANDLE};

        let mut overlapped: OVERLAPPED = unsafe { zeroed() };
        if unsafe {
            UnlockFileEx(
                file.as_raw_handle() as HANDLE,
                0,
                u32::MAX,
                u32::MAX,
                &mut overlapped,
            )
        } != 0
        {
            return Ok(());
        }
        return Err(std::io::Error::last_os_error());
    }

    #[cfg(all(not(unix), not(windows)))]
    {
        let _ = file;
        Ok(())
    }
}

#[derive(Debug)]
struct ReceivePathLease {
    path: PathBuf,
    file: std::fs::File,
    retire_on_drop: bool,
}

impl ReceivePathLease {
    fn acquire(final_path: &Path, create_parent: bool) -> std::io::Result<Self> {
        let path = recv_sidecar_path(final_path, ".download.lock");
        let file = open_recv_file_no_follow_std(&path, false, true, create_parent, false)?;
        acquire_receive_path_lock(&file)?;
        #[cfg(any(unix, windows))]
        ensure_recv_path_matches_open_file(&path, &file)?;
        sync_recv_regular_file(&file)?;
        #[cfg(unix)]
        sync_recv_parent_no_follow(final_path)?;
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        sync_recv_regular_file(&file)?;
        Ok(Self {
            path,
            file,
            retire_on_drop: false,
        })
    }

    fn retire(&mut self) {
        self.retire_on_drop = true;
    }
}

impl Drop for ReceivePathLease {
    fn drop(&mut self) {
        // A pathname-based advisory lock must keep one stable inode for as long as resumable state
        // exists. Once the owner has committed or removed every admitted artifact, it is safe to
        // retire that inode while still holding its lock: a new owner may start on a new inode, but
        // this retiring owner has no destination state left to mutate.
        if self.retire_on_drop {
            if let Err(err) =
                remove_receive_artifacts_and_sync_parent(&self.path, &[(&self.path, &self.file)])
            {
                log::warn!(
                    "cannot durably retire receive destination lease {}: {}",
                    self.path.display(),
                    err
                );
            }
        }
        if let Err(err) = release_receive_path_lock(&self.file) {
            log::warn!(
                "cannot release receive destination lease {}: {}",
                self.path.display(),
                err
            );
        }
    }
}

#[derive(Debug)]
struct ReceiveWriteClaim {
    final_path: PathBuf,
    download_file: std::fs::File,
    digest_file: std::fs::File,
    published: bool,
    _lease: ReceivePathLease,
}

impl ReceiveWriteClaim {
    fn start_new(final_path: PathBuf, digest: FileDigest) -> ResultType<(Self, std::fs::File)> {
        use std::io::Write;

        let mut lease = ReceivePathLease::acquire(&final_path, true)?;
        let download_path = recv_sidecar_path(&final_path, ".download");
        let digest_path = recv_sidecar_path(&final_path, ".digest");
        let download_file =
            match open_recv_file_no_follow_std(&download_path, true, true, false, false) {
                Ok(file) => file,
                Err(err) => {
                    lease.retire();
                    return Err(err.into());
                }
            };
        let mut digest_file =
            match open_recv_file_no_follow_std(&digest_path, true, true, false, true) {
                Ok(file) => file,
                Err(err) => {
                    if let Err(cleanup_err) = remove_receive_artifacts_and_sync_parent(
                        &final_path,
                        &[(&download_path, &download_file)],
                    ) {
                        log::warn!(
                            "cannot clean admitted receive artifact {}: {}",
                            download_path.display(),
                            cleanup_err
                        );
                    } else {
                        lease.retire();
                    }
                    return Err(err.into());
                }
            };
        let prepared = (|| -> ResultType<_> {
            sync_recv_regular_file(&download_file)?;
            digest_file.write_all(json!(digest).to_string().as_bytes())?;
            sync_recv_regular_file(&digest_file)?;
            #[cfg(unix)]
            sync_recv_parent_no_follow(&final_path)?;
            #[cfg(any(target_os = "macos", target_os = "ios"))]
            sync_recv_regular_file(&digest_file)?;
            Ok(download_file.try_clone()?)
        })();
        let stream_file = match prepared {
            Ok(file) => file,
            Err(err) => {
                if let Err(cleanup_err) = remove_receive_artifacts_and_sync_parent(
                    &final_path,
                    &[
                        (&digest_path, &digest_file),
                        (&download_path, &download_file),
                    ],
                ) {
                    log::warn!(
                        "cannot durably clean failed receive setup for {}: {}",
                        final_path.display(),
                        cleanup_err
                    );
                } else {
                    lease.retire();
                }
                return Err(err);
            }
        };
        Ok((
            Self {
                final_path,
                download_file,
                digest_file,
                published: false,
                _lease: lease,
            },
            stream_file,
        ))
    }

    fn resume(
        final_path: PathBuf,
        expected_digest: FileDigest,
    ) -> ResultType<(Self, std::fs::File)> {
        use std::io::Read;

        let lease = ReceivePathLease::acquire(&final_path, false)?;
        let download_path = recv_sidecar_path(&final_path, ".download");
        let digest_path = recv_sidecar_path(&final_path, ".digest");
        let mut digest_file =
            open_recv_file_no_follow_std(&digest_path, false, false, false, true)?;
        let mut content = String::new();
        (&mut digest_file).take(4097).read_to_string(&mut content)?;
        if content.len() > 4096 {
            bail!("resume digest is too large");
        }
        let stored_digest: FileDigest = serde_json::from_str(&content)?;
        if stored_digest != expected_digest {
            bail!("resume digest does not match the active transfer");
        }
        let download_file =
            open_recv_file_no_follow_std(&download_path, false, false, false, false)?;
        let stream_file = download_file.try_clone()?;
        Ok((
            Self {
                final_path,
                download_file,
                digest_file,
                published: false,
                _lease: lease,
            },
            stream_file,
        ))
    }

    fn finish(&mut self, modified_time: u64) -> std::io::Result<()> {
        let result = finish_recv_write_no_follow(
            &self.final_path,
            &self.download_file,
            &self.digest_file,
            modified_time,
            &mut self.published,
        );
        if result.is_ok() {
            self._lease.retire();
        }
        result
    }

    fn cleanup(mut self) {
        if self.published {
            let result = (|| -> std::io::Result<()> {
                #[cfg(unix)]
                sync_recv_parent_no_follow(&self.final_path)?;
                sync_recv_regular_file(&self.download_file)
            })();
            if let Err(error) = result {
                log::warn!(
                    "cannot recover uncertain published receive durability for {}: {}",
                    self.final_path.display(),
                    error
                );
            } else {
                self._lease.retire();
            }
            return;
        }

        let digest_path = recv_sidecar_path(&self.final_path, ".digest");
        let download_path = recv_sidecar_path(&self.final_path, ".download");
        if let Err(error) = remove_receive_artifacts_and_sync_parent(
            &self.final_path,
            &[
                (&digest_path, &self.digest_file),
                (&download_path, &self.download_file),
            ],
        ) {
            log::warn!(
                "cannot durably clean receive artifacts for {}: {}",
                self.final_path.display(),
                error
            );
        } else {
            self._lease.retire();
        }
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
            role: TransferRole::Receive,
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
                let total_size = checked_file_total_size(&files)?;
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
            role: TransferRole::Send,
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
        if self.file_num < 0 || self.file_num as usize > files.len() {
            bail!(
                "initial file number {} is outside the admitted file list ({} files)",
                self.file_num,
                files.len()
            );
        }
        self.total_size = checked_file_total_size(&files)?;
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

    async fn finish_current_write_file(&mut self) -> ResultType<()> {
        let DataSource::FilePath(base) = &self.data_source else {
            return Ok(());
        };
        if self.file_num < 0 || self.file_num as usize >= self.files.len() {
            bail!("invalid active write file number {}", self.file_num);
        }
        let entry = &self.files[self.file_num as usize];
        let modified_time = entry.modified_time;
        let path = self
            .resolve_entry_path(base, &entry.name)
            .ok_or_else(|| anyhow!("invalid receive-write path for file {}", self.file_num))?;
        if self
            .receive_write_claim
            .as_ref()
            .map(|claim| &claim.final_path)
            != Some(&path)
        {
            bail!(
                "write file {} does not own its receive artifact",
                self.file_num
            );
        }
        let stream = self
            .data_stream
            .take()
            .ok_or_else(|| anyhow!("write file {} has no admitted data stream", self.file_num))?;
        match stream {
            DataStream::FileStream(file) => file.sync_all().await?,
            DataStream::BufStream(_) => {
                bail!("file-backed write job owns an in-memory data stream")
            }
        }
        let claim = self
            .receive_write_claim
            .take()
            .ok_or_else(|| anyhow!("write file {} lost its receive claim", self.file_num))?;
        let (claim, result) = tokio::task::spawn_blocking(move || {
            let mut claim = claim;
            let result = claim.finish(modified_time);
            (claim, result)
        })
        .await?;
        if let Err(err) = result {
            self.receive_write_claim = Some(claim);
            return Err(err.into());
        }
        drop(claim);
        Ok(())
    }

    /// Commit the exact receive-write job after the sender's terminal `Done` index.
    ///
    /// The sender advances its file number after emitting the final (possibly empty) block, so an
    /// active stream must finish at `self.file_num + 1`. A job with no active stream is complete
    /// only when its current index is already the end of the admitted list (an empty or skipped
    /// transfer). Anything else is an incomplete or stale terminal command, not success.
    pub async fn finalize_write(&mut self, done_file_num: i32) -> ResultType<()> {
        if self.role != TransferRole::Receive {
            bail!("cannot finalize a send job as a receive write");
        }
        if self.data_stream.is_some() {
            let expected = self
                .file_num
                .checked_add(1)
                .ok_or_else(|| anyhow!("write file number overflow"))?;
            if done_file_num != expected {
                bail!(
                    "terminal file number {} does not follow active file {}",
                    done_file_num,
                    self.file_num
                );
            }
            self.finish_current_write_file().await?;
            self.file_num = done_file_num;
            return Ok(());
        }

        if self.file_num < 0
            || self.file_num as usize != self.files.len()
            || done_file_num != self.file_num
        {
            bail!(
                "write job is incomplete at file {} of {} (terminal file {})",
                self.file_num,
                self.files.len(),
                done_file_num
            );
        }
        Ok(())
    }

    pub fn remove_download_file(&mut self) {
        // Close the receive handle before unlinking. Unix permits unlinking an open file, but
        // Windows does not generally permit deletion while this job still owns the handle.
        drop(self.data_stream.take());
        if self.role != TransferRole::Receive {
            return;
        }
        if let Some(claim) = self.receive_write_claim.take() {
            claim.cleanup();
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
        if self.role != TransferRole::Receive {
            bail!("cannot write an incoming block into a send job");
        }
        if block.id != self.id {
            bail!("Wrong id");
        }
        if matches!(&self.data_source, DataSource::FilePath(_)) {
            if block.file_num < 0 {
                bail!("Wrong file number");
            }
            let file_num = block.file_num as usize;
            if file_num >= self.files.len() {
                bail!("Wrong file number");
            }
            if block.file_num != self.file_num {
                let expected = self
                    .file_num
                    .checked_add(1)
                    .ok_or_else(|| anyhow!("write file number overflow"))?;
                if block.file_num != expected {
                    bail!(
                        "unexpected write file transition from {} to {}",
                        self.file_num,
                        block.file_num
                    );
                }
                self.finish_current_write_file().await?;
                self.file_num = block.file_num;
            }
            if self.data_stream.is_none() {
                if self.receive_write_claim.is_some() {
                    bail!("receive write claim exists without its data stream");
                }
                let base = match &self.data_source {
                    DataSource::FilePath(base) => base,
                    DataSource::MemoryCursor(_) => {
                        bail!("file-path write branch changed data-source variant")
                    }
                };
                let entry = &self.files[file_num];
                let final_path = join_validated_path(base, &entry.name)?;
                let digest = self.digest;
                let (claim, stream_file) = tokio::task::spawn_blocking(move || {
                    ReceiveWriteClaim::start_new(final_path, digest)
                })
                .await??;
                self.data_stream = Some(DataStream::FileStream(File::from_std(stream_file)));
                self.receive_write_claim = Some(claim);
            }
        } else if self.data_stream.is_none() {
            let cursor = match &self.data_source {
                DataSource::MemoryCursor(cursor) => cursor.clone(),
                DataSource::FilePath(_) => {
                    bail!("in-memory write branch changed data-source variant")
                }
            };
            self.data_stream = Some(DataStream::BufStream(TokioBufStream::new(cursor)));
        }
        let transferred = self
            .transferred
            .checked_add(block.data.len() as u64)
            .ok_or_else(|| anyhow!("transferred byte counter overflow"))?;
        if block.compressed {
            let tmp = try_decompress(&block.data)?;
            let finished_size = self
                .finished_size
                .checked_add(tmp.len() as u64)
                .ok_or_else(|| anyhow!("finished byte counter overflow"))?;
            self.data_stream
                .as_mut()
                .ok_or(anyhow!("data stream is None"))?
                .write_all(&tmp)
                .await?;
            self.finished_size = finished_size;
        } else {
            let finished_size = self
                .finished_size
                .checked_add(block.data.len() as u64)
                .ok_or_else(|| anyhow!("finished byte counter overflow"))?;
            self.data_stream
                .as_mut()
                .ok_or(anyhow!("file is None"))?
                .write_all(&block.data)
                .await?;
            self.finished_size = finished_size;
        }
        self.transferred = transferred;
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

    async fn init_data_stream(
        &mut self,
        stream: &mut crate::Stream,
    ) -> ResultType<Option<crate::tcp::WriterReceipt>> {
        if self.open_data_stream().await? {
            return Ok(None);
        }
        if self.r#type == JobType::Generic
            && self.enable_overwrite_detection
            && !self.file_confirmed()
            && !self.file_is_waiting()
        {
            let receipt = self.send_current_digest(stream).await?;
            self.set_file_is_waiting(true);
            return Ok(Some(receipt));
        }
        Ok(None)
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
        if self.role != TransferRole::Send {
            bail!("cannot read an outgoing block from a receive job");
        }
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
            let finished_size = self
                .finished_size
                .checked_add(offset as u64)
                .ok_or_else(|| anyhow!("finished byte counter overflow"))?;
            if matches!(self.data_source, DataSource::FilePath(_)) && !is_compressed_file(name) {
                let tmp = compress(&buf);
                if tmp.len() < buf.len() {
                    buf = tmp;
                    compressed = true;
                }
            }
            let transferred = self
                .transferred
                .checked_add(buf.len() as u64)
                .ok_or_else(|| anyhow!("transferred byte counter overflow"))?;
            self.finished_size = finished_size;
            self.transferred = transferred;
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
    async fn send_current_digest(
        &mut self,
        stream: &mut Stream,
    ) -> ResultType<crate::tcp::WriterReceipt> {
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
        let receipt = stream.send_with_receipt(&msg).await?;
        log::info!(
            "id: {}, file_num: {}, digest message is admitted. waiting for confirm. msg: {:?}",
            self.id,
            self.file_num,
            msg
        );
        Ok(receipt)
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
        self.remove_download_file();
        self.set_file_confirmed(false);
        self.set_file_is_waiting(false);
        self.file_num += 1;
        self.file_skipped = true;
        true
    }

    async fn set_stream_offset(&mut self, file_num: usize, offset: u64) -> ResultType<()> {
        if let DataSource::FilePath(p) = &self.data_source {
            // §20 post-key DoS bound (defensive — mirrors write()'s "Wrong file number" guard):
            // file_num arrives from a peer FileTransferSendConfirmRequest. confirm() gates it on
            // self.file_num(), but that defaults to 0 and self.files can be empty (e.g. an
            // empty-directory send job), so a crafted confirm(file_num=0, OffsetBlk>0) would index
            // out of bounds and panic the connection task. Fail closed instead of indexing.
            if file_num >= self.files.len() {
                bail!("confirmation file number {} is out of range", file_num);
            }
            let entry = &self.files[file_num];
            let path = self
                .resolve_entry_path(p, &entry.name)
                .ok_or_else(|| anyhow!("invalid confirmation path for file {}", file_num))?;
            let file_path = get_string(&path);
            let transferred = self
                .transferred
                .checked_add(offset)
                .ok_or_else(|| anyhow!("transferred byte counter overflow"))?;
            let finished_size = self
                .finished_size
                .checked_add(offset)
                .ok_or_else(|| anyhow!("finished byte counter overflow"))?;
            let (mut f, receive_write_claim) = match self.role {
                TransferRole::Receive => {
                    if self.receive_write_claim.is_some() {
                        bail!("receive write job already owns a destination claim");
                    }
                    let digest = self.digest;
                    let (claim, stream_file) = tokio::task::spawn_blocking(move || {
                        ReceiveWriteClaim::resume(path, digest)
                    })
                    .await??;
                    (File::from_std(stream_file), Some(claim))
                }
                TransferRole::Send => (File::open(&file_path).await?, None),
            };
            let available = f.metadata().await?.len();
            if offset > available {
                bail!(
                    "confirmed offset {} exceeds file length {}",
                    offset,
                    available
                );
            }
            f.seek(std::io::SeekFrom::Start(offset)).await?;
            self.data_stream = Some(DataStream::FileStream(f));
            self.receive_write_claim = receive_write_claim;
            self.transferred = transferred;
            self.finished_size = finished_size;
            return Ok(());
        }
        bail!("cannot seek an in-memory transfer to a confirmed file offset")
    }

    pub async fn confirm(&mut self, r: &FileTransferSendConfirmRequest) -> ResultType<()> {
        if r.id != self.id {
            bail!(
                "confirmation job {} does not match active job {}",
                r.id,
                self.id
            );
        }
        if self.file_num() != r.file_num {
            bail!(
                "confirmation file {} does not match active file {}",
                r.file_num,
                self.file_num()
            );
        }
        if self.file_confirmed() {
            bail!("file {} is already confirmed", self.file_num());
        }
        match r.union {
            Some(file_transfer_send_confirm_request::Union::Skip(s)) => {
                if s {
                    self.set_file_skipped();
                } else {
                    self.set_file_confirmed(true);
                }
            }
            Some(file_transfer_send_confirm_request::Union::OffsetBlk(offset)) => {
                // A nonzero resume offset is admitted only after the exact local stream is open
                // and positioned. Publishing confirmation before that would let the peer continue
                // from an offset against a truncated or absent destination.
                if offset > 0 {
                    self.set_stream_offset(r.file_num as usize, offset as u64)
                        .await?;
                }
                self.set_file_confirmed(true);
            }
            None => bail!("confirmation has no action"),
        }
        Ok(())
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

async fn init_jobs(
    jobs: &mut Vec<TransferJob>,
    stream: &mut crate::Stream,
) -> ResultType<Option<crate::tcp::WriterReceipt>> {
    let Some(job) = jobs.iter_mut().find(|job| !job.is_last_job) else {
        return Ok(None);
    };
    match job.init_data_stream(stream).await {
        Ok(receipt) => Ok(receipt),
        Err(err) => {
            let receipt = stream
                .send_with_receipt(&new_error(job.id(), err, job.file_num()))
                .await?;
            Ok(Some(receipt))
        }
    }
}

pub async fn handle_read_jobs(
    jobs: &mut Vec<TransferJob>,
    stream: &mut crate::Stream,
) -> ResultType<(String, Option<crate::tcp::WriterReceipt>)> {
    // Preserve the one-job-at-a-time contract below all the way through initialization. Every call
    // returns ownership of at most one exact writer completion to the connection loop.
    if let Some(receipt) = init_jobs(jobs, stream).await? {
        return Ok((String::new(), Some(receipt)));
    }

    let mut job_log = Default::default();
    let mut finished = Vec::new();
    let mut receipt = None;
    for job in jobs.iter_mut() {
        if job.is_last_job {
            continue;
        }
        match job.read().await {
            Err(err) => {
                receipt = Some(
                    stream
                        .send_with_receipt(&new_error(job.id(), err, job.file_num()))
                        .await?,
                );
            }
            Ok(Some(block)) => {
                receipt = Some(stream.send_with_receipt(&new_block(block)).await?);
            }
            Ok(None) => {
                if job.job_completed() {
                    job_log = serialize_transfer_job(job, true, false, "");
                    finished.push(job.id());
                    match job.job_error() {
                        Some(err) => {
                            job_log = serialize_transfer_job(job, false, false, &err);
                            receipt = Some(
                                stream
                                    .send_with_receipt(&new_error(job.id(), err, job.file_num()))
                                    .await?,
                            );
                        }
                        None => {
                            receipt = Some(
                                stream
                                    .send_with_receipt(&new_done(job.id(), job.file_num()))
                                    .await?,
                            );
                        }
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
    Ok((job_log, receipt))
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
    // Inspection and mutation use the same destination lease. This makes the observed digest and
    // partial length one coherent snapshot; the later resume/open reacquires the lease and validates
    // the digest again before publishing stream ownership.
    let mut lease = match ReceivePathLease::acquire(path, false) {
        Ok(lease) => lease,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Ok(DigestCheckResult::NoSuchFile)
        }
        Err(err) => return Err(err.into()),
    };
    let result = (|| {
        let digest_file = format!("{}.digest", file_path);
        let download_file = format!("{}.download", file_path);
        if is_resume && Path::new(&digest_file).exists() && Path::new(&download_file).exists() {
            // If the digest file exists, it means the file was transferred before.
            // We can use the digest file to check whether the file is the same.
            if let Ok(content) =
                read_recv_sidecar_to_string_no_follow(Path::new(&digest_file), 4096)
            {
                if let Ok(local_digest) = serde_json::from_str::<FileDigest>(&content) {
                    let is_identical = local_digest.modified == digest.last_modified
                        && local_digest.size == digest.file_size;
                    if is_identical {
                        if let Ok(download_file) = open_recv_file_no_follow_std(
                            Path::new(&download_file),
                            false,
                            false,
                            false,
                            false,
                        ) {
                            // Get the file size of the local file
                            // Only send confirmation if the file is not empty.
                            let transferred_size = download_file.metadata()?.len();
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
    })();
    lease.retire();
    result
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
    use crate::protobuf::Message as _;

    #[tokio::test]
    async fn r_s11fg_read_step_returns_the_exact_file_frame_receipt() {
        let (sender_side, receiver_side) = tokio::io::duplex(64);
        let local_addr = std::net::SocketAddr::from(([127, 0, 0, 1], 0));
        let mut sender_tcp = crate::tcp::FramedStream::from(sender_side, local_addr);
        let mut receiver_tcp = crate::tcp::FramedStream::from(receiver_side, local_addr);
        sender_tcp.set_max_packet_length(8 * 1024);
        receiver_tcp.set_max_packet_length(8 * 1024);
        sender_tcp.set_session_keys(crate::cpace::DirectionalKeys {
            send: [0x51; 32],
            recv: [0x62; 32],
        });
        receiver_tcp.set_session_keys(crate::cpace::DirectionalKeys {
            send: [0x62; 32],
            recv: [0x51; 32],
        });
        let mut sender = crate::Stream::Tcp(sender_tcp);
        let mut receiver = crate::Stream::Tcp(receiver_tcp);
        let mut jobs = vec![
            TransferJob::new_read(
                41,
                JobType::Generic,
                "remote.bin".to_owned(),
                DataSource::MemoryCursor(Cursor::new(vec![0x7a; 4_096])),
                3,
                false,
                false,
                false,
            )
            .expect("the first in-memory transfer job must be valid"),
            TransferJob::new_read(
                42,
                JobType::Generic,
                "later.bin".to_owned(),
                DataSource::MemoryCursor(Cursor::new(vec![0x6b; 4_096])),
                4,
                false,
                false,
                false,
            )
            .expect("the second in-memory transfer job must be valid"),
        ];

        let (_log, receipt) = handle_read_jobs(&mut jobs, &mut sender)
            .await
            .expect("one read step must admit its file frame");
        let mut receipt = receipt.expect("the data-producing step must return exact ownership");
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut receipt)
                .await
                .is_err(),
            "the receipt must not complete while its exact file frame is back-pressured"
        );

        let encoded = receiver
            .next()
            .await
            .expect("the exact file frame must arrive")
            .expect("the exact file frame must authenticate");
        let message =
            Message::parse_from_bytes(encoded.as_ref()).expect("the exact file frame must decode");
        assert!(matches!(
            message.union,
            Some(message::Union::FileResponse(response))
                if matches!(
                    &response.union,
                    Some(file_response::Union::Block(block)) if block.id == 41
                )
        ));
        assert_eq!(jobs[1].transferred, 0);
        assert!(jobs[1].data_stream.is_none());
        receipt
            .await
            .expect("the writer must retain exact completion ownership")
            .expect("the exact file frame write must succeed");
    }

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
        let digest_path = recv_sidecar_path(&final_path, ".digest");
        std::fs::write(&download_path, b"payload").expect("write download");
        std::fs::write(&digest_path, b"{}").expect("write digest");
        std::os::unix::fs::symlink(&secret, &final_path).expect("create symlink final");
        let download_file =
            open_recv_file_no_follow_std(&download_path, false, false, false, false)
                .expect("open exact download");
        let digest_file = open_recv_file_no_follow_std(&digest_path, false, false, false, false)
            .expect("open exact digest");

        let mut published = false;
        finish_recv_write_no_follow(&final_path, &download_file, &digest_file, 1, &mut published)
            .expect("finish receive write");
        assert!(published);

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
    fn recv_finish_reports_visible_but_uncertain_after_parent_sync_failure() {
        const EXPECT_FAULT: &str = "RUSTDESK_TEST_EXPECT_RECEIVE_PARENT_SYNC_FAILURE";

        let tmp = TestTempDir::new("rustdesk_finish_parent_sync");
        std::fs::create_dir_all(&tmp.path).expect("create receive directory");
        let final_path = tmp.join("incoming.txt");
        let download_path = recv_sidecar_path(&final_path, ".download");
        let digest_path = recv_sidecar_path(&final_path, ".digest");
        std::fs::write(&download_path, b"durable-payload").expect("write download");
        std::fs::write(&digest_path, b"{}").expect("write digest");
        let download_file =
            open_recv_file_no_follow_std(&download_path, false, false, false, false)
                .expect("open exact download");
        let digest_file = open_recv_file_no_follow_std(&digest_path, false, false, false, false)
            .expect("open exact digest");

        let mut published = false;
        let result = finish_recv_write_no_follow(
            &final_path,
            &download_file,
            &digest_file,
            1_600_000_000,
            &mut published,
        );
        if std::env::var_os(EXPECT_FAULT).is_some() {
            let error = result.expect_err("injected parent-directory fsync must be reported");
            assert!(
                error
                    .to_string()
                    .contains("visible, but commit durability is uncertain"),
                "post-publication failure must name the uncertain visible outcome: {}",
                error
            );
        } else {
            result.expect("ordinary parent-directory synchronization must succeed");
        }
        assert!(
            published,
            "rename success must irreversibly mark publication"
        );

        assert_eq!(
            std::fs::read(&final_path).expect("read visible final file"),
            b"durable-payload"
        );
        assert!(!download_path.exists(), ".download must be renamed away");
        assert!(!digest_path.exists(), ".digest must be removed");
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

    // ---- R-S8/R-A5 Windows junction (IO_REPARSE_TAG_MOUNT_POINT) tests ----
    // These mirror the Unix `recv_write_no_follow_refuses_symlink_{parent_component,target}` tests
    // but plant an NTFS **junction** (which `is_symlink()` misses and which — unlike a symlink —
    // needs NO privilege to create, so it is the realistic local-attacker primitive on Windows).
    // They prove the NT `openat`-equivalent handle-relative walk closes the same parent/target
    // TOCTOU on Windows. Run in the §12.2 Windows build VM.

    // Create an NTFS junction (mount point) link -> target via `mklink /J` (needs no privilege).
    #[cfg(windows)]
    fn make_junction(link: &Path, target: &Path) -> bool {
        std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(link)
            .arg(target)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    // (mandate #1) A junction planted as an INTERMEDIATE component must be REFUSED, and must not
    // redirect the write outside the destination tree.
    #[cfg(windows)]
    #[test]
    fn recv_write_no_follow_refuses_junction_parent_component() {
        let tmp = TestTempDir::new("rustdesk_nofollow_junction_parent");
        let downloads = tmp.join("downloads");
        let outside = tmp.join("outside");
        std::fs::create_dir_all(&downloads).expect("create downloads");
        std::fs::create_dir_all(&outside).expect("create outside");

        let link = downloads.join("link");
        assert!(
            make_junction(&link, &outside),
            "mklink /J must succeed (unprivileged junction creation)"
        );
        let target = link.join("incoming.download");

        let res = open_recv_write_no_follow_std(&target, true);
        assert!(
            res.is_err(),
            "the NT no-follow parent walk must refuse a junction intermediate component"
        );
        assert!(
            !outside.join("incoming.download").exists(),
            "a junction parent must not redirect the receive write outside the destination tree"
        );
    }

    // (mandate #3) A junction planted as the FINAL component (the received-file name) must be
    // REFUSED, and the junction's target directory must be left untouched.
    #[cfg(windows)]
    #[test]
    fn recv_write_no_follow_refuses_junction_final_component() {
        let tmp = TestTempDir::new("rustdesk_nofollow_junction_final");
        let downloads = tmp.join("downloads");
        let secret_dir = tmp.join("secret_dir");
        std::fs::create_dir_all(&downloads).expect("create downloads");
        std::fs::create_dir_all(&secret_dir).expect("create secret_dir");
        let sentinel = secret_dir.join("sentinel.txt");
        std::fs::write(&sentinel, b"DO-NOT-TOUCH").expect("write sentinel");

        let target = downloads.join("incoming.download");
        assert!(
            make_junction(&target, &secret_dir),
            "mklink /J must succeed (unprivileged junction creation)"
        );

        let res = open_recv_write_no_follow_std(&target, true);
        assert!(
            res.is_err(),
            "the NT no-follow open must refuse a junction final component"
        );
        assert_eq!(
            std::fs::read(&sentinel).expect("read sentinel"),
            b"DO-NOT-TOUCH",
            "a junction final component must not let the write reach the junction target"
        );
        assert!(
            !secret_dir.join("incoming.download").exists(),
            "no file must be created inside the junction's target directory"
        );
    }

    // (mandate #2) A legitimate non-junction nested path must SUCCEED — the walk must create the
    // real intermediate directories and open the target (the hardening never breaks a real
    // transfer), and re-opening an existing regular target must also succeed.
    #[cfg(windows)]
    #[test]
    fn recv_write_no_follow_allows_regular_nested_target_windows() {
        let tmp = TestTempDir::new("rustdesk_nofollow_ok_win");
        let downloads = tmp.join("downloads");
        std::fs::create_dir_all(&downloads).expect("create downloads");
        let target = downloads
            .join("sub")
            .join("deeper")
            .join("incoming.download");

        let opened = open_recv_write_no_follow_std(&target, true);
        assert!(
            opened.is_ok(),
            "the NT no-follow walk must allow a legit nested non-junction target: {:?}",
            opened.err()
        );
        assert!(target.exists());
        assert!(
            open_recv_write_no_follow_std(&target, true).is_ok(),
            "re-opening an existing regular target (re-download) must not be blocked"
        );
    }

    // Defense-in-depth: the cross-platform stat-based `validate_no_symlink_components` must reject a
    // junction component on Windows (`is_symlink()` alone would miss `IO_REPARSE_TAG_MOUNT_POINT`).
    #[cfg(windows)]
    #[test]
    fn validate_no_symlink_components_rejects_junction_windows() {
        let tmp = TestTempDir::new("rustdesk_validate_junction");
        let base = tmp.join("base");
        let outside = tmp.join("outside");
        std::fs::create_dir_all(&base).expect("create base");
        std::fs::create_dir_all(&outside).expect("create outside");

        let link = base.join("j");
        assert!(
            make_junction(&link, &outside),
            "mklink /J must succeed (unprivileged junction creation)"
        );

        let err = validate_no_symlink_components(&base, "j/payload.txt")
            .expect_err("a junction path component must be rejected on Windows");
        let msg = err.to_string();
        assert!(
            msg.contains("reparse-point") || msg.contains("junction") || msg.contains("symlink"),
            "the rejection must name the reparse-point/junction cause: {}",
            msg
        );
    }

    // The NT handle-relative finalize (rename `.download` -> final via
    // `NtSetInformationFile(FileRenameInformation, RootDirectory=parent)` + handle-set mtime) must
    // work end-to-end on a legitimate path.
    #[cfg(windows)]
    #[test]
    fn recv_finish_rename_windows_happy_path() {
        let tmp = TestTempDir::new("rustdesk_finish_win");
        let downloads = tmp.join("downloads");
        std::fs::create_dir_all(&downloads).expect("create downloads");
        let final_path = downloads.join("incoming.txt");
        let download_path = recv_sidecar_path(&final_path, ".download");
        let digest_path = recv_sidecar_path(&final_path, ".digest");
        std::fs::write(&download_path, b"payload").expect("write download");
        std::fs::write(&digest_path, b"{}").expect("write digest");
        let download_file =
            open_recv_file_no_follow_std(&download_path, false, false, false, false)
                .expect("open exact download");
        let digest_file = open_recv_file_no_follow_std(&digest_path, false, false, false, false)
            .expect("open exact digest");

        let mut published = false;
        finish_recv_write_no_follow(
            &final_path,
            &download_file,
            &digest_file,
            1_600_000_000,
            &mut published,
        )
        .expect("finish receive write");
        assert!(published);

        assert_eq!(
            std::fs::read(&final_path).expect("read final"),
            b"payload",
            "the NT handle-relative rename must move .download onto the final name"
        );
        assert!(!download_path.exists(), ".download must be renamed away");
        assert!(!digest_path.exists(), ".digest must be removed");
    }

    // The finalize path shares the parent walk, so a junction PARENT must be refused there too —
    // even when the `.download` is reachable through the junction, finalization must not proceed.
    #[cfg(windows)]
    #[test]
    fn recv_finish_refuses_junction_parent_windows() {
        let tmp = TestTempDir::new("rustdesk_finish_junction_parent");
        let downloads = tmp.join("downloads");
        let outside = tmp.join("outside");
        std::fs::create_dir_all(&downloads).expect("create downloads");
        std::fs::create_dir_all(&outside).expect("create outside");
        // stage the .download inside `outside` so it is reachable through the junction
        let download_path = outside.join("incoming.txt.download");
        let digest_path = outside.join("incoming.txt.digest");
        std::fs::write(&download_path, b"payload").expect("write download");
        std::fs::write(&digest_path, b"{}").expect("write digest");
        let download_file =
            open_recv_file_no_follow_std(&download_path, false, false, false, false)
                .expect("open exact download");
        let digest_file = open_recv_file_no_follow_std(&digest_path, false, false, false, false)
            .expect("open exact digest");

        let link = downloads.join("link");
        assert!(
            make_junction(&link, &outside),
            "mklink /J must succeed (unprivileged junction creation)"
        );
        let final_path = link.join("incoming.txt");

        let mut published = false;
        let res = finish_recv_write_no_follow(
            &final_path,
            &download_file,
            &digest_file,
            1,
            &mut published,
        );
        assert!(
            res.is_err(),
            "finalize must refuse a junction parent component (no rename through the junction)"
        );
        assert!(
            !outside.join("incoming.txt").exists(),
            "the rename must not have completed through the junction parent"
        );
        assert!(!published);
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

    #[tokio::test]
    async fn receive_write_commits_only_the_exact_terminal_index() {
        let tmp = TestTempDir::new("rustdesk_receive_finality");
        std::fs::create_dir_all(&tmp.path).expect("create receive directory");
        let mut job =
            new_write_job(81, tmp.path.clone(), "incoming.bin").expect("create receive-write job");
        let payload = b"checked receive payload";

        job.write(FileTransferBlock {
            id: 81,
            file_num: 0,
            data: payload.to_vec().into(),
            ..Default::default()
        })
        .await
        .expect("write exact receive block");
        assert!(tmp.join("incoming.bin.download").exists());
        assert!(tmp.join("incoming.bin.digest").exists());
        assert!(!tmp.join("incoming.bin").exists());

        let error = job
            .finalize_write(0)
            .await
            .expect_err("a terminal index that does not follow the active file must fail");
        assert!(error.to_string().contains("does not follow active file"));
        assert_eq!(job.file_num(), 0);
        assert!(tmp.join("incoming.bin.download").exists());
        assert!(!tmp.join("incoming.bin").exists());

        job.finalize_write(1)
            .await
            .expect("the exact terminal index must commit");
        assert_eq!(job.file_num(), 1);
        assert_eq!(
            std::fs::read(tmp.join("incoming.bin")).expect("read committed receive file"),
            payload
        );
        assert!(!tmp.join("incoming.bin.download").exists());
        assert!(!tmp.join("incoming.bin.digest").exists());
    }

    #[cfg(unix)]
    #[test]
    fn receive_post_publish_sync_failure_never_deletes_visible_file() {
        const EXPECT_FAULT: &str = "RUSTDESK_TEST_EXPECT_RECEIVE_JOB_SYNC_FAILURE";
        use std::io::Write;

        let tmp = TestTempDir::new("rustdesk_receive_job_sync_failure");
        std::fs::create_dir_all(&tmp.path).expect("create receive directory");
        let final_path = tmp.join("incoming.bin");
        let (mut claim, mut stream) =
            ReceiveWriteClaim::start_new(final_path, FileDigest::default())
                .expect("admit exact receive claim");
        stream
            .write_all(b"published-payload")
            .expect("write receive payload");

        let result = claim.finish(1_600_000_000);
        if std::env::var_os(EXPECT_FAULT).is_some() {
            let error = result.expect_err("injected final parent fsync must be reported");
            assert!(
                error
                    .to_string()
                    .contains("visible, but commit durability is uncertain"),
                "post-publication failure must remain distinguishable: {}",
                error
            );
            claim.cleanup();
        } else {
            result.expect("ordinary receive commit must be durable");
            drop(claim);
        }

        assert_eq!(
            std::fs::read(tmp.join("incoming.bin")).expect("read published file"),
            b"published-payload",
            "error cleanup must never delete or replace an irreversibly published generation"
        );
        assert!(!tmp.join("incoming.bin.download").exists());
        assert!(!tmp.join("incoming.bin.digest").exists());
        assert!(!tmp.join("incoming.bin.download.lock").exists());
    }

    #[tokio::test]
    async fn receive_destination_lease_is_cross_process_and_crash_resumable() {
        const TEST_NAME: &str =
            "fs::tests::receive_destination_lease_is_cross_process_and_crash_resumable";
        const ROLE_ENV: &str = "RUSTDESK_TEST_RECEIVE_LEASE_ROLE";
        const PATH_ENV: &str = "RUSTDESK_TEST_RECEIVE_LEASE_PATH";
        const FIRST: &[u8] = b"first-";
        const SECOND: &[u8] = b"second";
        const TOTAL_SIZE: u64 = (FIRST.len() + SECOND.len()) as u64;
        const MODIFIED: u64 = 17;

        if let Some(role) = std::env::var_os(ROLE_ENV) {
            let path = PathBuf::from(
                std::env::var_os(PATH_ENV).expect("receive lease worker path must be provided"),
            );
            if role == std::ffi::OsStr::new("owner") {
                let mut job =
                    new_write_job(90, path, "incoming.bin").expect("create owning receive job");
                job.set_digest(TOTAL_SIZE, MODIFIED);
                job.write(FileTransferBlock {
                    id: 90,
                    file_num: 0,
                    data: FIRST.to_vec().into(),
                    ..Default::default()
                })
                .await
                .expect("admit the first process-owned partial download");
                let ready_path = match &job.data_source {
                    DataSource::FilePath(path) => path.join("receive-owner-ready"),
                    DataSource::MemoryCursor(_) => panic!("receive owner must use a filesystem"),
                };
                std::fs::write(ready_path, b"ready")
                    .expect("publish receive-owner readiness marker");
                std::thread::sleep(std::time::Duration::from_secs(60));
                panic!("receive-owner worker was not terminated by its parent");
            }
            if role == std::ffi::OsStr::new("contender") {
                let mut job =
                    new_write_job(91, path, "incoming.bin").expect("create competing receive job");
                job.set_digest(TOTAL_SIZE, MODIFIED);
                let error = job
                    .write(FileTransferBlock {
                        id: 91,
                        file_num: 0,
                        data: b"must-not-win".to_vec().into(),
                        ..Default::default()
                    })
                    .await
                    .expect_err("a second process must not acquire the live destination");
                assert!(
                    error
                        .to_string()
                        .contains("another receive job owns this destination"),
                    "unexpected competing-owner error: {}",
                    error
                );
                return;
            }
            if role == std::ffi::OsStr::new("resume") {
                let mut job =
                    new_write_job(92, path, "incoming.bin").expect("create resumed receive job");
                job.is_resume = true;
                job.set_digest(TOTAL_SIZE, MODIFIED);
                job.confirm(&FileTransferSendConfirmRequest {
                    id: 92,
                    file_num: 0,
                    union: Some(file_transfer_send_confirm_request::Union::OffsetBlk(
                        FIRST.len() as u32,
                    )),
                    ..Default::default()
                })
                .await
                .expect("reclaim the process-death-released destination lease");
                job.write(FileTransferBlock {
                    id: 92,
                    file_num: 0,
                    data: SECOND.to_vec().into(),
                    ..Default::default()
                })
                .await
                .expect("continue the exact partial download");
                job.finalize_write(1)
                    .await
                    .expect("commit the resumed destination generation");
                return;
            }
            panic!("unknown receive lease worker role: {:?}", role);
        }

        let tmp = TestTempDir::new("rustdesk_receive_process_lease");
        std::fs::create_dir_all(&tmp.path).expect("create receive directory");
        let run_worker = |role: &str| {
            std::process::Command::new(
                std::env::current_exe().expect("test executable path must be available"),
            )
            .args(["--exact", TEST_NAME, "--nocapture"])
            .env(ROLE_ENV, role)
            .env(PATH_ENV, &tmp.path)
            .output()
            .expect("launch receive lease worker")
        };

        let mut owner = std::process::Command::new(
            std::env::current_exe().expect("test executable path must be available"),
        )
        .args(["--exact", TEST_NAME, "--nocapture"])
        .env(ROLE_ENV, "owner")
        .env(PATH_ENV, &tmp.path)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("launch owning receive process");
        let ready_path = tmp.join("receive-owner-ready");
        for _ in 0..500 {
            if ready_path.exists() {
                break;
            }
            if owner
                .try_wait()
                .expect("inspect owning receive process")
                .is_some()
            {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        if !ready_path.exists() {
            if owner
                .try_wait()
                .expect("inspect failed owning receive process")
                .is_none()
            {
                owner
                    .kill()
                    .expect("terminate unresponsive owning receive process");
                owner
                    .wait()
                    .expect("reap unresponsive owning receive process");
            }
            panic!("owning receive process did not publish readiness");
        }

        let contender = run_worker("contender");
        assert!(
            contender.status.success(),
            "competing process failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&contender.stdout),
            String::from_utf8_lossy(&contender.stderr)
        );
        assert_eq!(
            std::fs::read(tmp.join("incoming.bin.download")).expect("read owner partial"),
            FIRST,
            "the rejected process must not truncate or replace the owner's generation"
        );
        assert!(tmp.join("incoming.bin.digest").exists());
        assert!(tmp.join("incoming.bin.download.lock").exists());

        // Termination bypasses every Rust destructor. The kernel must release the advisory lock,
        // while the stable lock inode and exact partial generation remain available for resume.
        owner.kill().expect("terminate the owning receive process");
        let owner_status = owner.wait().expect("reap the owning receive process");
        assert!(!owner_status.success());
        assert!(tmp.join("incoming.bin.download").exists());
        assert!(tmp.join("incoming.bin.digest").exists());
        assert!(tmp.join("incoming.bin.download.lock").exists());

        let resumed = run_worker("resume");
        assert!(
            resumed.status.success(),
            "resume process failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&resumed.stdout),
            String::from_utf8_lossy(&resumed.stderr)
        );
        assert_eq!(
            std::fs::read(tmp.join("incoming.bin")).expect("read resumed final file"),
            [FIRST, SECOND].concat()
        );
        assert!(!tmp.join("incoming.bin.download").exists());
        assert!(!tmp.join("incoming.bin.digest").exists());
        assert!(!tmp.join("incoming.bin.download.lock").exists());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn receive_sidecar_hard_links_are_refused_before_truncation() {
        async fn exercise(sidecar_suffix: &str, job_id: i32) {
            let tmp = TestTempDir::new(&format!("rustdesk_receive_hardlink_{job_id}"));
            std::fs::create_dir_all(&tmp.path).expect("create receive directory");
            let secret = tmp.join("must-not-truncate");
            let secret_contents = format!("secret-{job_id}").into_bytes();
            std::fs::write(&secret, &secret_contents).expect("write hard-link target");
            std::fs::hard_link(&secret, tmp.join(&format!("incoming.bin{sidecar_suffix}")))
                .expect("precreate receive sidecar as a hard link");

            let mut job = new_write_job(job_id, tmp.path.clone(), "incoming.bin")
                .expect("create receive-write job");
            let error = job
                .write(FileTransferBlock {
                    id: job_id,
                    file_num: 0,
                    data: b"attacker-controlled-write".to_vec().into(),
                    ..Default::default()
                })
                .await
                .expect_err("a hard-linked receive sidecar must not be admitted");
            assert!(
                error.to_string().contains("exactly one filesystem link"),
                "unexpected hard-link rejection: {}",
                error
            );
            assert_eq!(
                std::fs::read(&secret).expect("read protected hard-link target"),
                secret_contents,
                "authority validation must precede every sidecar truncation"
            );
            assert!(!tmp.join("incoming.bin").exists());
            assert!(!tmp.join("incoming.bin.download.lock").exists());
            if sidecar_suffix == ".download" {
                assert!(!tmp.join("incoming.bin.digest").exists());
            } else {
                assert!(
                    !tmp.join("incoming.bin.download").exists(),
                    "a separately admitted download must be cleaned by exact handle"
                );
            }
        }

        exercise(".download", 94).await;
        exercise(".digest", 95).await;
    }

    #[test]
    fn receive_confirmation_probe_retires_its_snapshot_lease() {
        let tmp = TestTempDir::new("rustdesk_receive_confirmation_lease");
        std::fs::create_dir_all(&tmp.path).expect("create receive directory");
        std::fs::write(tmp.join("incoming.bin.download"), b"partial")
            .expect("stage resumable download");
        let stored = FileDigest {
            size: 7,
            modified: 19,
        };
        std::fs::write(tmp.join("incoming.bin.digest"), json!(stored).to_string())
            .expect("stage matching resume digest");
        let final_path = tmp.join("incoming.bin");
        let final_path = final_path
            .to_str()
            .expect("temporary receive path must be UTF-8");
        let result = is_write_need_confirmation(
            true,
            final_path,
            &FileTransferDigest {
                id: 96,
                file_num: 0,
                last_modified: stored.modified,
                file_size: stored.size,
                ..Default::default()
            },
        )
        .expect("take a coherent receive confirmation snapshot");
        match result {
            DigestCheckResult::NeedConfirm(digest) => assert_eq!(digest.transferred_size, 7),
            _ => panic!("matching resumable state must require confirmation"),
        }
        assert!(tmp.join("incoming.bin.download").exists());
        assert!(tmp.join("incoming.bin.digest").exists());
        assert!(
            !tmp.join("incoming.bin.download.lock").exists(),
            "a read-only confirmation snapshot must not leave a lease inode behind"
        );

        let absent_parent = tmp.join("must-not-be-created");
        let absent_final = absent_parent.join("incoming.bin");
        let absent_final = absent_final
            .to_str()
            .expect("temporary absent receive path must be UTF-8");
        assert!(matches!(
            is_write_need_confirmation(false, absent_final, &FileTransferDigest::default())
                .expect("an absent confirmation path is not an error"),
            DigestCheckResult::NoSuchFile
        ));
        assert!(
            !absent_parent.exists(),
            "a read-only confirmation probe must not create destination directories"
        );
    }

    #[tokio::test]
    async fn receive_write_rejects_non_monotonic_file_transition() {
        let tmp = TestTempDir::new("rustdesk_receive_transition");
        std::fs::create_dir_all(&tmp.path).expect("create receive directory");
        let mut job = TransferJob::new_write(
            82,
            JobType::Generic,
            "/fake/remote".to_owned(),
            DataSource::FilePath(tmp.path.clone()),
            0,
            false,
            true,
            false,
        )
        .with_files(vec![
            new_file_entry("zero.bin"),
            new_file_entry("one.bin"),
            new_file_entry("two.bin"),
        ])
        .expect("create multi-file receive job");

        job.write(FileTransferBlock {
            id: 82,
            file_num: 0,
            data: b"zero".to_vec().into(),
            ..Default::default()
        })
        .await
        .expect("write first file");
        let error = job
            .write(FileTransferBlock {
                id: 82,
                file_num: 2,
                data: b"gap".to_vec().into(),
                ..Default::default()
            })
            .await
            .expect_err("a gap in peer file numbering must fail");
        assert!(error
            .to_string()
            .contains("unexpected write file transition"));
        assert_eq!(job.file_num(), 0);
        assert!(!tmp.join("zero.bin").exists());
        assert!(tmp.join("zero.bin.download").exists());
        assert!(!tmp.join("two.bin.download").exists());
        job.remove_download_file();
        assert!(!tmp.join("zero.bin.download").exists());
        assert!(!tmp.join("zero.bin.digest").exists());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn receive_finalize_refuses_a_replaced_staging_inode() {
        let tmp = TestTempDir::new("rustdesk_receive_replaced_inode");
        std::fs::create_dir_all(&tmp.path).expect("create receive directory");
        let mut job =
            new_write_job(93, tmp.path.clone(), "incoming.bin").expect("create receive-write job");
        job.write(FileTransferBlock {
            id: 93,
            file_num: 0,
            data: b"owned-payload".to_vec().into(),
            ..Default::default()
        })
        .await
        .expect("write the admitted staging inode");

        let download = tmp.join("incoming.bin.download");
        let displaced = tmp.join("displaced.download");
        std::fs::rename(&download, &displaced).expect("displace the admitted staging inode");
        std::fs::write(&download, b"replacement-must-survive")
            .expect("install a different regular staging inode");

        let error = job
            .finalize_write(1)
            .await
            .expect_err("finalize must not publish a re-resolved staging name");
        assert!(error.to_string().contains("generation changed"));
        assert!(!tmp.join("incoming.bin").exists());

        job.remove_download_file();
        assert_eq!(
            std::fs::read(&download).expect("read replacement staging inode"),
            b"replacement-must-survive",
            "cleanup must not unlink an inode outside the job's generation"
        );
        assert_eq!(
            std::fs::read(&displaced).expect("read displaced admitted inode"),
            b"owned-payload"
        );
        assert!(!tmp.join("incoming.bin.digest").exists());
        assert!(
            tmp.join("incoming.bin.download.lock").exists(),
            "uncertain exact-artifact cleanup must preserve the stable lease marker"
        );
    }

    #[tokio::test]
    async fn receive_write_rejects_malformed_compression_before_false_progress() {
        let tmp = TestTempDir::new("rustdesk_receive_bad_compression");
        std::fs::create_dir_all(&tmp.path).expect("create receive directory");
        let mut job =
            new_write_job(88, tmp.path.clone(), "incoming.bin").expect("create receive-write job");

        let error = job
            .write(FileTransferBlock {
                id: 88,
                file_num: 0,
                data: b"not a zstd frame".to_vec().into(),
                compressed: true,
                ..Default::default()
            })
            .await
            .expect_err("malformed compressed data must not become an empty successful block");
        assert!(!error.to_string().is_empty());
        assert_eq!(job.finished_size(), 0);
        assert_eq!(job.transferred(), 0);
        assert!(!tmp.join("incoming.bin").exists());
        job.remove_download_file();
        assert!(!tmp.join("incoming.bin.download").exists());
        assert!(!tmp.join("incoming.bin.digest").exists());
    }

    #[tokio::test]
    async fn receive_write_refuses_false_resume_and_cleans_only_claimed_artifacts() {
        let tmp = TestTempDir::new("rustdesk_receive_resume");
        std::fs::create_dir_all(&tmp.path).expect("create receive directory");
        let download = tmp.join("incoming.bin.download");
        let digest = tmp.join("incoming.bin.digest");
        std::fs::create_dir(&download).expect("stage a non-file resume target");
        std::fs::write(&digest, b"{}").expect("stage resume digest");
        let mut job =
            new_write_job(83, tmp.path.clone(), "incoming.bin").expect("create resume job");
        job.is_resume = true;
        let request = FileTransferSendConfirmRequest {
            id: 83,
            file_num: 0,
            union: Some(file_transfer_send_confirm_request::Union::OffsetBlk(1)),
            ..Default::default()
        };

        let error = job
            .confirm(&request)
            .await
            .expect_err("an unopenable resume target must not be confirmed");
        assert!(!error.to_string().is_empty());
        assert!(!job.file_confirmed());
        assert!(job.data_stream.is_none());
        job.remove_download_file();
        assert!(
            download.is_dir(),
            "cleanup must not delete a sidecar this job never opened"
        );
        assert!(digest.exists());
    }

    #[tokio::test]
    async fn send_resume_seeks_the_source_not_receive_sidecars() {
        let tmp = TestTempDir::new("rustdesk_send_resume");
        std::fs::create_dir_all(&tmp.path).expect("create source directory");
        let source = tmp.join("source.bin");
        std::fs::write(&source, b"source-bytes").expect("stage source file");
        std::fs::write(tmp.join("source.bin.download"), b"wrong-sidecar")
            .expect("stage unrelated receive sidecar");
        std::fs::write(tmp.join("source.bin.digest"), b"{}")
            .expect("stage unrelated digest sidecar");
        let mut job = TransferJob::new_read(
            84,
            JobType::Generic,
            "remote.bin".to_owned(),
            DataSource::FilePath(source),
            0,
            false,
            false,
            false,
        )
        .expect("create send job");
        let request = FileTransferSendConfirmRequest {
            id: 84,
            file_num: 0,
            union: Some(file_transfer_send_confirm_request::Union::OffsetBlk(7)),
            ..Default::default()
        };

        job.confirm(&request)
            .await
            .expect("seek the actual send source");
        let block = job
            .read()
            .await
            .expect("read resumed source")
            .expect("source has bytes after the offset");
        assert_eq!(block.data.as_ref(), b"bytes");
        assert_eq!(
            std::fs::read(tmp.join("source.bin.download")).expect("read unrelated receive sidecar"),
            b"wrong-sidecar"
        );
    }

    #[tokio::test]
    async fn confirmation_rejects_wrong_job_and_duplicate_progress() {
        let tmp = TestTempDir::new("rustdesk_receive_confirm_identity");
        std::fs::create_dir_all(&tmp.path).expect("create receive directory");
        std::fs::write(tmp.join("incoming.bin.download"), b"partial")
            .expect("stage partial download");
        std::fs::write(
            tmp.join("incoming.bin.digest"),
            json!(FileDigest::default()).to_string(),
        )
        .expect("stage resume digest");
        let mut job =
            new_write_job(85, tmp.path.clone(), "incoming.bin").expect("create receive-write job");
        let mut request = FileTransferSendConfirmRequest {
            id: 999,
            file_num: 0,
            union: Some(file_transfer_send_confirm_request::Union::OffsetBlk(2)),
            ..Default::default()
        };

        let error = job
            .confirm(&request)
            .await
            .expect_err("a confirmation for another job must fail");
        assert!(error.to_string().contains("does not match active job"));
        assert!(!job.file_confirmed());
        assert_eq!(job.transferred(), 0);

        request.id = 85;
        job.confirm(&request)
            .await
            .expect("the exact first confirmation must succeed");
        assert!(job.file_confirmed());
        assert_eq!(job.transferred(), 2);
        assert_eq!(job.finished_size(), 2);

        let error = job
            .confirm(&request)
            .await
            .expect_err("a duplicate confirmation must not count progress twice");
        assert!(error.to_string().contains("already confirmed"));
        assert_eq!(job.transferred(), 2);
        assert_eq!(job.finished_size(), 2);
        job.remove_download_file();
    }

    #[tokio::test]
    async fn resume_counter_overflow_does_not_publish_stream_ownership() {
        let tmp = TestTempDir::new("rustdesk_receive_resume_overflow");
        std::fs::create_dir_all(&tmp.path).expect("create receive directory");
        std::fs::write(tmp.join("incoming.bin.download"), b"partial")
            .expect("stage partial download");
        std::fs::write(tmp.join("incoming.bin.digest"), b"{}").expect("stage resume digest");
        let mut job =
            new_write_job(86, tmp.path.clone(), "incoming.bin").expect("create receive-write job");
        job.transferred = u64::MAX;
        let request = FileTransferSendConfirmRequest {
            id: 86,
            file_num: 0,
            union: Some(file_transfer_send_confirm_request::Union::OffsetBlk(1)),
            ..Default::default()
        };

        let error = job
            .confirm(&request)
            .await
            .expect_err("overflowing resume accounting must fail");
        assert!(error.to_string().contains("counter overflow"));
        assert!(!job.file_confirmed());
        assert!(job.data_stream.is_none());
        assert!(job.receive_write_claim.is_none());
        assert_eq!(job.transferred(), u64::MAX);
        assert_eq!(job.finished_size(), 0);
    }

    #[test]
    fn transfer_file_total_size_overflow_is_rejected_transactionally() {
        let mut job = new_validation_job(87);
        let mut first = new_file_entry("first.bin");
        first.size = u64::MAX;
        let mut second = new_file_entry("second.bin");
        second.size = 1;

        let error = job
            .set_files(vec![first, second])
            .expect_err("overflowing aggregate file sizes must fail");
        assert!(error.to_string().contains("total size overflow"));
        assert!(job.files().is_empty());
        assert_eq!(job.total_size(), 0);
    }

    // §20 post-key DoS regression: a peer FileTransferSendConfirmRequest(file_num=0, OffsetBlk>0)
    // against a job whose file list is empty must fail without
    // indexing files[0] or falsely confirming a seek that did not happen.
    #[tokio::test]
    async fn confirm_offset_blk_on_empty_files_job_fails_explicitly() {
        let mut job = TransferJob::new_write(
            1,
            JobType::Generic,
            "/fake/remote".to_string(),
            DataSource::FilePath(PathBuf::from("/nonexistent-empty-job")),
            0, // file_num == default self.file_num(), so confirm() takes the seek branch
            false,
            true,
            false,
        );
        assert!(job.files.is_empty(), "precondition: empty-files job");
        let mut r = FileTransferSendConfirmRequest::default();
        r.id = 1;
        r.file_num = 0;
        r.union = Some(file_transfer_send_confirm_request::Union::OffsetBlk(1));
        let error = job
            .confirm(&r)
            .await
            .expect_err("an offset into an empty file list must fail");
        assert!(error.to_string().contains("out of range"));
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
