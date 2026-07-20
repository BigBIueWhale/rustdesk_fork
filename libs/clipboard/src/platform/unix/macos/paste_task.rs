use crate::{
    platform::unix::{FileDescription, FileType, BLOCK_SIZE},
    send_data, ClipboardFile, CliprdrError, ProgressPercent,
};
use hbb_common::{allow_err, log, tokio::time::Instant};
use std::{
    cmp::min,
    ffi::{CString, OsStr},
    fs::{File, FileTimes},
    io::{self, BufWriter, Write},
    os::{
        macos::fs::FileTimesExt,
        unix::{
            ffi::OsStrExt,
            io::{AsRawFd, FromRawFd, RawFd},
        },
    },
    path::{Path, PathBuf},
    sync::{
        mpsc::{Receiver, RecvTimeoutError},
        Arc, Mutex,
    },
    thread,
    time::{Duration, SystemTime},
};

const RECV_RETRY_TIMES: usize = 3;

const DOWNLOAD_EXTENSION: &str = "rddownload";
const RECEIVE_WAIT_TIMEOUT: Duration = Duration::from_millis(5_000);
const UNIQUE_NAME_ATTEMPTS: usize = 9_999_999;

// https://stackoverflow.com/a/15112784/1926020
// "1984-01-24 08:00:00 +0000"
const TIMESTAMP_FOR_FILE_PROGRESS_COMPLETED: u64 = 443779200;
const ATTR_PROGRESS_FRACTION_COMPLETED: &str = "com.apple.progress.fractionCompleted";

pub struct FileContentsResponse {
    pub conn_id: i32,
    pub msg_flags: i32,
    pub stream_id: i32,
    pub requested_data: Vec<u8>,
}

#[derive(Debug)]
struct PasteTaskProgress {
    // Use list index to identify the file
    // `list_index` is also used as the stream id
    list_index: i32,
    offset: u64,
    total_size: u64,
    current_size: u64,
    last_sent_time: Instant,
    download_file_index: i32,
    download_file_size: u64,
    download_file_path: String,
    download_file_relative_path: Option<PathBuf>,
    download_file_current_size: u64,
    file_handle: Option<BufWriter<File>>,
    error: Option<CliprdrError>,
    is_canceled: bool,
}

struct PasteTaskHandle {
    progress: PasteTaskProgress,
    target_dir: PathBuf,
    target_dir_handle: File,
    files: Vec<FileDescription>,
}

pub struct PasteTask {
    exit: Arc<Mutex<bool>>,
    handle: Arc<Mutex<Option<PasteTaskHandle>>>,
    handle_worker: Option<thread::JoinHandle<()>>,
}

impl Drop for PasteTask {
    fn drop(&mut self) {
        *self.exit.lock().unwrap() = true;
        if let Some(handle_worker) = self.handle_worker.take() {
            handle_worker.join().ok();
        }
    }
}

fn common_error(description: impl Into<String>) -> CliprdrError {
    CliprdrError::CommonError {
        description: description.into(),
    }
}

fn file_error(path: &Path, err: io::Error) -> CliprdrError {
    CliprdrError::FileError {
        path: path.to_string_lossy().to_string(),
        err,
    }
}

fn io_invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn cstring_from_os_str(value: &OsStr, context: &str) -> io::Result<CString> {
    CString::new(value.as_bytes()).map_err(|err| {
        io_invalid_input(format!(
            "invalid macOS paste {context} path component contains NUL: {err}"
        ))
    })
}

fn duplicate_fd(fd: RawFd) -> io::Result<File> {
    let duplicated = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
    if duplicated < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(duplicated) })
}

fn open_child_dir_no_follow(parent_fd: RawFd, name: &CString) -> io::Result<File> {
    let fd = unsafe {
        libc::openat(
            parent_fd,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let dir = unsafe { File::from_raw_fd(fd) };
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(dir.as_raw_fd(), &mut stat) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if (stat.st_mode & libc::S_IFMT) != libc::S_IFDIR {
        return Err(io_invalid_input(
            "macOS paste parent component is not a directory",
        ));
    }
    Ok(dir)
}

fn mkdir_child_if_missing(parent_fd: RawFd, name: &CString) -> io::Result<()> {
    let rc = unsafe { libc::mkdirat(parent_fd, name.as_ptr(), 0o777 as libc::mode_t) };
    if rc == 0 {
        return Ok(());
    }
    let err = io::Error::last_os_error();
    if err.raw_os_error() == Some(libc::EEXIST) {
        Ok(())
    } else {
        Err(err)
    }
}

fn open_dir_path_no_follow(path: &Path) -> io::Result<File> {
    let mut dir = if path.is_absolute() {
        File::open(Path::new("/"))?
    } else {
        File::open(Path::new("."))?
    };

    for component in path.components() {
        match component {
            std::path::Component::RootDir => {}
            std::path::Component::Normal(name) => {
                let name = cstring_from_os_str(name, "target-directory")?;
                dir = open_child_dir_no_follow(dir.as_raw_fd(), &name)?;
            }
            std::path::Component::CurDir
            | std::path::Component::ParentDir
            | std::path::Component::Prefix(_) => {
                return Err(io_invalid_input(format!(
                    "unsupported macOS paste target directory shape: {}",
                    path.display()
                )));
            }
        }
    }

    Ok(dir)
}

fn open_relative_parent_dir_no_follow(
    base_fd: RawFd,
    relative_path: &Path,
    create_missing: bool,
) -> io::Result<(File, CString)> {
    let mut dir = duplicate_fd(base_fd)?;
    let mut components = relative_path.components().peekable();

    while let Some(component) = components.next() {
        let std::path::Component::Normal(name) = component else {
            return Err(io_invalid_input(format!(
                "unsafe macOS paste relative path: {}",
                relative_path.display()
            )));
        };
        let name = cstring_from_os_str(name, "relative")?;
        if components.peek().is_none() {
            return Ok((dir, name));
        }
        if create_missing {
            mkdir_child_if_missing(dir.as_raw_fd(), &name)?;
        }
        dir = open_child_dir_no_follow(dir.as_raw_fd(), &name)?;
    }

    Err(io_invalid_input("empty macOS paste relative path"))
}

fn ensure_relative_dir_no_follow(base_fd: RawFd, relative_path: &Path) -> io::Result<()> {
    let mut dir = duplicate_fd(base_fd)?;
    let mut has_component = false;

    for component in relative_path.components() {
        let std::path::Component::Normal(name) = component else {
            return Err(io_invalid_input(format!(
                "unsafe macOS paste directory path: {}",
                relative_path.display()
            )));
        };
        has_component = true;
        let name = cstring_from_os_str(name, "directory")?;
        mkdir_child_if_missing(dir.as_raw_fd(), &name)?;
        dir = open_child_dir_no_follow(dir.as_raw_fd(), &name)?;
    }

    if has_component {
        Ok(())
    } else {
        Err(io_invalid_input("empty macOS paste directory path"))
    }
}

fn stat_is_regular(stat: &libc::stat) -> bool {
    (stat.st_mode & libc::S_IFMT) == libc::S_IFREG
}

fn open_relative_file_exclusive_no_follow(
    base_fd: RawFd,
    relative_path: &Path,
) -> io::Result<File> {
    let (parent, name) = open_relative_parent_dir_no_follow(base_fd, relative_path, true)?;
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_WRONLY
                | libc::O_CREAT
                | libc::O_EXCL
                | libc::O_CLOEXEC
                | libc::O_NOFOLLOW
                | libc::O_NOCTTY,
            0o666 as libc::mode_t as libc::c_uint,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let file = unsafe { File::from_raw_fd(fd) };
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(file.as_raw_fd(), &mut stat) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if !stat_is_regular(&stat) {
        return Err(io_invalid_input(
            "opened macOS paste target is not a regular file",
        ));
    }
    Ok(file)
}

fn unlink_relative_file_no_follow(base_fd: RawFd, relative_path: &Path) -> io::Result<()> {
    let (parent, name) = open_relative_parent_dir_no_follow(base_fd, relative_path, false)?;
    let rc = unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), 0) };
    if rc == 0 {
        return Ok(());
    }
    let err = io::Error::last_os_error();
    if err.kind() == io::ErrorKind::NotFound {
        Ok(())
    } else {
        Err(err)
    }
}

fn rename_relative_file_exclusive_no_follow(
    base_fd: RawFd,
    from_relative_path: &Path,
    to_relative_path: &Path,
) -> io::Result<()> {
    let (from_parent, from_name) =
        open_relative_parent_dir_no_follow(base_fd, from_relative_path, false)?;
    let (to_parent, to_name) =
        open_relative_parent_dir_no_follow(base_fd, to_relative_path, false)?;
    let rc = unsafe {
        libc::renameatx_np(
            from_parent.as_raw_fd(),
            from_name.as_ptr(),
            to_parent.as_raw_fd(),
            to_name.as_ptr(),
            libc::RENAME_EXCL,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn is_name_collision(err: &io::Error) -> bool {
    err.raw_os_error() == Some(libc::EEXIST) || err.kind() == io::ErrorKind::AlreadyExists
}

fn append_download_extension(path: &Path) -> PathBuf {
    PathBuf::from(format!("{}.{}", path.to_string_lossy(), DOWNLOAD_EXTENSION))
}

fn indexed_candidate_path(path: &Path, r#type: FileType, index: usize) -> Option<PathBuf> {
    if index == 0 {
        return Some(path.to_path_buf());
    }

    match r#type {
        FileType::File => {
            let file_name = if let Some(ext) = path.extension() {
                let stem = path.file_stem()?.to_string_lossy();
                format!("{}-{}.{}", stem, index, ext.to_string_lossy())
            } else {
                format!("{} ({})", path.file_name()?.to_string_lossy(), index)
            };
            Some(path.with_file_name(file_name))
        }
        FileType::Directory => Some(path.with_file_name(format!(
            "{} ({})",
            path.file_name()?.to_string_lossy(),
            index
        ))),
        FileType::Symlink => None,
    }
}

fn progress_attr_name() -> io::Result<CString> {
    CString::new(ATTR_PROGRESS_FRACTION_COMPLETED)
        .map_err(|err| io_invalid_input(format!("invalid progress xattr name: {err}")))
}

fn set_progress_fraction_for_file(file: &File, fraction_completed: f64) -> io::Result<()> {
    let attr = progress_attr_name()?;
    let value = fraction_completed.to_string();
    let rc = unsafe {
        libc::fsetxattr(
            file.as_raw_fd(),
            attr.as_ptr(),
            value.as_bytes().as_ptr() as *const libc::c_void,
            value.len(),
            0,
            0,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn remove_progress_fraction_for_file(file: &File) -> io::Result<()> {
    let attr = progress_attr_name()?;
    let rc = unsafe { libc::fremovexattr(file.as_raw_fd(), attr.as_ptr(), 0) };
    if rc == 0 {
        return Ok(());
    }
    let err = io::Error::last_os_error();
    if err.raw_os_error() == Some(libc::ENOATTR) {
        Ok(())
    } else {
        Err(err)
    }
}

impl PasteTask {
    const INVALID_FILE_INDEX: i32 = -1;

    pub fn new(rx_file_contents: Receiver<FileContentsResponse>) -> Self {
        let exit = Arc::new(Mutex::new(false));
        let handle = Arc::new(Mutex::new(None));
        let handle_worker =
            Self::init_worker_thread(exit.clone(), handle.clone(), rx_file_contents);
        Self {
            handle,
            exit,
            handle_worker: Some(handle_worker),
        }
    }

    pub fn start(
        &mut self,
        target_dir: PathBuf,
        files: Vec<FileDescription>,
    ) -> Result<(), CliprdrError> {
        let files = FileDescription::sanitize_relative_names(files)?;
        let mut task_lock = self.handle.lock().unwrap();
        if task_lock
            .as_ref()
            .map(|x| !x.is_finished())
            .unwrap_or(false)
        {
            log::error!("Previous paste task is not finished, ignore new request.");
            return Ok(());
        }
        let total_size = files.iter().map(|f| f.size).sum();
        let target_dir_handle =
            open_dir_path_no_follow(&target_dir).map_err(|e| file_error(&target_dir, e))?;
        let mut task_handle = PasteTaskHandle {
            progress: PasteTaskProgress {
                list_index: -1,
                offset: 0,
                total_size,
                current_size: 0,
                last_sent_time: Instant::now(),
                download_file_index: Self::INVALID_FILE_INDEX,
                download_file_size: 0,
                download_file_path: "".to_owned(),
                download_file_relative_path: None,
                download_file_current_size: 0,
                file_handle: None,
                error: None,
                is_canceled: false,
            },
            target_dir,
            target_dir_handle,
            files,
        };
        task_handle.update_next(0)?;
        if task_handle.is_finished() {
            task_handle.on_finished();
        } else {
            if let Err(e) = task_handle.send_file_contents_request() {
                log::error!("Failed to send file contents request, error: {}", &e);
                task_handle.on_error(e);
            }
        }
        *task_lock = Some(task_handle);
        Ok(())
    }

    pub fn cancel(&self) {
        let mut task_handle = self.handle.lock().unwrap();
        if let Some(task_handle) = task_handle.as_mut() {
            task_handle.progress.is_canceled = true;
            task_handle.on_cancelled();
        }
    }

    fn init_worker_thread(
        exit: Arc<Mutex<bool>>,
        handle: Arc<Mutex<Option<PasteTaskHandle>>>,
        rx_file_contents: Receiver<FileContentsResponse>,
    ) -> thread::JoinHandle<()> {
        thread::spawn(move || {
            let mut retry_count = 0;
            loop {
                if *exit.lock().unwrap() {
                    break;
                }

                match rx_file_contents.recv_timeout(Duration::from_millis(300)) {
                    Ok(file_contents) => {
                        let mut task_lock = handle.lock().unwrap();
                        let Some(task_handle) = task_lock.as_mut() else {
                            continue;
                        };
                        if task_handle.is_finished() {
                            continue;
                        }

                        if file_contents.stream_id != task_handle.progress.list_index {
                            // ignore invalid stream id
                            continue;
                        } else if file_contents.msg_flags != 0x01 {
                            retry_count += 1;
                            if retry_count > RECV_RETRY_TIMES {
                                task_handle.progress.error = Some(CliprdrError::InvalidRequest {
                                    description: format!(
                                        "Failed to read file contents, stream id: {}, msg_flags: {}",
                                        file_contents.stream_id,
                                        file_contents.msg_flags
                                    ),
                                });
                            }
                        } else {
                            let resp_list_index = file_contents.stream_id;
                            let Some(file) = &task_handle.files.get(resp_list_index as usize)
                            else {
                                // unreachable
                                // Because `task_handle.progress.list_index >= task_handle.files.len()` should always be false
                                log::warn!(
                                    "Invalid response list index: {}, file length: {}",
                                    resp_list_index,
                                    task_handle.files.len()
                                );
                                continue;
                            };
                            if file.conn_id != file_contents.conn_id {
                                // unreachable
                                // We still add log here to make sure we can see the error message when it happens.
                                log::error!(
                                    "Invalid response conn id: {}, expected: {}",
                                    file_contents.conn_id,
                                    file.conn_id
                                );
                                continue;
                            }

                            if let Err(e) = task_handle.handle_file_contents_response(file_contents)
                            {
                                log::error!("Failed to handle file contents response: {}", &e);
                                task_handle.on_error(e);
                            }
                        }

                        if !task_handle.is_finished() {
                            if let Err(e) = task_handle.send_file_contents_request() {
                                log::error!("Failed to send file contents request: {}", &e);
                                task_handle.on_error(e);
                            }
                        } else {
                            retry_count = 0;
                            task_handle.on_finished();
                        }
                    }
                    Err(RecvTimeoutError::Timeout) => {
                        let mut task_lock = handle.lock().unwrap();
                        if let Some(task_handle) = task_lock.as_mut() {
                            if task_handle.check_receive_timemout() {
                                retry_count = 0;
                                task_handle.on_finished();
                            }
                        }
                    }
                    Err(RecvTimeoutError::Disconnected) => {
                        break;
                    }
                }
            }
        })
    }

    pub fn is_finished(&self) -> bool {
        self.handle
            .lock()
            .unwrap()
            .as_ref()
            .map(|handle| handle.is_finished())
            .unwrap_or(true)
    }

    pub fn progress_percent(&self) -> Option<ProgressPercent> {
        self.handle
            .lock()
            .unwrap()
            .as_ref()
            .map(|handle| handle.progress_percent())
    }
}

impl PasteTaskHandle {
    fn update_next(&mut self, size: u64) -> Result<(), CliprdrError> {
        if self.is_finished() {
            return Ok(());
        }
        self.progress.current_size += size;

        let is_start = self.progress.list_index == -1;
        if is_start || (self.progress.offset + size) >= self.progress.download_file_size {
            if !is_start {
                self.on_done();
                if self.progress.error.is_some() {
                    return Ok(());
                }
            }
            for i in (self.progress.list_index + 1)..self.files.len() as i32 {
                let Some(file_desc) = self.files.get(i as usize) else {
                    return Err(CliprdrError::InvalidRequest {
                        description: format!("Invalid file index: {}", i),
                    });
                };
                match file_desc.kind {
                    FileType::File => {
                        if file_desc.size == 0 {
                            let (new_relative_path, f) = self.create_unique_file(file_desc)?;
                            if let Err(e) = f.set_len(0) {
                                return Err(file_error(
                                    &self.target_dir.join(new_relative_path),
                                    e,
                                ));
                            }
                            Self::set_file_metadata(&f, file_desc);
                        } else {
                            self.progress.list_index = i;
                            self.progress.offset = 0;
                            self.open_new_writer()?;
                            break;
                        }
                    }
                    FileType::Directory => {
                        let relative_path =
                            FileDescription::normalize_relative_name(&file_desc.name)?;
                        ensure_relative_dir_no_follow(
                            self.target_dir_handle.as_raw_fd(),
                            &relative_path,
                        )
                        .map_err(|e| file_error(&self.target_dir.join(relative_path), e))?;
                    }
                    FileType::Symlink => {
                        // to-do: handle symlink
                    }
                }
            }
        } else {
            self.progress.offset += size;
            self.progress.download_file_current_size += size;
            self.update_progress_completed(None);
        }
        if self.progress.file_handle.is_none() {
            self.progress.list_index = self.files.len() as i32;
            self.progress.offset = 0;
            self.progress.download_file_size = 0;
            self.progress.download_file_current_size = 0;
        }
        Ok(())
    }

    fn start_progress_completed(&self) {
        if let Some(file) = self.progress.file_handle.as_ref() {
            let creation_time =
                SystemTime::UNIX_EPOCH + Duration::from_secs(TIMESTAMP_FOR_FILE_PROGRESS_COMPLETED);
            if let Err(e) = file
                .get_ref()
                .set_times(FileTimes::new().set_created(creation_time))
            {
                log::debug!("Failed to set macOS paste progress timestamp: {e}");
            }
            if let Err(e) = set_progress_fraction_for_file(file.get_ref(), 0.0) {
                log::debug!("Failed to set macOS paste progress xattr: {e}");
            }
        }
    }

    fn update_progress_completed(&mut self, fraction_completed: Option<f64>) {
        let Some(file) = self.progress.file_handle.as_ref() else {
            return;
        };
        let fraction_completed = fraction_completed.unwrap_or_else(|| {
            let current_size = self.progress.download_file_current_size as f64;
            let total_size = self.progress.download_file_size as f64;
            if total_size > 0.0 {
                current_size / total_size
            } else {
                1.0
            }
        });
        if let Err(e) = set_progress_fraction_for_file(file.get_ref(), fraction_completed) {
            log::debug!("Failed to update macOS paste progress xattr: {e}");
        }
    }

    fn open_new_writer(&mut self) -> Result<(), CliprdrError> {
        let Some(file) = &self.files.get(self.progress.list_index as usize) else {
            return Err(CliprdrError::InvalidRequest {
                description: format!(
                    "Invalid file index: {}, file count: {}",
                    self.progress.list_index,
                    self.files.len()
                ),
            });
        };

        let original_relative_path = FileDescription::normalize_relative_name(&file.name)?;
        let download_relative_path = append_download_extension(&original_relative_path);
        let (download_relative_path, handle) =
            self.create_unique_file_at(&download_relative_path, file.kind)?;
        let download_file_path = self.target_dir.join(&download_relative_path);
        let writer = BufWriter::with_capacity(BLOCK_SIZE as usize * 2, handle);
        self.progress.download_file_index = self.progress.list_index;
        self.progress.download_file_size = file.size;
        self.progress.download_file_path = download_file_path.to_string_lossy().to_string();
        self.progress.download_file_relative_path = Some(download_relative_path);
        self.progress.download_file_current_size = 0;
        self.progress.file_handle = Some(writer);
        self.start_progress_completed();
        Ok(())
    }

    fn create_unique_file(
        &self,
        file_desc: &FileDescription,
    ) -> Result<(PathBuf, File), CliprdrError> {
        let relative_path = FileDescription::normalize_relative_name(&file_desc.name)?;
        self.create_unique_file_at(&relative_path, file_desc.kind)
    }

    fn create_unique_file_at(
        &self,
        relative_path: &Path,
        r#type: FileType,
    ) -> Result<(PathBuf, File), CliprdrError> {
        for i in 0..UNIQUE_NAME_ATTEMPTS {
            let Some(candidate) = indexed_candidate_path(relative_path, r#type, i) else {
                return Err(common_error(
                    "failed to derive macOS paste target file name",
                ));
            };
            match open_relative_file_exclusive_no_follow(
                self.target_dir_handle.as_raw_fd(),
                &candidate,
            ) {
                Ok(file) => return Ok((candidate, file)),
                Err(e) if is_name_collision(&e) => continue,
                Err(e) => return Err(file_error(&self.target_dir.join(candidate), e)),
            }
        }

        Err(common_error(format!(
            "failed to reserve unique macOS paste target path under {}",
            self.target_dir.display()
        )))
    }

    fn progress_percent(&self) -> ProgressPercent {
        let percent = self.progress.current_size as f64 / self.progress.total_size as f64;
        ProgressPercent {
            percent,
            is_canceled: self.progress.is_canceled,
            is_failed: self.progress.error.is_some(),
        }
    }

    fn is_finished(&self) -> bool {
        self.progress.is_canceled
            || self.progress.error.is_some()
            || self.progress.list_index >= self.files.len() as i32
    }

    fn check_receive_timemout(&mut self) -> bool {
        if !self.is_finished() {
            if self.progress.last_sent_time.elapsed() > RECEIVE_WAIT_TIMEOUT {
                self.progress.error = Some(CliprdrError::InvalidRequest {
                    description: "Failed to read file contents".to_string(),
                });
                return true;
            }
        }
        false
    }

    fn on_finished(&mut self) {
        if self.progress.error.is_some() {
            self.on_cancelled();
        } else {
            self.on_done();
        }
        if self.progress.current_size != self.progress.total_size {
            self.progress.error = Some(CliprdrError::InvalidRequest {
                description: "Failed to download all files".to_string(),
            });
        }
    }

    fn on_error(&mut self, error: CliprdrError) {
        self.progress.error = Some(error);
        self.on_cancelled();
    }

    fn on_cancelled(&mut self) {
        self.progress.file_handle = None;
        if let Some(download_file_relative_path) = self.progress.download_file_relative_path.take()
        {
            if let Err(e) = unlink_relative_file_no_follow(
                self.target_dir_handle.as_raw_fd(),
                &download_file_relative_path,
            ) {
                log::debug!("Failed to remove cancelled macOS paste download file: {e}");
            }
        }
        self.progress.download_file_path.clear();
        self.progress.download_file_index = PasteTask::INVALID_FILE_INDEX;
    }

    fn on_done(&mut self) {
        let Some(mut file) = self.progress.file_handle.take() else {
            return;
        };
        if self.progress.download_file_index == PasteTask::INVALID_FILE_INDEX {
            self.progress.file_handle = Some(file);
            return;
        }

        if let Err(e) = file.flush() {
            let path = self.progress.download_file_path.clone();
            log::error!("Failed to flush file: {:?}", e);
            self.progress.error = Some(CliprdrError::FileError { path, err: e });
            if let Some(download_file_relative_path) =
                self.progress.download_file_relative_path.take()
            {
                if let Err(e) = unlink_relative_file_no_follow(
                    self.target_dir_handle.as_raw_fd(),
                    &download_file_relative_path,
                ) {
                    log::debug!("Failed to remove unflushed macOS paste download file: {e}");
                }
            }
            return;
        }

        let Some(file_desc) = self.files.get(self.progress.download_file_index as usize) else {
            // unreachable
            log::error!(
                "Failed to get file description: {}",
                self.progress.download_file_index
            );
            return;
        };

        if let Err(e) = set_progress_fraction_for_file(file.get_ref(), 1.0) {
            log::debug!("Failed to finish macOS paste progress xattr: {e}");
        }
        if let Err(e) = remove_progress_fraction_for_file(file.get_ref()) {
            log::debug!("Failed to remove macOS paste progress xattr: {e}");
        }
        Self::set_file_metadata(file.get_ref(), file_desc);
        drop(file);

        let Some(download_file_relative_path) = self.progress.download_file_relative_path.take()
        else {
            let error = common_error("missing macOS paste download file path");
            log::error!("{}", error);
            self.progress.error = Some(error);
            return;
        };
        match self.rename_download_to_unique_final(&download_file_relative_path, file_desc) {
            Ok(_) => {}
            Err(e) => {
                log::error!("Failed to finalize macOS paste file: {}", e);
                self.progress.error = Some(e);
            }
        }
        self.progress.download_file_path = "".to_owned();
        self.progress.download_file_index = PasteTask::INVALID_FILE_INDEX;
    }

    fn rename_download_to_unique_final(
        &self,
        download_file_relative_path: &Path,
        file_desc: &FileDescription,
    ) -> Result<PathBuf, CliprdrError> {
        let final_relative_path = FileDescription::normalize_relative_name(&file_desc.name)?;
        for i in 0..UNIQUE_NAME_ATTEMPTS {
            let Some(candidate) = indexed_candidate_path(&final_relative_path, file_desc.kind, i)
            else {
                return Err(common_error("failed to derive macOS paste final file name"));
            };
            match rename_relative_file_exclusive_no_follow(
                self.target_dir_handle.as_raw_fd(),
                download_file_relative_path,
                &candidate,
            ) {
                Ok(()) => return Ok(candidate),
                Err(e) if is_name_collision(&e) => continue,
                Err(e) => return Err(file_error(&self.target_dir.join(candidate), e)),
            }
        }

        Err(common_error(format!(
            "failed to choose unique macOS paste final path under {}",
            self.target_dir.display()
        )))
    }

    #[inline]
    fn set_file_metadata(f: &File, file_desc: &FileDescription) {
        let times = FileTimes::new()
            .set_accessed(file_desc.atime)
            .set_modified(file_desc.last_modified)
            .set_created(file_desc.creation_time);
        if let Err(e) = f.set_times(times) {
            log::debug!("Failed to set macOS paste file metadata: {e}");
        }
    }

    fn send_file_contents_request(&mut self) -> Result<(), CliprdrError> {
        if self.is_finished() {
            return Ok(());
        }

        let stream_id = self.progress.list_index;
        let list_index = self.progress.list_index;
        let Some(file) = &self.files.get(list_index as usize) else {
            // unreachable
            return Err(CliprdrError::InvalidRequest {
                description: format!("Invalid file index: {}", list_index),
            });
        };
        let cb_requested = min(BLOCK_SIZE as u64, file.size - self.progress.offset);
        let conn_id = file.conn_id;

        let (n_position_high, n_position_low) = (
            (self.progress.offset >> 32) as i32,
            (self.progress.offset & (u32::MAX as u64)) as i32,
        );
        let request = ClipboardFile::FileContentsRequest {
            stream_id,
            list_index,
            dw_flags: 2,
            n_position_low,
            n_position_high,
            cb_requested: cb_requested as _,
            have_clip_data_id: false,
            clip_data_id: 0,
        };
        allow_err!(send_data(conn_id, request));
        self.progress.last_sent_time = Instant::now();

        Ok(())
    }

    fn handle_file_contents_response(
        &mut self,
        file_contents: FileContentsResponse,
    ) -> Result<(), CliprdrError> {
        if let Some(file) = self.progress.file_handle.as_mut() {
            let data = file_contents.requested_data.as_slice();
            let mut write_len = 0;
            while write_len < data.len() {
                match file.write(&data[write_len..]) {
                    Ok(0) => {
                        return Err(CliprdrError::FileError {
                            path: self.progress.download_file_path.clone(),
                            err: std::io::Error::new(
                                std::io::ErrorKind::WriteZero,
                                "failed to write macOS paste file contents",
                            ),
                        });
                    }
                    Ok(len) => {
                        write_len += len;
                    }
                    Err(e) => {
                        return Err(CliprdrError::FileError {
                            path: self.progress.download_file_path.clone(),
                            err: e,
                        });
                    }
                }
            }
            self.update_next(write_len as _)?;
        } else {
            return Err(CliprdrError::FileError {
                path: self.progress.download_file_path.clone(),
                err: std::io::Error::new(std::io::ErrorKind::NotFound, "file handle is not opened"),
            });
        }
        Ok(())
    }
}
