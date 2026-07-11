use super::{
    item_data_provider::create_pasteboard_file_url_provider,
    paste_observer::PasteObserver,
    paste_task::{FileContentsResponse, PasteTask},
};
use crate::{
    platform::unix::{
        filetype::FileDescription, FILECONTENTS_FORMAT_NAME, FILEDESCRIPTORW_FORMAT_NAME,
    },
    send_data, ClipboardFile, CliprdrError, CliprdrServiceContext, ProgressPercent,
};
use hbb_common::{allow_err, bail, log, ResultType};
use objc2::{msg_send_id, rc::autoreleasepool, rc::Id, runtime::ProtocolObject, ClassType};
use objc2_app_kit::{NSPasteboard, NSPasteboardTypeFileURL};
use objc2_foundation::{NSArray, NSString};
use std::{
    ffi::{CString, OsStr},
    fs::File,
    io,
    os::unix::{
        ffi::OsStrExt,
        io::{AsRawFd, FromRawFd},
    },
    path::{Path, PathBuf},
    sync::{
        mpsc::{channel, Receiver, RecvTimeoutError, Sender},
        Arc, Mutex,
    },
    thread,
    time::Duration,
};

lazy_static::lazy_static! {
    static ref PASTE_OBSERVER_INFO: Arc<Mutex<Option<PasteObserverInfo>>> = Default::default();
}

pub const TEMP_FILE_PREFIX: &str = ".rustdesk_";
const PLACEHOLDER_DIR_PREFIX: &str = "rustdesk-clipboard-";
const PLACEHOLDER_CREATE_ATTEMPTS: usize = 16;

#[derive(Default, Debug, Clone, PartialEq)]
pub(super) struct PasteObserverInfo {
    pub file_descriptor_id: i32,
    pub conn_id: i32,
    pub source_path: String,
    pub target_path: String,
}

impl PasteObserverInfo {
    fn exit_msg() -> Self {
        Self::default()
    }
}

struct ContextInfo {
    tx: Sender<io::Result<PasteObserverInfo>>,
    handle: thread::JoinHandle<()>,
}

fn placeholder_invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn cstring_from_os_str(value: &OsStr, context: &str) -> io::Result<CString> {
    CString::new(value.as_bytes()).map_err(|err| {
        placeholder_invalid_input(format!(
            "invalid macOS clipboard {context} contains NUL: {err}"
        ))
    })
}

fn cstring_from_path(path: &Path, context: &str) -> io::Result<CString> {
    cstring_from_os_str(path.as_os_str(), context)
}

fn macos_temp_base_dir() -> io::Result<PathBuf> {
    let base = std::env::temp_dir();
    if !base.is_absolute()
        || base.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir | std::path::Component::Prefix(_)
            )
        })
    {
        return Err(placeholder_invalid_input(format!(
            "unsupported macOS clipboard temp directory shape: {}",
            base.display()
        )));
    }
    Ok(base)
}

fn open_private_placeholder_dir(path: &Path) -> io::Result<File> {
    let path_c = cstring_from_path(path, "placeholder-directory path")?;
    let fd = unsafe {
        libc::open(
            path_c.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let dir = unsafe { File::from_raw_fd(fd) };
    if unsafe { libc::fchmod(dir.as_raw_fd(), 0o700 as libc::mode_t) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(dir.as_raw_fd(), &mut stat) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if (stat.st_mode & libc::S_IFMT) != libc::S_IFDIR {
        return Err(placeholder_invalid_input(
            "macOS clipboard placeholder path is not a directory",
        ));
    }
    let current_euid = unsafe { libc::geteuid() };
    if stat.st_uid != current_euid {
        return Err(placeholder_invalid_input(format!(
            "macOS clipboard placeholder directory owner {} does not match euid {}",
            stat.st_uid, current_euid
        )));
    }
    if stat.st_mode & 0o077 != 0 {
        return Err(placeholder_invalid_input(
            "macOS clipboard placeholder directory is accessible by group or other users",
        ));
    }
    Ok(dir)
}

fn create_placeholder_dir() -> io::Result<(PathBuf, File)> {
    let base = macos_temp_base_dir()?;
    let current_euid = unsafe { libc::geteuid() };
    for _ in 0..PLACEHOLDER_CREATE_ATTEMPTS {
        let dir = base.join(format!(
            "{}{}-{}",
            PLACEHOLDER_DIR_PREFIX,
            current_euid,
            uuid::Uuid::new_v4()
        ));
        let dir_c = cstring_from_path(&dir, "placeholder-directory path")?;
        let rc = unsafe { libc::mkdir(dir_c.as_ptr(), 0o700 as libc::mode_t) };
        if rc == 0 {
            match open_private_placeholder_dir(&dir) {
                Ok(handle) => return Ok((dir, handle)),
                Err(err) => {
                    if let Err(remove_err) = std::fs::remove_dir(&dir) {
                        log::debug!(
                            "Failed to remove rejected macOS clipboard placeholder directory {}: {remove_err}",
                            dir.display()
                        );
                    }
                    return Err(err);
                }
            }
        }
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::AlreadyExists {
            return Err(err);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "failed to create a unique macOS clipboard placeholder directory",
    ))
}

pub(super) fn create_placeholder_file(
    placeholder_dir_handle: &File,
    placeholder_dir: &Path,
) -> io::Result<PathBuf> {
    for _ in 0..PLACEHOLDER_CREATE_ATTEMPTS {
        let name = format!("{}{}", TEMP_FILE_PREFIX, uuid::Uuid::new_v4());
        let name_c = cstring_from_os_str(OsStr::new(&name), "placeholder-file name")?;
        let fd = unsafe {
            libc::openat(
                placeholder_dir_handle.as_raw_fd(),
                name_c.as_ptr(),
                libc::O_WRONLY
                    | libc::O_CREAT
                    | libc::O_EXCL
                    | libc::O_CLOEXEC
                    | libc::O_NOFOLLOW
                    | libc::O_NOCTTY,
                0o600 as libc::mode_t,
            )
        };
        if fd >= 0 {
            drop(unsafe { File::from_raw_fd(fd) });
            return Ok(placeholder_dir.join(name));
        }
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::AlreadyExists {
            return Err(err);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "failed to create a unique macOS clipboard placeholder file",
    ))
}

fn placeholder_file_name<'a>(placeholder_dir: &Path, path: &'a Path) -> Option<&'a OsStr> {
    if path.parent()? != placeholder_dir {
        return None;
    }
    let name = path.file_name()?;
    if name.as_bytes().starts_with(TEMP_FILE_PREFIX.as_bytes()) {
        Some(name)
    } else {
        None
    }
}

fn remove_placeholder_file(
    placeholder_dir_handle: &File,
    placeholder_dir: &Path,
    path: &Path,
) -> io::Result<bool> {
    let Some(name) = placeholder_file_name(placeholder_dir, path) else {
        return Ok(false);
    };
    let name = cstring_from_os_str(name, "placeholder-file name")?;
    let rc = unsafe { libc::unlinkat(placeholder_dir_handle.as_raw_fd(), name.as_ptr(), 0) };
    if rc == 0 {
        return Ok(true);
    }
    let err = io::Error::last_os_error();
    if err.kind() == io::ErrorKind::NotFound {
        Ok(true)
    } else {
        Err(err)
    }
}

fn count_placeholder_files(placeholder_dir: &Path) -> io::Result<usize> {
    let mut count = 0;
    for entry in std::fs::read_dir(placeholder_dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        if let Some(file_name) = entry.file_name().to_str() {
            if file_name.starts_with(TEMP_FILE_PREFIX) {
                count += 1;
            }
        }
    }
    Ok(count)
}

fn remove_placeholder_file_logged(
    placeholder_dir_handle: &File,
    placeholder_dir: &Path,
    path: &Path,
) {
    match remove_placeholder_file(placeholder_dir_handle, placeholder_dir, path) {
        Ok(true) => {}
        Ok(false) => {
            log::debug!(
                "Ignoring non-placeholder macOS clipboard cleanup path {}",
                path.display()
            );
        }
        Err(err) => {
            log::debug!(
                "Failed to remove macOS clipboard placeholder file {}: {err}",
                path.display()
            );
        }
    }
}

pub struct PasteboardContext {
    pasteboard: Id<NSPasteboard>,
    observer: Arc<Mutex<PasteObserver>>,
    tx_handle: Option<ContextInfo>,
    tx_remove_file: Option<Sender<String>>,
    remove_file_handle: Option<thread::JoinHandle<()>>,
    tx_paste_task: Sender<FileContentsResponse>,
    paste_task: Arc<Mutex<PasteTask>>,
    placeholder_dir: PathBuf,
    placeholder_dir_handle: Arc<File>,
}

unsafe impl Send for PasteboardContext {}
unsafe impl Sync for PasteboardContext {}

impl Drop for PasteboardContext {
    fn drop(&mut self) {
        self.observer.lock().unwrap().stop();
        if let Some(tx_handle) = self.tx_handle.take() {
            if tx_handle.tx.send(Ok(PasteObserverInfo::exit_msg())).is_ok() {
                tx_handle.handle.join().ok();
            }
        }
        self.tx_remove_file.take();
        if let Some(remove_file_handle) = self.remove_file_handle.take() {
            remove_file_handle.join().ok();
        }
        if let Err(err) = std::fs::remove_dir(&self.placeholder_dir) {
            log::debug!(
                "Failed to remove macOS clipboard placeholder directory {}: {err}",
                self.placeholder_dir.display()
            );
        }
    }
}

impl CliprdrServiceContext for PasteboardContext {
    fn set_is_stopped(&mut self) -> Result<(), CliprdrError> {
        Ok(())
    }

    fn empty_clipboard(&mut self, conn_id: i32) -> Result<bool, CliprdrError> {
        Ok(self.empty_clipboard_(conn_id))
    }

    fn server_clip_file(&mut self, conn_id: i32, msg: ClipboardFile) -> Result<(), CliprdrError> {
        self.server_clip_file_(conn_id, msg)
    }

    fn get_progress_percent(&self) -> Option<ProgressPercent> {
        self.paste_task.lock().unwrap().progress_percent()
    }

    fn cancel(&mut self) {
        self.paste_task.lock().unwrap().cancel();
    }
}

impl PasteboardContext {
    fn init(&mut self) {
        let (tx_remove_file, rx_remove_file) = channel();
        let handle_remove_file = Self::init_thread_remove_file(
            rx_remove_file,
            self.placeholder_dir.clone(),
            self.placeholder_dir_handle.clone(),
        );
        self.tx_remove_file = Some(tx_remove_file.clone());
        self.remove_file_handle = Some(handle_remove_file);

        let (tx, rx) = channel();
        let observer: Arc<Mutex<PasteObserver>> = self.observer.clone();
        let handle = Self::init_thread_observer(tx_remove_file, rx, observer);
        self.tx_handle = Some(ContextInfo { tx, handle });
    }

    fn init_thread_observer(
        tx_remove_file: Sender<String>,
        rx: Receiver<io::Result<PasteObserverInfo>>,
        observer: Arc<Mutex<PasteObserver>>,
    ) -> thread::JoinHandle<()> {
        let exit_msg = PasteObserverInfo::exit_msg();
        thread::spawn(move || loop {
            match rx.recv() {
                Ok(Ok(task_info)) => {
                    if task_info == exit_msg {
                        log::debug!("pasteboard item data provider: exit");
                        break;
                    }
                    tx_remove_file.send(task_info.source_path.clone()).ok();
                    observer.lock().unwrap().start(task_info);
                }
                Ok(Err(e)) => {
                    log::error!("pasteboard item data provider, inner error: {e}");
                }
                Err(e) => {
                    log::error!("pasteboard item data provider, error: {e}");
                    break;
                }
            }
        })
    }

    fn init_thread_remove_file(
        rx: Receiver<String>,
        placeholder_dir: PathBuf,
        placeholder_dir_handle: Arc<File>,
    ) -> thread::JoinHandle<()> {
        thread::spawn(move || {
            let mut cur_file: Option<String> = None;
            loop {
                match rx.recv_timeout(Duration::from_secs(30)) {
                    Ok(path) => {
                        if let Some(file) = cur_file.take() {
                            if !file.is_empty() {
                                remove_placeholder_file_logged(
                                    &placeholder_dir_handle,
                                    &placeholder_dir,
                                    Path::new(&file),
                                );
                            }
                        }
                        if !path.is_empty() {
                            cur_file = Some(path);
                        }
                    }
                    Err(e) => {
                        if let Some(file) = cur_file.take() {
                            if !file.is_empty() {
                                remove_placeholder_file_logged(
                                    &placeholder_dir_handle,
                                    &placeholder_dir,
                                    Path::new(&file),
                                );
                            }
                        }
                        if e == RecvTimeoutError::Disconnected {
                            break;
                        }
                    }
                }
            }
        })
    }

    // Just removing the file can also make paste option in the context menu disappear.
    fn empty_clipboard_(&mut self, _conn_id: i32) -> bool {
        self.tx_remove_file
            .as_ref()
            .map(|tx| tx.send("".to_string()).ok());
        true
    }

    fn temp_files_count(&self) -> io::Result<usize> {
        count_placeholder_files(&self.placeholder_dir)
    }

    fn server_clip_file_(&mut self, conn_id: i32, msg: ClipboardFile) -> Result<(), CliprdrError> {
        match msg {
            ClipboardFile::FormatList { format_list } => {
                let temp_files =
                    self.temp_files_count()
                        .map_err(|err| CliprdrError::CommonError {
                            description: format!(
                                "failed to inspect macOS clipboard placeholder directory: {err}"
                            ),
                        })?;
                if temp_files >= 3 {
                    // The temp files should be 0 or 1 in normal case.
                    // We should not continue to paste files if there are more than 3 temp files.
                    return Err(CliprdrError::CommonError {
                        description: format!(
                            "too many temp files, current: {}, limit: {}",
                            temp_files, 3
                        ),
                    });
                }

                let task_lock = self.paste_task.lock().unwrap();
                if !task_lock.is_finished() {
                    return Err(CliprdrError::CommonError {
                        description: "previous file paste task is not finished".to_string(),
                    });
                }
                self.handle_format_list(conn_id, format_list)?;
            }
            ClipboardFile::FormatDataResponse {
                msg_flags,
                format_data,
            } => {
                self.handle_format_data_response(conn_id, msg_flags, format_data)?;
            }
            ClipboardFile::FileContentsResponse {
                msg_flags,
                stream_id,
                requested_data,
            } => {
                self.handle_file_contents_response(conn_id, msg_flags, stream_id, requested_data)?;
            }
            ClipboardFile::TryEmpty => self.handle_try_empty(conn_id),
            _ => {}
        }
        Ok(())
    }

    fn handle_format_list(
        &self,
        conn_id: i32,
        format_list: Vec<(i32, String)>,
    ) -> Result<(), CliprdrError> {
        if let Some(tx_handle) = self.tx_handle.as_ref() {
            if !format_list
                .iter()
                .find(|(_, name)| name == FILECONTENTS_FORMAT_NAME)
                .map(|(id, _)| *id)
                .is_some()
            {
                return Err(CliprdrError::CommonError {
                    description: "no file contents format found".to_string(),
                });
            };
            let Some(file_descriptor_id) = format_list
                .iter()
                .find(|(_, name)| name == FILEDESCRIPTORW_FORMAT_NAME)
                .map(|(id, _)| *id)
            else {
                return Err(CliprdrError::CommonError {
                    description: "no file descriptor format found".to_string(),
                });
            };

            autoreleasepool(|_| self.set_clipboard_item(tx_handle, conn_id, file_descriptor_id))?;
        } else {
            return Err(CliprdrError::CommonError {
                description: "pasteboard context is not inited".to_string(),
            });
        }
        Ok(())
    }

    fn set_clipboard_item(
        &self,
        tx_handle: &ContextInfo,
        conn_id: i32,
        file_descriptor_id: i32,
    ) -> Result<(), CliprdrError> {
        let tx = tx_handle.tx.clone();
        let provider = create_pasteboard_file_url_provider(
            PasteObserverInfo {
                file_descriptor_id,
                conn_id,
                source_path: "".to_string(),
                target_path: "".to_string(),
            },
            tx,
            self.placeholder_dir.clone(),
            self.placeholder_dir_handle.clone(),
        );
        unsafe {
            let types = NSArray::from_vec(vec![NSString::from_str(
                &NSPasteboardTypeFileURL.to_string(),
            )]);
            let item = objc2_app_kit::NSPasteboardItem::new();
            item.setDataProvider_forTypes(&ProtocolObject::from_id(provider), &types);
            self.pasteboard.clearContents();
            if !self
                .pasteboard
                .writeObjects(&Id::cast(NSArray::from_vec(vec![item])))
            {
                return Err(CliprdrError::CommonError {
                    description: "failed to write objects".to_string(),
                });
            }
        }
        Ok(())
    }

    fn handle_format_data_response(
        &self,
        conn_id: i32,
        msg_flags: i32,
        format_data: Vec<u8>,
    ) -> Result<(), CliprdrError> {
        log::debug!("handle format data response, msg_flags: {msg_flags}");
        if msg_flags != 0x1 {
            // return failure message?
        }

        let mut task_lock = self.paste_task.lock().unwrap();
        let target_dir = PASTE_OBSERVER_INFO
            .lock()
            .unwrap()
            .as_ref()
            .map(|task| task.target_path.clone());
        // unreachable in normal case
        let Some(target_dir) = target_dir.as_ref().map(|d| Path::new(d).parent()).flatten() else {
            return Err(CliprdrError::CommonError {
                description: "failed to get parent path".to_string(),
            });
        };
        // unreachable in normal case
        if !target_dir.exists() {
            return Err(CliprdrError::CommonError {
                description: "target path does not exist".to_string(),
            });
        }
        let target_dir = target_dir.to_owned();
        match FileDescription::parse_file_descriptors(format_data, conn_id) {
            Ok(files) => {
                if let Err(e) = task_lock.start(target_dir, files) {
                    PASTE_OBSERVER_INFO
                        .lock()
                        .unwrap()
                        .replace(PasteObserverInfo::default());
                    Err(e)
                } else {
                    Ok(())
                }
            }
            Err(e) => {
                PASTE_OBSERVER_INFO
                    .lock()
                    .unwrap()
                    .replace(PasteObserverInfo::default());
                Err(e)
            }
        }
    }

    fn handle_file_contents_response(
        &self,
        conn_id: i32,
        msg_flags: i32,
        stream_id: i32,
        requested_data: Vec<u8>,
    ) -> Result<(), CliprdrError> {
        log::debug!("handle file contents response");
        self.tx_paste_task
            .send(FileContentsResponse {
                conn_id,
                msg_flags,
                stream_id,
                requested_data,
            })
            .ok();
        Ok(())
    }

    fn handle_try_empty(&mut self, conn_id: i32) {
        log::debug!("empty_clipboard called");
        let ret = self.empty_clipboard_(conn_id);
        log::debug!(
            "empty_clipboard called, conn_id {}, return {}",
            conn_id,
            ret
        );
    }
}

fn handle_paste_result(
    task_info: &PasteObserverInfo,
    placeholder_dir: &Path,
    placeholder_dir_handle: &File,
) {
    log::info!(
        "file {} is pasted to {}",
        &task_info.source_path,
        &task_info.target_path
    );
    if Path::new(&task_info.target_path).parent().is_none() {
        log::error!(
            "failed to get parent path of {}, no need to perform pasting",
            &task_info.target_path
        );
        return;
    }

    PASTE_OBSERVER_INFO
        .lock()
        .unwrap()
        .replace(task_info.clone());
    // to-do: add a timeout to clear data in `PASTE_OBSERVER_INFO`.
    remove_placeholder_file_logged(
        placeholder_dir_handle,
        placeholder_dir,
        Path::new(&task_info.source_path),
    );
    if let Err(err) = std::fs::remove_file(&task_info.target_path) {
        log::debug!(
            "Failed to remove macOS clipboard paste placeholder target {}: {err}",
            &task_info.target_path
        );
    }
    let data = ClipboardFile::FormatDataRequest {
        requested_format_id: task_info.file_descriptor_id,
    };
    allow_err!(send_data(task_info.conn_id as _, data));
}

#[inline]
pub fn create_pasteboard_context() -> ResultType<Box<PasteboardContext>> {
    let pasteboard: Option<Id<NSPasteboard>> =
        unsafe { msg_send_id![NSPasteboard::class(), generalPasteboard] };
    let Some(pasteboard) = pasteboard else {
        bail!("failed to get general pasteboard");
    };
    let (placeholder_dir, placeholder_dir_handle) = create_placeholder_dir()?;
    let placeholder_dir_handle = Arc::new(placeholder_dir_handle);
    let mut observer = PasteObserver::new();
    {
        let placeholder_dir = placeholder_dir.clone();
        let placeholder_dir_handle = placeholder_dir_handle.clone();
        observer.init(move |task_info| {
            handle_paste_result(task_info, &placeholder_dir, &placeholder_dir_handle)
        })?;
    }
    let (tx, rx) = channel();
    let mut context = Box::new(PasteboardContext {
        pasteboard,
        observer: Arc::new(Mutex::new(observer)),
        tx_handle: None,
        tx_remove_file: None,
        remove_file_handle: None,
        tx_paste_task: tx,
        paste_task: Arc::new(Mutex::new(PasteTask::new(rx))),
        placeholder_dir,
        placeholder_dir_handle,
    });
    context.init();
    Ok(context)
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_private_placeholder_dir_file_count_and_cleanup() {
        let (placeholder_dir, placeholder_dir_handle) =
            super::create_placeholder_dir().expect("create placeholder dir");
        assert_eq!(0, super::count_placeholder_files(&placeholder_dir).unwrap());

        let path = super::create_placeholder_file(&placeholder_dir_handle, &placeholder_dir)
            .expect("create placeholder file");
        assert_eq!(1, super::count_placeholder_files(&placeholder_dir).unwrap());
        assert!(super::placeholder_file_name(&placeholder_dir, &path).is_some());
        assert!(
            super::remove_placeholder_file(&placeholder_dir_handle, &placeholder_dir, &path)
                .expect("remove placeholder file")
        );
        assert_eq!(0, super::count_placeholder_files(&placeholder_dir).unwrap());

        std::fs::remove_dir(placeholder_dir).expect("remove placeholder dir");
    }
}
