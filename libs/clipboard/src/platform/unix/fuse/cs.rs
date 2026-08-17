//! fuse server implement
//! we use fuse to provide file readers, warping data transfer to file interfaces
//!
//! # Name encoding
//!
//! There are different collection of characters forbidden in file names on different platforms:
//! - windows: `\/:*?"<>|`
//! - macos: `:/`
//! - linux: `/`
//!
//! what makes it troublesome is windows also used '\' as path separator.
//!
//! For now, we transfer all file names with windows separators, UTF-16 encoded.
//! *Need a way to transfer file names with '\' safely*.
//! Maybe we can use URL encoded file names and '/' separators as a new standard, while keep the support to old schemes.
//!
//! # Note
//! - all files on FS should be read only, and mark the owner to be the current user
//! - any write operations, hard links, and symbolic links on the FS should be denied

use std::{
    collections::{BTreeMap, HashMap},
    ffi::OsString,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc::{Receiver, SyncSender, TrySendError},
        Arc,
    },
    time::{Duration, SystemTime},
};

use fuser::{ReplyDirectory, FUSE_ROOT_ID};
use hbb_common::log;
use parking_lot::{Condvar, Mutex};

use crate::{
    platform::unix::{
        filetype::{FileDescription, FileType, Inode, MAX_NAME_LEN, PERM_RWX},
        BLOCK_SIZE,
    },
    send_data, ClipboardFile, CliprdrError,
};

/// fuse server ready retry max times
const READ_RETRY: i32 = 3;
pub(crate) const FUSE_RESPONSE_QUEUE_CAPACITY: usize = 8;

#[derive(Debug, Clone)]
pub(crate) struct FuseFileContentResponse {
    pub conn_id: i32,
    pub clip: ClipboardFile,
}

#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
struct FuseFileContentResponseKey {
    conn_id: i32,
    stream_id: i32,
}

#[derive(Debug, Clone)]
struct FuseFileContentResponseRoute {
    id: u64,
    tx: SyncSender<ClipboardFile>,
}

#[derive(Debug, Default)]
struct FuseFileContentResponseRoutes {
    next_id: u64,
    routes: HashMap<FuseFileContentResponseKey, FuseFileContentResponseRoute>,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct FuseFileContentResponseRouter {
    routes: Arc<Mutex<FuseFileContentResponseRoutes>>,
}

#[derive(Debug)]
struct FuseFileContentResponseGuard {
    router: FuseFileContentResponseRouter,
    key: FuseFileContentResponseKey,
    id: u64,
}

impl FuseFileContentResponse {
    fn key(&self) -> Result<FuseFileContentResponseKey, CliprdrError> {
        match &self.clip {
            ClipboardFile::FileContentsResponse { stream_id, .. } => {
                Ok(FuseFileContentResponseKey {
                    conn_id: self.conn_id,
                    stream_id: *stream_id,
                })
            }
            _ => Err(CliprdrError::InvalidRequest {
                description: "non file-content response routed to FUSE".to_owned(),
            }),
        }
    }
}

impl FuseFileContentResponseRouter {
    fn register(
        &self,
        conn_id: i32,
        stream_id: i32,
    ) -> Result<(Receiver<ClipboardFile>, FuseFileContentResponseGuard), CliprdrError> {
        let key = FuseFileContentResponseKey { conn_id, stream_id };
        let (tx, rx) = std::sync::mpsc::sync_channel(FUSE_RESPONSE_QUEUE_CAPACITY);
        let mut routes = self.routes.lock();
        if routes.routes.contains_key(&key) {
            return Err(CliprdrError::ClipboardOccupied);
        }
        let Some(id) = routes.next_id.checked_add(1) else {
            return Err(CliprdrError::ClipboardInternalError);
        };
        routes.next_id = id;
        routes
            .routes
            .insert(key, FuseFileContentResponseRoute { id, tx });
        Ok((
            rx,
            FuseFileContentResponseGuard {
                router: self.clone(),
                key,
                id,
            },
        ))
    }

    pub(crate) fn dispatch(&self, response: FuseFileContentResponse) -> Result<(), CliprdrError> {
        let key = response.key()?;
        let route = self.routes.lock().routes.get(&key).cloned();
        let Some(route) = route else {
            log::debug!("dropping FUSE file-content response without an active read route");
            return Ok(());
        };

        route.tx.try_send(response.clip).map_err(|e| match e {
            TrySendError::Full(_) => {
                log::warn!("FUSE file-content response queue is full; dropping peer response");
                CliprdrError::ClipboardOccupied
            }
            TrySendError::Disconnected(_) => {
                log::error!("failed to send file contents response to fuse: channel closed");
                CliprdrError::ClipboardInternalError
            }
        })
    }

    fn unregister(&self, key: FuseFileContentResponseKey, id: u64) {
        let mut routes = self.routes.lock();
        let Some(route) = routes.routes.get(&key) else {
            return;
        };
        if route.id == id {
            routes.routes.remove(&key);
        }
    }

    #[cfg(test)]
    fn active_route_count(&self) -> usize {
        self.routes.lock().routes.len()
    }
}

impl Drop for FuseFileContentResponseGuard {
    fn drop(&mut self) {
        self.router.unregister(self.key, self.id);
    }
}

impl From<FileType> for fuser::FileType {
    fn from(value: FileType) -> Self {
        match value {
            FileType::File => Self::RegularFile,
            FileType::Directory => Self::Directory,
            FileType::Symlink => Self::Symlink,
        }
    }
}

/// fuse client
/// this is a proxy to the fuse server
#[derive(Debug)]
pub struct FuseClient {
    server: Arc<Mutex<FuseServer>>,
}

impl fuser::Filesystem for FuseClient {
    fn init(
        &mut self,
        req: &fuser::Request<'_>,
        config: &mut fuser::KernelConfig,
    ) -> Result<(), libc::c_int> {
        let mut server = self.server.lock();
        server.init(req, config)
    }

    fn lookup(
        &mut self,
        req: &fuser::Request<'_>,
        parent: u64,
        name: &std::ffi::OsStr,
        reply: fuser::ReplyEntry,
    ) {
        let mut server = self.server.lock();
        server.lookup(req, parent, name, reply)
    }

    fn opendir(&mut self, req: &fuser::Request<'_>, ino: u64, flags: i32, reply: fuser::ReplyOpen) {
        let mut server = self.server.lock();
        server.opendir(req, ino, flags, reply)
    }

    fn readdir(
        &mut self,
        req: &fuser::Request<'_>,
        ino: u64,
        fh: u64,
        offset: i64,
        reply: fuser::ReplyDirectory,
    ) {
        let mut server = self.server.lock();
        server.readdir(req, ino, fh, offset, reply)
    }

    fn releasedir(
        &mut self,
        req: &fuser::Request<'_>,
        ino: u64,
        fh: u64,
        _flags: i32,
        reply: fuser::ReplyEmpty,
    ) {
        let mut server = self.server.lock();
        server.releasedir(req, ino, fh, _flags, reply)
    }

    fn open(&mut self, req: &fuser::Request<'_>, ino: u64, flags: i32, reply: fuser::ReplyOpen) {
        let mut server = self.server.lock();
        server.open(req, ino, flags, reply)
    }

    fn read(
        &mut self,
        req: &fuser::Request<'_>,
        ino: u64,
        fh: u64,
        offset: i64,
        size: u32,
        flags: i32,
        lock_owner: Option<u64>,
        reply: fuser::ReplyData,
    ) {
        let mut server = self.server.lock();
        server.read(req, ino, fh, offset, size, flags, lock_owner, reply)
    }

    fn release(
        &mut self,
        req: &fuser::Request<'_>,
        ino: u64,
        fh: u64,
        _flags: i32,
        _lock_owner: Option<u64>,
        _flush: bool,
        reply: fuser::ReplyEmpty,
    ) {
        let mut server = self.server.lock();
        server.release(req, ino, fh, _flags, _lock_owner, _flush, reply)
    }

    fn getattr(
        &mut self,
        req: &fuser::Request<'_>,
        ino: u64,
        fh: Option<u64>,
        reply: fuser::ReplyAttr,
    ) {
        let mut server = self.server.lock();
        server.getattr(req, ino, fh, reply)
    }

    fn statfs(&mut self, req: &fuser::Request<'_>, ino: u64, reply: fuser::ReplyStatfs) {
        let mut server = self.server.lock();
        server.statfs(req, ino, reply)
    }
}

/// fuse server
/// provides a read-only file system
#[derive(Debug)]
pub(crate) struct FuseServer {
    generation: AtomicU64,
    files: Vec<FuseNode>,
    // file handle counter
    file_handle_counter: AtomicU64,
    // timeout
    timeout: Duration,
    // active file-read response routes
    response_router: FuseFileContentResponseRouter,
}

impl FuseServer {
    /// create a new fuse server
    pub fn new(timeout: Duration) -> (Self, FuseFileContentResponseRouter) {
        let response_router = FuseFileContentResponseRouter::default();
        (
            Self {
                generation: AtomicU64::new(0),
                files: Vec::new(),
                file_handle_counter: AtomicU64::new(0),
                timeout,
                response_router: response_router.clone(),
            },
            response_router,
        )
    }

    pub fn client(server: Arc<Mutex<Self>>) -> FuseClient {
        FuseClient { server }
    }
}

impl FuseServer {
    pub fn load_file_list(&mut self, files: Vec<FileDescription>) -> Result<(), CliprdrError> {
        let tree = FuseNode::build_tree(files)?;
        self.files = tree;
        self.generation.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

impl fuser::Filesystem for FuseServer {
    fn init(
        &mut self,
        _req: &fuser::Request<'_>,
        _config: &mut fuser::KernelConfig,
    ) -> Result<(), libc::c_int> {
        if self.files.is_empty() {
            // create a root file
            let root = FuseNode::new_root();
            self.files.push(root);
        }
        Ok(())
    }

    fn lookup(
        &mut self,
        _req: &fuser::Request<'_>,
        parent: u64,
        name: &std::ffi::OsStr,
        reply: fuser::ReplyEntry,
    ) {
        if name.len() > MAX_NAME_LEN {
            log::debug!("fuse: name too long");
            reply.error(libc::ENAMETOOLONG);
            return;
        }

        let entries = &self.files;

        let generation = self.generation.load(Ordering::Relaxed);

        let parent_entry = match entries.get(parent as usize - 1) {
            Some(f) => f,
            None => {
                log::error!("fuse: parent not found");
                reply.error(libc::ENOENT);
                return;
            }
        };

        if parent_entry.attributes.kind != FileType::Directory {
            log::error!("fuse: parent is not a directory");
            reply.error(libc::ENOTDIR);
            return;
        }

        let children_inodes = &parent_entry.children;

        for inode in children_inodes.iter().copied() {
            let child = &entries[inode as usize - 1];
            let entry_name = OsString::from(&child.name);

            if &entry_name.as_os_str() == &name {
                let ttl = std::time::Duration::new(0, 0);
                reply.entry(&ttl, &(&child.attributes).into(), generation);
                log::debug!("fuse: found child");
                return;
            }
        }
        // error
        reply.error(libc::ENOENT);
        log::debug!("fuse: child not found");
    }

    fn opendir(
        &mut self,
        _req: &fuser::Request<'_>,
        ino: u64,
        _flags: i32,
        reply: fuser::ReplyOpen,
    ) {
        let files = &self.files;
        let Some(entry) = files.get(ino as usize - 1) else {
            reply.error(libc::ENOENT);
            log::error!("fuse: opendir: entry not found");
            return;
        };
        if entry.attributes.kind != FileType::Directory {
            reply.error(libc::ENOTDIR);
            log::error!("fuse: opendir: entry is not a directory");
            return;
        }
        // in gc, deny open
        if entry.marked() {
            log::error!("fuse: opendir: entry is in gc");
            reply.error(libc::EBUSY);
            return;
        }

        let fh = self.alloc_fd();
        entry.add_handler(fh);
        reply.opened(fh, 0);
    }

    fn readdir(
        &mut self,
        _req: &fuser::Request<'_>,
        ino: u64,
        fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        let files = &self.files;
        let Some(entry) = files.get(ino as usize - 1) else {
            reply.error(libc::ENOENT);
            log::error!("fuse: readdir: entry not found");
            return;
        };
        if !entry.have_handler(fh) {
            reply.error(libc::EBADF);
            log::error!("fuse: readdir: entry has no such handler");
            return;
        }
        if entry.attributes.kind != FileType::Directory {
            reply.error(libc::ENOTDIR);
            log::error!("fuse: readdir: entry is not a directory");
            return;
        }

        let offset = offset as usize;
        let mut entries = Vec::new();

        let self_entry = (ino, FileType::Directory, OsString::from("."));
        entries.push(self_entry);

        if let Some(parent_inode) = entry.parent {
            entries.push((parent_inode, FileType::Directory, OsString::from("..")));
        }

        for inode in entry.children.iter().copied() {
            let child = &files[inode as usize - 1];
            let kind = child.attributes.kind;
            let name = OsString::from(&child.name);
            let child_entry = (inode, kind, name.to_owned());
            entries.push(child_entry);
        }

        for (i, entry) in entries.into_iter().enumerate().skip(offset) {
            if reply.add(entry.0, i as i64 + 1, entry.1.into(), entry.2) {
                break;
            }
        }

        reply.ok();
    }

    fn releasedir(
        &mut self,
        _req: &fuser::Request<'_>,
        ino: u64,
        fh: u64,
        _flags: i32,
        reply: fuser::ReplyEmpty,
    ) {
        let files = &self.files;
        let Some(entry) = files.get(ino as usize - 1) else {
            reply.error(libc::ENOENT);
            log::error!("fuse: releasedir: entry not found");
            return;
        };
        if entry.attributes.kind != FileType::Directory {
            reply.error(libc::ENOTDIR);
            log::error!("fuse: releasedir: entry is not a directory");
            return;
        }
        if !entry.have_handler(fh) {
            reply.error(libc::EBADF);
            log::error!("fuse: releasedir: entry has no such handler");
            return;
        }

        let _ = entry.unregister_handler(fh);
        reply.ok();
    }

    fn open(&mut self, _req: &fuser::Request<'_>, ino: u64, _flags: i32, reply: fuser::ReplyOpen) {
        let files = &self.files;
        let Some(entry) = files.get(ino as usize - 1) else {
            reply.error(libc::ENOENT);
            log::error!("fuse: open: entry not found");
            return;
        };

        // todo: support link file
        if entry.attributes.kind != FileType::File {
            reply.error(libc::ENFILE);
            log::error!("fuse: open: entry is not a file");
            return;
        }

        // check gc
        if entry.marked() {
            reply.error(libc::EBUSY);
            log::error!("fuse: open: entry is in gc");
            return;
        }

        let fh = self.alloc_fd();
        entry.add_handler(fh);
        reply.opened(fh, 0);
    }

    // todo: implement retry
    fn read(
        &mut self,
        _req: &fuser::Request<'_>,
        ino: u64,
        fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: fuser::ReplyData,
    ) {
        let files = &self.files;
        let Some(entry) = files.get(ino as usize - 1) else {
            reply.error(libc::ENOENT);
            log::error!("fuse: read: entry not found");
            return;
        };
        if !entry.have_handler(fh) {
            reply.error(libc::EBADF);
            log::error!("fuse: read: entry has no such handler");
            return;
        }
        if entry.attributes.kind != FileType::File {
            reply.error(libc::ENFILE);
            log::error!("fuse: read: entry is not a file");
            return;
        }

        if entry.marked() {
            reply.error(libc::EBUSY);
            log::error!("fuse: read: entry is in gc");
            return;
        }

        let bytes = match self.read_node(entry, offset, size) {
            Ok(b) => b,
            Err(e) => {
                log::error!("failed to read entry: {:?}", e);
                reply.error(libc::EIO);
                return;
            }
        };

        reply.data(bytes.as_slice());
    }

    fn release(
        &mut self,
        _req: &fuser::Request<'_>,
        ino: u64,
        fh: u64,
        _flags: i32,
        _lock_owner: Option<u64>,
        _flush: bool,
        reply: fuser::ReplyEmpty,
    ) {
        let files = &self.files;
        let Some(entry) = files.get(ino as usize - 1) else {
            reply.error(libc::ENOENT);
            log::error!("fuse: release: entry not found");
            return;
        };

        if entry.unregister_handler(fh).is_err() {
            reply.error(libc::EBADF);
            log::error!("fuse: release: entry has no such handler");
            return;
        }
        reply.ok();
    }

    fn getattr(
        &mut self,
        _req: &fuser::Request<'_>,
        ino: u64,
        _fh: Option<u64>,
        reply: fuser::ReplyAttr,
    ) {
        let files = &self.files;
        let Some(entry) = files.get(ino as usize - 1) else {
            reply.error(libc::ENOENT);
            log::error!("fuse: getattr: entry not found");
            return;
        };

        let attr = (&entry.attributes).into();
        reply.attr(&std::time::Duration::default(), &attr)
    }

    fn statfs(&mut self, _req: &fuser::Request<'_>, _ino: u64, reply: fuser::ReplyStatfs) {
        let mut blocks = 0;
        for file in self.files.iter() {
            blocks += file.attributes.size / (BLOCK_SIZE as u64)
                + (file.attributes.size % (BLOCK_SIZE as u64) != 0) as u64;
        }
        reply.statfs(blocks, 0, 0, 0, 0, BLOCK_SIZE, 512, BLOCK_SIZE)
    }
}

impl FuseServer {
    // get files and directory path right in root of FUSE fs
    pub fn list_root(&self) -> Vec<PathBuf> {
        let files = &self.files;
        let children = &files[0].children;
        let mut paths = Vec::with_capacity(children.len());
        for inode in children.iter().copied() {
            let idx = inode as usize - 1;
            paths.push(PathBuf::from(&files[idx].name));
        }
        paths
    }

    /// allocate a new file descriptor
    fn alloc_fd(&self) -> u64 {
        self.file_handle_counter.fetch_add(1, Ordering::Relaxed)
    }

    fn read_node(
        &self,
        node: &FuseNode,
        offset: i64,
        size: u32,
    ) -> Result<Vec<u8>, std::io::Error> {
        let stream_id: i32 = rand::random();
        let cb_requested = unsafe {
            // convert `size` from u32 to i32
            // yet with same bit representation
            std::mem::transmute::<u32, i32>(size)
        };

        let (n_position_high, n_position_low) =
            ((offset >> 32) as i32, (offset & (u32::MAX as i64)) as i32);
        let request = ClipboardFile::FileContentsRequest {
            stream_id,
            list_index: node.index as i32,
            dw_flags: 2,
            n_position_low,
            n_position_high,
            cb_requested,
            have_clip_data_id: false,
            clip_data_id: 0,
        };

        let (rx, _response_route) = self
            .response_router
            .register(node.conn_id, stream_id)
            .map_err(|e| {
                log::error!("failed to register file-content response route: {:?}", e);
                std::io::Error::new(std::io::ErrorKind::Other, e)
            })?;

        send_data(node.conn_id, request.clone()).map_err(|e| {
            log::error!("failed to send file list to channel: {:?}", e);
            std::io::Error::new(std::io::ErrorKind::Other, e)
        })?;

        let mut retry_times = 0;

        // to-do: more tests needed
        loop {
            let reply = rx.recv_timeout(self.timeout).map_err(|e| {
                log::error!("failed to receive file list from channel: {:?}", e);
                std::io::Error::new(std::io::ErrorKind::TimedOut, e)
            })?;

            match reply {
                ClipboardFile::FileContentsResponse {
                    msg_flags,
                    stream_id: response_stream_id,
                    requested_data,
                } => {
                    if response_stream_id != stream_id {
                        log::debug!("stream id mismatch, ignore");
                        continue;
                    }

                    if msg_flags & 1 == 0 {
                        retry_times += 1;
                        if retry_times > READ_RETRY {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::Other,
                                "failure request",
                            ));
                        }

                        send_data(node.conn_id, request.clone()).map_err(|e| {
                            log::error!("failed to send file list to channel: {:?}", e);
                            std::io::Error::new(std::io::ErrorKind::Other, e)
                        })?;
                        continue;
                    }
                    return Ok(requested_data);
                }
                _ => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "invalid reply",
                    ))
                }
            }
        }
    }
}
/// a node in the FUSE file tree
#[derive(Debug)]
struct FuseNode {
    /// connection id
    pub conn_id: i32,

    /// file index in peer's file list
    /// NOTE:
    /// it is NOT the same as inode, this is the index in the file list
    pub index: usize,

    /// parent inode
    pub parent: Option<u64>,

    /// file name
    pub name: String,
    /// file attributes
    pub attributes: InodeAttributes,
    /// children inodes
    pub children: Vec<Inode>,

    /// marked gc
    pub file_handlers: FileHandles,
}

impl FuseNode {
    pub fn from_description(inode: Inode, desc: FileDescription) -> Self {
        Self {
            conn_id: desc.conn_id,
            index: inode as usize - 2,
            name: desc
                .name
                .to_str()
                .map(|s| s.to_string())
                .unwrap_or_default(),
            parent: None,
            attributes: InodeAttributes::from_description(inode, desc),
            children: Vec::new(),
            file_handlers: FileHandles::new(),
        }
    }

    pub fn new_root() -> Self {
        Self {
            conn_id: 0,
            index: 0,
            name: String::from("/"),
            parent: None,
            attributes: InodeAttributes::new_root(),
            children: Vec::new(),
            file_handlers: FileHandles::new(),
        }
    }

    #[allow(unused)]
    pub fn is_file(&self) -> bool {
        self.attributes.kind == FileType::File
    }

    pub fn marked(&self) -> bool {
        self.file_handlers.marked()
    }

    pub fn add_handler(&self, fh: u64) {
        self.file_handlers.add_handler(fh)
    }

    pub fn unregister_handler(&self, fh: u64) -> Result<(), std::io::Error> {
        self.file_handlers.unregister(fh)
    }

    pub fn have_handler(&self, fh: u64) -> bool {
        self.file_handlers.have_handler(fh)
    }

    /// add a child inode
    fn add_child(&mut self, inode: Inode) {
        self.children.push(inode);
    }

    /// calculate the file tree from a pre-ordered file list
    /// ## implement detail:
    /// - a new root entry will be prepended to the list
    /// - all file names will be trimed to the last component
    pub fn build_tree(files: Vec<FileDescription>) -> Result<Vec<Self>, CliprdrError> {
        // capacity set to file count + 1 (root)
        let mut tree_list = Vec::with_capacity(files.len() + 1);
        let root = Self::new_root();
        tree_list.push(root);

        // build the tree first
        // root map, name -> inode
        let mut sub_root_map = HashMap::new();
        sub_root_map.insert(Path::new("/").to_path_buf(), FUSE_ROOT_ID);
        sub_root_map.insert(Path::new("").to_path_buf(), FUSE_ROOT_ID);

        for file in files.into_iter() {
            let name = file.name.clone();

            let inode = tree_list.len() as u64 + FUSE_ROOT_ID;
            let parent_inode = match name.parent() {
                Some(parent) => sub_root_map.get(parent).copied().unwrap_or(FUSE_ROOT_ID),
                None => {
                    // parent should be root
                    FUSE_ROOT_ID
                }
            };
            tree_list[parent_inode as usize - 1].add_child(inode);

            let base_name = name.file_name().ok_or_else(|| {
                let err = std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("invalid file name {}", file.name.display()),
                );
                CliprdrError::FileError {
                    path: file.name.to_string_lossy().to_string(),
                    err,
                }
            })?;

            let mut desc = file.clone();

            if desc.kind == FileType::Directory {
                sub_root_map.insert(desc.name.clone(), inode);
            }

            desc.name = Path::new(base_name).to_path_buf();

            let mut fuse_node = FuseNode::from_description(inode, desc);
            fuse_node.parent = Some(parent_inode);
            tree_list.push(fuse_node);
        }
        Ok(tree_list)
    }
}

#[derive(Debug, Clone)]
pub struct InodeAttributes {
    inode: Inode,
    size: u64,
    // file reference meta
    // should be the only mutable field in this struct
    last_accessed: std::time::SystemTime,
    last_modified: std::time::SystemTime,
    last_metadata_changed: std::time::SystemTime,
    creation_time: std::time::SystemTime,
    kind: FileType,
    perm: u16,

    // not implemented
    _xattrs: BTreeMap<Vec<u8>, Vec<u8>>,
}

impl InodeAttributes {
    pub fn new(inode: u64, size: u64, perm: u16, kind: FileType) -> Self {
        Self {
            inode,
            size,
            last_accessed: std::time::SystemTime::now(),
            last_modified: std::time::SystemTime::now(),
            last_metadata_changed: std::time::SystemTime::now(),
            creation_time: std::time::SystemTime::now(),
            kind,
            perm,
            _xattrs: BTreeMap::new(),
        }
    }

    pub fn from_description(inode: u64, desc: FileDescription) -> Self {
        Self {
            inode,
            size: desc.size,
            last_modified: desc.last_modified,
            last_metadata_changed: desc.last_metadata_changed,
            creation_time: desc.creation_time,
            last_accessed: SystemTime::now(),
            kind: desc.kind,
            perm: desc.perm,

            _xattrs: BTreeMap::new(),
        }
    }

    pub fn new_root() -> Self {
        Self::new(FUSE_ROOT_ID, 0, PERM_RWX, FileType::Directory)
    }

    pub fn access(&mut self) {
        self.last_accessed = std::time::SystemTime::now();
    }
}

impl From<&InodeAttributes> for fuser::FileAttr {
    fn from(value: &InodeAttributes) -> Self {
        let blocks = if value.size % BLOCK_SIZE as u64 == 0 {
            value.size / BLOCK_SIZE as u64
        } else {
            value.size / BLOCK_SIZE as u64 + 1
        };
        Self {
            ino: value.inode,
            size: value.size,
            blocks,
            atime: value.last_accessed,
            mtime: value.last_modified,
            ctime: value.last_metadata_changed,
            crtime: value.creation_time,
            kind: value.kind.into(),

            // read only
            perm: value.perm,

            nlink: 1,
            // set to current user
            uid: unsafe { libc::getuid() },
            // set to current user
            gid: unsafe { libc::getgid() },
            rdev: 0,
            blksize: BLOCK_SIZE,
            // todo: support macos flags
            flags: 0,
        }
    }
}

#[derive(Debug)]
struct FileHandles {
    waiter: Condvar,
    handlers: Mutex<Vec<u64>>,
    gc: AtomicBool,
}

impl FileHandles {
    pub fn new() -> Self {
        Self {
            waiter: Condvar::new(),
            // the vector in handlers is sorted, from small to big
            // prove:
            // - later allocated handler will be bigger than previous ones
            // - new handlers will append to the end of the vector
            // - dropping old handlers won't affect the ordering
            handlers: Mutex::new(Vec::new()),
            gc: AtomicBool::new(false),
        }
    }

    pub fn add_handler(&self, fh: u64) {
        if self.marked() {
            panic!("adding new handler to a marked ref counter");
        }
        self.handlers.lock().push(fh);
    }

    pub fn marked(&self) -> bool {
        self.gc.load(Ordering::Relaxed)
    }

    pub fn have_handler(&self, handler: u64) -> bool {
        let handlers = self.handlers.lock();
        handlers.binary_search(&handler).is_ok()
    }

    pub fn unregister(&self, handler: u64) -> Result<(), std::io::Error> {
        let mut handlers = self.handlers.lock();

        let Ok(idx) = handlers.binary_search(&handler) else {
            let e = std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid handler");
            return Err(e);
        };

        handlers.remove(idx);
        self.waiter.notify_all();
        Ok(())
    }
}

#[cfg(test)]
mod fuse_test {
    use super::*;

    // todo: more tests needed!
    fn desc_gen(name: &str, kind: FileType) -> FileDescription {
        desc_gen_for_conn(0, name, kind)
    }

    fn desc_gen_for_conn(conn_id: i32, name: &str, kind: FileType) -> FileDescription {
        FileDescription {
            conn_id,
            name: PathBuf::from(name),
            kind,
            atime: SystemTime::UNIX_EPOCH,
            last_modified: SystemTime::UNIX_EPOCH,
            last_metadata_changed: SystemTime::UNIX_EPOCH,
            creation_time: SystemTime::UNIX_EPOCH,

            size: 0,
            perm: 0,
        }
    }
    fn generate_descriptions(prefix: &str) -> Vec<FileDescription> {
        let (d0_path, f0_path, f1_path, d1_path, f2_path, f3_path) = if prefix.is_empty() {
            (
                "folder0".to_string(),
                "folder0/file0".to_string(),
                "folder0/file1".to_string(),
                "folder1".to_string(),
                "folder1/file2".to_string(),
                "folder1/📄3".to_string(),
            )
        } else {
            (
                format!("{}/folder0", prefix),
                format!("{}/folder0/file0", prefix),
                format!("{}/folder0/file1", prefix),
                format!("{}/folder1", prefix),
                format!("{}/folder1/file2", prefix),
                format!("{}/folder1/📄3", prefix),
            )
        };
        let folder0 = desc_gen(&d0_path, FileType::Directory);
        let file0 = desc_gen(&f0_path, FileType::File);
        let file1 = desc_gen(&f1_path, FileType::File);
        let folder1 = desc_gen(&d1_path, FileType::Directory);
        let file2 = desc_gen(&f2_path, FileType::File);
        let file3 = desc_gen(&f3_path, FileType::File);

        vec![folder0, file0, file1, folder1, file2, file3]
    }

    fn build_tree(prefix: &str) {
        let source_list = generate_descriptions(prefix);

        let build_res = FuseNode::build_tree(source_list);
        assert!(build_res.is_ok());
        let tree_list = build_res.unwrap();

        assert_eq!(tree_list.len(), 7);

        assert_eq!(tree_list[0].name, "/");
        assert_eq!(tree_list[1].name, "folder0");
        assert_eq!(tree_list[2].name, "file0");
        assert_eq!(tree_list[3].name, "file1");
        assert_eq!(tree_list[4].name, "folder1");
        assert_eq!(tree_list[5].name, "file2");
        assert_eq!(tree_list[6].name, "📄3");

        assert_eq!(tree_list[0].children, vec![2, 5]);
        assert_eq!(tree_list[1].children, vec![3, 4]);
        assert!(tree_list[2].children.is_empty());
        assert!(tree_list[3].children.is_empty());
        assert_eq!(tree_list[4].children, vec![6, 7]);
        assert!(tree_list[5].children.is_empty());
        assert!(tree_list[6].children.is_empty());

        for (idx, node) in tree_list.iter().skip(1).enumerate() {
            assert_eq!(idx, node.index)
        }
    }

    fn build_single_file(prefix: &str) {
        let raw_name = "simple_test_file.txt";
        let f_name = if prefix == "" {
            raw_name.to_string()
        } else {
            prefix.to_string() + "/" + raw_name
        };
        let desc = desc_gen(&f_name, FileType::File);
        let tree = FuseNode::build_tree(vec![desc]).unwrap();

        assert_eq!(tree.len(), 2);
        assert_eq!(tree[0].name, "/");
        assert_eq!(tree[0].children, vec![2]);

        assert_eq!(tree[1].name, raw_name);
        assert_eq!(tree[1].index, 0);
        assert_eq!(tree[1].attributes.kind, FileType::File);
    }

    #[test]
    fn test_parse_single() {
        build_single_file("");
        build_single_file("/");
        build_single_file("test");
        build_single_file("/test");
        build_single_file("🗂");
        build_single_file("/🗂");
    }

    #[test]
    fn test_parse_tree() {
        build_tree("");
        build_tree("/");
        build_tree("test");
        build_tree("/test");
        build_tree("/test/test");
        build_tree("🗂");
        build_tree("/🗂");
        build_tree("🗂/test");
    }

    #[test]
    fn fuse_response_queue_is_bounded() {
        let (_server, router) = FuseServer::new(Duration::from_secs(1));
        let (_rx, _response_route) = router.register(11, 7).unwrap();
        let response = FuseFileContentResponse {
            conn_id: 11,
            clip: ClipboardFile::FileContentsResponse {
                msg_flags: 1,
                stream_id: 7,
                requested_data: vec![1, 2, 3],
            },
        };

        for _ in 0..FUSE_RESPONSE_QUEUE_CAPACITY {
            router.dispatch(response.clone()).unwrap();
        }

        assert!(matches!(
            router.dispatch(response),
            Err(CliprdrError::ClipboardOccupied)
        ));
    }

    #[test]
    fn file_content_response_requires_matching_connection_id() {
        let conn_id = 31337;
        let stream_id = 17;

        let (_server, router) = FuseServer::new(Duration::from_millis(50));
        let (rx, _response_route) = router.register(conn_id, stream_id).unwrap();

        router
            .dispatch(FuseFileContentResponse {
                conn_id: conn_id + 1,
                clip: ClipboardFile::FileContentsResponse {
                    msg_flags: 1,
                    stream_id,
                    requested_data: b"wrong-connection".to_vec(),
                },
            })
            .unwrap();
        assert!(matches!(
            rx.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ));

        router
            .dispatch(FuseFileContentResponse {
                conn_id,
                clip: ClipboardFile::FileContentsResponse {
                    msg_flags: 1,
                    stream_id: stream_id + 1,
                    requested_data: b"wrong-stream".to_vec(),
                },
            })
            .unwrap();
        assert!(matches!(
            rx.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ));

        router
            .dispatch(FuseFileContentResponse {
                conn_id,
                clip: ClipboardFile::FileContentsResponse {
                    msg_flags: 1,
                    stream_id,
                    requested_data: b"right".to_vec(),
                },
            })
            .unwrap();

        let ClipboardFile::FileContentsResponse { requested_data, .. } =
            rx.recv_timeout(Duration::from_millis(50)).unwrap()
        else {
            panic!("unexpected response type");
        };
        assert_eq!(requested_data, b"right");
    }

    #[test]
    fn file_content_response_route_is_removed_after_read() {
        let conn_id = 31337;
        let stream_id = 17;

        let (_server, router) = FuseServer::new(Duration::from_millis(50));
        {
            let (_rx, _response_route) = router.register(conn_id, stream_id).unwrap();
        }

        router
            .dispatch(FuseFileContentResponse {
                conn_id,
                clip: ClipboardFile::FileContentsResponse {
                    msg_flags: 1,
                    stream_id,
                    requested_data: b"stale".to_vec(),
                },
            })
            .unwrap();

        let (rx, _response_route) = router.register(conn_id, stream_id).unwrap();
        router
            .dispatch(FuseFileContentResponse {
                conn_id,
                clip: ClipboardFile::FileContentsResponse {
                    msg_flags: 1,
                    stream_id,
                    requested_data: b"fresh".to_vec(),
                },
            })
            .unwrap();

        let ClipboardFile::FileContentsResponse { requested_data, .. } =
            rx.recv_timeout(Duration::from_millis(50)).unwrap()
        else {
            panic!("unexpected response type");
        };
        assert_eq!(requested_data, b"fresh");
    }

    #[test]
    fn duplicate_file_content_response_route_is_rejected() {
        let (_server, router) = FuseServer::new(Duration::from_millis(50));
        let (_rx, _response_route) = router.register(1, 2).unwrap();

        assert!(matches!(
            router.register(1, 2),
            Err(CliprdrError::ClipboardOccupied)
        ));
    }

    #[test]
    fn file_content_response_route_rejects_non_response_message() {
        let (_server, router) = FuseServer::new(Duration::from_millis(50));
        assert!(matches!(
            router.dispatch(FuseFileContentResponse {
                conn_id: 1,
                clip: ClipboardFile::MonitorReady,
            }),
            Err(CliprdrError::InvalidRequest { .. })
        ));
    }

    #[test]
    fn read_node_routes_response_after_request() {
        let conn_id = 31337;
        let (mut rx, _route) = crate::register_cliprdr_controlled(conn_id).unwrap();

        let (mut server, router) = FuseServer::new(Duration::from_millis(500));
        server
            .load_file_list(vec![desc_gen_for_conn(
                conn_id,
                "payload.txt",
                FileType::File,
            )])
            .unwrap();
        let node = &server.files[1];
        let response_router = router.clone();

        let response_thread = std::thread::spawn(move || {
            let request = match rx.blocking_recv().unwrap() {
                crate::ClipboardFileEgressItem::Message(request) => request,
                crate::ClipboardFileEgressItem::Failed(failure) => {
                    panic!("file-clipboard route failed before request: {failure}")
                }
            };
            let ClipboardFile::FileContentsRequest {
                stream_id: request_stream_id,
                ..
            } = request
            else {
                panic!("unexpected request type");
            };

            response_router
                .dispatch(FuseFileContentResponse {
                    conn_id: conn_id + 1,
                    clip: ClipboardFile::FileContentsResponse {
                        msg_flags: 1,
                        stream_id: request_stream_id,
                        requested_data: b"wrong-connection".to_vec(),
                    },
                })
                .unwrap();
            response_router
                .dispatch(FuseFileContentResponse {
                    conn_id,
                    clip: ClipboardFile::FileContentsResponse {
                        msg_flags: 1,
                        stream_id: request_stream_id + 1,
                        requested_data: b"wrong-stream".to_vec(),
                    },
                })
                .unwrap();
            response_router
                .dispatch(FuseFileContentResponse {
                    conn_id,
                    clip: ClipboardFile::FileContentsResponse {
                        msg_flags: 1,
                        stream_id: request_stream_id,
                        requested_data: b"right".to_vec(),
                    },
                })
                .unwrap();
        });

        let data = server.read_node(node, 0, 5).unwrap();
        response_thread.join().unwrap();
        assert_eq!(data, b"right");
    }

    #[test]
    fn read_node_drops_route_when_send_fails() {
        let conn_id = 31338;
        let (mut server, router) = FuseServer::new(Duration::from_millis(50));
        server
            .load_file_list(vec![desc_gen_for_conn(
                conn_id,
                "payload.txt",
                FileType::File,
            )])
            .unwrap();
        let node = &server.files[1];

        assert_eq!(router.active_route_count(), 0);
        let err = server.read_node(node, 0, 5).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::Other);
        assert_eq!(router.active_route_count(), 0);
    }

    #[test]
    fn read_node_drops_route_when_response_times_out() {
        let conn_id = 31339;
        let (_rx, _route) = crate::register_cliprdr_controlled(conn_id).unwrap();
        let (mut server, router) = FuseServer::new(Duration::from_millis(1));
        server
            .load_file_list(vec![desc_gen_for_conn(
                conn_id,
                "payload.txt",
                FileType::File,
            )])
            .unwrap();
        let node = &server.files[1];

        assert_eq!(router.active_route_count(), 0);
        let err = server.read_node(node, 0, 5).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
        assert_eq!(router.active_route_count(), 0);
    }

    #[test]
    fn router_dispatch_without_active_route_drops_response() {
        let (_server, router) = FuseServer::new(Duration::from_millis(50));
        router
            .dispatch(FuseFileContentResponse {
                conn_id: 1,
                clip: ClipboardFile::FileContentsResponse {
                    msg_flags: 1,
                    stream_id: 2,
                    requested_data: b"stale".to_vec(),
                },
            })
            .unwrap();
    }

    #[test]
    fn router_dispatch_to_disconnected_route_fails_closed() {
        let (_server, router) = FuseServer::new(Duration::from_millis(50));
        let (rx, _response_route) = router.register(1, 2).unwrap();
        drop(rx);

        assert!(matches!(
            router.dispatch(FuseFileContentResponse {
                conn_id: 1,
                clip: ClipboardFile::FileContentsResponse {
                    msg_flags: 1,
                    stream_id: 2,
                    requested_data: b"stale".to_vec(),
                },
            }),
            Err(CliprdrError::ClipboardInternalError)
        ));
    }

    #[test]
    fn route_guard_does_not_remove_new_route_for_same_key() {
        let (_server, router) = FuseServer::new(Duration::from_millis(50));
        let (rx1, route1) = router.register(1, 2).unwrap();
        drop(rx1);
        assert!(matches!(
            router.dispatch(FuseFileContentResponse {
                conn_id: 1,
                clip: ClipboardFile::FileContentsResponse {
                    msg_flags: 1,
                    stream_id: 2,
                    requested_data: b"closed".to_vec(),
                },
            }),
            Err(CliprdrError::ClipboardInternalError)
        ));
        drop(route1);

        let (rx2, _route2) = router.register(1, 2).unwrap();
        router
            .dispatch(FuseFileContentResponse {
                conn_id: 1,
                clip: ClipboardFile::FileContentsResponse {
                    msg_flags: 1,
                    stream_id: 2,
                    requested_data: b"fresh".to_vec(),
                },
            })
            .unwrap();
        let ClipboardFile::FileContentsResponse { requested_data, .. } =
            rx2.recv_timeout(Duration::from_millis(50)).unwrap()
        else {
            panic!("unexpected response type");
        };
        assert_eq!(requested_data, b"fresh");
    }

    #[test]
    fn response_key_uses_connection_and_stream() {
        let conn_id = 1;
        let stream_id = 2;
        let response = FuseFileContentResponse {
            conn_id,
            clip: ClipboardFile::FileContentsResponse {
                msg_flags: 1,
                stream_id,
                requested_data: Vec::new(),
            },
        };
        assert_eq!(
            response.key().unwrap(),
            FuseFileContentResponseKey { conn_id, stream_id }
        );
    }

    #[test]
    fn response_key_rejects_non_response() {
        let response = FuseFileContentResponse {
            conn_id: 1,
            clip: ClipboardFile::MonitorReady,
        };
        assert!(matches!(
            response.key(),
            Err(CliprdrError::InvalidRequest { .. })
        ));
    }
}
