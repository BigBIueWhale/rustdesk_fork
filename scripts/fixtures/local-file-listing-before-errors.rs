// Exact export bodies from 419f04b0aa4f897ba27434e364b4fa4315a4f5d6.
// The native comparison uses the same current filesystem and JSON helpers.
use crate::{
    common::{make_fd_to_json, make_vec_fd_to_json},
    flutter_ffi::SessionID,
};
use hbb_common::fs;

pub fn session_read_local_dir_sync(
    _session_id: SessionID,
    path: String,
    show_hidden: bool,
) -> String {
    if let Ok(fd) = fs::read_dir(&fs::get_path(&path), show_hidden) {
        return make_fd_to_json(fd.id, path, &fd.entries);
    }
    "".to_string()
}

pub fn session_read_local_empty_dirs_recursive_sync(
    _session_id: SessionID,
    path: String,
    include_hidden: bool,
) -> String {
    if let Ok(fds) = fs::get_empty_dirs_recursive(&path, include_hidden) {
        return make_vec_fd_to_json(&fds);
    }
    "".to_string()
}
