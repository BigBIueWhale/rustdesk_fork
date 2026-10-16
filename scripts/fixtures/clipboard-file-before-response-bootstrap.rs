// Test-only Unix file-clipboard module from f6925fda040d1ca02c5e232a7901f4c84bdcd92c.
// Original module SHA-256: 9f009cf5a6658afa538ff7ce2e5ac8f6350f87d690e7dfd0af90867dfd6cd53c
#[cfg(feature = "unix-file-copy-paste")]
pub mod unix_file_clip {
    use super::*;
    #[cfg(target_os = "linux")]
    use crate::clipboard::update_clipboard_files;
    use crate::clipboard::{try_empty_clipboard_files, ClipboardSide};
    #[cfg(target_os = "linux")]
    use clipboard::platform::unix::fuse;
    use clipboard::platform::unix::{
        get_local_format, serv_files, FILECONTENTS_FORMAT_ID, FILECONTENTS_FORMAT_NAME,
        FILEDESCRIPTORW_FORMAT_NAME, FILEDESCRIPTOR_FORMAT_ID,
    };
    use hbb_common::log;
    use std::sync::{Arc, Mutex};

    lazy_static::lazy_static! {
        static ref CLIPBOARD_CTX: Arc<Mutex<Option<crate::clipboard::ClipboardContext>>> = Arc::new(Mutex::new(None));
    }

    pub fn get_format_list() -> ClipboardFile {
        let fd_format_name = get_local_format(FILEDESCRIPTOR_FORMAT_ID)
            .unwrap_or(FILEDESCRIPTORW_FORMAT_NAME.to_string());
        let fc_format_name = get_local_format(FILECONTENTS_FORMAT_ID)
            .unwrap_or(FILECONTENTS_FORMAT_NAME.to_string());
        ClipboardFile::FormatList {
            format_list: vec![
                (FILEDESCRIPTOR_FORMAT_ID, fd_format_name),
                (FILECONTENTS_FORMAT_ID, fc_format_name),
            ],
        }
    }

    #[inline]
    fn msg_resp_format_data_failure() -> Message {
        clip_2_msg(ClipboardFile::FormatDataResponse {
            msg_flags: 0x2,
            format_data: vec![],
        })
    }

    #[inline]
    fn resp_file_contents_fail(stream_id: i32) -> Message {
        clip_2_msg(ClipboardFile::FileContentsResponse {
            msg_flags: 0x2,
            stream_id,
            requested_data: vec![],
        })
    }

    pub fn serve_clip_messages(
        side: ClipboardSide,
        clip: ClipboardFile,
        conn_id: i32,
    ) -> Vec<Message> {
        log::debug!("got clipfile from client peer");
        match clip {
            ClipboardFile::MonitorReady => {
                log::debug!("client is ready for clipboard");
            }
            ClipboardFile::FormatList { format_list } => {
                if !format_list
                    .iter()
                    .find(|(_, name)| name == FILECONTENTS_FORMAT_NAME)
                    .map(|(id, _)| *id)
                    .is_some()
                {
                    log::error!("no file contents format found");
                    return vec![];
                };
                let Some(file_descriptor_id) = format_list
                    .iter()
                    .find(|(_, name)| name == FILEDESCRIPTORW_FORMAT_NAME)
                    .map(|(id, _)| *id)
                else {
                    log::error!("no file descriptor format found");
                    return vec![];
                };
                // sync file system from peer
                let data = ClipboardFile::FormatDataRequest {
                    requested_format_id: file_descriptor_id,
                };
                return vec![clip_2_msg(data)];
            }
            ClipboardFile::FormatListResponse {
                msg_flags: _msg_flags,
            } => {}
            ClipboardFile::FormatDataRequest {
                requested_format_id: _requested_format_id,
            } => {
                log::debug!("requested format id: {}", _requested_format_id);
                let format_data = serv_files::get_file_list_pdu();
                if !format_data.is_empty() {
                    return vec![clip_2_msg(ClipboardFile::FormatDataResponse {
                        msg_flags: 1,
                        format_data,
                    })];
                }
                // empty file list, send failure message
                return vec![msg_resp_format_data_failure()];
            }
            #[cfg(target_os = "linux")]
            ClipboardFile::FormatDataResponse {
                msg_flags,
                format_data,
            } => {
                log::debug!("format data response: msg_flags: {}", msg_flags);

                if msg_flags != 0x1 {
                    // return failure message?
                }

                log::debug!("parsing file descriptors");
                if fuse::init_fuse_context(true).is_ok() {
                    match fuse::format_data_response_to_urls(
                        side == ClipboardSide::Client,
                        format_data,
                        conn_id,
                    ) {
                        Ok(files) => {
                            update_clipboard_files(files, side);
                        }
                        Err(e) => {
                            log::error!("failed to parse file descriptors: {:?}", e);
                        }
                    }
                } else {
                    // send error message to server
                }
            }
            ClipboardFile::FileContentsRequest {
                stream_id,
                list_index,
                dw_flags,
                n_position_low,
                n_position_high,
                cb_requested,
                ..
            } => {
                log::debug!("file contents request: stream_id: {}, list_index: {}, dw_flags: {}, n_position_low: {}, n_position_high: {}, cb_requested: {}", stream_id, list_index, dw_flags, n_position_low, n_position_high, cb_requested);
                return serv_files::read_file_contents(
                    conn_id,
                    stream_id,
                    list_index,
                    dw_flags,
                    n_position_low,
                    n_position_high,
                    cb_requested,
                )
                .into_iter()
                .map(|res| match res {
                    Ok(data) => clip_2_msg(data),
                    Err(e) => {
                        log::error!("failed to read file contents: {:?}", e);
                        resp_file_contents_fail(stream_id)
                    }
                })
                .collect::<_>();
            }
            #[cfg(target_os = "linux")]
            ClipboardFile::FileContentsResponse {
                msg_flags,
                stream_id,
                ..
            } => {
                log::debug!(
                    "file contents response: msg_flags: {}, stream_id: {}",
                    msg_flags,
                    stream_id,
                );
                if fuse::init_fuse_context(true).is_ok() {
                    hbb_common::allow_err!(fuse::handle_file_content_response(
                        side == ClipboardSide::Client,
                        conn_id,
                        clip
                    ));
                } else {
                    // send error message to server
                }
            }
            ClipboardFile::NotifyCallback {
                r#type,
                title,
                text,
            } => {
                // unreachable, but still log it
                log::debug!(
                    "notify callback: type: {}, title: {}, text: {}",
                    r#type,
                    title,
                    text
                );
            }
            ClipboardFile::TryEmpty => {
                try_empty_clipboard_files(side, conn_id);
            }
            _ => {
                log::error!("unsupported clipboard file type");
            }
        }
        vec![]
    }
}
