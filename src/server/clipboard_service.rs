use super::*;
#[cfg(not(target_os = "android"))]
use crate::clipboard::clipboard_listener;
#[cfg(not(target_os = "android"))]
pub use crate::clipboard::{ClipboardContext, ClipboardSide};
pub use crate::clipboard::{CLIPBOARD_INTERVAL as INTERVAL, CLIPBOARD_NAME as NAME};
#[cfg(windows)]
use crate::ipc::{self, ClipboardFile, ClipboardNonFile, Data};
#[cfg(feature = "unix-file-copy-paste")]
pub use crate::{
    clipboard::{check_clipboard_files, FILE_CLIPBOARD_NAME as FILE_NAME},
    clipboard_file::unix_file_clip,
};
#[cfg(all(feature = "unix-file-copy-paste", target_os = "linux"))]
use clipboard::platform::unix::fuse::{init_fuse_context, uninit_fuse_context};
#[cfg(not(target_os = "android"))]
use clipboard_master::CallbackResult;
#[cfg(target_os = "android")]
use hbb_common::config::{keys, option2bool};
#[cfg(target_os = "android")]
use std::sync::atomic::{AtomicBool, Ordering};
use std::{io, time::Duration};
#[cfg(windows)]
use tokio::runtime::Runtime;

#[cfg(target_os = "android")]
static CLIPBOARD_SERVICE_OK: AtomicBool = AtomicBool::new(false);

#[cfg(not(target_os = "android"))]
struct Handler {
    ctx: Option<ClipboardContext>,
    #[cfg(target_os = "windows")]
    stream: Option<ipc::ConnectionTmpl<parity_tokio_ipc::ConnectionClient>>,
    #[cfg(target_os = "windows")]
    rt: Option<Runtime>,
}

#[cfg(target_os = "android")]
pub fn is_clipboard_service_ok() -> bool {
    CLIPBOARD_SERVICE_OK.load(Ordering::SeqCst)
}

pub fn new(name: String) -> GenericService {
    let svc = EmptyExtraFieldService::new(name, false);
    GenericService::run(&svc.clone(), run);
    svc.sp
}

#[cfg(not(target_os = "android"))]
fn run(sp: EmptyExtraFieldService) -> ResultType<()> {
    #[cfg(all(feature = "unix-file-copy-paste", target_os = "linux"))]
    let _fuse_call_on_ret = {
        if sp.name() == FILE_NAME {
            Some(init_fuse_context(false).map(|_| crate::SimpleCallOnReturn {
                b: true,
                f: Box::new(|| {
                    uninit_fuse_context(false);
                }),
            }))
        } else {
            None
        }
    };

    let ctx = Some(ClipboardContext::new().map_err(|e| io::Error::new(io::ErrorKind::Other, e))?);
    let (_subscription, rx_cb_result) = clipboard_listener::subscribe(sp.name())?;
    let mut handler = Handler {
        ctx,
        #[cfg(target_os = "windows")]
        stream: None,
        #[cfg(target_os = "windows")]
        rt: None,
    };

    while sp.ok() {
        match rx_cb_result.recv_timeout(Duration::from_millis(INTERVAL)) {
            Some(CallbackResult::Next) => {
                #[cfg(feature = "unix-file-copy-paste")]
                if sp.name() == FILE_NAME {
                    handler.check_clipboard_file();
                    continue;
                }
                if let Some(msg) = handler.get_clipboard_msg(&sp) {
                    sp.send(msg);
                }
            }
            Some(CallbackResult::Stop) => {
                log::debug!("Clipboard listener stopped");
                break;
            }
            Some(CallbackResult::StopWithError(err)) => {
                bail!("Clipboard listener stopped with error: {}", err);
            }
            None => {}
        }
    }

    Ok(())
}

// R-X13 (§8): the clipboard-text decode helpers (WAYLAND_CLIPBOARD_SKIP_CHECK_MAX_UTF8_BYTES +
// decode_utf8_prefix + decode_text_clipboard) fed only should_skip_wayland_clipboard_sync's
// echo-suppression check, removed with the Wayland clipboard-input path.

// R-X13 (§8): should_skip_wayland_clipboard_sync + is_recent_wayland_clipboard_input (the Wayland
// clipboard-input echo-suppression filter, fed by the excised uinput clipboard-paste injection) are
// removed — nothing self-injects clipboard text any more, so there is no echo to suppress.

#[cfg(not(target_os = "android"))]
impl Handler {
    #[cfg(feature = "unix-file-copy-paste")]
    fn check_clipboard_file(&mut self) {
        if let Some(urls) = check_clipboard_files(&mut self.ctx, ClipboardSide::Host, false) {
            if !urls.is_empty() {
                #[cfg(target_os = "macos")]
                if crate::clipboard::is_file_url_set_by_rustdesk(&urls) {
                    return;
                }
                match clipboard::platform::unix::serv_files::sync_files(&urls) {
                    Ok(()) => {
                        // Use `send_data()` here to reuse `handle_file_clip()` in `connection.rs`.
                        hbb_common::allow_err!(clipboard::send_data(
                            0,
                            unix_file_clip::get_format_list()
                        ));
                    }
                    Err(e) => {
                        log::error!("Failed to sync clipboard files: {}", e);
                    }
                }
            }
        }
    }

    fn get_clipboard_msg(&mut self, sp: &GenericService) -> Option<Message> {
        #[cfg(not(target_os = "windows"))]
        let _ = sp;

        #[cfg(target_os = "windows")]
        if crate::common::is_server() && crate::platform::is_root() {
            let Some(authority) = sp.cm_clipboard_authorities().into_iter().next() else {
                log::warn!("No subscribed CM clipboard authority available");
                return None;
            };
            match self.read_clipboard_from_cm_ipc(authority) {
                Err(e) => {
                    log::error!("Failed to read clipboard from cm: {}", e);
                }
                Ok(data) => {
                    if !data.is_empty() {
                        let mut msg = Message::new();
                        let multi_clipboards = MultiClipboards {
                            clipboards: data,
                            ..Default::default()
                        };
                        msg.set_multi_clipboards(multi_clipboards);
                        return Some(msg);
                    }
                }
            }
            return None;
        }

        #[cfg(target_os = "linux")]
        {
            // R-X13 (§8): the should_skip_wayland_clipboard_sync echo-suppression filter (which
            // skipped syncing clipboard text the server had just INJECTED via the Wayland uinput
            // clipboard-paste input) is removed — the uinput injection is excised, so nothing
            // self-injects to echo-suppress, and on the pinned-X11 fork the filter already returned
            // false (the is_x11 early-return). Peek + sync the host clipboard unconditionally.
            crate::clipboard::peek_clipboard(&mut self.ctx, ClipboardSide::Host, false)
        }
        #[cfg(not(target_os = "linux"))]
        {
            crate::clipboard::check_clipboard(&mut self.ctx, ClipboardSide::Host, false)
        }
    }

    #[cfg(windows)]
    fn read_clipboard_from_cm_ipc(
        &mut self,
        authority: ipc::CmClipboardAuthority,
    ) -> ResultType<Vec<Clipboard>> {
        if self.rt.is_none() {
            self.rt = Some(Runtime::new()?);
        }
        let Some(rt) = &self.rt else {
            bail!("failed to get tokio runtime");
        };
        let mut stream = self.stream.take();
        let result: ResultType<Vec<Clipboard>> = rt.block_on(async {
            hbb_common::timeout(2000, async {
                if stream.is_none() {
                    stream = Some(crate::server::connect_authenticated_cm(100, "--cm").await?);
                }
                let Some(stream) = stream.as_mut() else {
                    bail!("failed to get CM clipboard stream");
                };
                stream.send(&authorized_clipboard_non_file_request(&authority)).await?;
                let mut monitor_ready_seen = false;
                loop {
                    match stream.next().await? {
                        Some(Data::ClipboardNonFile(Some((err, contents)))) => {
                            if !err.is_empty() {
                                bail!("{}", err);
                            }
                            let raw = if ClipboardNonFile::raw_content_len(&contents)? != 0 {
                                stream.next_raw().await?
                            } else {
                                hbb_common::bytes::BytesMut::new()
                            };
                            return Ok(ClipboardNonFile::restore_raw_contents(contents, raw)?);
                        }
                        Some(Data::ClipboardFile(ClipboardFile::MonitorReady))
                            if !monitor_ready_seen => {
                                monitor_ready_seen = true;
                            }
                        _ => {
                            bail!("failed to get clipboard data from cm");
                        }
                    }
                }
            }).await?
        });
        if result.is_ok() {
            self.stream = stream;
        }
        result
    }
}

#[cfg(windows)]
fn authorized_clipboard_non_file_request(authority: &ipc::CmClipboardAuthority) -> Data {
    Data::AuthorizedClipboardNonFile {
        id: authority.id,
        conn_type: authority.conn_type,
        cm_auth_token: authority.cm_auth_token.clone(),
    }
}

#[cfg(target_os = "android")]
fn run(sp: EmptyExtraFieldService) -> ResultType<()> {
    CLIPBOARD_SERVICE_OK.store(sp.ok(), Ordering::SeqCst);
    while sp.ok() {
        if let Some(msg) = crate::clipboard::get_clipboards_msg(false) {
            sp.send(msg);
        }
        std::thread::sleep(Duration::from_millis(INTERVAL));
    }
    CLIPBOARD_SERVICE_OK.store(false, Ordering::SeqCst);
    Ok(())
}

// R-X13 (§8): the decode_utf8_prefix unit tests are removed with the decode helpers they covered.
