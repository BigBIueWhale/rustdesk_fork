//! TEST-ONLY CPace-initiator probe for the docker-loopback runtime tests. NOT shipped.
//!
//! Connects to a loopback `--server`, runs the CPace handshake (`run_initiator`) with a password,
//! and reports whether KEYING succeeded — runtime-validating, end-to-end against the REAL server:
//!   - R-A1 / R-S1   : the mandatory CPace keying choke-point — a correct password keys;
//!   - R-P3 / R-P14c : a WRONG password is refused (key-confirmation fails, no key derived).
//! (CPace keying is the sole gate; there is no source-IP ACL — the probe keys on the correct password.)
//!
//! 4th arg modes (after keying):
//!   - `read`   : engage the session keys and read the post-key keyed session flow;
//!   - `login`  : also send a minimal `LoginRequest` (CPace already authenticated, so the password
//!                proof is collapsed — empty `password`) with the exact current video-receipt
//!                capability to drive the post-key Remote login flow. It succeeds only after an
//!                exact receipt-version PeerInfo or the pinned headless image's post-authorization
//!                `connection refused` display error. Its
//!                `my_id` is the ASCII canary `PLAINTEXT-CANARY-DEADBEEF` so the R-A9 wire-capture
//!                test can assert it NEVER appears on the wire (the post-key frame is AEAD-sealed);
//!   - `inject` : R-A8/R-T7 — after keying, corrupt the engaged SEND key, then send a frame
//!                and send a forged frame; the server's AEAD MUST reject it (`decryption error`);
//!   - `filetransfer` : R-F1/R-F2 — send a FileTransfer `LoginRequest`, then a `ReadDir("")`, and
//!                report the `PeerInfo` (its `username` MUST be NON-EMPTY on a headless unix
//!                `--server` — the process-owner fallback — never the "No active console user"
//!                refusal) plus any directory `FileResponse`.
//!   - `cmfiletransfer` : strict installed-service CM lifecycle probe — the same exchange, but PASS
//!                additionally requires an actual directory `FileResponse` from the CM bridge.
//!   - `cmfileauthority` : VM-only CM authority probe — pre-login create must not mutate the
//!                fixture; post-login directory read/create, receive-write finality, and a
//!                two-file/four-block receive job, peer error, cancellation, and abrupt owner loss
//!                run through CM.
//!
//! 5th arg (optional) = local source address, e.g. `127.0.0.2:0`, to connect as a DIFFERENT source
//! for the R-A8.2 owner-safe-limiter test (a guess-flood from one source must not block another).
//!
//! Usage: `probe_client <addr> <password|--password-stdin> <ok|fail> [read|login|inject|portforward|filetransfer|cmfiletransfer|cmfileauthority] [local_addr]`  (exit 0 = matched)
use hbb_common::cpace::run_initiator;
use hbb_common::message_proto::{login_response, message, Message};
use hbb_common::protobuf::Message as _; // parse_from_bytes / write_to_bytes
use hbb_common::tcp::FramedStream;
use std::io::{BufRead, IsTerminal as _};

const PROBE_PASSWORD_MAX_BYTES: usize = 4096;
const CM_PRELOGIN_CREATE_ID: i32 = 17001;
const CM_POSTLOGIN_CREATE_ID: i32 = 17002;
const CM_PREMATURE_WRITE_ID: i32 = 17003;
const CM_COMMITTED_WRITE_ID: i32 = 17004;
const CM_MULTI_FILE_WRITE_ID: i32 = 17005;
const CM_PEER_ERROR_ID: i32 = 17006;
const CM_CANCEL_WRITE_ID: i32 = 17007;
const CM_OWNER_LOSS_WRITE_ID: i32 = 17008;
const CM_PRELOGIN_CREATE_PATH: &str = "/tmp/rd-cm-file-replay/blocked-before-login";
const CM_POSTLOGIN_CREATE_PATH: &str = "/tmp/rd-cm-file-replay/allowed-after-login";
const CM_WRITE_PAYLOAD: &[u8] = b"cm-file-write-finality-v1-0123456789";
const CM_MULTI_FIRST: &[u8] = b"first-file-two-blocks-0123456789";
const CM_MULTI_SECOND: &[u8] = b"second-file-two-blocks-abcdefghij";
const CM_PEER_ERROR: &str = "peer-aborted-cm-fixture";

struct ProbePassword(Vec<u8>);

impl ProbePassword {
    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for ProbePassword {
    fn drop(&mut self) {
        hbb_common::sodiumoxide::utils::memzero(&mut self.0);
    }
}

fn read_probe_password_line(reader: &mut impl BufRead) -> Result<ProbePassword, String> {
    let mut bytes = Vec::with_capacity(PROBE_PASSWORD_MAX_BYTES + 2);
    let mut bounded = std::io::Read::take(reader, (PROBE_PASSWORD_MAX_BYTES + 2) as u64);
    let read = bounded
        .read_until(b'\n', &mut bytes)
        .map_err(|err| format!("failed to read probe password from stdin: {err}"))?;
    if read == 0 {
        return Err("stdin ended before a probe password line was read".to_owned());
    }
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
    }
    if bytes.len() > PROBE_PASSWORD_MAX_BYTES {
        hbb_common::sodiumoxide::utils::memzero(&mut bytes);
        return Err(format!(
            "probe password exceeds {PROBE_PASSWORD_MAX_BYTES} bytes"
        ));
    }
    if std::str::from_utf8(&bytes).is_err() {
        hbb_common::sodiumoxide::utils::memzero(&mut bytes);
        return Err("probe password is not valid UTF-8".to_owned());
    }
    Ok(ProbePassword(bytes))
}

fn probe_password(args: &mut [String]) -> Result<ProbePassword, String> {
    let value = args
        .get_mut(2)
        .ok_or_else(|| "password or --password-stdin is required".to_owned())?;
    if value == "--password-stdin" {
        let stdin = std::io::stdin();
        if stdin.is_terminal() {
            return Err("--password-stdin requires redirected standard input".to_owned());
        }
        read_probe_password_line(&mut stdin.lock())
    } else {
        let mut bytes = std::mem::take(value).into_bytes();
        if bytes.len() > PROBE_PASSWORD_MAX_BYTES {
            hbb_common::sodiumoxide::utils::memzero(&mut bytes);
            return Err(format!(
                "probe password exceeds {PROBE_PASSWORD_MAX_BYTES} bytes"
            ));
        }
        Ok(ProbePassword(bytes))
    }
}

fn remote_login_admission(response: &login_response::Union) -> Option<&'static str> {
    match response {
        login_response::Union::PeerInfo(peer)
            if peer.video_frame_receipt_version == hbb_common::VIDEO_FRAME_RECEIPT_VERSION =>
        {
            Some("peer-info")
        }
        login_response::Union::Error(error) if error == "connection refused" => {
            Some("headless-display-error")
        }
        _ => None,
    }
}

async fn send_probe_message(stream: &mut FramedStream, message: Message) -> Result<(), String> {
    let bytes = message
        .write_to_bytes()
        .map_err(|error| format!("serialize: {error}"))?;
    stream
        .send_raw(bytes)
        .await
        .map_err(|error| format!("send: {error}"))
}

async fn probe_cm_receive_write(stream: &mut FramedStream, report: &mut String) -> bool {
    use hbb_common::message_proto::{
        file_response, FileAction, FileEntry, FileResponse, FileTransferBlock, FileTransferDone,
        FileTransferReceiveRequest, FileType,
    };

    for (id, name, payload, terminal_file_num, expect_commit) in [
        (
            CM_PREMATURE_WRITE_ID,
            "premature.txt",
            &b"partial-before-terminal"[..],
            0,
            false,
        ),
        (
            CM_COMMITTED_WRITE_ID,
            "payload.txt",
            CM_WRITE_PAYLOAD,
            1,
            true,
        ),
    ] {
        let mut action = FileAction::new();
        action.set_receive(FileTransferReceiveRequest {
            id,
            path: CM_POSTLOGIN_CREATE_PATH.to_owned(),
            files: vec![FileEntry {
                entry_type: FileType::File.into(),
                name: name.to_owned(),
                size: payload.len() as u64,
                ..Default::default()
            }],
            file_num: 0,
            total_size: payload.len() as u64,
            ..Default::default()
        });
        let mut request = Message::new();
        request.set_file_action(action);
        if let Err(error) = send_probe_message(stream, request).await {
            report.push_str(&format!("[FT-WRITE-REQUEST-ERROR id={id} {error}] "));
            return false;
        }

        let mut block = FileResponse::new();
        block.set_block(FileTransferBlock {
            id,
            file_num: 0,
            data: payload.to_vec().into(),
            ..Default::default()
        });
        let mut message = Message::new();
        message.set_file_response(block);
        if let Err(error) = send_probe_message(stream, message).await {
            report.push_str(&format!("[FT-WRITE-BLOCK-ERROR id={id} {error}] "));
            return false;
        }

        let mut done = FileResponse::new();
        done.set_done(FileTransferDone {
            id,
            file_num: terminal_file_num,
            ..Default::default()
        });
        let mut message = Message::new();
        message.set_file_response(done);
        if let Err(error) = send_probe_message(stream, message).await {
            report.push_str(&format!("[FT-WRITE-DONE-SEND-ERROR id={id} {error}] "));
            return false;
        }

        let mut matched = false;
        for _ in 0..8 {
            let Some(Ok(bytes)) = stream.next_timeout(4000).await else {
                report.push_str(&format!("[FT-WRITE-NO-RESPONSE id={id}] "));
                return false;
            };
            let response = match Message::parse_from_bytes(&bytes) {
                Ok(response) => response,
                Err(error) => {
                    report.push_str(&format!("[FT-WRITE-PARSE-ERROR id={id} {error}] "));
                    return false;
                }
            };
            match response.union {
                Some(message::Union::FileResponse(response)) => match response.union {
                    Some(file_response::Union::Error(error)) if error.id == id => {
                        if !expect_commit
                            && error.file_num == 0
                            && error.error.contains(
                                "terminal file number 0 does not follow active file 0",
                            )
                        {
                            report.push_str("[FT-PREMATURE-WRITE-REFUSED id=17003] ");
                            matched = true;
                        } else {
                            report.push_str(&format!("[FT-WRITE-UNEXPECTED-ERROR {error:?}] "));
                        }
                        break;
                    }
                    Some(file_response::Union::Done(done)) if done.id == id => {
                        if expect_commit && done.file_num == 1 {
                            report.push_str("[FT-WRITE-COMMITTED id=17004] ");
                            matched = true;
                        } else {
                            report.push_str(&format!("[FT-WRITE-UNEXPECTED-DONE {done:?}] "));
                        }
                        break;
                    }
                    _ => {}
                },
                Some(message::Union::LoginResponse(response))
                    if matches!(response.union, Some(login_response::Union::Error(_))) =>
                {
                    report.push_str("[FT-WRITE-LOGIN-ERROR] ");
                    return false;
                }
                _ => {}
            }
        }
        if !matched {
            return false;
        }
    }
    let mut action = FileAction::new();
    action.set_receive(FileTransferReceiveRequest {
        id: CM_MULTI_FILE_WRITE_ID,
        path: CM_POSTLOGIN_CREATE_PATH.to_owned(),
        files: [
            ("first.txt", CM_MULTI_FIRST),
            ("second.txt", CM_MULTI_SECOND),
        ]
        .iter()
        .map(|&(name, payload)| FileEntry {
            entry_type: FileType::File.into(),
            name: name.to_owned(),
            size: payload.len() as u64,
            ..Default::default()
        })
        .collect(),
        file_num: 0,
        total_size: (CM_MULTI_FIRST.len() + CM_MULTI_SECOND.len()) as u64,
        ..Default::default()
    });
    let mut request = Message::new();
    request.set_file_action(action);
    if let Err(error) = send_probe_message(stream, request).await {
        report.push_str(&format!("[FT-MULTI-REQUEST-ERROR {error}] "));
        return false;
    }
    for (file_num, chunk) in [
        (0, &CM_MULTI_FIRST[..11]),
        (0, &CM_MULTI_FIRST[11..]),
        (1, &CM_MULTI_SECOND[..13]),
        (1, &CM_MULTI_SECOND[13..]),
    ] {
        let mut response = FileResponse::new();
        response.set_block(FileTransferBlock {
            id: CM_MULTI_FILE_WRITE_ID,
            file_num,
            data: chunk.to_vec().into(),
            ..Default::default()
        });
        let mut message = Message::new();
        message.set_file_response(response);
        if let Err(error) = send_probe_message(stream, message).await {
            report.push_str(&format!("[FT-MULTI-BLOCK-ERROR {error}] "));
            return false;
        }
    }
    let mut response = FileResponse::new();
    response.set_done(FileTransferDone {
        id: CM_MULTI_FILE_WRITE_ID,
        file_num: 2,
        ..Default::default()
    });
    let mut message = Message::new();
    message.set_file_response(response);
    if let Err(error) = send_probe_message(stream, message).await {
        report.push_str(&format!("[FT-MULTI-DONE-SEND-ERROR {error}] "));
        return false;
    }
    for _ in 0..8 {
        let Some(Ok(bytes)) = stream.next_timeout(4000).await else {
            report.push_str("[FT-MULTI-NO-RESPONSE] ");
            return false;
        };
        let response = match Message::parse_from_bytes(&bytes) {
            Ok(response) => response,
            Err(error) => {
                report.push_str(&format!("[FT-MULTI-PARSE-ERROR {error}] "));
                return false;
            }
        };
        match response.union {
            Some(message::Union::FileResponse(response)) => match response.union {
                Some(file_response::Union::Done(done)) if done.id == CM_MULTI_FILE_WRITE_ID => {
                    if done.file_num == 2 {
                        report.push_str("[FT-MULTI-WRITE-COMMITTED id=17005 files=2 blocks=4] ");
                        return true;
                    }
                    report.push_str(&format!("[FT-MULTI-UNEXPECTED-DONE {done:?}] "));
                    return false;
                }
                Some(file_response::Union::Error(error)) if error.id == CM_MULTI_FILE_WRITE_ID => {
                    report.push_str(&format!("[FT-MULTI-ERROR {error:?}] "));
                    return false;
                }
                _ => {}
            },
            Some(message::Union::LoginResponse(response))
                if matches!(response.union, Some(login_response::Union::Error(_))) =>
            {
                report.push_str("[FT-MULTI-LOGIN-ERROR] ");
                return false;
            }
            _ => {}
        }
    }
    report.push_str("[FT-MULTI-MATCHING-RESPONSE-MISSING] ");
    false
}

async fn probe_cm_receive_abort(stream: &mut FramedStream, report: &mut String) -> bool {
    use hbb_common::message_proto::{
        file_response, FileAction, FileEntry, FileResponse, FileTransferBlock, FileTransferCancel,
        FileTransferError, FileTransferReceiveRequest, FileType, ReadDir,
    };

    for (id, name, payload, cancel) in [
        (CM_PEER_ERROR_ID, "peer-error.txt", &b"partial-before-peer-error"[..], false),
        (CM_CANCEL_WRITE_ID, "cancelled.txt", &b"partial-before-cancel"[..], true),
    ] {
        let mut action = FileAction::new();
        action.set_receive(FileTransferReceiveRequest {
            id,
            path: CM_POSTLOGIN_CREATE_PATH.to_owned(),
            files: vec![FileEntry {
                entry_type: FileType::File.into(),
                name: name.to_owned(),
                size: (payload.len() * 2) as u64,
                ..Default::default()
            }],
            file_num: 0,
            total_size: (payload.len() * 2) as u64,
            ..Default::default()
        });
        let mut message = Message::new();
        message.set_file_action(action);
        if let Err(error) = send_probe_message(stream, message).await {
            report.push_str(&format!("[FT-ABORT-REQUEST-ERROR id={id} {error}] "));
            return false;
        }

        let mut response = FileResponse::new();
        response.set_block(FileTransferBlock {
            id,
            file_num: 0,
            data: payload.to_vec().into(),
            ..Default::default()
        });
        let mut message = Message::new();
        message.set_file_response(response);
        if let Err(error) = send_probe_message(stream, message).await {
            report.push_str(&format!("[FT-ABORT-BLOCK-ERROR id={id} {error}] "));
            return false;
        }

        let mut message = Message::new();
        if cancel {
            let mut action = FileAction::new();
            action.set_cancel(FileTransferCancel {
                id,
                ..Default::default()
            });
            message.set_file_action(action);
        } else {
            let mut response = FileResponse::new();
            response.set_error(FileTransferError {
                id,
                file_num: 0,
                error: CM_PEER_ERROR.to_owned(),
                ..Default::default()
            });
            message.set_file_response(response);
        }
        if let Err(error) = send_probe_message(stream, message).await {
            report.push_str(&format!("[FT-ABORT-TERMINAL-SEND-ERROR id={id} {error}] "));
            return false;
        }
        if cancel {
            // CM handles its exact connection's FS commands sequentially. This directory reply
            // is a read-after-cancel barrier; the guest also checks the filesystem itself.
            let mut action = FileAction::new();
            action.set_read_dir(ReadDir {
                path: CM_POSTLOGIN_CREATE_PATH.to_owned(),
                include_hidden: true,
                ..Default::default()
            });
            let mut message = Message::new();
            message.set_file_action(action);
            if let Err(error) = send_probe_message(stream, message).await {
                report.push_str(&format!("[FT-CANCEL-BARRIER-SEND-ERROR {error}] "));
                return false;
            }
        }

        let mut matched = false;
        for _ in 0..8 {
            let Some(Ok(bytes)) = stream.next_timeout(4000).await else {
                report.push_str(&format!("[FT-ABORT-NO-RESPONSE id={id}] "));
                return false;
            };
            let response = match Message::parse_from_bytes(&bytes) {
                Ok(response) => response,
                Err(error) => {
                    report.push_str(&format!("[FT-ABORT-PARSE-ERROR id={id} {error}] "));
                    return false;
                }
            };
            match response.union {
                Some(message::Union::FileResponse(response)) => match response.union {
                    Some(file_response::Union::Dir(dir)) if cancel => {
                        if dir.path == CM_POSTLOGIN_CREATE_PATH {
                            report.push_str("[FT-CANCEL-BARRIER id=17007] ");
                            matched = true;
                        } else {
                            report.push_str(&format!("[FT-CANCEL-UNEXPECTED-DIR {dir:?}] "));
                        }
                        break;
                    }
                    Some(file_response::Union::Error(error)) if error.id == id => {
                        if !cancel && error.file_num == 0 && error.error == CM_PEER_ERROR {
                            report.push_str("[FT-PEER-ERROR-REPORTED id=17006] ");
                            matched = true;
                        } else {
                            report.push_str(&format!("[FT-ABORT-UNEXPECTED-ERROR {error:?}] "));
                        }
                        break;
                    }
                    Some(file_response::Union::Done(done)) if done.id == id => {
                        report.push_str(&format!("[FT-ABORT-UNEXPECTED-DONE {done:?}] "));
                        break;
                    }
                    _ => {}
                },
                Some(message::Union::LoginResponse(response))
                    if matches!(response.union, Some(login_response::Union::Error(_))) =>
                {
                    report.push_str("[FT-ABORT-LOGIN-ERROR] ");
                    return false;
                }
                _ => {}
            }
        }
        if !matched {
            return false;
        }
    }
    true
}

async fn probe_cm_receive_owner_loss(stream: &mut FramedStream, report: &mut String) -> bool {
    use hbb_common::message_proto::{
        file_response, FileAction, FileEntry, FileResponse, FileTransferBlock,
        FileTransferReceiveRequest, FileType, ReadDir,
    };

    let payload = b"partial-before-owner-loss";
    let mut action = FileAction::new();
    action.set_receive(FileTransferReceiveRequest {
        id: CM_OWNER_LOSS_WRITE_ID,
        path: CM_POSTLOGIN_CREATE_PATH.to_owned(),
        files: vec![FileEntry {
            entry_type: FileType::File.into(),
            name: "orphaned.txt".to_owned(),
            size: (payload.len() * 2) as u64,
            ..Default::default()
        }],
        file_num: 0,
        total_size: (payload.len() * 2) as u64,
        ..Default::default()
    });
    let mut message = Message::new();
    message.set_file_action(action);
    if let Err(error) = send_probe_message(stream, message).await {
        report.push_str(&format!("[FT-OWNER-LOSS-REQUEST-ERROR {error}] "));
        return false;
    }

    let mut response = FileResponse::new();
    response.set_block(FileTransferBlock {
        id: CM_OWNER_LOSS_WRITE_ID,
        file_num: 0,
        data: payload.to_vec().into(),
        ..Default::default()
    });
    let mut message = Message::new();
    message.set_file_response(response);
    if let Err(error) = send_probe_message(stream, message).await {
        report.push_str(&format!("[FT-OWNER-LOSS-BLOCK-ERROR {error}] "));
        return false;
    }

    // This CM directory read follows WriteBlock on the same IPC stream. Seeing all three
    // staging artifacts proves the partial receive was live before this peer disappears.
    let mut action = FileAction::new();
    action.set_read_dir(ReadDir {
        path: CM_POSTLOGIN_CREATE_PATH.to_owned(),
        include_hidden: true,
        ..Default::default()
    });
    let mut message = Message::new();
    message.set_file_action(action);
    if let Err(error) = send_probe_message(stream, message).await {
        report.push_str(&format!("[FT-OWNER-LOSS-BARRIER-SEND-ERROR {error}] "));
        return false;
    }

    for _ in 0..8 {
        let Some(Ok(bytes)) = stream.next_timeout(4000).await else {
            report.push_str("[FT-OWNER-LOSS-NO-RESPONSE] ");
            return false;
        };
        let response = match Message::parse_from_bytes(&bytes) {
            Ok(response) => response,
            Err(error) => {
                report.push_str(&format!("[FT-OWNER-LOSS-PARSE-ERROR {error}] "));
                return false;
            }
        };
        match response.union {
            Some(message::Union::FileResponse(response)) => match response.union {
                Some(file_response::Union::Dir(dir))
                    if dir.path == CM_POSTLOGIN_CREATE_PATH =>
                {
                    let has = |name: &str| dir.entries.iter().any(|entry| entry.name == name);
                    if has("orphaned.txt.download")
                        && has("orphaned.txt.digest")
                        && has("orphaned.txt.download.lock")
                    {
                        report.push_str("[FT-OWNER-LOSS-STAGED id=17008] ");
                        return true;
                    }
                    report.push_str("[FT-OWNER-LOSS-STAGING-MISSING] ");
                    return false;
                }
                Some(file_response::Union::Error(error)) => {
                    report.push_str(&format!("[FT-OWNER-LOSS-ERROR {error:?}] "));
                    return false;
                }
                _ => {}
            },
            Some(message::Union::LoginResponse(response))
                if matches!(response.union, Some(login_response::Union::Error(_))) =>
            {
                report.push_str("[FT-OWNER-LOSS-LOGIN-ERROR] ");
                return false;
            }
            _ => {}
        }
    }
    report.push_str("[FT-OWNER-LOSS-BARRIER-MISSING] ");
    false
}

fn main() {
    let mut a: Vec<String> = std::env::args().collect();
    let addr = a
        .get(1)
        .cloned()
        .expect("usage: probe_client <addr> <password|--password-stdin> <ok|fail> [read|login]");
    let pw = match probe_password(&mut a) {
        Ok(password) => password,
        Err(err) => {
            eprintln!("probe_client: {err}");
            std::process::exit(2);
        }
    };
    let expect = a.get(3).map(String::as_str).unwrap_or("ok").to_string();
    let mode = a.get(4).map(String::as_str).unwrap_or("").to_string();
    let do_read = mode == "read"
        || mode == "login"
        || mode == "inject"
        || mode == "portforward"
        || mode == "filetransfer"
        || mode == "cmfiletransfer"
        || mode == "cmfileauthority";
    // Optional local source address (6th arg) — e.g. 127.0.0.2:0 to connect as a DIFFERENT source,
    // for the R-A8.2 owner-safe limiter test (a flood from one source must not block another).
    let local = a
        .get(5)
        .and_then(|s| s.parse::<std::net::SocketAddr>().ok());

    // R-P1: the CPace PRS is base64(Argon2id(NFC(pw), fixed salt)) — a faithful viewer derives it
    // from the password alone (nothing per-box in the salt). This loopback probe shares the server's
    // config dir ($HOME) and derives the SAME PRS the server stored at provisioning. A WRONG password
    // derives a DIFFERENT PRS ⇒ CPace key-confirmation fails (the `fail` path) — exactly as for a real
    // viewer. This is the decisive two-process keying proof: viewer-derived PRS == server-stored PRS.
    let password_text = match std::str::from_utf8(pw.as_bytes()) {
        Ok(password) => password,
        Err(_) => {
            drop(pw);
            eprintln!("probe_client: probe password is not valid UTF-8");
            std::process::exit(2);
        }
    };
    let prs = hbb_common::config::derive_cpace_prs(password_text).unwrap_or_default();
    drop(pw);

    let rt = hbb_common::tokio::runtime::Runtime::new().expect("tokio runtime");
    let (keyed, postkey, file_transfer_ok, remote_login_ok) = rt.block_on(async {
        let mut stream = match FramedStream::new(&addr, local, 5000).await {
            Ok(s) => s,
            Err(e) => {
                println!("probe_client: CONNECT_FAIL {e}");
                std::process::exit(2);
            }
        };
        match run_initiator(&mut stream, &prs).await {
            Ok(keys) => {
                let mut pk = String::new();
                let mut remote_login_ok = mode != "login";
                if do_read {
                    stream.set_session_keys(keys); // engage the two-key cipher
                    if mode == "portforward" {
                        // R-F1/R-D6/R-S5/R-A9 END-TO-END: drive a REAL port-forward tunnel against the
                        // live server. Send a PortForward LoginRequest naming the LOCAL target the box
                        // will dial (PF_TARGET = the pf_echo server), wait for PeerInfo (the box
                        // authorized + dialed the target + switched to try_port_forward_loop), then send
                        // a canary THROUGH the tunnel and expect it echoed back — proving the restored
                        // relay shuttles sealed bytes both ways (login-grant + dial + break + relay).
                        use hbb_common::message_proto::{LoginRequest, PortForward};
                        let target = std::env::var("PF_TARGET").unwrap_or_default();
                        let (thost, tport) = target
                            .rsplit_once(':')
                            .map(|(h, p)| (h.to_string(), p.parse::<i32>().unwrap_or(0)))
                            .unwrap_or_default();
                        let mut lr = LoginRequest::new();
                        lr.username = addr.clone();
                        lr.my_id = "pf-probe".to_string();
                        lr.my_name = "pf-probe".to_string();
                        lr.version = "1.4.0".to_string();
                        lr.my_platform = "Linux".to_string();
                        lr.set_port_forward(PortForward {
                            host: thost,
                            port: tport,
                            ..Default::default()
                        });
                        let mut msg = Message::new();
                        msg.set_login_request(lr);
                        let _ = stream.send_raw(msg.write_to_bytes().unwrap_or_default()).await;
                        // Wait for PeerInfo (a latency-probe TestDelay is skipped, never replied to —
                        // exactly as the real port-forward viewer does, so no reply is injected).
                        let mut authed = false;
                        for _ in 0..8 {
                            match stream.next_timeout(4000).await {
                                Some(Ok(bytes)) => {
                                    match Message::parse_from_bytes(&bytes).map(|m| m.union) {
                                        Ok(Some(message::Union::LoginResponse(r))) => match r.union {
                                            Some(login_response::Union::PeerInfo(_)) => {
                                                authed = true;
                                                break;
                                            }
                                            Some(login_response::Union::Error(e)) => {
                                                pk.push_str(&format!("[PF-LOGIN-ERROR {e}] "));
                                                break;
                                            }
                                            _ => {}
                                        },
                                        Ok(Some(message::Union::TestDelay(_))) => {} // ignore, no reply
                                        _ => {}
                                    }
                                }
                                _ => {
                                    pk.push_str("[PF-NO-PEERINFO] ");
                                    break;
                                }
                            }
                        }
                        if authed {
                            const CANARY: &[u8] =
                                b"PF-RELAY-CANARY-abcdef-0123456789-through-the-sealed-tunnel";
                            let _ = stream.send_raw(CANARY.to_vec()).await;
                            // Reassemble until the full canary echoes back (localhost won't fragment
                            // ~58 bytes, but be robust to a split read).
                            let mut got = Vec::new();
                            for _ in 0..4 {
                                match stream.next_timeout(4000).await {
                                    Some(Ok(b)) => {
                                        got.extend_from_slice(&b);
                                        if got == CANARY {
                                            break;
                                        }
                                    }
                                    _ => break,
                                }
                            }
                            if got == CANARY {
                                pk.push_str("[PF-RELAY-ECHO-OK] ");
                            } else {
                                pk.push_str(&format!("[PF-RELAY-ECHO-FAIL got={}B] ", got.len()));
                            }
                        }
                    }
                    if mode == "login" {
                        use hbb_common::message_proto::LoginRequest;
                        let mut lr = LoginRequest::new();
                        lr.username = addr.clone();
                        // A distinctive ASCII canary so the R-A9 wire-capture test can assert it
                        // NEVER appears on the wire (the post-key LoginRequest is encrypted).
                        lr.my_id = "PLAINTEXT-CANARY-DEADBEEF".to_string();
                        lr.my_name = "probe".to_string();
                        lr.version = "1.4.0".to_string();
                        lr.my_platform = "Linux".to_string();
                        lr.video_frame_receipt_version =
                            hbb_common::VIDEO_FRAME_RECEIPT_VERSION;
                        let mut msg = Message::new();
                        msg.set_login_request(lr);
                        let remote_login_bytes = match msg.write_to_bytes() {
                            Ok(bytes) => bytes,
                            Err(err) => {
                                pk.push_str(&format!("[REMOTE-LOGIN-SERIALIZE-ERROR {err}] "));
                                return (true, pk, true, false);
                            }
                        };
                        if let Err(err) = stream.send_raw(remote_login_bytes).await {
                            pk.push_str(&format!("[REMOTE-LOGIN-SEND-ERROR {err}] "));
                            return (true, pk, true, false);
                        }
                    }
                    if mode == "filetransfer"
                        || mode == "cmfiletransfer"
                        || mode == "cmfileauthority"
                    {
                        // R-F1/R-F2 END-TO-END against a headless unix --server. Before the fix this box
                        // (no logind/console session) reported an EMPTY PeerInfo.username and the viewer
                        // refused file transfer with "No active console user logged on". The server now
                        // falls back to the --server process owner, so the keyed FileTransfer login MUST
                        // yield a PeerInfo whose username is NON-EMPTY — never that refusal. A ReadDir("")
                        // then drives the file path (served in the CM process at service privilege; its
                        // dir FileResponse is reported if the CM round-trips).
                        use hbb_common::message_proto::{file_response, FileAction, FileDirCreate, FileTransfer, LoginRequest, ReadDir};
                        if mode == "cmfileauthority" {
                            let mut action = FileAction::new();
                            action.set_create(FileDirCreate {
                                id: CM_PRELOGIN_CREATE_ID,
                                path: CM_PRELOGIN_CREATE_PATH.to_owned(),
                                ..Default::default()
                            });
                            let mut request = Message::new();
                            request.set_file_action(action);
                            let bytes = match request.write_to_bytes() {
                                Ok(bytes) => bytes,
                                Err(err) => {
                                    pk.push_str(&format!("[FT-PRELOGIN-SERIALIZE-ERROR {err}] "));
                                    return (true, pk, false, true);
                                }
                            };
                            if let Err(err) = stream.send_raw(bytes).await {
                                pk.push_str(&format!("[FT-PRELOGIN-SEND-ERROR {err}] "));
                                return (true, pk, false, true);
                            }
                        }
                        let mut lr = LoginRequest::new();
                        lr.username = addr.clone();
                        lr.my_id = "ft-probe".to_string();
                        lr.my_name = "ft-probe".to_string();
                        lr.version = "1.4.0".to_string();
                        lr.my_platform = "Linux".to_string();
                        lr.set_file_transfer(FileTransfer {
                            dir: "".to_string(),
                            show_hidden: false,
                            ..Default::default()
                        });
                        let mut msg = Message::new();
                        msg.set_login_request(lr);
                        let login_bytes = match msg.write_to_bytes() {
                            Ok(bytes) => bytes,
                            Err(err) => {
                                pk.push_str(&format!("[FT-LOGIN-SERIALIZE-ERROR {err}] "));
                                return (true, pk, false, true);
                            }
                        };
                        if let Err(err) = stream.send_raw(login_bytes).await {
                            pk.push_str(&format!("[FT-LOGIN-SEND-ERROR {err}] "));
                            return (true, pk, false, true);
                        }
                        let mut sent_readdir = false;
                        let mut peer_username_nonempty = false;
                        let mut readdir_send_ok = true;
                        let mut received_directory = false;
                        let mut sent_create = false;
                        let mut created = false;
                        for _ in 0..10 {
                            let bytes = match stream.next_timeout(4000).await {
                                Some(Ok(b)) => b,
                                _ => {
                                    pk.push_str("[FT-NO-RESPONSE] ");
                                    break;
                                }
                            };
                            match Message::parse_from_bytes(&bytes).map(|m| m.union) {
                                Ok(Some(message::Union::LoginResponse(r))) => match r.union {
                                    Some(login_response::Union::PeerInfo(peer)) => {
                                        peer_username_nonempty = !peer.username.is_empty();
                                        pk.push_str(&format!(
                                            "[FT-PEERINFO username_nonempty={} username={:?} platform={:?}] ",
                                            !peer.username.is_empty(),
                                            peer.username,
                                            peer.platform
                                        ));
                                        if !sent_readdir && mode != "cmfileauthority" {
                                            let mut fa = FileAction::new();
                                            fa.set_read_dir(ReadDir {
                                                path: "".to_string(),
                                                include_hidden: false,
                                                ..Default::default()
                                            });
                                            let mut m = Message::new();
                                            m.set_file_action(fa);
                                            let readdir_bytes = match m.write_to_bytes() {
                                                Ok(bytes) => bytes,
                                                Err(err) => {
                                                    pk.push_str(&format!("[FT-READDIR-SERIALIZE-ERROR {err}] "));
                                                    readdir_send_ok = false;
                                                    break;
                                                }
                                            };
                                            if let Err(err) = stream.send_raw(readdir_bytes).await {
                                                pk.push_str(&format!("[FT-READDIR-SEND-ERROR {err}] "));
                                                readdir_send_ok = false;
                                                break;
                                            }
                                            sent_readdir = true;
                                        }
                                    }
                                    Some(login_response::Union::Error(e)) => {
                                        pk.push_str(&format!("[FT-LOGIN-ERROR {e}] "));
                                        break;
                                    }
                                    _ => {}
                                },
                                Ok(Some(message::Union::FileResponse(fr))) => match fr.union {
                                    Some(file_response::Union::Dir(d)) => {
                                        received_directory = true;
                                        pk.push_str(&format!(
                                            "[FT-DIR-RESPONSE path={:?} entries={}] ",
                                            d.path,
                                            d.entries.len()
                                        ));
                                        if mode == "cmfileauthority" {
                                            if d.path != "/tmp/rd-cm-file-replay" || sent_create {
                                                pk.push_str("[FT-UNEXPECTED-DIR] ");
                                                return (true, pk, false, true);
                                            }
                                            let mut action = FileAction::new();
                                            action.set_create(FileDirCreate {
                                                id: CM_POSTLOGIN_CREATE_ID,
                                                path: CM_POSTLOGIN_CREATE_PATH.to_owned(),
                                                ..Default::default()
                                            });
                                            let mut request = Message::new();
                                            request.set_file_action(action);
                                            let bytes = match request.write_to_bytes() {
                                                Ok(bytes) => bytes,
                                                Err(err) => {
                                                    pk.push_str(&format!("[FT-CREATE-SERIALIZE-ERROR {err}] "));
                                                    return (true, pk, false, true);
                                                }
                                            };
                                            if let Err(err) = stream.send_raw(bytes).await {
                                                pk.push_str(&format!("[FT-CREATE-SEND-ERROR {err}] "));
                                                return (true, pk, false, true);
                                            }
                                            sent_create = true;
                                        } else {
                                            break;
                                        }
                                    }
                                    Some(file_response::Union::Done(done)) => {
                                        if done.id == CM_PRELOGIN_CREATE_ID {
                                            pk.push_str("[FT-PRELOGIN-CREATE-ACCEPTED] ");
                                            return (true, pk, false, true);
                                        }
                                        if mode == "cmfileauthority"
                                            && sent_create
                                            && done.id == CM_POSTLOGIN_CREATE_ID
                                            && done.file_num == 0
                                        {
                                            created = true;
                                            pk.push_str("[FT-CREATE-DONE id=17002] ");
                                            break;
                                        }
                                    }
                                    Some(file_response::Union::Error(e)) => {
                                        pk.push_str(&format!("[FT-FILE-ERROR {e:?}] "));
                                        if mode != "cmfileauthority"
                                            || e.id == CM_POSTLOGIN_CREATE_ID
                                        {
                                            break;
                                        }
                                    }
                                    _ => {}
                                },
                                _ => {}
                            }
                        }
                        if !peer_username_nonempty
                            || !readdir_send_ok
                            || (mode == "cmfiletransfer" && !received_directory)
                            || (mode == "cmfileauthority" && (!received_directory || !created))
                        {
                            return (true, pk, false, true);
                        }
                        if mode == "cmfileauthority" {
                            if !probe_cm_receive_write(&mut stream, &mut pk).await
                                || !probe_cm_receive_abort(&mut stream, &mut pk).await
                                || !probe_cm_receive_owner_loss(&mut stream, &mut pk).await
                            {
                                return (true, pk, false, true);
                            }
                        }
                    }
                    // The generic post-key frame dump is for read/login/inject only; a port-forward
                    // tunnel already did its round-trip above, and its post-PeerInfo bytes are RAW
                    // relay data (not Messages), so skip the dump there.
                    for i in 0..6 {
                        if mode == "portforward"
                            || mode == "filetransfer"
                            || mode == "cmfiletransfer"
                            || mode == "cmfileauthority"
                        {
                            break;
                        }
                        match stream.next_timeout(3000).await {
                            Some(Ok(bytes)) => {
                                let parsed = Message::parse_from_bytes(&bytes);
                                if mode == "login" {
                                    if let Ok(parsed_message) = &parsed {
                                        if let Some(message::Union::LoginResponse(response)) =
                                            &parsed_message.union
                                        {
                                            match response.union.as_ref() {
                                                Some(response) => {
                                                    if let Some(outcome) =
                                                        remote_login_admission(response)
                                                    {
                                                        remote_login_ok = true;
                                                        pk.push_str(&format!(
                                                            "[REMOTE-LOGIN-ADMITTED {outcome}] "
                                                        ));
                                                    } else {
                                                        pk.push_str(&format!(
                                                            "[REMOTE-LOGIN-REJECTED {response:?}] "
                                                        ));
                                                    }
                                                }
                                                None => pk.push_str(
                                                    "[REMOTE-LOGIN-REJECTED empty-response] ",
                                                ),
                                            }
                                        }
                                    }
                                }
                                let u = match parsed {
                                    Ok(m) => format!("{:?}", m.union)
                                        .chars()
                                        .take(140)
                                        .collect::<String>(),
                                    Err(e) => format!("PARSE_ERR {e}"),
                                };
                                pk.push_str(&format!("[{i} len={} {u}] ", bytes.len()));
                            }
                            Some(Err(e)) => {
                                pk.push_str(&format!("[{i}=READ_ERR {e}] "));
                                break;
                            }
                            None => {
                                pk.push_str(&format!("[{i}=TIMEOUT] "));
                                break;
                            }
                        }
                    }
                    if mode == "login" && !remote_login_ok {
                        pk.push_str("[REMOTE-LOGIN-NOT-ADMITTED] ");
                    }
                    if mode == "inject" {
                        // R-A8 / R-T7: POST-KEY injection. Garble the engaged SEND key (the recv
                        // direction is untouched — a benign, local, send-only corruption) and send a
                        // frame on the KEYED stream. The server still holds the REAL keys, so its
                        // AEAD MUST reject the frame fail-closed (secretbox::open fails the Poly1305
                        // tag), poison the recv direction, and tear the connection down — an
                        // unauthenticated/forged frame MUST NEVER reach the application parser.
                        // (Pre-R-T3 this re-keyed via set_session_keys; keying is now one-shot, so
                        // the forged frame comes from a deliberately-corrupted send key instead.)
                        stream.corrupt_send_key_for_test();
                        let _ = stream.send_raw(b"INJECTED-GARBAGE-KEY-FRAME".to_vec()).await;
                        pk.push_str("[sent a garbage-key frame] ");
                        // Hold briefly so the server processes + logs the AEAD rejection.
                        let _ = stream.next_timeout(2500).await;
                    }
                }
                (true, pk, true, remote_login_ok)
            }
            Err(_) => (false, String::new(), false, false),
        }
    });

    println!("probe_client: keying ok={keyed} (expected={expect})");
    if do_read {
        println!("probe_client: post-key = {postkey}");
    }

    let keying_matches = match expect.as_str() {
        "ok" => keyed,
        "fail" => !keyed,
        _ => false,
    };
    let pass = keying_matches
        && ((mode != "filetransfer"
            && mode != "cmfiletransfer"
            && mode != "cmfileauthority")
            || file_transfer_ok)
        && (mode != "login" || remote_login_ok);
    if pass {
        println!("probe_client: PASS");
    } else {
        println!("probe_client: FAIL");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hbb_common::message_proto::PeerInfo;
    use std::io::Cursor;

    #[test]
    fn redirected_probe_password_is_bounded_and_line_framed() {
        let mut input = Cursor::new(b"fixture-password\r\ntrailing".to_vec());
        let password = read_probe_password_line(&mut input).unwrap();
        assert_eq!(password.as_bytes(), b"fixture-password");

        let mut oversized = Cursor::new(vec![b'x'; PROBE_PASSWORD_MAX_BYTES + 1]);
        assert!(read_probe_password_line(&mut oversized).is_err());

        let mut empty = Cursor::new(Vec::<u8>::new());
        assert!(read_probe_password_line(&mut empty).is_err());
    }

    #[test]
    fn remote_login_admission_requires_current_protocol_or_exact_headless_error() {
        let mut peer = PeerInfo::new();
        peer.video_frame_receipt_version = hbb_common::VIDEO_FRAME_RECEIPT_VERSION;
        assert_eq!(
            remote_login_admission(&login_response::Union::PeerInfo(peer.clone())),
            Some("peer-info")
        );

        peer.video_frame_receipt_version = 0;
        assert_eq!(
            remote_login_admission(&login_response::Union::PeerInfo(peer)),
            None
        );
        assert_eq!(
            remote_login_admission(&login_response::Union::Error(
                "connection refused".to_owned()
            )),
            Some("headless-display-error")
        );
        assert_eq!(
            remote_login_admission(&login_response::Union::Error(
                "Incompatible remote video protocol. Upgrade both RustDesk peers.".to_owned()
            )),
            None
        );
    }
}
