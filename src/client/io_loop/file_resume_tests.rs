use super::*;
use crate::ipc;
use hbb_common::{
    cpace::{run_initiator, run_responder},
    libc,
    tokio::net::{TcpListener, TcpStream},
};
use std::{
    io::{Read, Seek, SeekFrom, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
};

type TestRemote = Remote<crate::flutter::FlutterHandler>;

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "viewer-resume-{}-{nonce}", std::process::id()
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn sparse(&self, name: &str, length: u64) -> std::fs::File {
        let file = std::fs::File::create(self.0.join(name)).unwrap();
        file.set_len(length).unwrap();
        assert!(file.metadata().unwrap().blocks() * 512 <= 128 * 1024);
        file
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

fn remote() -> TestRemote {
    let handler = Session::<crate::flutter::FlutterHandler>::default();
    {
        let mut config = handler.lc.write().unwrap();
        config.conn_type = ConnType::FILE_TRANSFER;
        config.version = hbb_common::get_version_number("1.4.7");
    }
    let (sender, receiver) = client::viewer_command_channel();
    let (_, refresh) = viewer_video_refresh_channel();
    let mut remote = Remote::new(handler, receiver, sender, refresh);
    remote.is_connected = true;
    remote
}

async fn keyed_pair() -> (Stream, Stream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (client, accepted) = tokio::join!(TcpStream::connect(address), listener.accept());
    let mut viewer = Stream::from(client.unwrap(), address);
    let mut peer = Stream::from(accepted.unwrap().0, address);
    let (initiator, responder) = tokio::join!(
        run_initiator(viewer.as_framed_tcp_mut().unwrap(), "viewer-resume-test"),
        run_responder(peer.as_framed_tcp_mut().unwrap(), "viewer-resume-test")
    );
    viewer.set_session_keys(initiator.unwrap());
    peer.set_session_keys(responder.unwrap());
    (viewer, peer)
}

async fn digest(remote: &mut TestRemote, viewer: &mut Stream, peer: &mut Stream,
                value: FileTransferDigest) -> bool {
    let mut response = FileResponse::new();
    response.set_digest(value);
    let mut message = Message::new();
    message.set_file_response(response);
    peer.send(&message).await.unwrap();
    peer.flush_writer().await.unwrap();
    let bytes = viewer.next_timeout(2000).await.unwrap().unwrap();
    remote.handle_msg_from_peer(&bytes, std::time::Instant::now(), viewer, None).await
}

fn assert_resume_confirmation(confirm: &FileTransferSendConfirmRequest, id: i32, expected: u64) {
    assert_eq!((confirm.id, confirm.file_num), (id, 0));
    let forwarded = ipc::CmFileConfirmation::try_from(confirm.union.as_ref().unwrap()).unwrap();
    let forwarded: ipc::CmFileConfirmation =
        serde_json::from_slice(&serde_json::to_vec(&forwarded).unwrap()).unwrap();
    assert_eq!(Some(forwarded.into()), confirm.union);
    let Some(file_transfer_send_confirm_request::Union::Resume(resume)) = &confirm.union else {
        panic!("missing content-bound resume action");
    };
    assert_eq!(u64::from(resume.offset), expected);
    assert_eq!(resume.prefix_sha256.len(), 32);
}

async fn no_confirmation(viewer: &mut Stream, peer: &mut Stream) {
    // A later message on the same ordered writer makes any preceding confirmation observable.
    let mut barrier = Message::new();
    barrier.set_test_delay(TestDelay { time: 371, ..Default::default() });
    viewer.send(&barrier).await.unwrap();
    viewer.flush_writer().await.unwrap();
    let bytes = peer.next_timeout(2000).await.unwrap().unwrap();
    assert_eq!(Message::parse_from_bytes(&bytes).unwrap(), barrier);
}

fn sender(fixture: &Fixture) -> fs::TransferJob {
    let mut job = fs::TransferJob::new_read(371, fs::JobType::Generic,
        "remote".to_owned(), fixture.0.join("source"), 0, false, false, true).unwrap();
    job.is_resume = true;
    job
}

fn receiver(fixture: &Fixture, size: u64) -> fs::TransferJob {
    let mut job = fs::TransferJob::new_write(371, fs::JobType::Generic,
        "remote".to_owned(), fixture.0.clone(), 0, false, true, true)
        .with_files(vec![FileEntry { name: "incoming".to_owned(), size,
            entry_type: FileType::File.into(),
            ..Default::default() }]).unwrap();
    job.is_resume = true;
    job
}

async fn stage_partial(fixture: &Fixture, offset: u64, size: u64) -> PathBuf {
    use hbb_common::sha2::{Digest, Sha256};

    // Establish retained staging in a shared fixture parent, then protect the
    // parent again before seeding the saved bytes tested by the callers below.
    use std::os::unix::fs::PermissionsExt;
    let permissions = std::fs::metadata(&fixture.0).unwrap().permissions();
    std::fs::set_permissions(&fixture.0, std::fs::Permissions::from_mode(0o777)).unwrap();
    let mut job = receiver(fixture, size);
    let prepared = async {
        job.inspect_receive_digest(&FileTransferDigest {
            id: 371, file_num: 0, file_size: size, last_modified: 19,
            ..Default::default()
        }, false).await?;
        job.confirm_with_offset(0, 0).await?;
        job.retire_current_file_state()
    }.await;
    std::fs::set_permissions(&fixture.0, permissions).unwrap();
    prepared.unwrap();
    let directories: Vec<_> = std::fs::read_dir(&fixture.0).unwrap()
        .map(|entry| entry.unwrap())
        .filter(|entry| entry.file_name().as_encoded_bytes().starts_with(b".rustdesk-receive-"))
        .map(|entry| entry.path()).collect();
    assert_eq!(directories.len(), 1);
    let metadata = std::fs::symlink_metadata(&directories[0]).unwrap();
    assert!(metadata.is_dir());
    assert_eq!((metadata.uid(), metadata.mode() & 0o7777),
        (unsafe { libc::geteuid() }, 0o700));
    let mut hash = Sha256::new();
    hash.update(b"rustdesk.receive.file.v1\0");
    hash.update(b"incoming");
    let artifacts = directories[0].join(format!("{:x}", hash.finalize()));
    std::fs::DirBuilder::new().mode(0o700).create(&artifacts).unwrap();
    let payload = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600)
        .open(artifacts.join("payload.download")).unwrap();
    payload.set_len(offset).unwrap();
    payload.sync_all().unwrap();
    assert!(payload.metadata().unwrap().blocks() * 512 <= 128 * 1024);
    let mut digest = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600)
        .open(artifacts.join("resume.digest")).unwrap();
    digest.write_all(&serde_json::to_vec(&fs::FileDigest { size, modified: 19 }).unwrap()).unwrap();
    digest.sync_all().unwrap();
    std::fs::File::open(&artifacts).unwrap().sync_all().unwrap();
    artifacts
}

#[tokio::test]
async fn upload_refuses_unrepresentable_resume_before_wire_confirmation() {
    for offset in [1u64 << 32, (1u64 << 32) + 2, 1u64 << 33, u64::MAX] {
        let fixture = Fixture::new();
        std::fs::write(fixture.0.join("source"), b"partial").unwrap();
        let mut remote = remote();
        let mut job = sender(&fixture);
        job.init_data_stream_for_cm().await.unwrap();
        remote.read_jobs.push(job);
        let (mut viewer, mut peer) = keyed_pair().await;
        assert!(!digest(&mut remote, &mut viewer, &mut peer, FileTransferDigest {
            id: 371, file_num: 0, is_upload: true, is_identical: true,
            transferred_size: offset, ..Default::default()
        }).await);
        let (context, error) = remote.file_flow_failure.as_ref().unwrap();
        assert_eq!((context.job_id, context.file_num), (Some(371), 0));
        assert!(error.contains("exceeds the protocol limit"));
        assert_eq!(remote.read_jobs.len(), 1);
        assert!(!remote.file_confirmation_pending(371));
        let job = &remote.read_jobs[0];
        assert_eq!((job.id(), job.file_num(), job.transferred(), job.finished_size()), (371, 0, 0, 0));
        assert!(!job.file_confirmed());
        assert_eq!(remote.transfer_checkpoint().unwrap().unwrap().read_jobs,
            vec![serde_json::to_string(&job.gen_meta()).unwrap()]);
        assert!(remote.file_writes.is_empty());
        assert_eq!(std::fs::read(fixture.0.join("source")).unwrap(), b"partial");
        no_confirmation(&mut viewer, &mut peer).await;
        remote.audio_thread.close_and_join().await;
    }
}

#[tokio::test]
async fn download_refuses_large_partial_without_adopting_or_removing_it() {
    let fixture = Fixture::new();
    let offset = (1u64 << 32) + 2;
    let size = offset + 4;
    let artifacts = stage_partial(&fixture, offset, size).await;
    let path = artifacts.join("payload.download");
    let mut partial = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
    partial.seek(SeekFrom::Start(offset - 8)).unwrap();
    partial.write_all(b"retained").unwrap();
    drop(partial);
    let before = std::fs::metadata(&path).unwrap();
    let digest_before = std::fs::read(artifacts.join("resume.digest")).unwrap();
    let mut remote = remote();
    remote.write_jobs.push(receiver(&fixture, size));
    let (mut viewer, mut peer) = keyed_pair().await;
    assert!(!digest(&mut remote, &mut viewer, &mut peer, FileTransferDigest {
        id: 371, file_num: 0, file_size: size, last_modified: 19, ..Default::default()
    }).await);
    let (context, error) = remote.file_flow_failure.as_ref().unwrap();
    assert_eq!((context.job_id, context.file_num), (Some(371), 0));
    assert!(error.contains("exceeds the protocol limit"));
    assert_eq!(remote.write_jobs.len(), 1);
    assert!(!remote.file_confirmation_pending(371));
    let job = &remote.write_jobs[0];
    assert_eq!((job.id(), job.file_num(), job.transferred(), job.finished_size()), (371, 0, 0, 0));
    assert!(!job.file_confirmed());
    assert_eq!(remote.transfer_checkpoint().unwrap().unwrap().write_jobs,
        vec![serde_json::to_string(&job.gen_meta()).unwrap()]);
    assert!(remote.file_writes.is_empty());
    let after = std::fs::metadata(&path).unwrap();
    assert_eq!((before.dev(), before.ino(), before.len()),
        (after.dev(), after.ino(), after.len()));
    let mut partial = std::fs::File::open(&path).unwrap();
    partial.seek(SeekFrom::Start(offset - 8)).unwrap();
    let mut retained = [0; 8];
    partial.read_exact(&mut retained).unwrap();
    assert_eq!(&retained, b"retained");
    assert_eq!(std::fs::read(artifacts.join("resume.digest")).unwrap(), digest_before);
    assert!(!artifacts.join("claim.download.lock").exists());
    assert!(!fixture.0.join("incoming").exists());
    no_confirmation(&mut viewer, &mut peer).await;
    remote.audio_thread.close_and_join().await;
}

#[tokio::test]
async fn valid_resume_offsets_reach_the_wire_and_exact_file_tail() {
    // The test UI observes completion for this exact smoke job.
    const ID: i32 = 18001;
    for offset in [2, u64::from(u32::MAX)] {
        for upload in [true, false] {
            let fixture = Fixture::new();
            let size = offset + 4;
            let mut source = fixture.sparse("source", size);
            source.seek(SeekFrom::Start(offset)).unwrap();
            source.write_all(b"tail").unwrap();
            let artifacts = if upload { None } else {
                Some(stage_partial(&fixture, offset, size).await)
            };
            let observed = artifacts.as_ref().map(|path| path.join("payload.download"))
                .unwrap_or_else(|| fixture.0.join("source"));
            let watch = DirectoryOpenWatch::with_mask(&observed, libc::IN_ACCESS);
            let (live, mut peer, started) = start_live_resume(&fixture, ID, upload, offset, size).await;
            let deadline = started + Duration::from_secs(120);
            let mut timer = time::interval(Duration::from_secs(1));
            timer.set_missed_tick_behavior(time::MissedTickBehavior::Delay);
            let mut pending_ping: Option<(i64, Instant)> = None;
            let mut keepalives = 0;
            let mut worst_ping = Duration::ZERO;
            let mut confirmation_elapsed = None;
            let mut last_read_elapsed = Duration::ZERO;
            let mut tail = Vec::new();
            let mut complete = false;
            while !complete || pending_ping.is_some() {
                if watch.take_opened() { last_read_elapsed = started.elapsed(); }
                let response_deadline = pending_ping.as_ref()
                    .map(|(_, sent)| *sent + Duration::from_secs(1)).unwrap_or(deadline).min(deadline);
                let bytes = tokio::select! {
                    _ = time::sleep_until(response_deadline) => panic!("live resume or keepalive deadline expired"),
                    _ = timer.tick(), if !complete => {
                        assert!(pending_ping.is_none(), "keepalive reply missed its interval");
                        let sequence = i64::from(keepalives) + 100;
                        let mut message = Message::new();
                        message.set_test_delay(TestDelay { time: sequence, ..Default::default() });
                        pending_ping = Some((sequence, Instant::now()));
                        peer.send(&message).await.unwrap();
                        peer.flush_writer().await.unwrap();
                        continue;
                    }
                    result = peer.next() => result.expect("viewer closed before completion").unwrap(),
                };
                let message = Message::parse_from_bytes(&bytes).unwrap();
                match message.union {
                    Some(message::Union::TestDelay(reply)) => {
                        let (sequence, sent) = pending_ping.take().expect("unsolicited keepalive reply");
                        assert_eq!(reply.time, sequence);
                        assert!(!reply.from_client);
                        worst_ping = worst_ping.max(sent.elapsed());
                        keepalives += 1;
                    }
                    Some(message::Union::FileAction(action)) => {
                        let Some(file_action::Union::SendConfirm(confirm)) = action.union else {
                            panic!("unexpected resume action: {action:?}");
                        };
                        assert!(confirmation_elapsed.is_none(), "duplicate confirmation");
                        assert_resume_confirmation(&confirm, ID, offset);
                        confirmation_elapsed = Some(started.elapsed());
                        if !upload {
                            let mut response = FileResponse::new();
                            response.set_block(FileTransferBlock { id: ID, file_num: 0,
                                data: b"tail".to_vec().into(), ..Default::default() });
                            let mut message = Message::new();
                            message.set_file_response(response);
                            peer.send(&message).await.unwrap();
                            let mut response = FileResponse::new();
                            response.set_done(FileTransferDone { id: ID, file_num: 1, ..Default::default() });
                            let mut message = Message::new();
                            message.set_file_response(response);
                            peer.send(&message).await.unwrap();
                            peer.flush_writer().await.unwrap();
                            complete = true;
                        }
                    }
                    Some(message::Union::FileResponse(response)) if upload => match response.union {
                        Some(file_response::Union::Digest(digest)) => {
                            assert_eq!((digest.id, digest.file_num, digest.file_size), (ID, 0, size));
                        }
                        Some(file_response::Union::Block(block)) => {
                            assert!(confirmation_elapsed.is_some(), "data preceded confirmation");
                            assert_eq!((block.id, block.file_num, block.compressed), (ID, 0, false));
                            tail.extend_from_slice(&block.data);
                            assert!(tail.len() <= 4, "resumed transfer sent prefix bytes");
                        }
                        Some(file_response::Union::Done(done)) => {
                            assert!(confirmation_elapsed.is_some());
                            assert_eq!((done.id, done.file_num), (ID, 1));
                            assert_eq!(tail, b"tail");
                            complete = true;
                        }
                        _ => panic!("unexpected resume response: {response:?}"),
                    },
                    _ => panic!("unexpected message during live resume: {message:?}"),
                }
            }
            // The ordered reply follows downloaded data/Done through the real viewer.
            live_keepalive(&mut peer, 99999).await;
            assert!(live.0.ui_handler.take_errors().is_empty());
            let session = live.0.clone();
            assert!(tokio::task::spawn_blocking(move || session.close_and_join()).await.unwrap());
            assert!(live.0.thread.lock().unwrap().is_none());
            let saved = live.0.lc.read().unwrap();
            assert!(saved.config.transfer.read_jobs.is_empty() && saved.config.transfer.write_jobs.is_empty());
            drop(saved);
            if !upload {
                assert_eq!(live.0.ui_handler.file_completion_count(), 1);
                let mut published = std::fs::File::open(fixture.0.join("incoming")).unwrap();
                assert_eq!(published.metadata().unwrap().len(), size);
                published.seek(SeekFrom::Start(offset)).unwrap();
                let mut tail = Vec::new();
                published.read_to_end(&mut tail).unwrap();
                assert_eq!(tail, b"tail");
                assert!(!artifacts.unwrap().exists());
            }
            let confirmation_elapsed = confirmation_elapsed.unwrap();
            println!("VIEWER_RESUME_COMPLETE=pass upload={upload} offset={offset} preparation_ms={} last_read_ms={} crossed_inactivity_window={} keepalives={keepalives} worst_ping_us={} tail=exact checkpoint=empty worker=joined",
                confirmation_elapsed.as_millis(), last_read_elapsed.as_millis(),
                confirmation_elapsed >= SEC30 && last_read_elapsed >= SEC30, worst_ping.as_micros());
            drop(live);
        }
    }
}

struct DirectoryOpenWatch(std::fs::File);

impl DirectoryOpenWatch {
    fn new(path: &std::path::Path) -> Self {
        Self::with_mask(path, libc::IN_OPEN)
    }

    fn with_mask(path: &std::path::Path, mask: u32) -> Self {
        use std::os::{fd::FromRawFd, unix::ffi::OsStrExt};
        let path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        let fd = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
        assert!(fd >= 0, "{}", std::io::Error::last_os_error());
        let file = unsafe { std::fs::File::from_raw_fd(fd) };
        assert!(unsafe { libc::inotify_add_watch(fd, path.as_ptr(), mask) } >= 0,
            "{}", std::io::Error::last_os_error());
        Self(file)
    }

    fn take_opened(&self) -> bool {
        let mut buffer = [0u8; 4096];
        match (&self.0).read(&mut buffer) {
            Ok(count) => { assert!(count > 0); true }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => false,
            Err(error) => panic!("inotify observation failed: {error}"),
        }
    }
}

struct LiveResumeViewer(Session<crate::viewer_pipeline_smoke_tests::ViewerPipelineUi>);

impl Drop for LiveResumeViewer {
    fn drop(&mut self) {
        // On an assertion failure the viewer still owns its runtime and must join.
        // The normal path below performs this blocking join off the test executor.
        self.0.close_and_join();
    }
}

async fn live_message(peer: &mut Stream) -> Message {
    let bytes = peer.next_timeout(2000).await.expect("viewer response deadline")
        .expect("viewer transport");
    Message::parse_from_bytes(&bytes).unwrap()
}

async fn live_keepalive(peer: &mut Stream, sequence: i64) {
    let mut barrier = Message::new();
    barrier.set_test_delay(TestDelay { time: sequence, ..Default::default() });
    peer.send(&barrier).await.unwrap();
    peer.flush_writer().await.unwrap();
    time::timeout(Duration::from_secs(1), async {
        loop {
            let message = live_message(peer).await;
            if message == barrier { break; }
            // The sender may publish its initial source digest before our reply.
            // Confirmation or transfer data while hashing is still pending fails.
            assert!(matches!(message.union,
                Some(message::Union::FileResponse(FileResponse {
                    union: Some(file_response::Union::Digest(FileTransferDigest {
                        id: 371, file_num: 0, ..
                    })), ..
                }))), "unexpected message before keepalive: {message:?}");
        }
    }).await.expect("live viewer keepalive stalled during resume hashing");
}

async fn start_live_resume(
    fixture: &Fixture, id: i32, upload: bool, offset: u64, size: u64,
) -> (LiveResumeViewer, Stream, Instant) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let ui = crate::viewer_pipeline_smoke_tests::ViewerPipelineUi::file_transfer_with_size(size);
    let session = Session { ui_handler: ui.clone(), ..Default::default() };
    {
        let mut login = session.lc.write().unwrap();
        login.initialize(address.to_string(), ConnType::FILE_TRANSFER, None);
        login.password_prs = b"viewer-resume-test".to_vec();
    }
    let live = LiveResumeViewer(session.clone());
    assert!(session.start_io_thread().unwrap());
    let (socket, remote_address) = time::timeout(Duration::from_secs(5), listener.accept())
        .await.unwrap().unwrap();
    drop(listener);
    let mut peer = Stream::from(socket, remote_address);
    let keys = run_responder(peer.as_framed_tcp_mut().unwrap(), "viewer-resume-test")
        .await.unwrap();
    peer.set_session_keys(keys);
    assert!(matches!(live_message(&mut peer).await.union,
        Some(message::Union::LoginRequest(LoginRequest {
            union: Some(login_request::Union::FileTransfer(_)), ..
        }))));
    let mut login = LoginResponse::new();
    login.set_peer_info(PeerInfo { version: "1.4.7".to_owned(),
        platform: "Linux".to_owned(), ..Default::default() });
    let mut message = Message::new();
    message.set_login_response(login);
    peer.send(&message).await.unwrap();
    live_keepalive(&mut peer, 1).await;
    assert!(ui.take_errors().is_empty());

    session.send(Data::AddJob((id, fs::JobType::Generic,
        if upload { fixture.0.join("source").to_str().unwrap().to_owned() }
            else { "remote".to_owned() },
        if upload { "remote".to_owned() } else { fixture.0.to_str().unwrap().to_owned() },
        0, false, !upload)));
    session.send(Data::ResumeJob((id, !upload)));
    let request = live_message(&mut peer).await;
    assert!(matches!(&request.union,
        Some(message::Union::FileAction(action)) if matches!(&action.union,
            Some(file_action::Union::Receive(value)) if upload && value.id == id)
            || matches!(&action.union,
            Some(file_action::Union::Send(value)) if !upload && value.id == id)),
        "unexpected resume request: {request:?}");
    if !upload {
        let mut response = FileResponse::new();
        response.set_dir(FileDirectory { id,
            entries: vec![FileEntry { name: "incoming".to_owned(), size,
                entry_type: FileType::File.into(), ..Default::default() }],
            ..Default::default() });
        let mut message = Message::new();
        message.set_file_response(response);
        peer.send(&message).await.unwrap();
    }
    let mut response = FileResponse::new();
    response.set_digest(FileTransferDigest { id, file_num: 0,
        file_size: size, last_modified: 19, is_upload: upload,
        is_identical: upload, transferred_size: offset, ..Default::default() });
    let mut message = Message::new();
    message.set_file_response(response);
    let started = Instant::now();
    peer.send(&message).await.unwrap();
    peer.flush_writer().await.unwrap();
    (live, peer, started)
}

#[tokio::test]
async fn live_resume_round_keeps_control_and_joins_pending_hashes() {
    for upload in [true, false] {
        let fixture = Fixture::new();
        let offset = u64::from(u32::MAX);
        let size = offset + 4;
        let artifacts = if upload {
            fixture.sparse("source", size);
            None
        } else {
            Some(stage_partial(&fixture, offset, size).await)
        };
        let observed = artifacts.as_ref().map(|path| path.join("payload.download"))
            .unwrap_or_else(|| fixture.0.join("source"));
        let mut saved_bytes = std::fs::OpenOptions::new().write(true).open(&observed).unwrap();
        saved_bytes.seek(SeekFrom::Start(offset - 8)).unwrap();
        saved_bytes.write_all(b"retained").unwrap();
        drop(saved_bytes);
        let before = std::fs::metadata(&observed).unwrap();
        let digest_before = artifacts.as_ref()
            .map(|path| std::fs::read(path.join("resume.digest")).unwrap());
        let watch = DirectoryOpenWatch::with_mask(&observed, libc::IN_ACCESS);
        let (live, mut peer, _) = start_live_resume(&fixture, 371, upload, offset, size).await;
        let session = &live.0;
        time::timeout(Duration::from_secs(2), async {
            while !watch.take_opened() { time::sleep(Duration::from_millis(10)).await; }
        }).await.expect("resume hashing never read its actual file");
        let started = Instant::now();
        let mut worst_ping = Duration::ZERO;
        for sequence in 2..22 {
            let ping = Instant::now();
            live_keepalive(&mut peer, sequence).await;
            worst_ping = worst_ping.max(ping.elapsed());
            time::sleep(Duration::from_millis(100)).await;
        }
        assert!(watch.take_opened(), "hashing stopped before the observed keepalive interval");
        live_keepalive(&mut peer, 22).await;
        let join_started = Instant::now();
        let joined_session = session.clone();
        let mut join = tokio::task::spawn_blocking(move || joined_session.close_and_join());
        // Retain and collect the exact join even on a missed deadline.
        let prompt = time::timeout(Duration::from_secs(3), &mut join).await;
        let (within_deadline, joined) = match prompt {
            Ok(result) => (true, result.unwrap()),
            Err(_) => (false, join.await.unwrap()),
        };
        let join_elapsed = join_started.elapsed();
        assert!(joined && within_deadline, "viewer did not join promptly: {:?}", join_started.elapsed());
        assert!(session.thread.lock().unwrap().is_none());
        assert!(session.ui_handler.take_errors().is_empty());
        let config = session.lc.read().unwrap();
        let checkpoint = &config.config.transfer;
        assert_eq!((checkpoint.read_jobs.len(), checkpoint.write_jobs.len()),
            if upload { (1, 0) } else { (0, 1) });
        let jobs = if upload { &checkpoint.read_jobs } else { &checkpoint.write_jobs };
        let saved: fs::TransferJobMeta = serde_json::from_str(&jobs[0]).unwrap();
        assert_eq!((saved.id, saved.file_num, saved.is_remote), (371, 0, !upload));
        drop(config);
        let after = std::fs::metadata(&observed).unwrap();
        assert_eq!((before.dev(), before.ino(), before.len()),
            (after.dev(), after.ino(), after.len()));
        let mut saved_bytes = std::fs::File::open(&observed).unwrap();
        saved_bytes.seek(SeekFrom::Start(offset - 8)).unwrap();
        let mut retained = [0; 8];
        saved_bytes.read_exact(&mut retained).unwrap();
        assert_eq!(&retained, b"retained");
        if let Some(artifacts) = artifacts {
            assert_eq!(std::fs::read(artifacts.join("resume.digest")).unwrap(), digest_before.unwrap());
            assert!(!artifacts.join("claim.download.lock").exists());
            assert!(!fixture.0.join("incoming").exists());
            let mut recovered = receiver(&fixture, size);
            recovered.inspect_receive_digest(&FileTransferDigest { id: 371, file_num: 0,
                file_size: size, last_modified: 19, ..Default::default() }, true).await.unwrap();
            recovered.retire_current_file_state().unwrap();
        }
        println!("VIEWER_RESUME_LIVE=pass upload={upload} observed_ms={} keepalives=21 worst_ping_us={} join_ms={} checkpoint=retained",
            started.elapsed().as_millis(), worst_ping.as_micros(), join_elapsed.as_millis());
        drop(live);
    }
}

async fn actions_before_barrier(viewer: &mut Stream, peer: &mut Stream) -> Vec<FileAction> {
    let mut barrier = Message::new();
    barrier.set_test_delay(TestDelay { time: 90421, ..Default::default() });
    viewer.send(&barrier).await.unwrap();
    viewer.flush_writer().await.unwrap();
    let mut actions = Vec::new();
    loop {
        let bytes = peer.next_timeout(2000).await.unwrap().unwrap();
        let message = Message::parse_from_bytes(&bytes).unwrap();
        if message == barrier { return actions; }
        let Some(message::Union::FileAction(action)) = message.union else {
            panic!("unexpected message before viewer admission barrier");
        };
        actions.push(action);
        assert!(actions.len() <= 4, "unbounded admission fixture output");
    }
}

#[tokio::test]
async fn viewer_job_limit_precedes_scan_dispatch_and_recovers() {
    let mut refused = Vec::new();
    for is_remote in [false, true] {
        for paused in [false, true] {
            for restore in [false, true] {
                let fixture = Fixture::new();
                std::fs::write(fixture.0.join("source"), b"retained payload").unwrap();
                let handler = Session::<crate::viewer_pipeline_smoke_tests::ViewerPipelineUi>::default();
                {
                    let mut config = handler.lc.write().unwrap();
                    config.conn_type = ConnType::FILE_TRANSFER;
                    config.version = hbb_common::get_version_number("1.4.7");
                }
                let (sender, receiver) = client::viewer_command_channel();
                let (_, refresh) = viewer_video_refresh_channel();
                let mut remote = Remote::new(handler, receiver, sender, refresh);
                let limit = if is_remote {
                    fs::MAX_ACTIVE_FILE_TRANSFER_WRITE_JOBS_PER_CONN
                } else {
                    fs::MAX_ACTIVE_FILE_TRANSFER_READ_JOBS_PER_CONN
                };
                assert_eq!(limit, 32);
                for id in 1..=31 {
                    let mut job = if is_remote {
                        fs::TransferJob::new_write(id, fs::JobType::Generic,
                            "peer-source".to_owned(), fixture.0.clone(), 0, false, true, true)
                    } else {
                        fs::TransferJob::new_read(id, fs::JobType::Generic,
                            "peer-destination".to_owned(), fixture.0.clone(),
                            0, false, false, true).unwrap()
                    };
                    job.is_last_job = paused;
                    if is_remote { remote.write_jobs.push(job); }
                    else { remote.read_jobs.push(job); }
                }
                let request = |id, incoming, waiting| {
                    let args = (id, fs::JobType::Generic,
                        fixture.0.to_str().unwrap().to_owned(),
                        fixture.0.join("destination").to_str().unwrap().to_owned(),
                        0, false, incoming);
                    if waiting { Data::AddJob(args) } else { Data::SendFiles(args) }
                };
                let watch = DirectoryOpenWatch::new(&fixture.0);
                let (mut viewer, mut peer) = keyed_pair().await;
                assert!(remote.handle_msg_from_ui(request(32, is_remote, restore), &mut viewer).await);
                let accepted = actions_before_barrier(&mut viewer, &mut peer).await;
                assert_eq!(accepted.len(), usize::from(!restore));
                assert_eq!(watch.take_opened(), !is_remote);
                assert!(remote.handler.take_errors().is_empty());
                let snapshot = |remote: &Remote<crate::viewer_pipeline_smoke_tests::ViewerPipelineUi>| {
                    remote.read_jobs.iter().chain(remote.write_jobs.iter())
                        .map(|job| (job.id(), job.is_last_job, job.files().len(),
                            job.total_size(), job.transferred(), job.finished_size()))
                        .collect::<Vec<_>>()
                };
                let before = snapshot(&remote);
                assert_eq!(before.len(), limit);
                assert!(remote.handle_msg_from_ui(request(33, is_remote, restore), &mut viewer).await);
                let denied_actions = actions_before_barrier(&mut viewer, &mut peer).await;
                let scanned = watch.take_opened();
                let errors = remote.handler.take_errors();
                let direction = if is_remote { "write" } else { "read" };
                let expected = format!(
                    "unexpected file job error 33/-1: too many retained {direction} jobs (limit 32)");
                let bounded = snapshot(&remote) == before;
                let reported = errors == vec![expected];
                let no_peer_action = denied_actions.is_empty();
                println!("VIEWER_JOB_ADMISSION_CASE=observed remote={is_remote} paused={paused} restore={restore} bounded={bounded} reported={reported} scanned={scanned} peer_actions={}", denied_actions.len());
                if !(bounded && reported && !scanned && no_peer_action) {
                    refused.push((is_remote, paused, restore));
                    remote.audio_thread.close_and_join().await;
                    continue;
                }
                // Saturating one direction must not close admission in the other direction.
                assert!(remote.handle_msg_from_ui(request(40, !is_remote, true), &mut viewer).await);
                assert!(actions_before_barrier(&mut viewer, &mut peer).await.is_empty());
                assert_eq!((remote.read_jobs.len(), remote.write_jobs.len()),
                    if is_remote { (1, 32) } else { (32, 1) });
                assert_eq!(watch.take_opened(), is_remote);
                assert!(remote.handler.take_errors().is_empty());
                assert!(remote.handle_msg_from_ui(Data::CancelJob(1), &mut viewer).await);
                let cancelled = actions_before_barrier(&mut viewer, &mut peer).await;
                assert_eq!(cancelled.len(), 1);
                assert!(matches!(&cancelled[0].union,
                    Some(file_action::Union::Cancel(value)) if value.id == 1));
                assert!(remote.handle_msg_from_ui(request(33, is_remote, restore), &mut viewer).await);
                let retried = actions_before_barrier(&mut viewer, &mut peer).await;
                assert_eq!(retried.len(), usize::from(!restore));
                assert_eq!(watch.take_opened(), !is_remote);
                let jobs = if is_remote { &remote.write_jobs } else { &remote.read_jobs };
                assert_eq!(jobs.len(), 32);
                assert_eq!(jobs.last().unwrap().id(), 33);
                assert_eq!(jobs.last().unwrap().is_last_job, restore);
                assert!(remote.handler.take_errors().is_empty());
                assert!(remote.file_flow_failure.is_none());
                assert_eq!(std::fs::read(fixture.0.join("source")).unwrap(), b"retained payload");
                remote.audio_thread.close_and_join().await;
            }
        }
    }
    assert!(refused.is_empty(), "unbounded or incorrectly refused admission: {refused:?}");
}
