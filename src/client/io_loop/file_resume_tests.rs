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

async fn confirmation(peer: &mut Stream, expected: u64) {
    let bytes = peer.next_timeout(2000).await.unwrap().unwrap();
    let message = Message::parse_from_bytes(&bytes).unwrap();
    let Some(message::Union::FileAction(action)) = message.union else {
        panic!("missing actual viewer confirmation");
    };
    let Some(file_action::Union::SendConfirm(confirm)) = action.union else {
        panic!("wrong viewer action");
    };
    assert_eq!((confirm.id, confirm.file_num), (371, 0));
    let forwarded = ipc::CmFileConfirmation::try_from(confirm.union.as_ref().unwrap()).unwrap();
    let forwarded: ipc::CmFileConfirmation =
        serde_json::from_slice(&serde_json::to_vec(&forwarded).unwrap()).unwrap();
    assert_eq!(Some(forwarded.into()), confirm.union);
    let Some(file_transfer_send_confirm_request::Union::Resume(resume)) = confirm.union else {
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

    // Establish the namespace through production inspection, then seed the saved
    // bytes whose admission is the subject of the caller tests below.
    let mut job = receiver(fixture, size);
    job.inspect_receive_digest(&FileTransferDigest {
        id: 371, file_num: 0, file_size: size, last_modified: 19,
        ..Default::default()
    }, false).await.unwrap();
    job.retire_current_file_state().unwrap();
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
    for offset in [2, u64::from(u32::MAX)] {
        for upload in [true, false] {
            let fixture = Fixture::new();
            let size = offset + 4;
            let mut source = fixture.sparse("source", size);
            source.seek(SeekFrom::Start(offset)).unwrap();
            source.write_all(b"tail").unwrap();
            let mut remote = remote();
            let mut artifacts = None;
            if upload {
                let mut job = sender(&fixture);
                job.init_data_stream_for_cm().await.unwrap();
                remote.read_jobs.push(job);
            } else {
                artifacts = Some(stage_partial(&fixture, offset, size).await);
                remote.write_jobs.push(receiver(&fixture, size));
            }
            let (mut viewer, mut peer) = keyed_pair().await;
            assert!(digest(&mut remote, &mut viewer, &mut peer, FileTransferDigest {
                id: 371, file_num: 0, file_size: size, last_modified: 19,
                is_upload: upload, is_identical: upload, transferred_size: offset,
                ..Default::default()
            }).await);
            assert!(remote.read_jobs.is_empty() && remote.write_jobs.is_empty());
            assert!(remote.file_confirmation_pending(371));
            let checkpoint = remote.transfer_checkpoint().unwrap().unwrap();
            assert_eq!((checkpoint.read_jobs.len(), checkpoint.write_jobs.len()),
                if upload { (1, 0) } else { (0, 1) });
            no_confirmation(&mut viewer, &mut peer).await;
            let completion = if upload {
                time::timeout(Duration::from_secs(120), remote.read_confirmations.next()).await.unwrap()
            } else {
                time::timeout(Duration::from_secs(120), remote.write_confirmations.next()).await.unwrap()
            };
            assert!(remote.complete_file_confirmation(completion, !upload, &mut viewer).await);
            assert!(!remote.file_confirmation_pending(371));
            viewer.flush_writer().await.unwrap();
            confirmation(&mut peer, offset).await;
            assert!(remote.file_flow_failure.is_none());
            let job = if upload { &mut remote.read_jobs[0] } else { &mut remote.write_jobs[0] };
            assert_eq!((job.transferred(), job.finished_size()), (offset, offset));
            assert!(job.file_confirmed());
            if upload {
                let block = job.read().await.unwrap().unwrap();
                assert_eq!(block.data.as_ref(), b"tail");
            } else {
                job.write(FileTransferBlock { id: 371, file_num: 0,
                    data: b"tail".to_vec().into(), ..Default::default() }).await.unwrap();
                job.finalize_write(1).await.unwrap();
                let mut published = std::fs::File::open(fixture.0.join("incoming")).unwrap();
                assert_eq!(published.metadata().unwrap().len(), size);
                published.seek(SeekFrom::Start(offset)).unwrap();
                let mut tail = Vec::new();
                published.read_to_end(&mut tail).unwrap();
                assert_eq!(tail, b"tail");
                assert!(!artifacts.unwrap().exists());
            }
            remote.audio_thread.close_and_join().await;
        }
    }
}

struct DirectoryOpenWatch(std::fs::File);

impl DirectoryOpenWatch {
    fn new(path: &std::path::Path) -> Self {
        use std::os::{fd::FromRawFd, unix::ffi::OsStrExt};
        let path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        let fd = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
        assert!(fd >= 0, "{}", std::io::Error::last_os_error());
        let file = unsafe { std::fs::File::from_raw_fd(fd) };
        assert!(unsafe { libc::inotify_add_watch(fd, path.as_ptr(), libc::IN_OPEN) } >= 0,
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
