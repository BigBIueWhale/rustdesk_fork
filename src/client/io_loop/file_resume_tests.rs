use super::*;
use hbb_common::{
    cpace::{run_initiator, run_responder},
    tokio::net::{TcpListener, TcpStream},
};
use std::{
    io::{Read, Seek, SeekFrom, Write},
    os::unix::fs::MetadataExt,
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
    Remote::new(handler, receiver, sender, refresh)
}

async fn keyed_pair() -> (Stream, Stream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (client, accepted) = tokio::join!(TcpStream::connect(address), listener.accept());
    let mut viewer = Stream::from(client.unwrap(), address);
    let mut peer = Stream::from(accepted.unwrap().0, address);
    let (initiator, responder) = tokio::join!(
        run_initiator(&mut viewer, "viewer-resume-test"),
        run_responder(&mut peer, "viewer-resume-test")
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
    assert_eq!(confirm.union,
        Some(file_transfer_send_confirm_request::Union::OffsetBlk(expected as u32)));
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

fn stage_partial(fixture: &Fixture, offset: u64, size: u64) {
    fixture.sparse("incoming.download", offset);
    std::fs::write(fixture.0.join("incoming.digest"),
        serde_json::to_vec(&fs::FileDigest { size, modified: 19 }).unwrap()).unwrap();
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
        assert!(remote.read_jobs.is_empty());
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
    stage_partial(&fixture, offset, size);
    let path = fixture.0.join("incoming.download");
    let mut partial = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
    partial.seek(SeekFrom::Start(offset - 8)).unwrap();
    partial.write_all(b"retained").unwrap();
    drop(partial);
    let before = std::fs::metadata(&path).unwrap();
    let digest_before = std::fs::read(fixture.0.join("incoming.digest")).unwrap();
    let mut remote = remote();
    remote.write_jobs.push(receiver(&fixture, size));
    let (mut viewer, mut peer) = keyed_pair().await;
    assert!(!digest(&mut remote, &mut viewer, &mut peer, FileTransferDigest {
        id: 371, file_num: 0, file_size: size, last_modified: 19, ..Default::default()
    }).await);
    let (context, error) = remote.file_flow_failure.as_ref().unwrap();
    assert_eq!((context.job_id, context.file_num), (Some(371), 0));
    assert!(error.contains("exceeds the protocol limit"));
    assert!(remote.write_jobs.is_empty());
    assert!(remote.file_writes.is_empty());
    let after = std::fs::metadata(&path).unwrap();
    assert_eq!((before.dev(), before.ino(), before.len()),
        (after.dev(), after.ino(), after.len()));
    let mut partial = std::fs::File::open(&path).unwrap();
    partial.seek(SeekFrom::Start(offset - 8)).unwrap();
    let mut retained = [0; 8];
    partial.read_exact(&mut retained).unwrap();
    assert_eq!(&retained, b"retained");
    assert_eq!(std::fs::read(fixture.0.join("incoming.digest")).unwrap(), digest_before);
    assert!(!fixture.0.join("incoming.download.lock").exists());
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
            if upload {
                let mut job = sender(&fixture);
                job.init_data_stream_for_cm().await.unwrap();
                remote.read_jobs.push(job);
            } else {
                stage_partial(&fixture, offset, size);
                remote.write_jobs.push(receiver(&fixture, size));
            }
            let (mut viewer, mut peer) = keyed_pair().await;
            assert!(digest(&mut remote, &mut viewer, &mut peer, FileTransferDigest {
                id: 371, file_num: 0, file_size: size, last_modified: 19,
                is_upload: upload, is_identical: upload, transferred_size: offset,
                ..Default::default()
            }).await);
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
                for suffix in [".download", ".digest", ".download.lock"] {
                    assert!(!fixture.0.join(format!("incoming{suffix}")).exists());
                }
            }
            remote.audio_thread.close_and_join().await;
        }
    }
}
