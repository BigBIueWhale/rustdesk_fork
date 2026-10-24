// Production Session producers, cache methods and viewer mailbox run here. The
// peer-file adapter uses a private native file; it does not test TOML/encryption,
// installed settings, the full parent application or a remote tunnel peer.
use crate::{anyhow::{anyhow, bail}, message_proto::*, ResultType, tokio, log};
use protobuf::Message as _;
use std::{path::PathBuf, sync::{Arc, Mutex, RwLock}, time::Duration};

type JobType = ();
#[derive(Clone)]
pub struct DisplaySelectionCommand;
impl DisplaySelectionCommand { fn payload_bytes(&self) -> Option<usize> { Some(0) } }
#[derive(Clone)]
pub struct KeyboardInputCommand;
impl KeyboardInputCommand { fn payload_bytes(&self) -> Option<usize> { Some(0) } }

include!(env!("PF_SETTINGS_REQUEST"));
include!(env!("PF_SETTINGS_DATA"));
include!(env!("PF_SETTINGS_QUEUE"));
include!(env!("PF_SETTINGS_TARGET"));

const MAX_OWNED_PORT_FORWARD_MAPPINGS: usize = 32;
#[derive(Default, serde_derive::Serialize, serde_derive::Deserialize)]
struct PeerConfig { port_forwards: Vec<(i32, String, i32)> }
impl PeerConfig {
    fn load_for_write(id: &str) -> ResultType<Self> {
        match std::fs::read(id) {
            Ok(bytes) => Ok(serde_json::from_slice(&bytes)?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e.into()),
        }
    }
    fn store(&self, id: &str) -> ResultType<()> {
        std::fs::write(id, serde_json::to_vec(self)?)?;
        Ok(())
    }
}
include!(env!("PF_SETTINGS_PEER_MUTATION"));
struct LoginConfigHandler { id: String, config: PeerConfig }
include!(env!("PF_SETTINGS_CACHE"));

#[derive(Clone)]
struct Session {
    lc: Arc<RwLock<LoginConfigHandler>>,
    sender: Arc<RwLock<Option<ViewerCommandSender>>>,
}
impl Session {
    fn is_port_forward(&self) -> bool { true }
    fn is_rdp(&self) -> bool { false }
}
include!(env!("PF_SETTINGS_PRODUCER"));
include!(env!("PF_SETTINGS_SEND"));

struct Fixture { root: PathBuf, session: Session }
impl Fixture {
    fn new(sender: Option<ViewerCommandSender>) -> Self {
        let root = std::env::temp_dir().join(format!("pf-settings-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        let id = root.join("peer.json").to_str().unwrap().to_owned();
        Self { root, session: Session {
            lc: Arc::new(RwLock::new(LoginConfigHandler { id, config: PeerConfig::default() })),
            sender: Arc::new(RwLock::new(sender)),
        } }
    }
    fn bytes(&self) -> Option<Vec<u8>> { std::fs::read(self.root.join("peer.json")).ok() }
    fn seed(&self, port: i32) {
        self.session.lc.write().unwrap().add_port_forward(&(port, "localhost".into(), 22)).unwrap();
    }
}
impl Drop for Fixture { fn drop(&mut self) { std::fs::remove_dir_all(&self.root).unwrap(); } }

async fn add(session: &Session, port: i32) -> ResultType<()> {
    #[cfg(pf_settings_async)]
    { session.add_port_forward(port, "localhost".into(), 22).await }
    #[cfg(not(pf_settings_async))]
    { session.add_port_forward(port, "localhost".into(), 22) }
}
async fn remove(session: &Session, port: i32) -> ResultType<()> {
    #[cfg(pf_settings_async)]
    { session.remove_port_forward(port).await }
    #[cfg(not(pf_settings_async))]
    { session.remove_port_forward(port) }
}

#[tokio::test(flavor = "current_thread")]
async fn unavailable_mapping_round_refuses_before_persistence() {
    let mut correct = true;
    for action in ["add", "remove"] {
        for state in ["unpublished", "closed", "receiver-gone", "full"] {
            let (sender, receiver) = viewer_command_channel();
            let mut receiver = Some(receiver);
            match state {
                "closed" => { sender.send(Data::Close).unwrap(); }
                "receiver-gone" => { receiver.take(); }
                "full" => { for _ in 0..VIEWER_COMMAND_QUEUE_CAPACITY { sender.send(Data::NewRDP).unwrap(); } }
                _ => {}
            }
            let fixture = Fixture::new((state != "unpublished").then_some(sender));
            if action == "remove" { fixture.seed(31001); }
            let before = fixture.bytes();
            let result = if action == "add" { add(&fixture.session, 31001).await }
                else { remove(&fixture.session, 31001).await };
            let preserved = fixture.bytes() == before;
            let case_correct = result.is_err() && preserved;
            println!("PF_SETTINGS_REFUSAL_CASE=observed action={action} state={state} refused={} preserved={preserved} correct={case_correct}", result.is_err());
            correct &= case_correct;
            drop(receiver);
        }
    }
    assert!(correct, "an unavailable mapping owner reported success or changed the saved mapping");
    println!("PF_SETTINGS_REFUSAL=pass cases=8 queues=production storage=preserved");
}

#[tokio::test(flavor = "current_thread")]
async fn identical_saved_mapping_still_requests_runtime_application() {
    let (sender, mut receiver) = viewer_command_channel();
    let fixture = Fixture::new(Some(sender));
    fixture.seed(31002);
    let before = fixture.bytes();
    let session = fixture.session.clone();
    let operation = tokio::spawn(async move { add(&session, 31002).await });
    let command = tokio::time::timeout(Duration::from_millis(200), receiver.recv()).await;
    let queued = match command {
        #[cfg(pf_settings_async)]
        Ok(Some(Ok(Data::SavedPortForward(request)))) => {
            request.completed.send(Ok(())).unwrap(); true
        }
        #[cfg(not(pf_settings_async))]
        Ok(Some(Ok(Data::AddPortForward(_)))) => true,
        _ => false,
    };
    if !queued { operation.abort(); }
    let succeeded = matches!(operation.await, Ok(Ok(())));
    let preserved = fixture.bytes() == before;
    println!("PF_SETTINGS_RETRY=observed queued={queued} succeeded={succeeded} file_unchanged={preserved}");
    assert!(queued && succeeded && preserved, "an identical durable mapping suppressed its runtime retry");
}
