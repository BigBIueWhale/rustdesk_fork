use std::sync::{Arc, RwLock};

use crate::client::{Data, Interface, LoginConfigHandler};
use hbb_common::{bail, tokio::sync::mpsc, ResultType};

const TUNNEL_DISABLED_MESSAGE: &str =
    "Port forwarding/RDP tunnel is unavailable in this direct-IP hardened build";

pub async fn listen(
    id: String,
    password: String,
    port: i32,
    interface: impl Interface,
    ui_receiver: mpsc::UnboundedReceiver<Data>,
    key: &str,
    token: &str,
    lc: Arc<RwLock<LoginConfigHandler>>,
    remote_host: String,
    remote_port: i32,
) -> ResultType<()> {
    let _ = (
        &id,
        &password,
        port,
        &interface,
        &ui_receiver,
        key,
        token,
        &lc,
        &remote_host,
        remote_port,
    );
    bail!("{}", TUNNEL_DISABLED_MESSAGE)
}
