use std::sync::{Arc, RwLock};

use crate::client::{Client, Data, Interface, LoginConfigHandler};
#[cfg(windows)]
use std::{
    process::Command,
    ptr::null_mut,
    sync::atomic::{AtomicBool, Ordering},
};

use hbb_common::{
    allow_err,
    anyhow::anyhow,
    bail,
    config::READ_TIMEOUT,
    futures::{SinkExt, StreamExt},
    log,
    message_proto::*,
    protobuf::Message as _,
    rendezvous_proto::ConnType,
    tcp, timeout,
    tokio::{self, net::TcpStream, sync::mpsc},
    tokio_util::codec::{BytesCodec, Framed},
    ResultType, Stream,
};

#[cfg(windows)]
const RDP_CREDENTIAL_TARGET: &str = "TERMSRV/localhost";
#[cfg(windows)]
static RDP_CREDENTIAL_ACTIVE: AtomicBool = AtomicBool::new(false);

const PORT_FORWARD_SEND_TIMEOUT: u64 = 120_000;
const LOCAL_FORWARD_SEND_TIMEOUT: u64 = 5_000;

fn rdp_endpoint_arg(port: u16) -> String {
    format!("/v:localhost:{}", port)
}

#[cfg(windows)]
fn wide_null(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(windows)]
unsafe fn copy_pwstr(ptr: windows::core::PWSTR) -> Option<Vec<u16>> {
    if ptr.is_null() {
        return None;
    }
    let mut len = 0usize;
    while unsafe { *ptr.0.add(len) } != 0 {
        len += 1;
    }
    let mut out = unsafe { std::slice::from_raw_parts(ptr.0, len) }.to_vec();
    out.push(0);
    Some(out)
}

#[cfg(windows)]
unsafe fn copy_bytes(ptr: *mut u8, len: u32) -> ResultType<Vec<u8>> {
    let len = len as usize;
    if len == 0 {
        return Ok(Vec::new());
    }
    if ptr.is_null() {
        bail!("credential blob pointer is null but size is nonzero");
    }
    Ok(unsafe { std::slice::from_raw_parts(ptr, len) }.to_vec())
}

#[cfg(windows)]
fn pwstr_from_option(value: &mut Option<Vec<u16>>) -> windows::core::PWSTR {
    value
        .as_mut()
        .map(|v| windows::core::PWSTR(v.as_mut_ptr()))
        .unwrap_or_else(windows::core::PWSTR::null)
}

#[cfg(windows)]
struct OwnedCredentialAttribute {
    keyword: Option<Vec<u16>>,
    flags: u32,
    value: Vec<u8>,
}

#[cfg(windows)]
struct OwnedCredential {
    flags: windows::Win32::Security::Credentials::CRED_FLAGS,
    credential_type: windows::Win32::Security::Credentials::CRED_TYPE,
    target_name: Option<Vec<u16>>,
    comment: Option<Vec<u16>>,
    credential_blob: Vec<u8>,
    persist: windows::Win32::Security::Credentials::CRED_PERSIST,
    attribute_storage: Vec<OwnedCredentialAttribute>,
    target_alias: Option<Vec<u16>>,
    user_name: Option<Vec<u16>>,
}

#[cfg(windows)]
impl OwnedCredential {
    unsafe fn from_raw(
        raw: &windows::Win32::Security::Credentials::CREDENTIALW,
    ) -> ResultType<Self> {
        let mut attribute_storage = Vec::new();
        if raw.AttributeCount > 0 {
            if raw.Attributes.is_null() {
                bail!("credential attributes pointer is null but count is nonzero");
            }
            let attrs =
                unsafe { std::slice::from_raw_parts(raw.Attributes, raw.AttributeCount as usize) };
            for attr in attrs {
                attribute_storage.push(OwnedCredentialAttribute {
                    keyword: unsafe { copy_pwstr(attr.Keyword) },
                    flags: attr.Flags,
                    value: unsafe { copy_bytes(attr.Value, attr.ValueSize)? },
                });
            }
        }

        Ok(Self {
            flags: raw.Flags,
            credential_type: raw.Type,
            target_name: unsafe { copy_pwstr(raw.TargetName) },
            comment: unsafe { copy_pwstr(raw.Comment) },
            credential_blob: unsafe { copy_bytes(raw.CredentialBlob, raw.CredentialBlobSize)? },
            persist: raw.Persist,
            attribute_storage,
            target_alias: unsafe { copy_pwstr(raw.TargetAlias) },
            user_name: unsafe { copy_pwstr(raw.UserName) },
        })
    }

    fn temporary_rdp(username: &str, password: &str) -> Self {
        let password_blob: Vec<u8> = password
            .encode_utf16()
            .flat_map(|unit| unit.to_le_bytes())
            .collect();
        Self {
            flags: Default::default(),
            credential_type: windows::Win32::Security::Credentials::CRED_TYPE_GENERIC,
            target_name: Some(wide_null(RDP_CREDENTIAL_TARGET)),
            comment: None,
            credential_blob: password_blob,
            persist: windows::Win32::Security::Credentials::CRED_PERSIST_SESSION,
            attribute_storage: Vec::new(),
            target_alias: None,
            user_name: Some(wide_null(username)),
        }
    }

    fn as_raw_parts(
        &mut self,
    ) -> ResultType<(
        windows::Win32::Security::Credentials::CREDENTIALW,
        Vec<windows::Win32::Security::Credentials::CREDENTIAL_ATTRIBUTEW>,
    )> {
        let mut attributes = Vec::with_capacity(self.attribute_storage.len());
        for attr in &mut self.attribute_storage {
            attributes.push(
                windows::Win32::Security::Credentials::CREDENTIAL_ATTRIBUTEW {
                    Keyword: pwstr_from_option(&mut attr.keyword),
                    Flags: attr.flags,
                    ValueSize: attr
                        .value
                        .len()
                        .try_into()
                        .map_err(|_| anyhow!("credential attribute value is too large"))?,
                    Value: if attr.value.is_empty() {
                        null_mut()
                    } else {
                        attr.value.as_mut_ptr()
                    },
                },
            );
        }
        let raw = windows::Win32::Security::Credentials::CREDENTIALW {
            Flags: self.flags,
            Type: self.credential_type,
            TargetName: pwstr_from_option(&mut self.target_name),
            Comment: pwstr_from_option(&mut self.comment),
            LastWritten: Default::default(),
            CredentialBlobSize: self
                .credential_blob
                .len()
                .try_into()
                .map_err(|_| anyhow!("credential blob is too large"))?,
            CredentialBlob: if self.credential_blob.is_empty() {
                null_mut()
            } else {
                self.credential_blob.as_mut_ptr()
            },
            Persist: self.persist,
            AttributeCount: attributes
                .len()
                .try_into()
                .map_err(|_| anyhow!("credential attribute count is too large"))?,
            Attributes: if attributes.is_empty() {
                null_mut()
            } else {
                attributes.as_mut_ptr()
            },
            TargetAlias: pwstr_from_option(&mut self.target_alias),
            UserName: pwstr_from_option(&mut self.user_name),
        };
        Ok((raw, attributes))
    }
}

#[cfg(windows)]
fn credential_error_is_not_found(err: &windows::core::Error) -> bool {
    err.code() == windows::core::HRESULT::from_win32(windows::Win32::Foundation::ERROR_NOT_FOUND.0)
}

#[cfg(windows)]
fn read_rdp_credential() -> ResultType<Option<OwnedCredential>> {
    use windows::Win32::Security::Credentials::{
        CredFree, CredReadW, CREDENTIALW, CRED_TYPE_GENERIC,
    };

    let target = wide_null(RDP_CREDENTIAL_TARGET);
    let mut raw: *mut CREDENTIALW = null_mut();
    match unsafe {
        CredReadW(
            windows::core::PCWSTR(target.as_ptr()),
            CRED_TYPE_GENERIC,
            None,
            &mut raw,
        )
    } {
        Ok(()) => {
            if raw.is_null() {
                bail!("CredReadW returned a null credential pointer");
            }
            let credential = unsafe { OwnedCredential::from_raw(&*raw) };
            unsafe {
                CredFree(raw.cast());
            }
            credential.map(Some)
        }
        Err(err) if credential_error_is_not_found(&err) => Ok(None),
        Err(err) => Err(anyhow!("CredReadW({RDP_CREDENTIAL_TARGET}) failed: {err}")),
    }
}

#[cfg(windows)]
fn write_rdp_credential(mut credential: OwnedCredential) -> ResultType<()> {
    let (raw, _attributes) = credential.as_raw_parts()?;
    unsafe { windows::Win32::Security::Credentials::CredWriteW(&raw, 0) }
        .map_err(|err| anyhow!("CredWriteW({RDP_CREDENTIAL_TARGET}) failed: {err}"))?;
    Ok(())
}

#[cfg(windows)]
fn delete_rdp_credential() -> ResultType<()> {
    use windows::Win32::Security::Credentials::{CredDeleteW, CRED_TYPE_GENERIC};

    let target = wide_null(RDP_CREDENTIAL_TARGET);
    match unsafe {
        CredDeleteW(
            windows::core::PCWSTR(target.as_ptr()),
            CRED_TYPE_GENERIC,
            None,
        )
    } {
        Ok(()) => Ok(()),
        Err(err) if credential_error_is_not_found(&err) => Ok(()),
        Err(err) => Err(anyhow!(
            "CredDeleteW({RDP_CREDENTIAL_TARGET}) failed: {err}"
        )),
    }
}

#[cfg(windows)]
struct RdpCredentialLease {
    original: Option<OwnedCredential>,
    temporary_written: bool,
}

#[cfg(windows)]
impl RdpCredentialLease {
    fn acquire() -> ResultType<Self> {
        RDP_CREDENTIAL_ACTIVE
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .map_err(|_| anyhow!("another RustDesk RDP credential launch is active"))?;
        match read_rdp_credential() {
            Ok(original) => Ok(Self {
                original,
                temporary_written: false,
            }),
            Err(err) => {
                RDP_CREDENTIAL_ACTIVE.store(false, Ordering::Release);
                Err(err)
            }
        }
    }

    fn write_temporary(&mut self, username: &str, password: &str) -> ResultType<()> {
        write_rdp_credential(OwnedCredential::temporary_rdp(username, password))?;
        self.temporary_written = true;
        Ok(())
    }

    fn restore(&mut self) -> ResultType<()> {
        if !self.temporary_written {
            return Ok(());
        }
        match self.original.take() {
            Some(original) => write_rdp_credential(original)?,
            None => delete_rdp_credential()?,
        }
        self.temporary_written = false;
        Ok(())
    }
}

#[cfg(windows)]
impl Drop for RdpCredentialLease {
    fn drop(&mut self) {
        if let Err(err) = self.restore() {
            log::error!("{}", err);
        }
        RDP_CREDENTIAL_ACTIVE.store(false, Ordering::Release);
    }
}

#[cfg(windows)]
fn cleanup_rdp_credentials_when_mstsc_exits(
    mut lease: RdpCredentialLease,
    mut child: std::process::Child,
) {
    std::thread::spawn(move || {
        if let Err(err) = child.wait() {
            log::debug!("Failed to wait for mstsc credential restoration: {}", err);
        }
        if let Err(err) = lease.restore() {
            log::error!("{}", err);
        }
    });
}

// R-F1/R-D6: the RDP convenience launches the local Windows RDP client at the tunnel's ephemeral
// loopback port. R-S11d-8: when seeding saved RDP credentials, bind mstsc.exe to a checked
// System32 path, write credentials through native CredWriteW instead of argv/env, and restore the
// previous Credential Manager state after mstsc exits.
#[cfg(windows)]
fn run_rdp(port: u16, username: &str, password: &str) -> ResultType<()> {
    let mstsc = crate::platform::windows::trusted_system_tool_path("mstsc.exe")?;
    let has_complete_credentials = !username.is_empty() && !password.is_empty();

    let mut lease = if has_complete_credentials {
        let mut lease = RdpCredentialLease::acquire()?;
        lease.write_temporary(username, password)?;
        Some(lease)
    } else {
        if !username.is_empty() || !password.is_empty() {
            log::warn!(
                "Ignoring incomplete RDP credential; username and password are both required"
            );
        }
        if RDP_CREDENTIAL_ACTIVE.load(Ordering::Acquire) {
            bail!("another RustDesk RDP credential launch is active");
        }
        None
    };

    let mut args = vec![rdp_endpoint_arg(port)];
    if !has_complete_credentials {
        args.push("/prompt".to_owned());
    }
    let child = match Command::new(&mstsc).args(&args).spawn() {
        Ok(child) => child,
        Err(err) => {
            if let Some(mut lease) = lease.take() {
                lease.restore()?;
            }
            return Err(err.into());
        }
    };
    if let Some(lease) = lease {
        cleanup_rdp_credentials_when_mstsc_exits(lease, child);
    }
    Ok(())
}

#[cfg(not(windows))]
fn run_rdp(port: u16, _username: &str, _password: &str) -> ResultType<()> {
    log::info!(
        "RDP helper launch is Windows-only; connect a local RDP client to 127.0.0.1:{}",
        port
    );
    Ok(())
}

// R-F1/R-D6/R-S5: the viewer-side port-forward/RDP tunnel. Bind a LOCAL 127.0.0.1 listener (never
// exposed off-box); for each accepted local connection, establish a fresh PAKE-keyed session to the
// box (Client::start) and relay the raw local bytes <-> the SEALED session stream. R-S5 option 1: the
// tunnel rides the secretbox — the relay never set_raw's (a downgrade that would panic on the keyed
// stream, tcp.rs R-A3), so every wire-bound byte is ciphertext (R-A9). connect_and_login asserts
// is_secured() before a single byte is tunnelled (§4.4 fail-closed).
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
    rdp_username: String,
    rdp_password: String,
) -> ResultType<()> {
    // 127.0.0.1 only — the tunnel entry point is a loopback listener, never bound to a public
    // interface (direct-IP-only, R-SV4/R-F4).
    let listener = tcp::new_listener(format!("127.0.0.1:{}", port), true).await?;
    let addr = listener.local_addr()?;
    log::info!("listening on port {:?}", addr);
    let is_rdp = port == 0;
    if is_rdp {
        run_rdp(addr.port(), &rdp_username, &rdp_password)?;
    }
    let mut ui_receiver = ui_receiver;
    loop {
        tokio::select! {
            Ok((forward, addr)) = listener.accept() => {
                log::info!("new connection from {:?}", addr);
                lc.write().unwrap().port_forward = (remote_host.clone(), remote_port);
                let id = id.clone();
                let password = password.clone();
                let mut forward = Framed::new(forward, BytesCodec::new());
                match connect_and_login(&id, &password, &mut ui_receiver, interface.clone(), &mut forward, key, token, is_rdp).await {
                    Ok(Some(stream)) => {
                        let interface = interface.clone();
                        tokio::spawn(async move {
                            if let Err(err) = run_forward(forward, stream).await {
                                interface.msgbox("error", "Error", &err.to_string(), "");
                            }
                            log::info!("connection from {:?} closed", addr);
                        });
                    }
                    Err(err) => {
                        reset_local_forward(&forward);
                        interface.on_establish_connection_error(err.to_string());
                    }
                    _ => {}
                }
            }
            d = ui_receiver.recv() => {
                match d {
                    Some(Data::Close) => {
                        break;
                    }
                    Some(Data::NewRDP) => {
                        allow_err!(run_rdp(addr.port(), &rdp_username, &rdp_password));
                    }
                    _ => {}
                }
            }
        }
    }
    Ok(())
}

// Establish a PAKE-keyed session to the box and drive it to a successful login, then hand back the
// KEYED stream for the raw relay. The fork's `Client::start` already runs the single mandatory CPace
// handshake (keying the stream) and sends the login
// PROACTIVELY (empty-password, CPace-authenticated), so there is NO legacy `Hash` challenge to answer
// here (R-T15c). `_password` is consumed at keying time via the interface (Session::get_connect_password
// folds it into the PRS), not in this function — it stays only for signature parity with the caller.
async fn connect_and_login(
    id: &str,
    _password: &str,
    ui_receiver: &mut mpsc::UnboundedReceiver<Data>,
    interface: impl Interface,
    forward: &mut Framed<TcpStream, BytesCodec>,
    key: &str,
    token: &str,
    is_rdp: bool,
) -> ResultType<Option<Stream>> {
    let conn_type = if is_rdp {
        ConnType::RDP
    } else {
        ConnType::PORT_FORWARD
    };
    let ((mut stream, direct, _stream_type), (_feedback, _rendezvous_server)) =
        Client::start(id, key, token, conn_type, interface.clone()).await?;
    interface.update_direct(Some(direct));

    // R-S5 note / R-S13 (§4.4): the fork's direct-IP initiator MUST tunnel only over a PAKE-keyed
    // stream. `Client::start`/`_start` already key and assert is_secured, but assert AGAIN here —
    // before a single tunnelled byte, at the exact choke where the raw relay begins — and abort
    // fail-closed otherwise. A forward that rode an unkeyed stream would put the RDP/port-forward
    // payload on the wire in plaintext, exactly the leak R-A9 forbids.
    if !stream.is_secured() {
        bail!("R-S5/R-S13: refusing to port-forward over an unkeyed stream (fail-closed)");
    }

    let mut buffer = Vec::new();
    let mut received = false;

    loop {
        tokio::select! {
            res = timeout(READ_TIMEOUT, stream.next()) => match res {
                Err(_) => {
                    bail!("Timeout");
                }
                Ok(Some(Ok(bytes))) => {
                    if !received {
                        received = true;
                        interface.update_received(true);
                    }
                    let msg_in = Message::parse_from_bytes(&bytes)?;
                    match msg_in.union {
                        Some(message::Union::LoginResponse(lr)) => match lr.union {
                            Some(login_response::Union::Error(err)) => {
                                if !interface.handle_login_error(&err) {
                                    return Ok(None);
                                }
                            }
                            Some(login_response::Union::PeerInfo(pi)) => {
                                interface.handle_peer_info(pi);
                                break;
                            }
                            _ => {}
                        },
                        // R-F1/R-S5/R-A9: do NOT reply to a latency-probe TestDelay in port-forward
                        // mode. The box switches to the raw tunnel relay the instant it authorizes
                        // (connection.rs breaks to try_port_forward_loop), so a TestDelay reply sent
                        // afterwards would be relayed as DATA into the forwarded (RDP) stream and
                        // corrupt it. The port-forward viewer commits to the tunnel and silently drops
                        // TestDelay (a port forward has no video QoS to tune). The frame is still
                        // consumed here (read + dropped), so it never leaks into run_forward either.
                        Some(message::Union::TestDelay(_t)) => {}
                        _ => {}
                    }
                }
                Ok(Some(Err(err))) => {
                    bail!("Connection closed: {}", err);
                }
                _ => {
                    bail!("Reset by the peer");
                }
            },
            d = ui_receiver.recv() => {
                match d {
                    Some(Data::Login((password, remember))) => {
                        interface.handle_login_from_ui(password, remember, &mut stream).await;
                    }
                    Some(Data::Message(msg)) => {
                        allow_err!(stream.send(&msg).await);
                    }
                    _ => {}
                }
            },
            res = forward.next() => {
                if let Some(Ok(bytes)) = res {
                    buffer.extend(bytes);
                } else {
                    return Ok(None);
                }
            },
        }
    }
    // R-A3/R-S5/R-A9: NO `stream.set_raw()` — the tunnel stays on the KEYED framed stream so every
    // relayed byte is sealed by the secretbox. `set_raw()` would panic on a keyed stream (tcp.rs
    // R-A3). Flush any bytes the local client already sent during the login handshake through the
    // SEALED path (the backpressured send seals on the keyed stream).
    if !buffer.is_empty() {
        timeout(
            PORT_FORWARD_SEND_TIMEOUT,
            stream.send_bytes_backpressured(buffer.into()),
        )
        .await??;
    }
    Ok(Some(stream))
}

// The raw relay: shuttle bytes between the LOCAL socket (`forward`, plaintext to the operator's RDP /
// port-forward client) and the KEYED session `stream`. `send_bytes` SEALS on the keyed stream, so the
// wire bytes are ciphertext (R-A9); `stream.next()` yields already-DECRYPTED frames. No `set_raw` —
// the secretbox rides the whole tunnel end-to-end.
async fn run_forward(forward: Framed<TcpStream, BytesCodec>, stream: Stream) -> ResultType<()> {
    log::info!("new port forwarding connection started");
    let mut forward = forward;
    let mut stream = stream;
    loop {
        tokio::select! {
            res = forward.next() => {
                match res {
                    Some(Ok(bytes)) => {
                        // Preserve the tunnel under bursts by waiting for writer capacity. Capacity
                        // is reserved before sealing, so cancelling this branch cannot skip a nonce.
                        match timeout(
                            PORT_FORWARD_SEND_TIMEOUT,
                            stream.send_bytes_backpressured(bytes.into()),
                        )
                        .await
                        {
                            Ok(Ok(())) => {}
                            Ok(Err(err)) => {
                                reset_local_forward(&forward);
                                return Err(err);
                            }
                            Err(err) => {
                                reset_local_forward(&forward);
                                return Err(err.into());
                            }
                        }
                    }
                    Some(Err(err)) => return Err(err.into()),
                    None => return Ok(()),
                }
            },
            res = stream.next() => {
                match res {
                    Some(Ok(bytes)) => {
                        // box -> next() already DECRYPTED the frame -> local client.
                        // A renderer that was backgrounded or suspended can stop draining its
                        // loopback socket. Bound this write so the relay can reset the stale local
                        // connection and a reopened viewer can establish a fresh tunnel without
                        // requiring the whole RustDesk process to quit.
                        match timeout(
                            LOCAL_FORWARD_SEND_TIMEOUT,
                            forward.send(bytes),
                        )
                        .await
                        {
                            Ok(Ok(())) => {}
                            Ok(Err(err)) => {
                                reset_local_forward(&forward);
                                return Err(err.into());
                            }
                            Err(err) => {
                                reset_local_forward(&forward);
                                return Err(err.into());
                            }
                        }
                    }
                    Some(Err(err)) => {
                        reset_local_forward(&forward);
                        return Err(err.into());
                    }
                    None => {
                        reset_local_forward(&forward);
                        bail!("Remote port-forward stream closed");
                    }
                }
            },
        }
    }
}

/// Force an immediately observable connection failure for a local viewer after the remote side
/// dies or stops making progress. A normal FIN can leave the T3 viewer holding a stale socket in
/// CLOSE_WAIT; zero linger makes the close abortive (RST), prompting it to create a fresh socket.
fn reset_local_forward(forward: &Framed<TcpStream, BytesCodec>) {
    if let Err(err) = forward
        .get_ref()
        .set_linger(Some(std::time::Duration::ZERO))
    {
        log::warn!("Failed to configure abortive close for stale local tunnel: {err}");
    }
}
