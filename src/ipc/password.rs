use super::{IpcMutationResult, PasswordMutationStatus, UNATTENDED_PASSWORD_MAX_BYTES};
use hbb_common::{bail, ResultType};
use std::{fmt, sync::Arc};

pub(crate) const USER_PASSWORD_IPC_POSTFIX: &str = "_password";
pub(crate) const SERVICE_PASSWORD_IPC_POSTFIX: &str = "_service_password";
pub(crate) const MACOS_AUTHORIZATION_MAX_BYTES: usize = 1024;

const REQUEST_MAGIC: [u8; 8] = *b"RDPWREQ\0";
const STATUS_MAGIC: [u8; 8] = *b"RDPWSTS\0";
const ACK_MAGIC: [u8; 8] = *b"RDPWACK\0";
const PROTOCOL_VERSION: u8 = 1;
pub(crate) const REQUEST_HEADER_BYTES: usize = 36;
pub(crate) const STATUS_FRAME_BYTES: usize = 32;
pub(crate) const ACK_FRAME_BYTES: usize = 28;
const REQUEST_BODY_MAX_BYTES: usize = UNATTENDED_PASSWORD_MAX_BYTES + MACOS_AUTHORIZATION_MAX_BYTES;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum SensitivePayloadKind {
    Password = 1,
    PasswordWithAuthorization = 2,
}

impl SensitivePayloadKind {
    fn from_wire(value: u8) -> ResultType<Self> {
        match value {
            1 => Ok(Self::Password),
            2 => Ok(Self::PasswordWithAuthorization),
            _ => bail!("unsupported sensitive password request kind"),
        }
    }
}

pub(crate) fn zeroize_sensitive_bytes(value: &mut [u8]) {
    hbb_common::sodiumoxide::utils::memzero(value);
}

fn zeroize_sensitive_string(value: &mut String) {
    zeroize_sensitive_bytes(unsafe { value.as_mut_vec() });
}

enum SensitivePasswordStorage {
    Origin(String),
    Inbound { bytes: Box<[u8]>, len: usize },
}

impl SensitivePasswordStorage {
    fn as_str(&self) -> &str {
        match self {
            Self::Origin(value) => value.as_str(),
            Self::Inbound { bytes, len } => {
                // Construction validates exactly this initialized prefix as UTF-8.
                unsafe { std::str::from_utf8_unchecked(&bytes[..*len]) }
            }
        }
    }

    fn erase(&mut self) {
        match self {
            Self::Origin(value) => zeroize_sensitive_string(value),
            Self::Inbound { bytes, .. } => zeroize_sensitive_bytes(bytes),
        }
    }
}

impl Drop for SensitivePasswordStorage {
    fn drop(&mut self) {
        self.erase();
    }
}

pub(crate) struct SensitivePassword(Arc<SensitivePasswordStorage>);

impl SensitivePassword {
    pub(crate) fn new(value: String) -> Self {
        Self(Arc::new(SensitivePasswordStorage::Origin(value)))
    }

    fn from_inbound(bytes: Box<[u8]>, len: usize) -> Self {
        Self(Arc::new(SensitivePasswordStorage::Inbound { bytes, len }))
    }

    pub(crate) fn as_str(&self) -> &str {
        self.0.as_str()
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.as_str().as_bytes()
    }

    pub(crate) fn zeroize(&mut self) -> bool {
        let Some(value) = Arc::get_mut(&mut self.0) else {
            return false;
        };
        value.erase();
        true
    }

    #[cfg(test)]
    fn allocation_identity(&self) -> (*const u8, usize) {
        match self.0.as_ref() {
            SensitivePasswordStorage::Origin(value) => (value.as_ptr(), value.capacity()),
            SensitivePasswordStorage::Inbound { bytes, .. } => (bytes.as_ptr(), bytes.len()),
        }
    }
}

impl Clone for SensitivePassword {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl PartialEq for SensitivePassword {
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl Eq for SensitivePassword {}

impl fmt::Debug for SensitivePassword {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SensitivePassword([REDACTED])")
    }
}

pub(crate) struct SensitiveAuthorization(Vec<u8>);

impl SensitiveAuthorization {
    pub(crate) fn new(value: Vec<u8>) -> ResultType<Self> {
        if value.is_empty() || value.len() > MACOS_AUTHORIZATION_MAX_BYTES {
            let mut value = value;
            zeroize_sensitive_bytes(&mut value);
            bail!("macOS authorization metadata has an invalid length");
        }
        Ok(Self(value))
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn as_mut_bytes(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl Drop for SensitiveAuthorization {
    fn drop(&mut self) {
        zeroize_sensitive_bytes(&mut self.0);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SensitiveRequestHeader {
    operation_id: hbb_common::uuid::Uuid,
    kind: SensitivePayloadKind,
    password_len: usize,
    authorization_len: usize,
}

impl SensitiveRequestHeader {
    pub(crate) fn new(
        operation_id: hbb_common::uuid::Uuid,
        kind: SensitivePayloadKind,
        password_len: usize,
        authorization_len: usize,
    ) -> ResultType<Self> {
        let header = Self {
            operation_id,
            kind,
            password_len,
            authorization_len,
        };
        header.validate()?;
        Ok(header)
    }

    fn validate(&self) -> ResultType<()> {
        if self.operation_id.as_bytes().iter().all(|byte| *byte == 0) {
            bail!("sensitive password request has a nil operation UUID");
        }
        if self.password_len > UNATTENDED_PASSWORD_MAX_BYTES {
            bail!("sensitive password request exceeds the password limit");
        }
        match self.kind {
            SensitivePayloadKind::Password if self.authorization_len != 0 => {
                bail!("password-only request has authorization metadata")
            }
            SensitivePayloadKind::PasswordWithAuthorization
                if self.authorization_len == 0
                    || self.authorization_len > MACOS_AUTHORIZATION_MAX_BYTES =>
            {
                bail!("password request has invalid authorization metadata")
            }
            _ => {}
        }
        self.password_len
            .checked_add(self.authorization_len)
            .filter(|total| *total <= REQUEST_BODY_MAX_BYTES)
            .ok_or_else(|| hbb_common::anyhow::anyhow!("sensitive request length overflow"))?;
        Ok(())
    }

    pub(crate) fn encode(&self) -> [u8; REQUEST_HEADER_BYTES] {
        let mut bytes = [0u8; REQUEST_HEADER_BYTES];
        bytes[..8].copy_from_slice(&REQUEST_MAGIC);
        bytes[8] = PROTOCOL_VERSION;
        bytes[9] = 0;
        bytes[10] = self.kind as u8;
        bytes[11] = 0;
        bytes[12..28].copy_from_slice(self.operation_id.as_bytes());
        bytes[28..32].copy_from_slice(&(self.password_len as u32).to_be_bytes());
        bytes[32..36].copy_from_slice(&(self.authorization_len as u32).to_be_bytes());
        bytes
    }

    pub(crate) fn decode(
        bytes: &[u8; REQUEST_HEADER_BYTES],
        expected_kind: SensitivePayloadKind,
    ) -> ResultType<Self> {
        if bytes[..8] != REQUEST_MAGIC {
            bail!("invalid sensitive password request magic");
        }
        if bytes[8] != PROTOCOL_VERSION {
            bail!("unsupported sensitive password request version");
        }
        if bytes[9] != 0 || bytes[11] != 0 {
            bail!("sensitive password request has noncanonical flags");
        }
        let kind = SensitivePayloadKind::from_wire(bytes[10])?;
        if kind != expected_kind {
            bail!("sensitive password request kind does not match its endpoint");
        }
        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&bytes[12..28]);
        let operation_id = hbb_common::uuid::Uuid::from_bytes(uuid);
        let password_len = u32::from_be_bytes(bytes[28..32].try_into()?) as usize;
        let authorization_len = u32::from_be_bytes(bytes[32..36].try_into()?) as usize;
        Self::new(operation_id, kind, password_len, authorization_len)
    }

    pub(crate) fn operation_id(&self) -> hbb_common::uuid::Uuid {
        self.operation_id
    }

    pub(crate) fn password_len(&self) -> usize {
        self.password_len
    }

    pub(crate) fn authorization_len(&self) -> usize {
        self.authorization_len
    }

    pub(crate) fn body_len(&self) -> usize {
        self.password_len + self.authorization_len
    }
}

struct FixedSensitiveBody {
    bytes: Box<[u8]>,
}

impl FixedSensitiveBody {
    fn new() -> ResultType<Self> {
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(REQUEST_BODY_MAX_BYTES)
            .map_err(|err| {
                hbb_common::anyhow::anyhow!("sensitive request allocation failed: {err}")
            })?;
        bytes.resize(REQUEST_BODY_MAX_BYTES, 0);
        Ok(Self {
            bytes: bytes.into_boxed_slice(),
        })
    }
}

impl Drop for FixedSensitiveBody {
    fn drop(&mut self) {
        zeroize_sensitive_bytes(&mut self.bytes);
    }
}

pub(crate) struct InboundSensitiveRequest {
    header: SensitiveRequestHeader,
    body: Option<FixedSensitiveBody>,
}

impl InboundSensitiveRequest {
    pub(crate) fn allocate(header: SensitiveRequestHeader) -> ResultType<Self> {
        Ok(Self {
            header,
            body: Some(FixedSensitiveBody::new()?),
        })
    }

    pub(crate) fn operation_id(&self) -> hbb_common::uuid::Uuid {
        self.header.operation_id()
    }

    pub(crate) fn body_mut(&mut self) -> &mut [u8] {
        let len = self.header.body_len();
        match self.body.as_mut() {
            Some(body) => &mut body.bytes[..len],
            None => &mut [],
        }
    }

    pub(crate) fn authorization(&self) -> &[u8] {
        let start = self.header.password_len();
        let end = start + self.header.authorization_len();
        match self.body.as_ref() {
            Some(body) => &body.bytes[start..end],
            None => &[],
        }
    }

    pub(crate) fn validate_utf8(&self) -> ResultType<()> {
        let Some(body) = self.body.as_ref() else {
            bail!("sensitive request body ownership was already moved");
        };
        std::str::from_utf8(&body.bytes[..self.header.password_len()])
            .map(|_| ())
            .map_err(|_| hbb_common::anyhow::anyhow!("password is not valid UTF-8"))
    }

    pub(crate) fn into_password(mut self) -> ResultType<SensitivePassword> {
        self.validate_utf8()?;
        let mut body = self
            .body
            .take()
            .ok_or_else(|| hbb_common::anyhow::anyhow!("sensitive request body is unavailable"))?;
        let password_len = self.header.password_len();
        zeroize_sensitive_bytes(&mut body.bytes[password_len..]);
        let bytes = std::mem::replace(&mut body.bytes, Box::new([]));
        Ok(SensitivePassword::from_inbound(bytes, password_len))
    }

    #[cfg(test)]
    fn allocation_identity(&self) -> (*const u8, usize) {
        match self.body.as_ref() {
            Some(body) => (body.bytes.as_ptr(), body.bytes.len()),
            None => (std::ptr::null(), 0),
        }
    }
}

struct SensitiveStackBytes<const N: usize>([u8; N]);

impl<const N: usize> SensitiveStackBytes<N> {
    fn zeroed() -> Self {
        Self([0u8; N])
    }
}

impl<const N: usize> Drop for SensitiveStackBytes<N> {
    fn drop(&mut self) {
        zeroize_sensitive_bytes(&mut self.0);
    }
}

pub(crate) fn encode_status(
    operation_id: hbb_common::uuid::Uuid,
    status: PasswordMutationStatus,
) -> [u8; STATUS_FRAME_BYTES] {
    let status = match status {
        PasswordMutationStatus::Prepared => 1,
        PasswordMutationStatus::Pending => 2,
        PasswordMutationStatus::Complete(IpcMutationResult::Applied) => 3,
        PasswordMutationStatus::Complete(IpcMutationResult::Rejected) => 4,
        PasswordMutationStatus::Complete(IpcMutationResult::InternalFailure) => 5,
        PasswordMutationStatus::Unknown => 6,
        PasswordMutationStatus::ShuttingDown => 7,
    };
    let mut bytes = [0u8; STATUS_FRAME_BYTES];
    bytes[..8].copy_from_slice(&STATUS_MAGIC);
    bytes[8] = PROTOCOL_VERSION;
    bytes[9] = 0;
    bytes[10] = status;
    bytes[11] = 0;
    bytes[12..28].copy_from_slice(operation_id.as_bytes());
    bytes
}

pub(crate) fn decode_status(
    bytes: &[u8; STATUS_FRAME_BYTES],
    expected_operation_id: hbb_common::uuid::Uuid,
) -> ResultType<PasswordMutationStatus> {
    if bytes[..8] != STATUS_MAGIC
        || bytes[8] != PROTOCOL_VERSION
        || bytes[9] != 0
        || bytes[11] != 0
        || bytes[28..].iter().any(|byte| *byte != 0)
    {
        bail!("invalid sensitive password status frame");
    }
    if bytes[12..28] != expected_operation_id.as_bytes()[..] {
        bail!("sensitive password status operation UUID mismatch");
    }
    match bytes[10] {
        1 => Ok(PasswordMutationStatus::Prepared),
        2 => Ok(PasswordMutationStatus::Pending),
        3 => Ok(PasswordMutationStatus::Complete(IpcMutationResult::Applied)),
        4 => Ok(PasswordMutationStatus::Complete(
            IpcMutationResult::Rejected,
        )),
        5 => Ok(PasswordMutationStatus::Complete(
            IpcMutationResult::InternalFailure,
        )),
        6 => Ok(PasswordMutationStatus::Unknown),
        7 => Ok(PasswordMutationStatus::ShuttingDown),
        _ => bail!("unsupported sensitive password status code"),
    }
}

pub(crate) fn encode_ack(operation_id: hbb_common::uuid::Uuid) -> [u8; ACK_FRAME_BYTES] {
    let mut bytes = [0u8; ACK_FRAME_BYTES];
    bytes[..8].copy_from_slice(&ACK_MAGIC);
    bytes[8] = PROTOCOL_VERSION;
    bytes[12..28].copy_from_slice(operation_id.as_bytes());
    bytes
}

pub(crate) fn decode_ack(
    bytes: &[u8; ACK_FRAME_BYTES],
    expected_operation_id: hbb_common::uuid::Uuid,
) -> ResultType<()> {
    if bytes[..8] != ACK_MAGIC
        || bytes[8] != PROTOCOL_VERSION
        || bytes[9..12].iter().any(|byte| *byte != 0)
    {
        bail!("invalid sensitive password acknowledgement frame");
    }
    if bytes[12..28] != expected_operation_id.as_bytes()[..] {
        bail!("sensitive password acknowledgement operation UUID mismatch");
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
async fn with_deadline<F, T>(deadline: hbb_common::tokio::time::Instant, future: F) -> ResultType<T>
where
    F: std::future::Future<Output = std::io::Result<T>>,
{
    hbb_common::tokio::time::timeout_at(deadline, future)
        .await
        .map_err(|_| hbb_common::anyhow::anyhow!("sensitive password transaction timed out"))?
        .map_err(Into::into)
}

pub(crate) fn remaining_millis(deadline: hbb_common::tokio::time::Instant) -> ResultType<u64> {
    let remaining = deadline
        .checked_duration_since(hbb_common::tokio::time::Instant::now())
        .ok_or_else(|| hbb_common::anyhow::anyhow!("sensitive password transaction timed out"))?;
    let millis = remaining.as_millis().max(1);
    u64::try_from(millis)
        .map_err(|_| hbb_common::anyhow::anyhow!("sensitive password deadline is invalid"))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) enum UnixSensitivePasswordSendError {
    NotSent(hbb_common::anyhow::Error),
    Uncertain(hbb_common::anyhow::Error),
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) async fn send_request_unix<T>(
    stream: &mut T,
    operation_id: hbb_common::uuid::Uuid,
    password: &SensitivePassword,
    authorization: Option<&SensitiveAuthorization>,
    deadline: hbb_common::tokio::time::Instant,
) -> std::result::Result<(), UnixSensitivePasswordSendError>
where
    T: hbb_common::tokio::io::AsyncWrite + Unpin,
{
    use hbb_common::tokio::io::AsyncWriteExt as _;

    let (kind, authorization_bytes) = match authorization {
        Some(value) => (
            SensitivePayloadKind::PasswordWithAuthorization,
            value.as_bytes(),
        ),
        None => (SensitivePayloadKind::Password, &[][..]),
    };
    let header = SensitiveRequestHeader::new(
        operation_id,
        kind,
        password.as_bytes().len(),
        authorization_bytes.len(),
    )
    .map_err(UnixSensitivePasswordSendError::NotSent)?
    .encode();
    remaining_millis(deadline).map_err(UnixSensitivePasswordSendError::NotSent)?;
    with_deadline(deadline, stream.write_all(&header))
        .await
        .map_err(UnixSensitivePasswordSendError::Uncertain)?;
    with_deadline(deadline, stream.write_all(password.as_bytes()))
        .await
        .map_err(UnixSensitivePasswordSendError::Uncertain)?;
    if !authorization_bytes.is_empty() {
        with_deadline(deadline, stream.write_all(authorization_bytes))
            .await
            .map_err(UnixSensitivePasswordSendError::Uncertain)?;
    }
    with_deadline(deadline, stream.shutdown())
        .await
        .map_err(UnixSensitivePasswordSendError::Uncertain)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) async fn receive_request_unix<T>(
    stream: &mut T,
    expected_kind: SensitivePayloadKind,
    deadline: hbb_common::tokio::time::Instant,
) -> ResultType<InboundSensitiveRequest>
where
    T: hbb_common::tokio::io::AsyncRead + Unpin,
{
    use hbb_common::tokio::io::AsyncReadExt as _;

    let mut header_bytes = SensitiveStackBytes::<REQUEST_HEADER_BYTES>::zeroed();
    with_deadline(deadline, stream.read_exact(&mut header_bytes.0)).await?;
    let header = SensitiveRequestHeader::decode(&header_bytes.0, expected_kind)?;
    let mut request = InboundSensitiveRequest::allocate(header)?;
    with_deadline(deadline, stream.read_exact(request.body_mut())).await?;
    request.validate_utf8()?;
    let mut trailing = SensitiveStackBytes::<1>::zeroed();
    let read = with_deadline(deadline, stream.read(&mut trailing.0)).await?;
    if read != 0 {
        bail!("sensitive password request has trailing bytes");
    }
    Ok(request)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) async fn send_status_unix<T>(
    stream: &mut T,
    operation_id: hbb_common::uuid::Uuid,
    status: PasswordMutationStatus,
    deadline: hbb_common::tokio::time::Instant,
) -> ResultType<()>
where
    T: hbb_common::tokio::io::AsyncWrite + Unpin,
{
    use hbb_common::tokio::io::AsyncWriteExt as _;

    let bytes = encode_status(operation_id, status);
    with_deadline(deadline, stream.write_all(&bytes)).await?;
    with_deadline(deadline, stream.shutdown()).await
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) async fn receive_status_unix<T>(
    stream: &mut T,
    operation_id: hbb_common::uuid::Uuid,
    deadline: hbb_common::tokio::time::Instant,
) -> ResultType<PasswordMutationStatus>
where
    T: hbb_common::tokio::io::AsyncRead + Unpin,
{
    use hbb_common::tokio::io::AsyncReadExt as _;

    let mut bytes = SensitiveStackBytes::<STATUS_FRAME_BYTES>::zeroed();
    with_deadline(deadline, stream.read_exact(&mut bytes.0)).await?;
    let status = decode_status(&bytes.0, operation_id)?;
    let mut trailing = SensitiveStackBytes::<1>::zeroed();
    if with_deadline(deadline, stream.read(&mut trailing.0)).await? != 0 {
        bail!("sensitive password status has trailing bytes");
    }
    Ok(status)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    use hbb_common::tokio;

    const UUID: hbb_common::uuid::Uuid = hbb_common::uuid::Uuid::from_bytes([
        0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x4a, 0xbc, 0x8d, 0xef, 0x12, 0x34, 0x56, 0x78, 0x9a,
        0xbc,
    ]);

    fn encoded_request(password: &[u8], authorization: Option<&[u8]>) -> Vec<u8> {
        let (kind, authorization) = match authorization {
            Some(value) => (SensitivePayloadKind::PasswordWithAuthorization, value),
            None => (SensitivePayloadKind::Password, &[][..]),
        };
        let header = SensitiveRequestHeader::new(UUID, kind, password.len(), authorization.len())
            .unwrap()
            .encode();
        let mut bytes = Vec::with_capacity(header.len() + password.len() + authorization.len());
        bytes.extend_from_slice(&header);
        bytes.extend_from_slice(password);
        bytes.extend_from_slice(authorization);
        bytes
    }

    fn decode_complete(bytes: &[u8], kind: SensitivePayloadKind) -> ResultType<SensitivePassword> {
        if bytes.len() < REQUEST_HEADER_BYTES {
            bail!("short request");
        }
        let header_bytes: &[u8; REQUEST_HEADER_BYTES] = bytes[..REQUEST_HEADER_BYTES].try_into()?;
        let header = SensitiveRequestHeader::decode(header_bytes, kind)?;
        if bytes.len() != REQUEST_HEADER_BYTES + header.body_len() {
            bail!("request has trailing or missing bytes");
        }
        let mut request = InboundSensitiveRequest::allocate(header)?;
        request
            .body_mut()
            .copy_from_slice(&bytes[REQUEST_HEADER_BYTES..]);
        request.into_password()
    }

    #[test]
    fn request_wire_golden_values() {
        let cases = ["", "\"", "\\", "\0\u{1f}", "Grüße", "密碼"];
        for value in cases {
            let bytes = encoded_request(value.as_bytes(), None);
            assert_eq!(&bytes[..8], b"RDPWREQ\0");
            assert_eq!(bytes[8..12], [1, 0, 1, 0]);
            assert_eq!(&bytes[12..28], UUID.as_bytes());
            assert_eq!(
                u32::from_be_bytes(bytes[28..32].try_into().unwrap()) as usize,
                value.len()
            );
            assert_eq!(
                decode_complete(&bytes, SensitivePayloadKind::Password)
                    .unwrap()
                    .as_str(),
                value
            );
        }

        let maximum = "x".repeat(UNATTENDED_PASSWORD_MAX_BYTES);
        let bytes = encoded_request(maximum.as_bytes(), None);
        assert_eq!(
            decode_complete(&bytes, SensitivePayloadKind::Password)
                .unwrap()
                .as_str(),
            maximum
        );

        let authorization = vec![0xa5; MACOS_AUTHORIZATION_MAX_BYTES];
        let bytes = encoded_request(b"secret", Some(&authorization));
        let header_bytes: &[u8; REQUEST_HEADER_BYTES] =
            bytes[..REQUEST_HEADER_BYTES].try_into().unwrap();
        let header = SensitiveRequestHeader::decode(
            header_bytes,
            SensitivePayloadKind::PasswordWithAuthorization,
        )
        .unwrap();
        let mut request = InboundSensitiveRequest::allocate(header).unwrap();
        request
            .body_mut()
            .copy_from_slice(&bytes[REQUEST_HEADER_BYTES..]);
        assert_eq!(request.authorization(), authorization);
        assert_eq!(request.into_password().unwrap().as_str(), "secret");
    }

    #[test]
    fn request_header_rejects_every_noncanonical_field() {
        let valid = SensitiveRequestHeader::new(UUID, SensitivePayloadKind::Password, 1, 0)
            .unwrap()
            .encode();
        for index in 0..8 {
            let mut bytes = valid;
            bytes[index] ^= 1;
            assert!(
                SensitiveRequestHeader::decode(&bytes, SensitivePayloadKind::Password).is_err()
            );
        }
        for (index, value) in [(8, 2), (9, 1), (10, 9), (11, 1)] {
            let mut bytes = valid;
            bytes[index] = value;
            assert!(
                SensitiveRequestHeader::decode(&bytes, SensitivePayloadKind::Password).is_err()
            );
        }
        let mut nil_uuid = valid;
        nil_uuid[12..28].fill(0);
        assert!(SensitiveRequestHeader::decode(&nil_uuid, SensitivePayloadKind::Password).is_err());
        let mut too_long = valid;
        too_long[28..32]
            .copy_from_slice(&((UNATTENDED_PASSWORD_MAX_BYTES as u32) + 1).to_be_bytes());
        assert!(SensitiveRequestHeader::decode(&too_long, SensitivePayloadKind::Password).is_err());
        let mut bad_aux = valid;
        bad_aux[32..36].copy_from_slice(&1u32.to_be_bytes());
        assert!(SensitiveRequestHeader::decode(&bad_aux, SensitivePayloadKind::Password).is_err());
        assert!(SensitiveRequestHeader::decode(
            &valid,
            SensitivePayloadKind::PasswordWithAuthorization
        )
        .is_err());
    }

    #[test]
    fn request_rejects_invalid_utf8_missing_and_trailing_data() {
        assert!(decode_complete(
            &encoded_request(&[0xff], None),
            SensitivePayloadKind::Password
        )
        .is_err());
        let mut missing = encoded_request(b"secret", None);
        missing.pop();
        assert!(decode_complete(&missing, SensitivePayloadKind::Password).is_err());
        let mut trailing = encoded_request(b"secret", None);
        trailing.push(0);
        assert!(decode_complete(&trailing, SensitivePayloadKind::Password).is_err());
    }

    #[test]
    fn inbound_password_keeps_one_fixed_allocation() {
        let header = SensitiveRequestHeader::new(
            UUID,
            SensitivePayloadKind::PasswordWithAuthorization,
            6,
            4,
        )
        .unwrap();
        let mut request = InboundSensitiveRequest::allocate(header).unwrap();
        let before = request.allocation_identity();
        request.body_mut().copy_from_slice(b"secretAUTH");
        assert_eq!(request.allocation_identity(), before);
        assert_eq!(request.authorization(), b"AUTH");
        let password = request.into_password().unwrap();
        assert_eq!(password.allocation_identity(), before);
        assert_eq!(password.as_str(), "secret");
    }

    #[test]
    fn sensitive_password_retries_share_the_originating_allocation() {
        let origin = "retry-secret".to_owned();
        let identity = (origin.as_ptr(), origin.capacity());
        let password = SensitivePassword::new(origin);
        assert_eq!(password.allocation_identity(), identity);
        let retry = password.clone();
        assert_eq!(retry.allocation_identity(), identity);
        assert_eq!(password.as_str(), retry.as_str());
    }

    #[test]
    fn explicit_erasure_overwrites_origin_and_inbound_storage() {
        let mut origin = SensitivePassword::new("secret".to_owned());
        assert!(origin.zeroize());
        assert_eq!(origin.as_bytes(), &[0; 6]);

        let bytes = encoded_request(b"secret", None);
        let mut inbound = decode_complete(&bytes, SensitivePayloadKind::Password).unwrap();
        assert!(inbound.zeroize());
        assert_eq!(inbound.as_bytes(), &[0; 6]);
    }

    #[test]
    fn status_wire_is_fixed_canonical_and_operation_bound() {
        let statuses = [
            PasswordMutationStatus::Prepared,
            PasswordMutationStatus::Pending,
            PasswordMutationStatus::Complete(IpcMutationResult::Applied),
            PasswordMutationStatus::Complete(IpcMutationResult::Rejected),
            PasswordMutationStatus::Complete(IpcMutationResult::InternalFailure),
            PasswordMutationStatus::Unknown,
            PasswordMutationStatus::ShuttingDown,
        ];
        for status in statuses {
            let bytes = encode_status(UUID, status);
            assert_eq!(bytes.len(), STATUS_FRAME_BYTES);
            assert_eq!(decode_status(&bytes, UUID).unwrap(), status);
            assert!(decode_status(&bytes, hbb_common::uuid::Uuid::new_v4()).is_err());
        }

        let valid = encode_status(UUID, PasswordMutationStatus::Pending);
        for index in [0, 7, 8, 9, 11, 28, 31] {
            let mut malformed = valid;
            malformed[index] ^= 1;
            assert!(decode_status(&malformed, UUID).is_err());
        }
        let mut unknown_status = valid;
        unknown_status[10] = u8::MAX;
        assert!(decode_status(&unknown_status, UUID).is_err());
    }

    #[test]
    fn acknowledgement_wire_is_fixed_canonical_and_operation_bound() {
        let valid = encode_ack(UUID);
        assert_eq!(valid.len(), ACK_FRAME_BYTES);
        assert!(decode_ack(&valid, UUID).is_ok());
        assert!(decode_ack(&valid, hbb_common::uuid::Uuid::new_v4()).is_err());
        for index in [0, 7, 8, 9, 11, 12, 27] {
            let mut malformed = valid;
            malformed[index] ^= 1;
            assert!(decode_ack(&malformed, UUID).is_err());
        }
    }

    #[test]
    fn password_types_have_no_serde_or_generic_framing_surface() {
        let source = include_str!("password.rs");
        let production = source
            .rsplit_once("\n#[cfg(test)]\nmod tests {")
            .map(|(production, _)| production)
            .unwrap();
        for forbidden in [
            "impl serde::Serialize for SensitivePassword",
            "impl<'de> serde::Deserialize<'de> for SensitivePassword",
            "bytes::Bytes",
            "bytes::BytesMut",
            "BytesCodec",
            "Framed<",
            "FramedRead",
            "FramedWrite",
            "tokio_util::codec",
            "asynchronous_codec",
            "serde_json",
            "tokio_serde",
            "bincode",
            "postcard",
            "rmp_serde",
        ] {
            assert!(
                !production.contains(forbidden),
                "found forbidden token {forbidden}"
            );
        }
        let identifiers: std::collections::HashSet<&str> = production
            .split(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
            .filter(|identifier| !identifier.is_empty())
            .collect();
        for forbidden in [
            "Bytes",
            "BytesMut",
            "BytesCodec",
            "Framed",
            "FramedRead",
            "FramedWrite",
            "Decoder",
            "Encoder",
            "Buf",
            "BufMut",
            "Serialize",
            "Deserialize",
            "serde_json",
            "tokio_util",
            "asynchronous_codec",
            "tokio_serde",
            "bincode",
            "postcard",
            "rmp_serde",
        ] {
            assert!(
                !identifiers.contains(forbidden),
                "found forbidden production identifier {forbidden}"
            );
        }
        for line in production.lines().map(str::trim_start).filter(|line| {
            line.starts_with("use ")
                || line.starts_with("pub use ")
                || line.starts_with("extern crate ")
        }) {
            let imported: std::collections::HashSet<&str> = line
                .split(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
                .filter(|identifier| !identifier.is_empty())
                .collect();
            for forbidden in [
                "bytes",
                "serde",
                "serde_json",
                "tokio_util",
                "asynchronous_codec",
                "tokio_serde",
                "bincode",
                "postcard",
                "rmp_serde",
            ] {
                assert!(
                    !imported.contains(forbidden),
                    "found forbidden production import {forbidden}"
                );
            }
        }
    }

    #[test]
    fn windows_sensitive_facade_retains_raw_pipe_and_cancellation_invariants() {
        let source = include_str!("../platform/windows.rs");
        let start = source
            .find("const WINDOWS_SENSITIVE_PIPE_BUFFER_BYTES")
            .unwrap();
        let end = source[start..]
            .find("fn authorize_service_scoped_ipc_connection")
            .map(|offset| start + offset)
            .unwrap();
        let facade = &source[start..end];
        assert!(source.contains("WAIT_TIMEOUT as WINDOWS_WAIT_TIMEOUT"));
        for required in [
            "WINDOWS_SENSITIVE_PIPE_MAX_INSTANCES: u32 = 1",
            "WINDOWS_OVERLAPPED_WAIT_TIMEOUT",
            "FILE_FLAG_FIRST_PIPE_INSTANCE",
            "WINDOWS_SENSITIVE_PASSWORD_LISTENER_WORKERS",
            "retain_windows_sensitive_password_listener",
            "pub(crate) async fn quiesce(&self)",
            "pipe.disconnect_client()",
            "PIPE_REJECT_REMOTE_CLIENTS",
            "PIPE_READMODE_MESSAGE",
            "SECURITY_IDENTIFICATION",
            "SECURITY_SQOS_PRESENT",
            "FILE_WRITE_ATTRIBUTES.0",
            "CreateEventW(None, true, false, None)",
            "CancelIoEx(handle, Some(&self.value))",
            "GetOverlappedResultEx",
            "WINDOWS_INFINITE",
            "windows_sensitive_pipe_kernel_sddl",
            "pipe.ensure_kernel_dacl_retained().and_then",
            "preauthorize_windows_sensitive_pipe_client",
            "authorize_windows_sensitive_pipe_client",
            "authenticate_windows_sensitive_pipe_server",
            "windows-sensitive-ipc-client-supervisor",
            "Ok(worker) => match worker.join()",
            "ipc::password::decode_ack",
            "windows_sensitive_deadline_live(deadline, \"Windows sensitive IPC status\")",
        ] {
            assert!(
                facade.contains(required),
                "missing raw pipe invariant {required}"
            );
        }
        assert!(!facade.contains("parity_tokio_ipc"));
        assert!(!facade.contains("BytesCodec"));
        assert!(!facade.contains("Framed"));

        let drain = facade.find("fn cancel_and_drain").unwrap();
        let cancel = facade[drain..].find("CancelIoEx").unwrap();
        let exact_drain = facade[drain..].find("GetOverlappedResultEx").unwrap();
        assert!(cancel < exact_drain);

        let handler = facade
            .find("fn handle_windows_sensitive_password_pipe")
            .unwrap();
        let handler_end = facade[handler..]
            .find("pub(crate) fn start_windows_sensitive_password_listener")
            .unwrap();
        let handler = &facade[handler..handler + handler_end];
        let preauthorization = handler
            .find("ipc::preauthorize_windows_sensitive_pipe_client(")
            .unwrap();
        let header_read = handler
            .find("pipe.read_message(&mut header_bytes.0")
            .unwrap();
        let client_proof = handler
            .find("ipc::authorize_windows_sensitive_pipe_client(")
            .unwrap();
        let password_read = handler
            .find("pipe.read_message(request.body_mut()")
            .unwrap();
        assert!(preauthorization < header_read);
        assert!(header_read < client_proof && client_proof < password_read);
        let final_proof = handler
            .rfind("proof.revalidate(pipe.handle.0, deadline)")
            .unwrap();
        let admission = handler.find("requests.try_send(request)").unwrap();
        assert!(password_read < final_proof && final_proof < admission);
        let status_write = handler.find("pipe.write_message(&response.0").unwrap();
        let acknowledgement = handler.find("ipc::password::decode_ack").unwrap();
        assert!(admission < status_write && status_write < acknowledgement);
        assert!(!facade.contains("create_standby_server"));

        let auth = include_str!("auth.rs");
        assert!(auth.contains("PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE"));
        assert!(auth.contains("fn stable_active_session_principal("));
        let revalidate = auth.find("impl WindowsSensitivePipeClientProof").unwrap();
        let revalidate_end = auth[revalidate..]
            .find("pub(crate) fn preauthorize_windows_sensitive_pipe_client")
            .map(|offset| revalidate + offset)
            .unwrap();
        let revalidate = &auth[revalidate..revalidate_end];
        let identity = revalidate.find("self.process.fresh_identity()").unwrap();
        let process_token = revalidate.find("self.process.live_token_proof()").unwrap();
        let pipe_token = revalidate
            .find("windows_named_pipe_client_token_proof")
            .unwrap();
        let security = revalidate
            .find("windows_sensitive_pipe_security_at_deadline")
            .unwrap();
        assert!(identity < process_token && process_token < pipe_token && pipe_token < security);
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[tokio::test(flavor = "current_thread")]
    async fn unix_request_parser_accepts_every_fragmentation_boundary() {
        use tokio::io::AsyncWriteExt as _;

        let wire = encoded_request("密碼/\0secret".as_bytes(), None);
        for chunk_size in 1..=wire.len() {
            let (mut sender, mut receiver) = tokio::io::duplex(wire.len() * 2);
            let bytes = wire.clone();
            let writer = tokio::spawn(async move {
                for chunk in bytes.chunks(chunk_size) {
                    sender.write_all(chunk).await.unwrap();
                }
                sender.shutdown().await.unwrap();
            });
            let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(1);
            let request =
                receive_request_unix(&mut receiver, SensitivePayloadKind::Password, deadline)
                    .await
                    .unwrap();
            assert_eq!(request.into_password().unwrap().as_str(), "密碼/\0secret");
            writer.await.unwrap();
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[tokio::test(flavor = "current_thread")]
    async fn unix_request_parser_rejects_eof_at_every_offset() {
        use tokio::io::AsyncWriteExt as _;

        let wire = encoded_request(b"secret", None);
        for cutoff in 0..wire.len() {
            let (mut sender, mut receiver) = tokio::io::duplex(wire.len() * 2);
            let prefix = wire[..cutoff].to_vec();
            let writer = tokio::spawn(async move {
                sender.write_all(&prefix).await.unwrap();
                sender.shutdown().await.unwrap();
            });
            let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(1);
            assert!(
                receive_request_unix(&mut receiver, SensitivePayloadKind::Password, deadline,)
                    .await
                    .is_err(),
                "accepted EOF at wire offset {cutoff}"
            );
            writer.await.unwrap();
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[tokio::test(flavor = "current_thread")]
    async fn unix_request_parser_times_out_without_abandoning_partial_input() {
        use tokio::io::AsyncWriteExt as _;

        let wire = encoded_request(b"secret", None);
        for cutoff in [
            0,
            REQUEST_HEADER_BYTES - 1,
            REQUEST_HEADER_BYTES,
            wire.len() - 1,
        ] {
            let (mut sender, mut receiver) = tokio::io::duplex(wire.len() * 2);
            sender.write_all(&wire[..cutoff]).await.unwrap();
            let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(1);
            assert!(
                receive_request_unix(&mut receiver, SensitivePayloadKind::Password, deadline,)
                    .await
                    .is_err(),
                "accepted timed-out wire offset {cutoff}"
            );
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[tokio::test(flavor = "current_thread")]
    async fn unix_send_classifies_preflight_and_started_write_failures() {
        let oversized = SensitivePassword::new("x".repeat(UNATTENDED_PASSWORD_MAX_BYTES + 1));
        let (mut sender, _receiver) = tokio::io::duplex(REQUEST_HEADER_BYTES * 2);
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(1);
        assert!(matches!(
            send_request_unix(&mut sender, UUID, &oversized, None, deadline).await,
            Err(UnixSensitivePasswordSendError::NotSent(_))
        ));

        let password = SensitivePassword::new("x".repeat(UNATTENDED_PASSWORD_MAX_BYTES));
        let (mut sender, _receiver) = tokio::io::duplex(1);
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(1);
        assert!(matches!(
            send_request_unix(&mut sender, UUID, &password, None, deadline).await,
            Err(UnixSensitivePasswordSendError::Uncertain(_))
        ));
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[tokio::test(flavor = "current_thread")]
    async fn unix_status_parser_handles_fragmentation_eof_and_timeout() {
        use tokio::io::AsyncWriteExt as _;

        let wire = encode_status(UUID, PasswordMutationStatus::Pending);
        for chunk_size in 1..=wire.len() {
            let (mut sender, mut receiver) = tokio::io::duplex(wire.len() * 2);
            let writer = tokio::spawn(async move {
                for chunk in wire.chunks(chunk_size) {
                    sender.write_all(chunk).await.unwrap();
                }
                sender.shutdown().await.unwrap();
            });
            let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(1);
            assert_eq!(
                receive_status_unix(&mut receiver, UUID, deadline)
                    .await
                    .unwrap(),
                PasswordMutationStatus::Pending
            );
            writer.await.unwrap();
        }

        for cutoff in 0..wire.len() {
            let (mut sender, mut receiver) = tokio::io::duplex(wire.len() * 2);
            sender.write_all(&wire[..cutoff]).await.unwrap();
            sender.shutdown().await.unwrap();
            let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(1);
            assert!(receive_status_unix(&mut receiver, UUID, deadline)
                .await
                .is_err());
        }

        let (_sender, mut receiver) = tokio::io::duplex(wire.len() * 2);
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(1);
        assert!(receive_status_unix(&mut receiver, UUID, deadline)
            .await
            .is_err());
    }
}
