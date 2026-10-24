use hbb_common::{
    get_time,
    message_proto::{Message, VoiceCallRequest, VoiceCallResponse},
};
use scrap::CodecFormat;
use std::{
    collections::HashMap,
    num::NonZeroI64,
    sync::atomic::{AtomicI64, Ordering},
};

#[derive(Debug, Default)]
pub struct QualityStatus {
    pub speed: Option<String>,
    pub fps: HashMap<usize, i32>,
    pub delay: Option<i32>,
    pub target_bitrate: Option<i32>,
    pub codec_format: Option<CodecFormat>,
    pub chroma: Option<String>,
}

static VOICE_CALL_REQUEST_ID: AtomicI64 = AtomicI64::new(0);

fn allocate_voice_call_request_id(_last_id: &AtomicI64) -> Option<NonZeroI64> {
    NonZeroI64::new(get_time())
}

#[inline]
pub fn new_voice_call_request() -> Option<(NonZeroI64, Message)> {
    let request_id = allocate_voice_call_request_id(&VOICE_CALL_REQUEST_ID)?;
    let mut req = VoiceCallRequest::new();
    req.is_connect = true;
    req.req_timestamp = request_id.get();
    let mut msg = Message::new();
    msg.set_voice_call_request(req);
    Some((request_id, msg))
}

#[inline]
pub fn new_voice_call_close() -> Message {
    let mut msg = Message::new();
    msg.set_voice_call_request(VoiceCallRequest::new());
    msg
}

#[inline]
pub fn new_voice_call_response(request_timestamp: i64, accepted: bool) -> Message {
    let mut resp = VoiceCallResponse::new();
    resp.accepted = accepted;
    resp.req_timestamp = request_timestamp;
    resp.ack_timestamp = get_time();
    let mut msg = Message::new();
    msg.set_voice_call_response(resp);
    msg
}
