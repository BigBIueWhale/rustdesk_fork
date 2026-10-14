extern crate self as hbb_common;

pub use bytes;
pub use protobuf;
pub mod protos {
    include!(concat!(env!("OUT_DIR"), "/protos/mod.rs"));
}
pub use protos::message as message_proto;

#[path = "../src/client/audio_mailbox.rs"]
mod audio_mailbox;
