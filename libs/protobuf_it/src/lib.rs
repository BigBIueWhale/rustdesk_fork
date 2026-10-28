pub use protobuf;
#[path = "../../hbb_common/src/protos/mod.rs"]
pub mod protos;
pub use protos::message as message_proto;

#[cfg(test)]
mod protobuf_tests;
