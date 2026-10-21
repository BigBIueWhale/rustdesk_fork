extern crate self as hbb_common;

pub use log;
pub use sodiumoxide;
pub use tokio;

#[path = "../libs/hbb_common/src/protos/mod.rs"]
pub mod protos;
pub use protos::message as message_proto;

pub mod cpace {
    include!(env!("CONTROL_EGRESS_LIMIT"));
}

use message_proto::*;
use protobuf::Message as _;
use std::{
    collections::VecDeque,
    fmt,
    sync::{Arc, Mutex as StdMutex},
    time::Duration,
};
use tokio::{sync::mpsc, time};

include!(env!("CONTROL_EGRESS_SOURCE"));
include!(env!("CONTROL_EGRESS_TESTS"));
