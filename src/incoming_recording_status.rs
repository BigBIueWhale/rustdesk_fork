use hbb_common::{bail, ResultType};
use serde::{Deserialize, Serialize};

pub(crate) const MAX_RECORDERS: u32 = 64;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureStage {
    Start,
    Write,
    Finish,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecordingFailure {
    pub display: usize,
    pub camera: bool,
    pub stage: FailureStage,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IncomingRecordingStatus {
    pub starting: u16,
    pub active: u16,
    pub finishing: u16,
    pub last_failure: Option<RecordingFailure>,
}

impl IncomingRecordingStatus {
    pub(crate) fn writers(&self) -> u32 {
        u32::from(self.starting) + u32::from(self.active) + u32::from(self.finishing)
    }

    pub fn validate(self) -> ResultType<Self> {
        if self.writers() > MAX_RECORDERS {
            bail!("Incoming recording status exceeds the writer limit");
        }
        Ok(self)
    }
}
