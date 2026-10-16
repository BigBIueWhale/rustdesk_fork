// Test-only getter from 784daba1600e99e09873f4c6c8bb663612c85961.
// Original method SHA-256: 4b3b35e69ae51e5604481ba4fbe7f6bd68472a005623aaa62de687b0a91f8757
use super::TransferJob;
use crate::{anyhow::anyhow, ResultType};
use std::time::SystemTime;

impl TransferJob {
    pub(super) async fn digest_before_size_admission(&self) -> ResultType<(u64, u64)> {
        let meta = self
            .data_stream
            .as_ref()
            .ok_or(anyhow!("file is None"))?
            .metadata()
            .await?;
        let last_modified = meta
            .modified()?
            .duration_since(SystemTime::UNIX_EPOCH)?
            .as_secs();
        Ok((last_modified, meta.len()))
    }
}
