pub(super) struct BoundedScreenshotPng {
    data: Vec<u8>,
    max_bytes: usize,
}

impl BoundedScreenshotPng {
    pub(super) fn new() -> Self {
        Self::with_limit(crate::peer_text::MAX_PEER_SCREENSHOT_RESPONSE_BYTES)
    }

    pub(super) fn with_limit(max_bytes: usize) -> Self {
        Self {
            data: Vec::new(),
            max_bytes,
        }
    }

    pub(super) fn into_bytes(self) -> Vec<u8> {
        self.data
    }
}

impl std::io::Write for BoundedScreenshotPng {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let next_len = self
            .data
            .len()
            .checked_add(buf.len())
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidData))?;
        if next_len > self.max_bytes {
            return Err(std::io::ErrorKind::InvalidData.into());
        }
        if next_len > self.data.capacity() {
            let capacity = next_len
                .max(self.data.capacity().saturating_mul(2))
                .min(self.max_bytes);
            self.data
                .try_reserve_exact(capacity - self.data.len())
                .map_err(|_| std::io::Error::from(std::io::ErrorKind::OutOfMemory))?;
        }
        self.data.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
