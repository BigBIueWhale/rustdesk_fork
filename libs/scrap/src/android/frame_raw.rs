use std::ops::Not;
use std::time::{Duration, Instant};

use super::frame_raw_generation::{BeginGeneration, FrameRawGenerationOwner};

pub(crate) struct FrameRaw {
    name: &'static str,
    data: Vec<u8>,
    last_update: Instant,
    timeout: Duration,
    enable: bool,
}

impl FrameRaw {
    pub(crate) fn new(name: &'static str, timeout: Duration) -> Self {
        Self {
            name,
            data: Vec::new(),
            last_update: Instant::now(),
            timeout,
            enable: false,
        }
    }

    pub(crate) fn set_enable(&mut self, value: bool) {
        self.enable = value;
        self.data.clear();
    }

    pub(crate) fn update_from_jni_buffer(&mut self, data: *mut u8, len: usize, max_len: usize) {
        if self.enable.not() {
            return;
        }
        if data.is_null() || len == 0 {
            log::warn!("dropping empty Android {} raw buffer", self.name);
            return;
        }
        if len > max_len {
            log::warn!(
                "dropping oversized Android {} raw buffer before Rust-owned copy: {} > {}",
                self.name,
                len,
                max_len
            );
            return;
        }
        let slice = unsafe { std::slice::from_raw_parts(data, len) };
        self.data.clear();
        self.data.extend_from_slice(slice);
        self.last_update = Instant::now();
    }

    pub(crate) fn take(&mut self, dst: &mut Vec<u8>, last: &mut Vec<u8>) -> Option<()> {
        if self.enable.not() {
            return None;
        }
        if self.data.is_empty() {
            None
        } else {
            if self.last_update.elapsed() > self.timeout {
                log::trace!("Failed to take {} raw,timeout!", self.name);
                self.release();
                return None;
            }
            if last.len() == self.data.len()
                && crate::would_block_if_equal(last, &self.data).is_err()
            {
                self.release();
                return None;
            }
            dst.clear();
            dst.extend_from_slice(&self.data);
            self.release();
            Some(())
        }
    }

    fn release(&mut self) {
        self.data.clear();
    }
}

pub(crate) struct GenerationOwnedFrameRaw {
    owner: FrameRawGenerationOwner,
    frame: FrameRaw,
}

impl GenerationOwnedFrameRaw {
    pub(crate) fn new(name: &'static str, timeout: Duration) -> Self {
        Self {
            owner: FrameRawGenerationOwner::default(),
            frame: FrameRaw::new(name, timeout),
        }
    }

    pub(crate) fn begin_generation(&mut self, generation: u64) -> bool {
        match self.owner.begin(generation) {
            BeginGeneration::New => {
                self.frame.set_enable(false);
                true
            }
            BeginGeneration::Current => true,
            BeginGeneration::Rejected => false,
        }
    }

    pub(crate) fn retire_generation(&mut self, generation: u64) -> bool {
        if !self.owner.retire(generation) {
            return false;
        }
        self.frame.set_enable(false);
        true
    }

    pub(crate) fn set_enable(&mut self, generation: u64, value: bool) -> bool {
        if !self.owner.admits(generation) {
            return false;
        }
        self.frame.set_enable(value);
        true
    }

    pub(crate) fn update_from_jni_buffer(
        &mut self,
        generation: u64,
        data: *mut u8,
        len: usize,
        max_len: usize,
    ) {
        if !self.owner.admits(generation) {
            return;
        }
        self.frame.update_from_jni_buffer(data, len, max_len);
    }

    pub(crate) fn take(&mut self, dst: &mut Vec<u8>, last: &mut Vec<u8>) -> Option<()> {
        self.frame.take(dst, last)
    }
}
