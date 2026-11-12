//! Single-planar V4L2 capture with owned mappings and retryable bounded reads.

use memmap2::{MmapMut, MmapOptions};
use std::{
    io, mem,
    sync::Arc,
    time::{Duration, Instant},
};
use v4l::{device::Handle, v4l2, v4l_sys::*, Device};

const CAPTURE_TYPE: u32 = v4l::buffer::Type::VideoCapture as u32;
const MMAP_MEMORY: u32 = v4l::memory::Memory::Mmap as u32;
const BUFFER_COUNT: u32 = 4;
const MAX_BUFFERS: u32 = 32;
// Per-buffer ceiling matches the application's decoded-frame allocation ceiling.
// Drivers may require more than four buffers; their total mapping remains bounded.
const MAX_BUFFER_BYTES: usize = 160 * 1024 * 1024;
pub(crate) const MAX_FRAME_WAIT: Duration = Duration::from_secs(1);

pub(crate) struct CaptureStream {
    handle: Arc<Handle>,
    buffers: Vec<MmapMut>,
    allocated: bool,
    active: bool,
    failed: bool,
    // Only a successful DQBUF creates an index that may be queued again.
    dequeued: Option<usize>,
}

fn buffer(index: u32) -> v4l2_buffer {
    v4l2_buffer {
        type_: CAPTURE_TYPE,
        memory: MMAP_MEMORY,
        index,
        // All reserved fields and the unused union must be zero.
        ..unsafe { mem::zeroed() }
    }
}

impl CaptureStream {
    pub(crate) fn new(device: &Device) -> io::Result<Self> {
        let mut stream = Self {
            handle: device.handle(),
            buffers: Vec::new(),
            allocated: false,
            active: false,
            failed: false,
            dequeued: None,
        };
        let count = stream.request_buffers(BUFFER_COUNT)?;
        stream.allocated = true;
        if count == 0 || count > MAX_BUFFERS {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "V4L2 buffer count exceeds capture bounds"));
        }
        let mut mapped_bytes = 0;
        for index in 0..count {
            let mut description = buffer(index);
            // The request and argument type are paired by the V4L2 ABI.
            unsafe {
                v4l2::ioctl(stream.handle.fd(), v4l2::vidioc::VIDIOC_QUERYBUF,
                            &mut description as *mut _ as *mut _)?;
            }
            let length = description.length as usize;
            if length == 0 || length > MAX_BUFFER_BYTES {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "V4L2 mapping exceeds capture bounds"));
            }
            mapped_bytes += length;
            if mapped_bytes > MAX_BUFFER_BYTES * BUFFER_COUNT as usize {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "V4L2 mapped capture exceeds total bounds"));
            }
            // MMAP buffers use m.offset. The retained handle owns the allocation.
            // No Rust reference accesses a buffer while it is queued to the driver;
            // next() borrows only a dequeued buffer until the next mutable call.
            let mapping = unsafe {
                MmapOptions::new().len(length).offset(description.m.offset as u64)
                    .map_mut(stream.handle.fd())?
            };
            stream.buffers.push(mapping);
        }
        for index in 0..stream.buffers.len() {
            stream.queue(index)?;
        }
        let mut kind = CAPTURE_TYPE;
        unsafe {
            v4l2::ioctl(stream.handle.fd(), v4l2::vidioc::VIDIOC_STREAMON,
                        &mut kind as *mut _ as *mut _)?;
        }
        stream.active = true;
        Ok(stream)
    }

    fn request_buffers(&self, count: u32) -> io::Result<u32> {
        let mut request = v4l2_requestbuffers {
            count, type_: CAPTURE_TYPE, memory: MMAP_MEMORY,
            ..unsafe { mem::zeroed() }
        };
        unsafe {
            v4l2::ioctl(self.handle.fd(), v4l2::vidioc::VIDIOC_REQBUFS,
                        &mut request as *mut _ as *mut _)?;
        }
        Ok(request.count)
    }

    fn queue(&self, index: usize) -> io::Result<()> {
        let mut description = buffer(index as u32);
        unsafe {
            v4l2::ioctl(self.handle.fd(), v4l2::vidioc::VIDIOC_QBUF,
                        &mut description as *mut _ as *mut _)
        }
    }

    pub(crate) fn next(&mut self, timeout: Duration) -> io::Result<&[u8]> {
        if !self.active || self.failed {
            return Err(io::Error::new(io::ErrorKind::Other, "V4L2 stream is stopped or failed"));
        }
        let started = Instant::now();
        let timeout = timeout.min(MAX_FRAME_WAIT);
        if let Some(index) = self.dequeued {
            if let Err(error) = self.queue(index) {
                self.failed = true;
                return Err(error);
            }
            self.dequeued = None;
        }
        loop {
            let mut description = buffer(0);
            // Device::new opens O_NONBLOCK. A readiness race must never turn this
            // into an unbounded wait, and EAGAIN must not requeue a buffer twice.
            let result = unsafe {
                v4l2::ioctl(self.handle.fd(), v4l2::vidioc::VIDIOC_DQBUF,
                            &mut description as *mut _ as *mut _)
            };
            match result {
                Ok(()) => {
                    let index = description.index as usize;
                    let used = description.bytesused as usize;
                    if index >= self.buffers.len() || used > self.buffers[index].len() {
                        self.failed = true;
                        return Err(io::Error::new(io::ErrorKind::InvalidData, "V4L2 returned an invalid buffer"));
                    }
                    self.dequeued = Some(index);
                    if description.flags & V4L2_BUF_FLAG_ERROR != 0 || used == 0 {
                        return Err(io::Error::new(io::ErrorKind::WouldBlock, "V4L2 frame was not usable"));
                    }
                    return Ok(&self.buffers[index][..used]);
                }
                Err(error) if matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted) => {}
                Err(error) => {
                    // EIO can consume an unknown buffer. Do not guess its identity.
                    self.failed = true;
                    return Err(error);
                }
            }
            let remaining = timeout.saturating_sub(started.elapsed());
            if remaining.is_zero() {
                return Err(io::Error::new(io::ErrorKind::WouldBlock, "V4L2 frame deadline elapsed"));
            }
            // Round up sub-millisecond waits; the one-second cap makes this cast bounded.
            let millis = ((remaining.as_nanos() + 999_999) / 1_000_000) as i32;
            let mut descriptor = libc::pollfd {
                fd: self.handle.fd(), events: libc::POLLIN, revents: 0,
            };
            let ready = unsafe { libc::poll(&mut descriptor, 1, millis) };
            if ready < 0 {
                let error = io::Error::last_os_error();
                if error.kind() != io::ErrorKind::Interrupted {
                    self.failed = true;
                    return Err(error);
                }
            } else if descriptor.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
                self.failed = true;
                return Err(io::Error::new(io::ErrorKind::Other, "V4L2 stream poll failed"));
            }
            if started.elapsed() >= timeout {
                return Err(io::Error::new(io::ErrorKind::WouldBlock, "V4L2 frame deadline elapsed"));
            }
        }
    }

    pub(crate) fn close(&mut self) -> io::Result<()> {
        if !self.allocated {
            return Ok(());
        }
        let mut kind = CAPTURE_TYPE;
        // Also cancel buffers queued during a partially failed start. A failed
        // REQBUFS never sets allocated and cannot stop another handle's stream.
        unsafe {
            v4l2::ioctl(self.handle.fd(), v4l2::vidioc::VIDIOC_STREAMOFF,
                        &mut kind as *mut _ as *mut _)?;
        }
        self.active = false;
        self.dequeued = None;
        self.buffers.clear();
        self.request_buffers(0)?;
        self.allocated = false;
        Ok(())
    }
}

impl Drop for CaptureStream {
    fn drop(&mut self) {
        if let Err(error) = self.close() {
            log::error!("V4L2 stream cleanup failed: {}", error);
        }
    }
}
