use super::{CodecFormat, RecorderContext2};
use hbb_common::{bail, ResultType};
use std::{
    cell::UnsafeCell,
    io::{self, Seek, SeekFrom, Write},
    os::raw::c_void,
    ptr,
};
use webm_sys::mux as ffi;

// The pinned C++ adapter takes a signed get-position callback; its Rust
// new_writer declaration incorrectly uses u64. Match the actual C ABI here.
extern "C" {
    #[link_name = "mux_new_writer"]
    fn new_writer(
        write: Option<ffi::WriterWriteFn>,
        position: Option<extern "C" fn(*mut c_void) -> i64>,
        seek: Option<ffi::WriterSetPosFn>,
        notify: Option<ffi::WriterElementStartNotifyFn>,
        data: *mut c_void,
    ) -> ffi::WriterMutPtr;
}

struct WriterState<T> {
    dest: T,
    error: Option<io::Error>,
}

pub(super) struct WebmMux<T: Write + Seek> {
    io: Box<UnsafeCell<WriterState<T>>>,
    writer: ffi::WriterMutPtr,
    segment: ffi::SegmentMutPtr,
    track: ffi::TrackMutPtr,
    failed: bool,
}

// The callback data is one stable boxed UnsafeCell. Native calls are synchronous
// and exclusively entered by this owner's mutable methods. No Rust borrow of
// WriterState remains live across a native call.
extern "C" fn write<T: Write + Seek>(data: *mut c_void, buf: *const c_void, len: usize) -> bool {
    let state = unsafe { &mut *data.cast::<WriterState<T>>() };
    if state.error.is_some() {
        return false;
    }
    if len > isize::MAX as usize || (len != 0 && buf.is_null()) {
        state.error = Some(io::Error::from(io::ErrorKind::InvalidInput));
        return false;
    }
    if len == 0 {
        return true;
    }
    // The native adapter supplies a buffer valid for this synchronous call.
    let bytes = unsafe { std::slice::from_raw_parts(buf.cast::<u8>(), len) };
    match state.dest.write_all(bytes) {
        Ok(()) => true,
        Err(error) => {
            state.error = Some(error);
            false
        }
    }
}

extern "C" fn position<T: Write + Seek>(data: *mut c_void) -> i64 {
    let state = unsafe { &mut *data.cast::<WriterState<T>>() };
    if state.error.is_some() {
        return -1;
    }
    match state.dest.stream_position() {
        Ok(pos) if pos <= i64::MAX as u64 => pos as i64,
        result => {
            state.error = Some(match result {
                Err(error) => error,
                Ok(_) => io::Error::from(io::ErrorKind::InvalidData),
            });
            -1
        }
    }
}

extern "C" fn seek<T: Write + Seek>(data: *mut c_void, pos: u64) -> bool {
    let state = unsafe { &mut *data.cast::<WriterState<T>>() };
    if state.error.is_some() {
        return false;
    }
    if pos > i64::MAX as u64 {
        state.error = Some(io::Error::from(io::ErrorKind::InvalidInput));
        return false;
    }
    match state.dest.seek(SeekFrom::Start(pos)) {
        Ok(actual) if actual == pos => true,
        result => {
            state.error = Some(match result {
                Err(error) => error,
                Ok(_) => io::Error::from(io::ErrorKind::InvalidData),
            });
            false
        }
    }
}

impl<T: Write + Seek> WebmMux<T> {
    pub(super) fn new(dest: T, ctx: &RecorderContext2) -> ResultType<Self> {
        if ctx.width == 0 || ctx.height == 0
            || ctx.width > i32::MAX as usize || ctx.height > i32::MAX as usize
        {
            bail!("Invalid WebM dimensions");
        }
        let codec = match ctx.format {
            CodecFormat::VP8 => ffi::VP8_CODEC_ID,
            CodecFormat::VP9 => ffi::VP9_CODEC_ID,
            _ => bail!("Unsupported WebM codec"),
        };
        let mut mux = Self {
            io: Box::new(UnsafeCell::new(WriterState { dest, error: None })),
            writer: ptr::null_mut(),
            segment: ptr::null_mut(),
            track: ptr::null_mut(),
            failed: false,
        };
        mux.writer = unsafe {
            new_writer(Some(write::<T>), Some(position::<T>), Some(seek::<T>), None, mux.io.get().cast())
        };
        if mux.writer.is_null() {
            bail!("Failed to create WebM writer");
        }
        mux.segment = unsafe { ffi::new_segment() };
        if mux.segment.is_null() || !unsafe { ffi::initialize_segment(mux.segment, mux.writer) } {
            bail!("Failed to initialize WebM segment");
        }
        let mut number = 0;
        let number_out: *mut u64 = &mut number;
        let video = unsafe {
            ffi::segment_add_video_track(
                mux.segment, ctx.width as i32, ctx.height as i32, 0, codec, number_out,
            )
        };
        if video.is_null() || number == 0 {
            bail!("Failed to create WebM video track");
        }
        mux.track = unsafe { ffi::video_track_base_mut(video) };
        if mux.track.is_null() {
            bail!("Failed to obtain WebM video track");
        }
        Ok(mux)
    }

    fn io_failed(&self) -> bool {
        unsafe { (&*self.io.get()).error.is_some() }
    }

    pub(super) fn add_frame(&mut self, data: &[u8], pts: u64, key: bool) -> bool {
        if self.failed || self.io_failed() {
            return false;
        }
        let accepted = unsafe {
            ffi::segment_add_frame(self.segment, self.track, data.as_ptr(), data.len(), pts, key)
        };
        self.failed = !accepted || self.io_failed();
        !self.failed
    }

    pub(super) fn finalize(self) -> bool {
        if self.failed || self.io_failed() {
            return false;
        }
        if !unsafe { ffi::finalize_segment(self.segment, 0) } || self.io_failed() {
            return false;
        }
        let state = unsafe { &mut *self.io.get() };
        match state.dest.flush() {
            Ok(()) => true,
            Err(error) => {
                state.error = Some(error);
                false
            }
        }
    }
}

impl<T: Write + Seek> Drop for WebmMux<T> {
    fn drop(&mut self) {
        // Segment owns its track. Retire both native objects before the boxed
        // callback state and destination are dropped, including constructor errors.
        unsafe {
            if !self.segment.is_null() {
                ffi::delete_segment(self.segment);
            }
            if !self.writer.is_null() {
                ffi::delete_writer(self.writer);
            }
        }
    }
}
