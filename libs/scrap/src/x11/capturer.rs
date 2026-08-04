use super::ffi::*;
use super::Display;
use hbb_common::libc;
use std::{io, ptr, slice};

const SHM_OWNER_READ_WRITE: libc::c_int = 0o600;

struct SharedMemory {
    id: libc::c_int,
    buffer: *const u8,
    removal_pending: bool,
}

impl SharedMemory {
    fn create(size: usize) -> io::Result<Self> {
        if size == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "X11 capture shared memory cannot be empty",
            ));
        }

        let id = unsafe {
            libc::shmget(
                libc::IPC_PRIVATE,
                size,
                libc::IPC_CREAT | SHM_OWNER_READ_WRITE,
            )
        };
        if id == -1 {
            return Err(io::Error::last_os_error());
        }

        let mut memory = Self {
            id,
            buffer: ptr::null(),
            removal_pending: false,
        };
        let buffer = unsafe { libc::shmat(id, ptr::null(), libc::SHM_RDONLY) };
        if buffer as isize == -1 {
            return Err(io::Error::last_os_error());
        }
        memory.buffer = buffer.cast();
        Ok(memory)
    }

    fn mark_for_removal(&mut self) -> io::Result<()> {
        if self.removal_pending {
            return Ok(());
        }
        if unsafe { libc::shmctl(self.id, libc::IPC_RMID, ptr::null_mut()) } == -1 {
            return Err(io::Error::last_os_error());
        }
        self.removal_pending = true;
        Ok(())
    }
}

impl Drop for SharedMemory {
    fn drop(&mut self) {
        if !self.buffer.is_null() && unsafe { libc::shmdt(self.buffer.cast()) } == -1 {
            hbb_common::log::warn!(
                "failed to detach X11 capture shared memory: {}",
                io::Error::last_os_error()
            );
        }
        if !self.removal_pending
            && unsafe { libc::shmctl(self.id, libc::IPC_RMID, ptr::null_mut()) } == -1
        {
            hbb_common::log::warn!(
                "failed to remove X11 capture shared memory: {}",
                io::Error::last_os_error()
            );
        }
    }
}

fn check_xcb_request(
    server: *mut xcb_connection_t,
    cookie: xcb_void_cookie_t,
    operation: &str,
) -> io::Result<()> {
    let error = unsafe { xcb_request_check(server, cookie) };
    if !error.is_null() {
        let error_code = unsafe { (*error).error_code };
        unsafe { libc::free(error.cast()) };
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("X server rejected {operation} with error {error_code}"),
        ));
    }
    let connection_error = unsafe { xcb_connection_has_error(server) };
    if connection_error != 0 {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionAborted,
            format!("X connection failed during {operation}: {connection_error}"),
        ));
    }
    Ok(())
}

fn check_get_image_result(
    reply_size: Option<usize>,
    protocol_error: Option<(u8, u8, u16, u32)>,
    connection_error: i32,
    expected_size: usize,
) -> io::Result<()> {
    if let Some((error_code, major_code, minor_code, resource_id)) = protocol_error {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!(
                "X server rejected MIT-SHM GetImage with error {error_code} \
                 (major {major_code}, minor {minor_code}, resource {resource_id})"
            ),
        ));
    }
    if connection_error != 0 {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionAborted,
            format!("X connection failed during MIT-SHM GetImage: {connection_error}"),
        ));
    }
    let reply_size = reply_size.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::Other,
            "X server returned no MIT-SHM GetImage reply",
        )
    })?;
    if reply_size != expected_size {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "X server MIT-SHM GetImage size {reply_size} does not match capture buffer size {expected_size}"
            ),
        ));
    }
    Ok(())
}

pub struct Capturer {
    display: Display,
    memory: SharedMemory,
    xcbid: u32,

    size: usize,
    saved_raw_data: Vec<u8>, // for faster compare and copy
}

impl Capturer {
    pub fn new(display: Display) -> io::Result<Capturer> {
        // Calculate dimensions.

        let pixel_width = display.pixfmt().bytes_per_pixel();
        let rect = display.rect();
        let size = (rect.w as usize)
            .checked_mul(rect.h as usize)
            .and_then(|pixels| pixels.checked_mul(pixel_width))
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "X11 capture dimensions overflow",
                )
            })?;

        // Create a shared memory segment.
        let mut memory = SharedMemory::create(size)?;

        // Attach the segment to XCB.

        let server = display.server().raw();
        let xcbid = unsafe { xcb_generate_id(server) };
        let attach = unsafe {
            xcb_shm_attach_checked(
                server,
                xcbid,
                memory.id as u32,
                0, // False, i.e. not read-only.
            )
        };
        check_xcb_request(server, attach, "MIT-SHM attach")?;
        if let Err(remove_error) = memory.mark_for_removal() {
            let detach = unsafe { xcb_shm_detach_checked(server, xcbid) };
            let detach_result = check_xcb_request(server, detach, "MIT-SHM cleanup detach");
            let detach_detail = detach_result
                .err()
                .map(|error| format!("; cleanup detach also failed: {error}"))
                .unwrap_or_default();
            return Err(io::Error::new(
                remove_error.kind(),
                format!(
                    "failed to make X11 capture shared memory deletion-pending: {remove_error}{detach_detail}"
                ),
            ));
        }

        let c = Capturer {
            display,
            memory,
            xcbid,
            size,
            saved_raw_data: Vec::new(),
        };
        Ok(c)
    }

    pub fn display(&self) -> &Display {
        &self.display
    }

    fn get_image(&self) -> io::Result<()> {
        let rect = self.display.rect();
        let server = self.display.server().raw();
        let mut error = ptr::null_mut();
        let (reply_size, protocol_error, connection_error) = unsafe {
            let request = xcb_shm_get_image(
                server,
                self.display.root(),
                rect.x,
                rect.y,
                rect.w,
                rect.h,
                !0,
                XCB_IMAGE_FORMAT_Z_PIXMAP,
                self.xcbid,
                0,
            );
            let response = xcb_shm_get_image_reply(server, request, &mut error);
            let reply_size = if response.is_null() {
                None
            } else {
                Some((*response).size as usize)
            };
            let protocol_error = if error.is_null() {
                None
            } else {
                Some((
                    (*error).error_code,
                    (*error).major_code,
                    (*error).minor_code,
                    (*error).resource_id,
                ))
            };
            libc::free(response.cast());
            libc::free(error.cast());
            (reply_size, protocol_error, xcb_connection_has_error(server))
        };
        check_get_image_result(reply_size, protocol_error, connection_error, self.size)
    }

    pub fn frame<'b>(&'b mut self) -> std::io::Result<&'b [u8]> {
        self.get_image()?;
        let result = unsafe { slice::from_raw_parts(self.memory.buffer, self.size) };
        crate::would_block_if_equal(&mut self.saved_raw_data, result)?;
        Ok(result)
    }
}

impl Drop for Capturer {
    fn drop(&mut self) {
        let server = self.display.server().raw();
        let detach = unsafe { xcb_shm_detach_checked(server, self.xcbid) };
        if let Err(error) = check_xcb_request(server, detach, "MIT-SHM drop detach") {
            hbb_common::log::warn!("failed to detach X11 capture shared memory from XCB: {error}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::MaybeUninit;

    const LINUX_SHM_DEST: libc::c_ushort = 0o1000;

    fn segment_status(id: libc::c_int) -> io::Result<libc::shmid_ds> {
        let mut status = MaybeUninit::<libc::shmid_ds>::zeroed();
        if unsafe { libc::shmctl(id, libc::IPC_STAT, status.as_mut_ptr()) } == -1 {
            return Err(io::Error::last_os_error());
        }
        Ok(unsafe { status.assume_init() })
    }

    fn assert_segment_absent(id: libc::c_int) {
        let error = match segment_status(id) {
            Ok(_) => panic!("dropped segment must not remain addressable"),
            Err(error) => error,
        };
        assert!(
            matches!(error.raw_os_error(), Some(libc::EINVAL) | Some(libc::EIDRM)),
            "unexpected status error after segment removal: {}",
            error
        );
    }

    #[test]
    fn r_s11fw_shared_memory_is_owner_only_and_drop_removes_it() {
        let memory = SharedMemory::create(4096).expect("create owner-only shared memory");
        let id = memory.id;
        let status = segment_status(id).expect("inspect live shared memory");
        assert_eq!(status.shm_perm.uid, unsafe { libc::geteuid() });
        assert_eq!(status.shm_perm.mode & 0o777, 0o600);
        assert_eq!(status.shm_nattch, 1);

        drop(memory);
        assert_segment_absent(id);
    }

    #[test]
    fn r_s11fw_attached_shared_memory_becomes_deletion_pending() {
        let mut memory = SharedMemory::create(4096).expect("create owner-only shared memory");
        let id = memory.id;
        memory
            .mark_for_removal()
            .expect("mark attached shared memory for removal");

        let status = segment_status(id).expect("inspect deletion-pending shared memory");
        assert_eq!(status.shm_perm.mode & 0o777, 0o600);
        assert_ne!(status.shm_perm.mode & LINUX_SHM_DEST, 0);

        drop(memory);
        assert_segment_absent(id);
    }

    #[test]
    fn r_s11fx_get_image_accepts_only_an_exact_reply() {
        check_get_image_result(Some(4096), None, 0, 4096).expect("accept exact reply size");

        let error = check_get_image_result(Some(4095), None, 0, 4096)
            .expect_err("reject mismatched reply size");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn r_s11fx_get_image_rejects_protocol_connection_and_missing_reply() {
        let protocol = check_get_image_result(Some(4096), Some((8, 130, 4, 17)), 0, 4096)
            .expect_err("reject X protocol error");
        assert_eq!(protocol.kind(), io::ErrorKind::Other);
        assert!(protocol.to_string().contains("error 8"));
        assert!(protocol.to_string().contains("major 130"));
        assert!(protocol.to_string().contains("minor 4"));
        assert!(protocol.to_string().contains("resource 17"));

        let connection =
            check_get_image_result(None, None, 5, 4096).expect_err("reject X connection error");
        assert_eq!(connection.kind(), io::ErrorKind::ConnectionAborted);

        let missing =
            check_get_image_result(None, None, 0, 4096).expect_err("reject missing X reply");
        assert_eq!(missing.kind(), io::ErrorKind::Other);
    }
}
