use dashmap::DashMap;
use lazy_static::lazy_static;
use std::time::{Duration, SystemTime};

mod filetype;
pub use filetype::{FileDescription, FileType};
/// use FUSE for file pasting on these platforms
#[cfg(target_os = "linux")]
pub mod fuse;
#[cfg(target_os = "macos")]
pub mod macos;

pub mod local_file;
pub mod serv_files;

/// has valid file attributes
pub const FLAGS_FD_ATTRIBUTES: u32 = 0x04;
/// has valid file size
pub const FLAGS_FD_SIZE: u32 = 0x40;
/// has valid last write time
pub const FLAGS_FD_LAST_WRITE: u32 = 0x20;
/// show progress
pub const FLAGS_FD_PROGRESSUI: u32 = 0x4000;
/// transferred from unix, contains file mode
/// P.S. this flag is not used in windows
pub const FLAGS_FD_UNIX_MODE: u32 = 0x08;

// not actual format id, just a placeholder
pub const FILEDESCRIPTOR_FORMAT_ID: i32 = 49334;
pub const FILEDESCRIPTORW_FORMAT_NAME: &str = "FileGroupDescriptorW";
// not actual format id, just a placeholder
pub const FILECONTENTS_FORMAT_ID: i32 = 49267;
pub const FILECONTENTS_FORMAT_NAME: &str = "FileContents";

/// block size for fuse, align to our asynchronic request size over FileContentsRequest.
pub(crate) const BLOCK_SIZE: u32 = 4 * 1024 * 1024;

const FILETIME_TICKS_PER_SECOND: u64 = 10_000_000;
// FILETIME counts 100 ns intervals from 1601-01-01 00:00:00 UTC.
const FILETIME_EPOCH_OFFSET: Duration = Duration::from_secs(11_644_473_600);

fn filetime_to_system_time(ticks: u64) -> Option<SystemTime> {
    let epoch = SystemTime::UNIX_EPOCH.checked_sub(FILETIME_EPOCH_OFFSET)?;
    let elapsed = Duration::new(
        ticks / FILETIME_TICKS_PER_SECOND,
        ((ticks % FILETIME_TICKS_PER_SECOND) * 100) as u32,
    );
    epoch.checked_add(elapsed)
}

fn system_time_to_filetime(time: SystemTime) -> Option<u64> {
    let epoch = SystemTime::UNIX_EPOCH.checked_sub(FILETIME_EPOCH_OFFSET)?;
    let elapsed = time.duration_since(epoch).ok()?;
    elapsed.as_secs().checked_mul(FILETIME_TICKS_PER_SECOND)?
        .checked_add(u64::from(elapsed.subsec_nanos() / 100))
}

lazy_static! {
    static ref REMOTE_FORMAT_MAP: DashMap<i32, String> = DashMap::from_iter(
        [
            (
                FILEDESCRIPTOR_FORMAT_ID,
                FILEDESCRIPTORW_FORMAT_NAME.to_string()
            ),
            (FILECONTENTS_FORMAT_ID, FILECONTENTS_FORMAT_NAME.to_string())
        ]
        .iter()
        .cloned()
    );
}

#[inline]
pub fn get_local_format(remote_id: i32) -> Option<String> {
    REMOTE_FORMAT_MAP.get(&remote_id).map(|s| s.clone())
}
