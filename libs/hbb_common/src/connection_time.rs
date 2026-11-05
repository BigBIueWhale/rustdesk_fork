use serde_derive::{Deserialize, Serialize};
#[cfg(not(target_os = "windows"))]
use std::convert::TryFrom;
use std::{io, time::Duration};

/// A suspend-aware timestamp shared by processes in the same OS boot/clock domain.
/// Connection metadata only: never persist it or compare it across machines/boots.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct BootTime(u64);

impl BootTime {
    pub fn now() -> io::Result<Self> {
        #[cfg(target_os = "windows")]
        {
            // System-wide milliseconds, including sleep; no wall-clock adjustment.
            Ok(Self(unsafe { winapi::um::sysinfoapi::GetTickCount64() }))
        }
        #[cfg(any(
            target_os = "linux",
            target_os = "android",
            target_os = "macos",
            target_os = "ios"
        ))]
        {
            #[cfg(any(target_os = "linux", target_os = "android"))]
            let clock = libc::CLOCK_BOOTTIME;
            #[cfg(any(target_os = "macos", target_os = "ios"))]
            let clock = libc::CLOCK_MONOTONIC_RAW;
            let mut value = libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            if unsafe { libc::clock_gettime(clock, &mut value) } != 0 {
                return Err(io::Error::last_os_error());
            }
            let seconds = u64::try_from(value.tv_sec)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "negative boot time"))?;
            if !(0..1_000_000_000).contains(&value.tv_nsec) {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid boot nanoseconds"));
            }
            let millis = seconds
                .checked_mul(1000)
                .and_then(|seconds| seconds.checked_add(value.tv_nsec as u64 / 1_000_000))
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "boot time overflow"))?;
            Ok(Self(millis))
        }
    }

    pub fn elapsed(self) -> io::Result<Duration> {
        Self::now()?
            .0
            .checked_sub(self.0)
            .map(Duration::from_millis)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "connection time is in the future")
            })
    }
}
