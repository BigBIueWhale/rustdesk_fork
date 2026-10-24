use hbb_common::libc;
use std::io;

/// Apply the controlled server's fd ceiling without weakening an inherited bound.
/// The hard limit remains available to an authorized child raising its own soft limit.
pub(super) fn enforce_fd_ceiling() -> io::Result<libc::rlimit> {
    const SOFT_NOFILE: libc::rlim_t = 8192;
    let mut limits = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: fixed resource identifier and a valid writable rlimit.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limits) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if limits.rlim_cur > SOFT_NOFILE {
        limits.rlim_cur = SOFT_NOFILE;
        // SAFETY: the soft limit only decreases and the inherited hard limit is unchanged.
        if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limits) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(limits)
}
