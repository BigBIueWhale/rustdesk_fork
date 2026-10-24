#[cfg(target_os = "linux")]
fn self_enforce_resource_limits() {
    use hbb_common::libc;
    // R-T1(a): bound THIS process's open-fd ceiling so an accept()-flood is service-fatal, not
    // host-fatal, under ANY launcher (systemd / a per-user supervisor / a bare container — R-D8).
    // We lower only the SOFT limit and PRESERVE the inherited HARD ceiling: the --server is held
    // at SOFT_NOFILE (the kernel returns EMFILE past it — R-T12 backs off), while a child the
    // --server spawns — notably the owner's full-access terminal (R-F1) — can raise its own soft
    // limit back via `ulimit -n`. A resource bound is launcher-independent AND owner-safe; a
    // PRIVILEGE/syscall sandbox is neither, so the binary never self-applies one (R-D3a — that is
    // the launcher's job, since a self-applied prctl latch would confine the owner's shell too).
    const SOFT_NOFILE: libc::rlim_t = 8192;
    let mut lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: valid resource id + writable rlimit pointer.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) } != 0 {
        log::warn!(
            "R-T1(a): getrlimit(RLIMIT_NOFILE) failed, fd ceiling not self-enforced: {}",
            std::io::Error::last_os_error()
        );
        return;
    }
    lim.rlim_cur = SOFT_NOFILE.min(lim.rlim_max);
    // SAFETY: same; lowers the soft limit only, never raises the inherited hard ceiling.
    let rc = unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &lim) };
    if rc == 0 {
        log::info!(
            "R-T1(a): self-enforced RLIMIT_NOFILE soft={} (hard ceiling {} preserved for child shells)",
            lim.rlim_cur, lim.rlim_max
        );
    } else {
        log::warn!(
            "R-T1(a): setrlimit(RLIMIT_NOFILE) failed: {}",
            std::io::Error::last_os_error()
        );
    }
}
