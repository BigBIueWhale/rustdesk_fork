//! Complete production focus module, real XCB replies and independent Xlib errors.
#[path = "/work/src/platform/linux/native_context.rs"]
mod native_context;
#[path = "/work/src/platform/linux/window_focus.rs"]
mod window_focus;
use window_focus::{FocusError, WindowFocus};

extern "C" {
    fn focus_fixture_init();
    fn focus_fixture_old_shape();
    fn focus_fixture_case(mode: u32);
    fn focus_fixture_fault(fault: u32);
    fn focus_fixture_errors() -> u32;
    fn focus_fixture_balanced();
    fn focus_fixture_close();
}
fn descriptors() -> usize { std::fs::read_dir("/proc/self/fd").unwrap().count() }
fn threads() -> usize { std::fs::read_dir("/proc/self/task").unwrap().count() }
fn workers() -> Vec<String> {
    std::fs::read_dir("/proc/self/task").unwrap().map(|entry| entry.unwrap())
        .filter(|entry| std::fs::read_to_string(entry.path().join("comm")).unwrap() == "x11-focus-timer\n")
        .map(|entry| entry.file_name().into_string().unwrap()).collect()
}

fn main() {
    let baseline = descriptors();
    let baseline_threads = threads();
    unsafe { focus_fixture_init(); focus_fixture_old_shape(); }
    assert_eq!(descriptors(), baseline + 1);
    let mut focus = WindowFocus::default();
    let mut worker_identity = None;
    for _ in 0..16 {
        for mode in 1..=12 {
            unsafe { focus_fixture_case(mode); }
            let result = focus.center();
            match mode {
                1 | 12 => assert_eq!(result.unwrap(), Some((164, 92))),
                2 => assert_eq!(result.unwrap(), Some((-1, 117))),
                3 | 4 | 7 | 8 | 11 => assert_eq!(result.unwrap(), None),
                5 | 6 | 9 | 10 => assert!(matches!(result, Err(FocusError::InvalidReply))),
                _ => unreachable!(),
            }
            assert_eq!(unsafe { focus_fixture_errors() }, u32::from(mode == 12));
            unsafe { focus_fixture_balanced(); }
            assert_eq!(descriptors(), baseline + 3);
            assert_eq!(threads(), baseline_threads + 1);
            let workers = workers();
            assert_eq!(workers.len(), 1);
            if let Some(previous) = worker_identity.as_ref() {
                assert_eq!(previous, &workers[0]);
            } else {
                worker_identity = Some(workers[0].clone());
            }
        }
    }
    drop(focus);
    assert_eq!(descriptors(), baseline + 1);
    assert_eq!(threads(), baseline_threads);
    std::env::set_var("DISPLAY", ":00098.0001");
    assert_eq!(WindowFocus::default().center().unwrap(), None);
    assert_eq!(descriptors(), baseline + 1);
    assert_eq!(threads(), baseline_threads);
    std::env::set_var("DISPLAY", ":98");
    for fault in 1..=7 {
        unsafe { focus_fixture_fault(fault); }
        let result = WindowFocus::default().center();
        assert!(matches!(result, Err(FocusError::InvalidReply)), "setup fault {fault}: {result:?}");
        assert_eq!(descriptors(), baseline + 1);
        assert_eq!(threads(), baseline_threads);
        unsafe { focus_fixture_balanced(); }
    }
    unsafe { focus_fixture_fault(0); focus_fixture_case(1); }
    for display in ["", ":", ":1.", ":.0", ":1.0.0", ":+1", ":-1", ":1.-1",
                    "localhost:98", "unix/:98", "/tmp/.X11-unix/X98", "tcp/:98",
                    ":2147483648", ":98.2147483648", ":98\n", " :98"] {
        std::env::set_var("DISPLAY", display);
        assert!(matches!(WindowFocus::default().center(), Err(FocusError::InvalidDisplay)));
        assert_eq!(descriptors(), baseline + 1);
        assert_eq!(threads(), baseline_threads);
    }
    std::env::remove_var("DISPLAY");
    assert!(matches!(WindowFocus::default().center(), Err(FocusError::InvalidDisplay)));
    use std::os::unix::ffi::OsStringExt;
    std::env::set_var("DISPLAY", std::ffi::OsString::from_vec(vec![0xff]));
    assert!(matches!(WindowFocus::default().center(), Err(FocusError::InvalidDisplay)));
    assert_eq!(descriptors(), baseline + 1);
    assert_eq!(threads(), baseline_threads);
    std::env::set_var("DISPLAY", ":98");
    for _ in 0..16 {
        std::thread::spawn(move || {
            let mut focus = WindowFocus::default();
            assert_eq!(focus.center().unwrap(), Some((164, 92)));
        }).join().unwrap();
        assert_eq!(descriptors(), baseline + 1);
        assert_eq!(threads(), baseline_threads);
        unsafe { focus_fixture_balanced(); }
    }
    let mut focus = WindowFocus::default();
    std::env::set_var("DISPLAY", ":97");
    for _ in 0..16 {
        assert!(matches!(focus.center(), Err(FocusError::Connection(error)) if error != 0));
        assert_eq!(descriptors(), baseline + 1);
        assert_eq!(threads(), baseline_threads);
    }
    std::env::set_var("DISPLAY", ":00098.0000");
    assert_eq!(focus.center().unwrap(), Some((164, 92)));
    drop(focus);
    unsafe { focus_fixture_balanced(); focus_fixture_close(); }
    assert_eq!(descriptors(), baseline);
    assert_eq!(threads(), baseline_threads);
    let libraries: std::collections::BTreeSet<_> = std::fs::read_to_string("/proc/self/maps").unwrap()
        .lines().filter_map(|line| line.split_whitespace().last())
        .filter(|name| name.contains("/libxcb.so.")).map(str::to_owned).collect();
    assert_eq!(libraries.len(), 1);
    println!("X11_FOCUS_LOADED library={}", libraries.iter().next().unwrap());
    println!("X11_FOCUS_NATIVE=pass source=production-module old=unrelated-error-swallowed cases=12 repeats=16 geometry=server-real destroy_after_geometry=16 unrelated_errors=16 setup_faults=7 selectors_refused=18 canonical=normalized screen=selected constructors_refused=16 thread_exits=16 allocations=paired descriptors=retired deadline_workers=constant-and-joined handler=unchanged scope=focus-component");
}
