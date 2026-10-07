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

fn main() {
    let baseline = descriptors();
    unsafe { focus_fixture_init(); focus_fixture_old_shape(); }
    assert_eq!(descriptors(), baseline + 1);
    let mut focus = WindowFocus::default();
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
            assert_eq!(descriptors(), baseline + 2);
        }
    }
    drop(focus);
    assert_eq!(descriptors(), baseline + 1);
    for fault in 1..=7 {
        unsafe { focus_fixture_fault(fault); }
        let result = WindowFocus::default().center();
        assert!(matches!(result, Err(FocusError::InvalidReply)), "setup fault {fault}: {result:?}");
        assert_eq!(descriptors(), baseline + 1);
        unsafe { focus_fixture_balanced(); }
    }
    unsafe { focus_fixture_fault(0); focus_fixture_case(1); }
    for _ in 0..16 {
        std::thread::spawn(move || {
            let mut focus = WindowFocus::default();
            assert_eq!(focus.center().unwrap(), Some((164, 92)));
        }).join().unwrap();
        assert_eq!(descriptors(), baseline + 1);
        unsafe { focus_fixture_balanced(); }
    }
    let mut focus = WindowFocus::default();
    std::env::set_var("DISPLAY", ":97");
    for _ in 0..16 {
        assert!(matches!(focus.center(), Err(FocusError::Connection(error)) if error != 0));
        assert_eq!(descriptors(), baseline + 1);
    }
    std::env::set_var("DISPLAY", ":98");
    assert_eq!(focus.center().unwrap(), Some((164, 92)));
    drop(focus);
    unsafe { focus_fixture_balanced(); focus_fixture_close(); }
    assert_eq!(descriptors(), baseline);
    let libraries: std::collections::BTreeSet<_> = std::fs::read_to_string("/proc/self/maps").unwrap()
        .lines().filter_map(|line| line.split_whitespace().last())
        .filter(|name| name.contains("/libxcb.so.")).map(str::to_owned).collect();
    assert_eq!(libraries.len(), 1);
    println!("X11_FOCUS_LOADED library={}", libraries.iter().next().unwrap());
    println!("X11_FOCUS_NATIVE=pass source=production-module old=unrelated-error-swallowed cases=12 repeats=16 geometry=server-real destroy_after_geometry=16 unrelated_errors=16 setup_faults=7 constructors_refused=16 thread_exits=16 allocations=paired descriptors=retired handler=unchanged scope=focus-component");
}
