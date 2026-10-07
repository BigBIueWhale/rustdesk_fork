//! Real established focus connection: paused server, retirement, same-owner retry.
extern crate self as hbb_common;
mod platform {
    #[path = "/work/libs/hbb_common/src/platform/x11_display.rs"]
    pub mod x11_display;
}
#[path = "/work/src/platform/linux/native_context.rs"]
mod native_context;
#[cfg(historical)]
#[path = "/work/scripts/fixtures/x11-window-focus-before-deadline.rs"]
mod window_focus;
#[cfg(not(historical))]
#[path = "/work/src/platform/linux/window_focus.rs"]
mod window_focus;
use std::{io::{Read, Write}, time::{Duration, Instant}};
use window_focus::{FocusError, WindowFocus};

extern "C" {
    fn focus_fixture_init();
    fn focus_fixture_case(mode: u32);
    fn focus_fixture_balanced();
    fn focus_fixture_close();
    fn focus_fixture_backpressure();
}
fn descriptors() -> usize { std::fs::read_dir("/proc/self/fd").unwrap().count() }
fn threads() -> usize { std::fs::read_dir("/proc/self/task").unwrap().count() }
fn token(expected: u8) {
    let mut token = [0];
    std::io::stdin().read_exact(&mut token).unwrap();
    assert_eq!(token[0], expected);
}
fn marker(line: &str) {
    println!("{line}");
    std::io::stdout().flush().unwrap();
}
fn main() {
    let scenario = std::env::args().nth(1).unwrap();
    if scenario == "route" {
        let baseline = descriptors();
        let baseline_threads = threads();
        std::env::set_var("DISPLAY", ":97");
        let mut focus = WindowFocus::default();
        let result = focus.center();
        assert!(matches!(result, Err(FocusError::Connection(error)) if error != 0), "{result:?}");
        drop(focus);
        assert_eq!(descriptors(), baseline);
        assert_eq!(threads(), baseline_threads);
        marker(&format!("X11_FOCUS_ROUTE_CHILD variant={} result=refused descriptors=retired threads=retired",
                        if cfg!(historical) { "historical" } else { "corrected" }));
        return;
    }
    assert!(matches!(scenario.as_str(), "stalled" | "dead" | "fragmented" | "backpressure"));
    let baseline = descriptors();
    let baseline_threads = threads();
    std::env::set_var("DISPLAY", ":98");
    unsafe { focus_fixture_init(); focus_fixture_case(1); }
    if scenario == "fragmented" { std::env::set_var("DISPLAY", ":99"); }
    let mut focus = WindowFocus::default();
    assert_eq!(focus.center().unwrap(), Some((164, 92)));
    unsafe { focus_fixture_close(); }
    assert_eq!(descriptors(), baseline + if cfg!(historical) { 1 } else { 2 });
    assert_eq!(threads(), baseline_threads + usize::from(!cfg!(historical)));
    marker("X11_FOCUS_LIFECYCLE_READY established=true fixture=closed");
    token(match scenario.as_str() { "stalled" => b'T', "dead" => b'D', "backpressure" => b'B', _ => b'F' });
    if scenario == "backpressure" { unsafe { focus_fixture_backpressure(); } }
    marker("X11_FOCUS_LIFECYCLE_ENTERING source=complete-module");
    let began = Instant::now();
    let result = focus.center();
    let elapsed = began.elapsed();
    #[cfg(historical)] {
        assert!(scenario == "fragmented" || scenario == "backpressure");
        assert!(matches!(result, Err(FocusError::Deadline)), "{result:?}");
        assert!(elapsed >= Duration::from_millis(250));
        drop(focus);
        assert_eq!(descriptors(), baseline);
        unsafe { focus_fixture_balanced(); }
        assert_eq!(threads(), baseline_threads);
        marker(&format!("X11_FOCUS_WAIT_NATIVE variant=historical scenario={scenario} elapsed_ms={} result=retired descriptors=retired", elapsed.as_millis()));
    }
    #[cfg(not(historical))] {
        if scenario != "dead" {
            assert!(matches!(result, Err(FocusError::Deadline)), "{result:?}");
            assert!(elapsed >= Duration::from_millis(90) && elapsed < Duration::from_secs(1), "{elapsed:?}");
        } else {
            assert!(matches!(result, Err(FocusError::Connection(error)) if error != 0), "{result:?}");
            assert!(elapsed < Duration::from_secs(1), "{elapsed:?}");
        }
        assert_eq!(descriptors(), baseline);
        assert_eq!(threads(), baseline_threads);
        unsafe { focus_fixture_balanced(); }
        marker(&format!("X11_FOCUS_WAIT_NATIVE variant=corrected scenario={scenario} elapsed_ms={} result=retired descriptors=retired", elapsed.as_millis()));
        token(b'R');
        std::env::set_var("DISPLAY", ":98");
        unsafe { focus_fixture_init(); focus_fixture_case(1); }
        if scenario == "fragmented" { std::env::set_var("DISPLAY", ":99"); }
        assert_eq!(focus.center().unwrap(), Some((164, 92)));
        assert_eq!(descriptors(), baseline + 3);
        assert_eq!(threads(), baseline_threads + 1);
        drop(focus);
        unsafe { focus_fixture_close(); focus_fixture_balanced(); }
        assert_eq!(descriptors(), baseline);
        assert_eq!(threads(), baseline_threads);
        marker(&format!("X11_FOCUS_RECOVERY_NATIVE scenario={scenario} owner=same connection=fresh geometry=server-real center=164,92 allocations=paired descriptors=retired"));
    }
}
