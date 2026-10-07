//! Real established focus connection: paused server, retirement, same-owner retry.
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
}
fn descriptors() -> usize { std::fs::read_dir("/proc/self/fd").unwrap().count() }
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
    assert!(scenario == "stalled" || scenario == "dead");
    let baseline = descriptors();
    unsafe { focus_fixture_init(); focus_fixture_case(1); }
    let mut focus = WindowFocus::default();
    assert_eq!(focus.center().unwrap(), Some((164, 92)));
    unsafe { focus_fixture_close(); }
    assert_eq!(descriptors(), baseline + 1);
    marker("X11_FOCUS_LIFECYCLE_READY established=true fixture=closed");
    token(if scenario == "stalled" { b'T' } else { b'D' });
    marker("X11_FOCUS_LIFECYCLE_ENTERING source=complete-module");
    let began = Instant::now();
    let result = focus.center();
    let elapsed = began.elapsed();
    #[cfg(historical)] {
        assert_eq!(scenario, "stalled");
        assert_eq!(result.unwrap(), None);
        assert!(elapsed >= Duration::from_millis(250));
        drop(focus);
        assert_eq!(descriptors(), baseline);
        unsafe { focus_fixture_balanced(); }
        marker(&format!("X11_FOCUS_WAIT_NATIVE variant=historical scenario=stalled elapsed_ms={} result=late-reply descriptors=retired", elapsed.as_millis()));
    }
    #[cfg(not(historical))] {
        if scenario == "stalled" {
            assert!(matches!(result, Err(FocusError::Deadline)), "{result:?}");
            assert!(elapsed >= Duration::from_millis(90) && elapsed < Duration::from_secs(1), "{elapsed:?}");
        } else {
            assert!(matches!(result, Err(FocusError::Connection(error)) if error != 0), "{result:?}");
            assert!(elapsed < Duration::from_secs(1), "{elapsed:?}");
        }
        assert_eq!(descriptors(), baseline);
        unsafe { focus_fixture_balanced(); }
        marker(&format!("X11_FOCUS_WAIT_NATIVE variant=corrected scenario={scenario} elapsed_ms={} result=retired descriptors=retired", elapsed.as_millis()));
        token(b'R');
        unsafe { focus_fixture_init(); focus_fixture_case(1); }
        assert_eq!(focus.center().unwrap(), Some((164, 92)));
        assert_eq!(descriptors(), baseline + 2);
        drop(focus);
        unsafe { focus_fixture_close(); focus_fixture_balanced(); }
        assert_eq!(descriptors(), baseline);
        marker(&format!("X11_FOCUS_RECOVERY_NATIVE scenario={scenario} owner=same connection=fresh geometry=server-real center=164,92 allocations=paired descriptors=retired"));
    }
}
