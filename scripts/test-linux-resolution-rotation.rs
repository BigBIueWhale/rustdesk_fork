//! Production resolution functions, with controlled query and command boundaries.
use std::{cell::RefCell, process::{Command, Output}};

use super::xrandr_query;
use anyhow::{bail, Result as ResultType};
use regex::{Captures, Regex};

#[derive(Default, Debug, PartialEq)]
pub(crate) struct Resolution {
    pub width: i32,
    pub height: i32,
}

thread_local! {
    static QUERY: RefCell<String> = RefCell::new(String::new());
    static COMMANDS: RefCell<Vec<Vec<String>>> = RefCell::new(Vec::new());
}

fn xrandr_query() -> ResultType<String> {
    QUERY.with(|query| {
        let query = query.borrow();
        if query.is_empty() { bail!("query unavailable"); }
        Ok(query.clone())
    })
}

fn xrandr_path() -> Option<&'static str> { Some("/fixture/xrandr") }

fn configure_command_close_nonstdio_on_exec(_: &mut Command) -> ResultType<()> { Ok(()) }

mod xrandr_command {
    use super::*;
    use std::os::unix::process::ExitStatusExt;

    pub(super) fn run(command: Command) -> ResultType<Output> {
        assert_eq!(command.get_program(), "/fixture/xrandr");
        let arguments = command.get_args().map(|a| a.to_str().unwrap().to_owned()).collect();
        COMMANDS.with(|commands| commands.borrow_mut().push(arguments));
        Ok(Output { status: std::process::ExitStatus::from_raw(0), stdout: vec![], stderr: vec![] })
    }
}

include!(env!("RUSTDESK_XRANDR_FUNCTIONS"));

#[path = "../src/server/display_service/resolution_restore.rs"]
mod resolution_restore;

fn query(rotation: &str, width: i32, height: i32) {
    QUERY.with(|query| *query.borrow_mut() = format!(
        "eDP-1 connected primary 1600x900+0+0 (normal left inverted right x axis y axis)\n \
         1600x900 60.00*+\n\
         DP-1 connected {width}x{height}+1600+0 {rotation} (normal left inverted right x axis y axis)\n \
         1920x1080 60.00\n 1280x720 60.00\n"
    ));
}

fn commands() -> Vec<Vec<String>> { COMMANDS.with(|commands| commands.borrow().clone()) }

fn round_trip(rotation: &str, swapped: bool) {
    let original = if swapped { (1080, 1920) } else { (1920, 1080) };
    let requested = if swapped { (720, 1280) } else { (1280, 720) };
    query(rotation, original.0, original.1);
    COMMANDS.with(|commands| commands.borrow_mut().clear());
    assert_eq!(current_resolution("DP-1").unwrap(), Resolution { width: original.0, height: original.1 });
    assert_eq!(resolutions("DP-1"), vec![
        Resolution { width: original.0, height: original.1 },
        Resolution { width: requested.0, height: requested.1 },
    ]);
    let restorations = resolution_restore::ResolutionRestorations::default();
    restorations.record("DP-1", original);
    change_resolution("DP-1", requested.0 as usize, requested.1 as usize).unwrap();
    assert_eq!(commands(), vec![vec!["--output", "DP-1", "--mode", "1280x720"]]);
    query(rotation, requested.0, requested.1);
    restorations.restore(|name, width, height| change_resolution(name, width, height).map_err(|e| e.to_string())).unwrap();
    assert_eq!(commands(), vec![
        vec!["--output", "DP-1", "--mode", "1280x720"],
        vec!["--output", "DP-1", "--mode", "1920x1080"],
    ]);
    assert_eq!(restorations.original("DP-1"), None);
}

#[test]
fn left_rotation_offers_applies_and_restores_visible_sizes() { round_trip("left", true); }

#[test]
fn right_rotation_offers_applies_and_restores_visible_sizes() { round_trip("right", true); }

#[test]
fn normal_rotation_preserves_mode_sizes() { round_trip("", false); }

#[test]
fn inverted_rotation_preserves_mode_sizes() { round_trip("inverted", false); }

#[test]
fn reflection_does_not_change_axis_conversion() {
    for (rotation, swapped) in [("normal x axis", false), ("inverted x axis y axis", false), ("left x axis", true), ("right x axis y axis", true)] {
        round_trip(rotation, swapped);
    }
}

#[test]
fn current_visible_size_is_a_noop() {
    query("left", 1080, 1920);
    change_resolution("DP-1", 1080, 1920).unwrap();
    assert!(commands().is_empty());
}

#[test]
fn unavailable_output_refuses_mutation() {
    query("left", 1080, 1920);
    assert!(change_resolution_directly("missing", 720, 1280).is_err());
    QUERY.with(|query| query.borrow_mut().clear());
    assert!(change_resolution_directly("DP-1", 720, 1280).is_err());
    assert!(commands().is_empty());
}
