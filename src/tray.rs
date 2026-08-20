use crate::client::translate;
#[cfg(any(windows, test))]
use hbb_common::tokio;
use hbb_common::{allow_err, log};
use std::sync::{Arc, Mutex};
#[cfg(windows)]
use std::time::Duration;

#[cfg(any(windows, test))]
#[derive(Debug, Eq, PartialEq)]
enum TraySessionCountUpdate {
    Unchanged,
    Count(usize),
    Closed,
}

#[cfg(any(windows, test))]
fn tray_session_count_channel() -> (
    tokio::sync::watch::Sender<usize>,
    tokio::sync::watch::Receiver<usize>,
) {
    tokio::sync::watch::channel(0)
}

#[cfg(any(windows, test))]
fn publish_tray_session_count(sender: &tokio::sync::watch::Sender<usize>, count: usize) -> bool {
    let changed = {
        let current = sender.borrow();
        *current != count
    };
    if changed && sender.send(count).is_err() {
        return false;
    }
    !sender.is_closed()
}

#[cfg(any(windows, test))]
fn take_tray_session_count_update(
    receiver: &mut tokio::sync::watch::Receiver<usize>,
) -> TraySessionCountUpdate {
    match receiver.has_changed() {
        Ok(true) => TraySessionCountUpdate::Count(*receiver.borrow_and_update()),
        Ok(false) => TraySessionCountUpdate::Unchanged,
        Err(_) => TraySessionCountUpdate::Closed,
    }
}

pub fn start_tray() {
    if crate::ui_interface::get_builtin_option(hbb_common::config::keys::OPTION_HIDE_TRAY) == "Y" {
        #[cfg(not(target_os = "macos"))]
        {
            return;
        }
    }

    #[cfg(target_os = "linux")]
    crate::server::check_zombie();

    allow_err!(make_tray());
}

fn make_tray() -> hbb_common::ResultType<()> {
    // https://github.com/tauri-apps/tray-icon/blob/dev/examples/tao.rs
    use hbb_common::anyhow::Context;
    use tao::event_loop::{ControlFlow, EventLoopBuilder};
    use tray_icon::{
        menu::{Menu, MenuEvent, MenuItem},
        TrayIcon, TrayIconBuilder, TrayIconEvent as TrayEvent,
    };
    let icon;
    #[cfg(target_os = "macos")]
    {
        icon = include_bytes!("../res/mac-tray-dark-x2.png"); // use as template, so color is not important
    }
    #[cfg(not(target_os = "macos"))]
    {
        icon = include_bytes!("../res/tray-icon.ico");
    }

    let (icon_rgba, icon_width, icon_height) = {
        let image = load_icon_from_asset()
            .unwrap_or(image::load_from_memory(icon).context("Failed to open icon path")?)
            .into_rgba8();
        let (width, height) = image.dimensions();
        let rgba = image.into_raw();
        (rgba, width, height)
    };
    let icon = tray_icon::Icon::from_rgba(icon_rgba, icon_width, icon_height)
        .context("Failed to open icon")?;

    let mut event_loop = EventLoopBuilder::new().build();

    let tray_menu = Menu::new();
    // T1 / §19 / R-X9 / R-X10: the destructive "Stop service" tray item is REMOVED on all three
    // desktops. It ran `uninstall_service` — Windows `sc stop`+`sc delete` (a self-DoS that DELETED
    // the installed service the GUI cannot reinstall, the cavity-1 permanent wedge), Linux `systemctl
    // disable`+`stop`, macOS an admin uninstall — so a single tray click tore down the OS-supervised
    // controlled-host service. A tray action MUST NOT stop or uninstall that service. (The unset
    // OPTION_HIDE_STOP_SERVICE gate that used to hide it is now dead in the TRAY, but the key lives
    // on — it still gates the mobile/desktop-settings Service card — so it is NOT removed.)
    let open_i = MenuItem::new(translate("Open".to_owned()), true, None);
    // The replacement NON-destructive "Exit" is offered ONLY where the tray is its OWN process, so
    // closing it cannot touch the listener:
    //   * Linux/Windows — the tray is a SEPARATE `--tray` process (core_main.rs), so tao's
    //     ControlFlow::Exit → process::exit closes ONLY the tray; the installed service (SCM/systemd)
    //     keeps serving :21118, and the tray re-appears on the next service/session (re)launch.
    //   * macOS — the tray runs IN the `--server` process (core_main.rs: start_server(true) on a
    //     thread + start_tray() on the main thread), and tao's macOS run() exits via
    //     process::exit(0). That code-0 exit is read as "successful" by the `--server` LaunchAgent
    //     (KeepAlive{SuccessfulExit=false}; the fork's exit(-1) is what triggers a restart,
    //     ipc.rs:766), so an "Exit" would drop the listener with NO launchd recovery — the R-X9 macOS
    //     twin of the wedge. So macOS offers NO destructive Exit; the app/server is managed at the OS
    //     level (Cmd-Q / launchd), untouched here.
    #[cfg(not(target_os = "macos"))]
    let quit_i = MenuItem::new(translate("Exit".to_owned()), true, None);
    #[cfg(not(target_os = "macos"))]
    tray_menu.append_items(&[&open_i, &quit_i]).ok();
    #[cfg(target_os = "macos")]
    tray_menu.append_items(&[&open_i]).ok();
    let tooltip = |count: usize| {
        if count == 0 {
            format!(
                "{} {}",
                crate::get_app_name(),
                translate("Service is running".to_owned()),
            )
        } else {
            format!(
                "{} - {}\n{}",
                crate::get_app_name(),
                translate("Ready".to_owned()),
                translate("{".to_string() + &format!("{count}") + "} sessions"),
            )
        }
    };
    let mut _tray_icon: Arc<Mutex<Option<TrayIcon>>> = Default::default();

    let menu_channel = MenuEvent::receiver();
    let tray_channel = TrayEvent::receiver();
    #[cfg(windows)]
    let (ipc_sender, ipc_receiver) = tray_session_count_channel();
    #[cfg(windows)]
    let mut ipc_receiver = Some(ipc_receiver);

    let open_func = move || {
        if cfg!(not(feature = "flutter")) {
            crate::run_me::<&str>(vec![]).ok();
            return;
        }
        #[cfg(target_os = "macos")]
        crate::platform::macos::handle_application_should_open_untitled_file();
        #[cfg(target_os = "windows")]
        {
            // Do not use "start uni link" way, it may not work on some Windows, and pop out error
            // dialog, I found on one user's desktop, but no idea why, Windows is shit.
            // Use `run_me` instead.
            // `allow_multiple_instances` in `flutter/windows/runner/main.cpp` allows only one instance without args.
            crate::run_me::<&str>(vec![]).ok();
        }
        #[cfg(target_os = "linux")]
        {
            // R-X6: the D-Bus IPC (org.rustdesk.rustdesk NewConnection) is excised — open a fresh
            // instance directly rather than forwarding to a running one over the session bus.
            if let Ok(task) = crate::run_me::<&str>(vec![]) {
                crate::server::CHILD_PROCESS.lock().unwrap().push(task);
            }
        }
    };

    #[cfg(windows)]
    std::thread::spawn(move || {
        start_query_session_count(ipc_sender);
    });
    #[cfg(windows)]
    let mut last_click = std::time::Instant::now();
    #[cfg(target_os = "macos")]
    {
        use tao::platform::macos::EventLoopExtMacOS;
        event_loop.set_activation_policy(tao::platform::macos::ActivationPolicy::Accessory);
    }
    event_loop.run(move |event, _, control_flow| {
        *control_flow = ControlFlow::WaitUntil(
            std::time::Instant::now() + std::time::Duration::from_millis(100),
        );

        if let tao::event::Event::NewEvents(tao::event::StartCause::Init) = event {
            // for fixing https://github.com/rustdesk/rustdesk/discussions/10210#discussioncomment-14600745
            // so we start tray, but not to show it
            if crate::ui_interface::get_builtin_option(hbb_common::config::keys::OPTION_HIDE_TRAY)
                == "Y"
            {
                return;
            }
            // We create the icon once the event loop is actually running
            // to prevent issues like https://github.com/tauri-apps/tray-icon/issues/90
            let tray = TrayIconBuilder::new()
                .with_menu(Box::new(tray_menu.clone()))
                .with_tooltip(tooltip(0))
                .with_icon(icon.clone())
                .with_icon_as_template(true) // mac only
                .build();
            match tray {
                Ok(tray) => _tray_icon = Arc::new(Mutex::new(Some(tray))),
                Err(err) => {
                    log::error!("Failed to create tray icon: {}", err);
                }
            };

            // We have to request a redraw here to have the icon actually show up.
            // Tao only exposes a redraw method on the Window so we use core-foundation directly.
            #[cfg(target_os = "macos")]
            unsafe {
                use core_foundation::runloop::{CFRunLoopGetMain, CFRunLoopWakeUp};

                let rl = CFRunLoopGetMain();
                CFRunLoopWakeUp(rl);
            }
        }

        if let Ok(event) = menu_channel.try_recv() {
            if event.id == open_i.id() {
                open_func();
            }
            // T1 / R-X9 / R-X10: NON-destructive quit — close ONLY the separate `--tray` process
            // (Linux/Windows). tao's ControlFlow::Exit → process::exit ends just the tray; the
            // installed service keeps running and accepting on :21118, and the tray re-appears on the
            // next service/session (re)launch. NOT built on macOS (see the menu comment): there the
            // tray shares the `--server` process, so a code-0 process::exit would self-DoS the
            // listener with no launchd recovery.
            #[cfg(not(target_os = "macos"))]
            if event.id == quit_i.id() {
                *control_flow = ControlFlow::Exit;
            }
        }

        if let Ok(_event) = tray_channel.try_recv() {
            #[cfg(target_os = "windows")]
            match _event {
                TrayEvent::Click {
                    button,
                    button_state,
                    ..
                } => {
                    if button == tray_icon::MouseButton::Left
                        && button_state == tray_icon::MouseButtonState::Up
                    {
                        if last_click.elapsed() < std::time::Duration::from_secs(1) {
                            return;
                        }
                        open_func();
                        last_click = std::time::Instant::now();
                    }
                }
                _ => {}
            }
        }

        #[cfg(windows)]
        {
            let update = ipc_receiver.as_mut().map(take_tray_session_count_update);
            match update {
                Some(TraySessionCountUpdate::Count(count)) => {
                    _tray_icon
                        .lock()
                        .unwrap()
                        .as_mut()
                        .map(|t| t.set_tooltip(Some(tooltip(count))));
                }
                Some(TraySessionCountUpdate::Closed) => {
                    log::debug!("Windows tray session-count publisher stopped");
                    ipc_receiver = None;
                }
                Some(TraySessionCountUpdate::Unchanged) | None => {}
            }
        }
    });
}

#[cfg(windows)]
#[tokio::main(flavor = "current_thread")]
async fn start_query_session_count(sender: tokio::sync::watch::Sender<usize>) {
    loop {
        if sender.is_closed() {
            return;
        }
        if let Ok(count) = crate::ipc::get_controlled_session_count(1000).await {
            if !publish_tray_session_count(&sender, count) {
                return;
            }
        }
        hbb_common::sleep(1.).await;
    }
}

fn load_icon_from_asset() -> Option<image::DynamicImage> {
    let Some(path) = std::env::current_exe().map_or(None, |x| x.parent().map(|x| x.to_path_buf()))
    else {
        return None;
    };
    #[cfg(target_os = "macos")]
    let path = path.join("../Frameworks/App.framework/Resources/flutter_assets/assets/icon.png");
    #[cfg(windows)]
    let path = path.join(r"data\flutter_assets\assets\icon.png");
    #[cfg(target_os = "linux")]
    let path = path.join(r"data/flutter_assets/assets/icon.png");
    if path.exists() {
        if let Ok(image) = image::open(path) {
            return Some(image);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tray_session_count_publication_is_latest_state_only() {
        let (sender, mut receiver) = tray_session_count_channel();
        assert_eq!(
            take_tray_session_count_update(&mut receiver),
            TraySessionCountUpdate::Unchanged
        );

        assert!(publish_tray_session_count(&sender, 1));
        assert!(publish_tray_session_count(&sender, 2));
        assert!(publish_tray_session_count(&sender, 3));

        assert_eq!(
            take_tray_session_count_update(&mut receiver),
            TraySessionCountUpdate::Count(3)
        );
        assert_eq!(
            take_tray_session_count_update(&mut receiver),
            TraySessionCountUpdate::Unchanged
        );
    }

    #[test]
    fn unchanged_tray_session_count_does_not_wake_the_ui() {
        let (sender, mut receiver) = tray_session_count_channel();
        assert!(publish_tray_session_count(&sender, 0));
        assert_eq!(
            take_tray_session_count_update(&mut receiver),
            TraySessionCountUpdate::Unchanged
        );
    }

    #[test]
    fn tray_session_count_receiver_retirement_closes_publication() {
        let (sender, receiver) = tray_session_count_channel();
        drop(receiver);
        assert!(!publish_tray_session_count(&sender, 1));
    }

    #[test]
    fn tray_session_count_publisher_retirement_is_observable() {
        let (sender, mut receiver) = tray_session_count_channel();
        drop(sender);
        assert_eq!(
            take_tray_session_count_update(&mut receiver),
            TraySessionCountUpdate::Closed
        );
    }
}
