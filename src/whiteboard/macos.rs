use super::{
    server::{
        install_whiteboard_event_proxy, Ripple, WhiteboardPresentationState,
        RIPPLE_FRAME_INTERVAL,
    },
    Cursor, CustomEvent,
};
use core_graphics::context::CGContextRef;
use foreign_types::ForeignTypeRef;
use hbb_common::{bail, log, ResultType};
use objc::{class, msg_send, runtime::Object, sel, sel_impl};
use piet::{
    kurbo::{BezPath, Point},
    FontFamily, RenderContext, Text, TextLayout, TextLayoutBuilder,
};
use piet_coregraphics::{CoreGraphicsContext, CoreGraphicsTextLayout};
use std::{collections::HashMap, sync::Arc, time::Instant};
use tao::{
    dpi::{LogicalSize, PhysicalPosition},
    event::{Event, StartCause, WindowEvent},
    event_loop::{ControlFlow, EventLoop, EventLoopBuilder},
    platform::macos::MonitorHandleExtMacOS,
    rwh_06::{HasWindowHandle, RawWindowHandle},
    window::{Window, WindowBuilder, WindowId},
};

const MAXIMUM_WINDOW_LEVEL: i64 = 2147483647;
const CURSOR_TEXT_FONT_SIZE: f64 = 14.0;
const CURSOR_TEXT_OFFSET: f64 = 20.0;

struct WindowState {
    window: Arc<Window>,
    logical_size: LogicalSize<f64>,
    outer_position: PhysicalPosition<i32>,
    // A simple workaround to the (logical) cursor position.
    display_origin: (f64, f64),
}

struct CursorInfo {
    window_id: WindowId,
    cursor: Cursor,
}

struct CursorTextLayout {
    text: String,
    argb: u32,
    layout: CoreGraphicsTextLayout,
}

fn set_window_properties(window: &Arc<Window>) -> ResultType<()> {
    let handle = window.window_handle()?;
    if let RawWindowHandle::AppKit(appkit_handle) = handle.as_raw() {
        unsafe {
            let ns_view = appkit_handle.ns_view.as_ptr() as *mut Object;
            if ns_view.is_null() {
                bail!("Ns view of the window handle is null.");
            }
            let ns_window: *mut Object = msg_send![ns_view, window];
            if ns_window.is_null() {
                bail!("Ns window of the ns view is null.");
            }
            let _: () = msg_send![ns_window, setOpaque: false];
            let _: () = msg_send![ns_window, setLevel: MAXIMUM_WINDOW_LEVEL];
            // NSWindowCollectionBehaviorCanJoinAllSpaces | NSWindowCollectionBehaviorIgnoresCycle
            let _: () = msg_send![ns_window, setCollectionBehavior: 5];
            let current_style_mask: u64 = msg_send![ns_window, styleMask];
            // NSWindowStyleMaskNonactivatingPanel
            let new_style_mask = current_style_mask | (1 << 7);
            let _: () = msg_send![ns_window, setStyleMask: new_style_mask];
            let _: () = msg_send![ns_window, setIgnoresMouseEvents: true];
        }
    }
    Ok(())
}

fn create_windows(event_loop: &EventLoop<(i32, CustomEvent)>) -> ResultType<Vec<WindowState>> {
    let mut windows = Vec::new();
    let map_display_origins: HashMap<_, _> = crate::server::display_service::try_get_displays()?
        .into_iter()
        .map(|display| (display.name(), display.origin()))
        .collect();
    // We can't use `crate::server::display_service::try_get_displays()` here.
    // Because the `display` returned by `crate::server::display_service::try_get_displays()`:
    // 1. `display.origin()` is the logic position.
    // 2. `display.width()` and `display.height()` are the physical size.
    for monitor in event_loop.available_monitors() {
        let Some(origin) = map_display_origins.get(&monitor.native_id().to_string()) else {
            // unreachable!
            bail!(
                "Failed to find display origin for monitor: {}",
                monitor.native_id()
            );
        };

        let window_builder = WindowBuilder::new()
            .with_title("RustDesk whiteboard")
            .with_transparent(true)
            .with_decorations(false)
            .with_position(monitor.position())
            .with_inner_size(monitor.size());

        let window = Arc::new(window_builder.build::<(i32, CustomEvent)>(event_loop)?);
        set_window_properties(&window)?;

        let mut scale_factor = window.scale_factor();
        if scale_factor == 0.0 {
            scale_factor = 1.0;
        }
        let physical_size = window.inner_size();
        let logical_size = physical_size.to_logical::<f64>(scale_factor);
        let inner_position = window.inner_position()?;
        let outer_position = inner_position;
        windows.push(WindowState {
            window,
            logical_size,
            outer_position,
            display_origin: (origin.0 as f64, origin.1 as f64),
        });
    }
    Ok(windows)
}

fn draw_cursors(
    windows: &Vec<WindowState>,
    window_id: WindowId,
    presentation: &mut WhiteboardPresentationState<CursorInfo, (WindowId, Ripple)>,
    cursor_text_layouts: &mut HashMap<i32, CursorTextLayout>,
) {
    presentation.retain_ripples(|(_, ripple)| ripple.is_active());
    for window in windows.iter() {
        if window.window.id() != window_id {
            continue;
        }

        if let Ok(handle) = window.window.window_handle() {
            if let RawWindowHandle::AppKit(appkit_handle) = handle.as_raw() {
                unsafe {
                    let ns_view = appkit_handle.ns_view.as_ptr() as *mut Object;
                    let current_context: *mut Object =
                        msg_send![class!(NSGraphicsContext), currentContext];
                    if !current_context.is_null() {
                        let cg_context_ptr: *mut std::ffi::c_void =
                            msg_send![current_context, CGContext];
                        if !cg_context_ptr.is_null() {
                            let cg_context_ref =
                                CGContextRef::from_ptr_mut(cg_context_ptr as *mut _);
                            let mut context = CoreGraphicsContext::new_y_up(
                                cg_context_ref,
                                window.logical_size.height,
                                None,
                            );
                            context.clear(None, piet::Color::TRANSPARENT);

                            for (ripple_window_id, ripple) in presentation.ripple_values() {
                                if *ripple_window_id == window_id {
                                    let (radius, alpha) = ripple.get_radius_alpha();
                                    let color = piet::Color::rgba(1.0, 0.25, 0.25, alpha * 0.5);
                                    let circle =
                                        piet::kurbo::Circle::new((ripple.x, ripple.y), radius);
                                    context.stroke(circle, &color, 2.0);
                                }
                            }

                            for (conn_id, info) in presentation.cursor_entries() {
                                if info.window_id != window.window.id() {
                                    continue;
                                }
                                let cursor = &info.cursor;

                                let (x, y) = (cursor.x as f64, cursor.y as f64);
                                let size = 1.0;

                                let mut pb = BezPath::new();
                                pb.move_to((x, y));
                                pb.line_to((x, y + 16.0 * size));
                                pb.line_to((x + 4.0 * size, y + 13.0 * size));
                                pb.line_to((x + 7.0 * size, y + 20.0 * size));
                                pb.line_to((x + 9.0 * size, y + 19.0 * size));
                                pb.line_to((x + 6.0 * size, y + 12.0 * size));
                                pb.line_to((x + 11.0 * size, y + 12.0 * size));

                                let rgba = super::argb_to_rgba(cursor.argb);
                                let color = piet::Color::rgba8(rgba.0, rgba.1, rgba.2, rgba.3);
                                context.fill(pb, &color);

                                let pos =
                                    (x + CURSOR_TEXT_OFFSET * size, y + CURSOR_TEXT_OFFSET * size);
                                let get_rounded_rect = |layout: &CoreGraphicsTextLayout| {
                                    let text_pos = Point::new(pos.0, pos.1);
                                    let padded_bounds = (layout.image_bounds()
                                        + text_pos.to_vec2())
                                    .inflate(3.0, 3.0);
                                    padded_bounds.to_rounded_rect(5.0)
                                };

                                let layout_is_current = cursor_text_layouts
                                    .get(conn_id)
                                    .is_some_and(|cached| {
                                        cached.text == cursor.text && cached.argb == cursor.argb
                                    });
                                if !layout_is_current {
                                    cursor_text_layouts.remove(conn_id);
                                    let text = context.text();
                                    let color = piet::Color::rgba8(0, 0, 0, 255);
                                    if let Ok(layout) = text
                                        .new_text_layout(cursor.text.clone())
                                        .font(FontFamily::SYSTEM_UI, CURSOR_TEXT_FONT_SIZE)
                                        .text_color(color)
                                        .build()
                                    {
                                        cursor_text_layouts.insert(
                                            *conn_id,
                                            CursorTextLayout {
                                                text: cursor.text.clone(),
                                                argb: cursor.argb,
                                                layout,
                                            },
                                        );
                                    }
                                }
                                if let Some(cached) = cursor_text_layouts.get(conn_id) {
                                    context.fill(
                                        get_rounded_rect(&cached.layout),
                                        &piet::Color::WHITE,
                                    );
                                    context.draw_text(&cached.layout, pos);
                                }
                            }
                            if let Err(e) = context.finish() {
                                log::error!("Failed to draw cursor: {}", e);
                            }
                        } else {
                            log::warn!("CGContext is null");
                        }
                    }
                }
            }
        }
    }
}

pub(super) fn create_event_loop() -> ResultType<()> {
    crate::platform::hide_dock();
    let event_loop = EventLoopBuilder::<(i32, CustomEvent)>::with_user_event().build();

    let windows = create_windows(&event_loop)?;

    let proxy = event_loop.create_proxy();
    let _event_proxy = install_whiteboard_event_proxy(proxy);

    let mut presentation =
        WhiteboardPresentationState::<CursorInfo, (WindowId, Ripple)>::default();
    let mut cursor_text_layouts: HashMap<i32, CursorTextLayout> = HashMap::new();

    event_loop.run(move |event, _, control_flow| {
        *control_flow = if presentation.has_ripples() {
            ControlFlow::WaitUntil(Instant::now() + RIPPLE_FRAME_INTERVAL)
        } else {
            ControlFlow::Wait
        };

        match event {
            Event::NewEvents(cause) => match cause {
                StartCause::Init => {
                    for window in windows.iter() {
                        window.window.set_outer_position(window.outer_position);
                        window.window.request_redraw();
                    }
                    crate::platform::hide_dock();
                }
                StartCause::ResumeTimeReached { .. } => {
                    let had_ripples = presentation.has_ripples();
                    presentation.retain_ripples(|(_, ripple)| ripple.is_active());
                    if had_ripples {
                        for window in windows.iter() {
                            window.window.request_redraw();
                        }
                    }
                    *control_flow = if presentation.has_ripples() {
                        ControlFlow::WaitUntil(Instant::now() + RIPPLE_FRAME_INTERVAL)
                    } else {
                        ControlFlow::Wait
                    };
                }
                _ => {}
            },
            Event::WindowEvent { event, .. } => match event {
                WindowEvent::CloseRequested => {
                    *control_flow = ControlFlow::Exit;
                }
                _ => {}
            },
            Event::RedrawRequested(window_id) => {
                draw_cursors(
                    &windows,
                    window_id,
                    &mut presentation,
                    &mut cursor_text_layouts,
                );
                *control_flow = if presentation.has_ripples() {
                    ControlFlow::WaitUntil(Instant::now() + RIPPLE_FRAME_INTERVAL)
                } else {
                    ControlFlow::Wait
                };
            }
            Event::UserEvent((conn_id, evt)) => match evt {
                CustomEvent::Cursor(cursor) => {
                    let previous_window_id =
                        presentation.cursor(conn_id).map(|info| info.window_id);
                    let mut matched = false;
                    for window in windows.iter() {
                        let (l, t, r, b) = (
                            window.display_origin.0,
                            window.display_origin.1,
                            window.display_origin.0 + window.logical_size.width,
                            window.display_origin.1 + window.logical_size.height,
                        );
                        if (cursor.x as f64) < l
                            || (cursor.x as f64) >= r
                            || (cursor.y as f64) < t
                            || (cursor.y as f64) >= b
                        {
                            continue;
                        }
                        matched = true;

                        let ripple = if cursor.btns != 0 {
                            let window_id = window.window.id();
                            Some((
                                window_id,
                                Ripple {
                                    x: (cursor.x as f64 - window.display_origin.0),
                                    y: (cursor.y as f64 - window.display_origin.1),
                                    start_time: Instant::now(),
                                },
                            ))
                        } else {
                            None
                        };
                        let accepted = presentation.update(
                            conn_id,
                            CursorInfo {
                                window_id: window.window.id(),
                                cursor: Cursor {
                                    x: (cursor.x - window.display_origin.0 as f32),
                                    y: (cursor.y - window.display_origin.1 as f32),
                                    ..cursor
                                },
                            },
                            ripple,
                        );
                        if accepted {
                            window.window.request_redraw();
                            if previous_window_id != Some(window.window.id()) {
                                if let Some(previous) = previous_window_id.and_then(|window_id| {
                                    windows
                                        .iter()
                                        .find(|previous| previous.window.id() == window_id)
                                }) {
                                    previous.window.request_redraw();
                                }
                            }
                        } else {
                            log::error!(
                                "Whiteboard presentation rejected invalid or excess owner {conn_id}"
                            );
                            *control_flow = ControlFlow::Exit;
                        }
                        break;
                    }
                    if !matched {
                        let had_owner = presentation.cursor(conn_id).is_some();
                        presentation.clear(conn_id);
                        cursor_text_layouts.remove(&conn_id);
                        if had_owner {
                            for window in windows.iter() {
                                window.window.request_redraw();
                            }
                        }
                    }
                }
                CustomEvent::Clear => {
                    presentation.clear(conn_id);
                    cursor_text_layouts.remove(&conn_id);
                    for window in windows.iter() {
                        window.window.request_redraw();
                    }
                }
                CustomEvent::Exit => {
                    *control_flow = ControlFlow::Exit;
                }
            },
            _ => (),
        }
    });
}
