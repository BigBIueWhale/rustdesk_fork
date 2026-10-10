use super::{
    server::{
        install_whiteboard_event_proxy, Ripple, WhiteboardIpcWorker,
        WhiteboardPresentationState, RIPPLE_FRAME_INTERVAL,
    },
    win_linux::{create_font_face, draw_text},
    Cursor, CustomEvent,
};
use hbb_common::{bail, log, ResultType};
use softbuffer::{Context, Surface};
use std::{
    ffi::{c_int, c_short, c_ulong, c_ushort},
    num::NonZeroU32,
    sync::Arc,
    time::Instant,
};
use tiny_skia::{Color, FillRule, Paint, PathBuilder, PixmapMut, Stroke, Transform};
use ttf_parser::Face;
use winit::raw_window_handle::{HasDisplayHandle, HasWindowHandle, RawDisplayHandle, RawWindowHandle};
use winit::{
    application::ApplicationHandler,
    dpi::{PhysicalPosition, PhysicalSize},
    event::{StartCause, WindowEvent},
    event_loop::{ActiveEventLoop, ControlFlow, EventLoop, OwnedDisplayHandle},
    platform::x11::{WindowAttributesExtX11, WindowType},
    window::{Window, WindowId, WindowLevel},
};

enum _XDisplay {}
type Display = _XDisplay;

type XID = c_ulong;
type XserverRegion = XID;

#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(C)]
pub struct XRectangle {
    pub x: c_short,
    pub y: c_short,
    pub width: c_ushort,
    pub height: c_ushort,
}

#[link(name = "Xfixes")]
extern "C" {
    fn XFixesCreateRegion(
        dpy: *mut Display,
        rectangles: *mut XRectangle,
        nrectangles: c_int,
    ) -> XserverRegion;
    fn XFixesDestroyRegion(dpy: *mut Display, region: XserverRegion) -> ();
    fn XFixesSetWindowShapeRegion(
        dpy: *mut Display,
        win: XID,
        shape_kind: c_int,
        x_off: c_int,
        y_off: c_int,
        region: XserverRegion,
    ) -> ();
}

const SHAPE_INPUT: std::ffi::c_int = 2;

fn get_display_from_xwayland() -> Option<String> {
    crate::platform::linux::xwayland_display_from_proc()
}

fn preset_env() -> bool {
    if crate::platform::is_x11() {
        return true;
    }
    if let Some(display) = get_display_from_xwayland() {
        // https://github.com/rust-windowing/winit/blob/f6893a4390dfe6118ce4b33458d458fd3efd3025/src/event_loop.rs#L99
        // It is acceptable to modify global environment variables here because this process is an isolated,
        // dedicated "whiteboard" process.
        std::env::set_var("DISPLAY", display);
        std::env::remove_var("WAYLAND_DISPLAY");
        return true;
    }
    false
}

pub fn is_supported() -> bool {
    crate::platform::is_x11() || get_display_from_xwayland().is_some()
}

pub fn run() {
    if !preset_env() {
        return;
    }

    let event_loop = match EventLoop::<(i32, CustomEvent)>::with_user_event().build() {
        Ok(el) => el,
        Err(e) => {
            log::error!("Failed to create event loop: {}", e);
            return;
        }
    };

    let event_loop_proxy = event_loop.create_proxy();
    let _event_proxy = install_whiteboard_event_proxy(event_loop_proxy);

    let worker = match WhiteboardIpcWorker::spawn() {
        Ok(worker) => worker,
        Err(err) => {
            log::error!("Failed to start whiteboard IPC worker: {err}");
            return;
        }
    };

    let mut app = match WhiteboardApplication::new(&event_loop) {
        Ok(app) => app,
        Err(e) => {
            log::error!("Failed to create whiteboard application: {}", e);
            if let Err(err) = worker.stop_and_join() {
                log::error!("Failed to finish whiteboard IPC worker: {err}");
            }
            return;
        }
    };

    if let Err(e) = event_loop.run_app(&mut app) {
        log::error!("Failed to run app: {}", e);
    }
    if let Err(err) = worker.stop_and_join() {
        log::error!("Failed to finish whiteboard IPC worker: {err}");
    }
}

struct WindowState {
    // NOTE: This surface must be dropped before the `Window`.
    surface: Surface<OwnedDisplayHandle, Arc<Window>>,
    window: Arc<Window>,
    presentation: WhiteboardPresentationState<Cursor, Ripple>,
}

struct WhiteboardApplication {
    windows: Vec<WindowState>,
    context: Context<OwnedDisplayHandle>,
    face: Option<Face<'static>>,
    close_requested: bool,
}

impl WhiteboardApplication {
    fn new<T>(event_loop: &EventLoop<T>) -> ResultType<Self> {
        let context = match Context::new(event_loop.owned_display_handle()) {
            Ok(ctx) => ctx,
            Err(e) => {
                bail!("Failed to create context: {}", e);
            }
        };
        let face = match create_font_face() {
            Ok(face) => Some(face),
            Err(err) => {
                log::error!("Failed to create font face: {}", err);
                None
            }
        };
        Ok(Self {
            windows: Vec::new(),
            context,
            face,
            close_requested: false,
        })
    }
}

impl ApplicationHandler<(i32, CustomEvent)> for WhiteboardApplication {
    fn new_events(&mut self, _event_loop: &ActiveEventLoop, cause: StartCause) {
        if matches!(cause, StartCause::ResumeTimeReached { .. }) {
            for state in self.windows.iter_mut() {
                let had_ripples = state.presentation.has_ripples();
                state.presentation.retain_ripples(Ripple::is_active);
                if had_ripples {
                    state.window.request_redraw();
                }
            }
        }
    }

    fn user_event(&mut self, _event_loop: &ActiveEventLoop, (conn_id, evt): (i32, CustomEvent)) {
        match evt {
            CustomEvent::Cursor(cursor) => {
                if let Some(state) = self.windows.first_mut() {
                    let ripple = if cursor.btns != 0 {
                        Some(Ripple {
                            x: cursor.x,
                            y: cursor.y,
                            start_time: Instant::now(),
                        })
                    } else {
                        None
                    };
                    if !state.presentation.update(conn_id, cursor, ripple) {
                        log::error!(
                            "Whiteboard presentation rejected invalid or excess owner {conn_id}"
                        );
                        self.close_requested = true;
                    } else {
                        state.window.request_redraw();
                    }
                }
            }
            CustomEvent::Clear => {
                if let Some(state) = self.windows.first_mut() {
                    state.presentation.clear(conn_id);
                    state.window.request_redraw();
                }
            }
            CustomEvent::Exit => {
                self.close_requested = true;
            }
        }
    }

    fn resumed(&mut self, event_loop: &ActiveEventLoop) {
        let (x, y, w, h) = match super::server::get_displays_rect() {
            Ok(r) => r,
            Err(err) => {
                log::error!("Failed to get displays rect: {}", err);
                self.close_requested = true;
                return;
            }
        };

        let window_attributes = Window::default_attributes()
            .with_title("RustDesk whiteboard")
            .with_inner_size(PhysicalSize::new(w, h))
            .with_position(PhysicalPosition::new(x, y))
            .with_decorations(false)
            .with_transparent(true)
            .with_window_level(WindowLevel::AlwaysOnTop)
            .with_x11_window_type(vec![WindowType::Dock])
            .with_override_redirect(true);

        let window = match event_loop.create_window(window_attributes) {
            Ok(window) => Arc::new(window),
            Err(e) => {
                log::error!("Failed to create window: {}", e);
                self.close_requested = true;
                return;
            }
        };

        let display = match window.display_handle() {
            Ok(d) => d,
            Err(e) => {
                log::error!("Failed to get display handle: {}", e);
                self.close_requested = true;
                return;
            }
        };
        let rwh = match window.window_handle() {
            Ok(w) => w,
            Err(e) => {
                log::error!("Failed to get window handle: {}", e);
                self.close_requested = true;
                return;
            }
        };

        // Both the following block and `window.set_cursor_hittest(false)` in `draw()` are necessary to ensure cursor events are properly passed through the window.
        // These issues may be related to winit X11 handling.
        // https://github.com/rust-windowing/winit/issues/3509
        // https://github.com/rust-windowing/winit/issues/4120
        // If either block is removed, cursor events may not be passed through as expected.
        // If you update winit, please revisit this workaround.
        match (rwh.as_raw(), display.as_raw()) {
            (RawWindowHandle::Xlib(xlib_window), RawDisplayHandle::Xlib(xlib_display)) => {
                unsafe {
                    let xwindow = xlib_window.window;
                    if let Some(display_ptr) = xlib_display.display {
                        let xdisplay = display_ptr.as_ptr() as *mut Display;
                        // Mouse event passthrough
                        let empty_region = XFixesCreateRegion(xdisplay, std::ptr::null_mut(), 0);
                        if empty_region == 0 {
                            log::error!("XFixesCreateRegion failed: returned null region");
                        } else {
                            XFixesSetWindowShapeRegion(
                                xdisplay,
                                xwindow,
                                SHAPE_INPUT,
                                0,
                                0,
                                empty_region,
                            );
                            XFixesDestroyRegion(xdisplay, empty_region);
                        }
                    }
                }
            }
            _ => {
                log::error!("Unsupported windowing system for shape extension");
                self.close_requested = true;
                return;
            }
        }

        let surface = match Surface::new(&self.context, window.clone()) {
            Ok(s) => s,
            Err(e) => {
                log::error!("Failed to create surface: {}", e);
                self.close_requested = true;
                return;
            }
        };

        let state = WindowState {
            window,
            surface,
            presentation: WhiteboardPresentationState::default(),
        };

        state.window.request_redraw();
        self.windows.push(state);
    }

    fn window_event(
        &mut self,
        _event_loop: &ActiveEventLoop,
        window_id: WindowId,
        event: WindowEvent,
    ) {
        match event {
            WindowEvent::CloseRequested => {
                self.close_requested = true;
            }
            WindowEvent::RedrawRequested => {
                let Some(state) = self.windows.iter_mut().find(|w| w.window.id() == window_id)
                else {
                    log::error!("No window found for id: {:?}", window_id);
                    return;
                };
                if let Err(err) = state.draw(&self.face) {
                    log::error!("Failed to draw window: {}", err);
                }
            }
            _ => (),
        }
    }

    fn about_to_wait(&mut self, event_loop: &ActiveEventLoop) {
        if self.close_requested {
            event_loop.exit();
        } else if self
            .windows
            .iter()
            .any(|state| state.presentation.has_ripples())
        {
            event_loop.set_control_flow(ControlFlow::WaitUntil(
                Instant::now() + RIPPLE_FRAME_INTERVAL,
            ));
        } else {
            event_loop.set_control_flow(ControlFlow::Wait);
        }
    }

    fn exiting(&mut self, _event_loop: &ActiveEventLoop) {
        self.windows.clear();
    }
}

impl WindowState {
    fn draw(&mut self, face: &Option<Face<'static>>) -> ResultType<()> {
        let (width, height) = {
            let size = self.window.inner_size();
            (size.width, size.height)
        };

        let (Some(width), Some(height)) = (NonZeroU32::new(width), NonZeroU32::new(height)) else {
            bail!("Invalid window size, {width}x{height}")
        };
        if let Err(e) = self.surface.resize(width, height) {
            bail!("Failed to resize surface: {}", e);
        }

        let mut buffer = match self.surface.buffer_mut() {
            Ok(buf) => buf,
            Err(e) => {
                bail!("Failed to get buffer: {}", e);
            }
        };

        let Some(mut pixmap) = PixmapMut::from_bytes(
            bytemuck::cast_slice_mut(&mut buffer),
            width.get(),
            height.get(),
        ) else {
            bail!("Failed to create pixmap from buffer");
        };
        pixmap.fill(Color::TRANSPARENT);

        self.presentation.retain_ripples(Ripple::is_active);
        for ripple in self.presentation.ripple_values() {
            let (radius, alpha) = ripple.get_radius_alpha();

            let mut ripple_paint = Paint::default();
            // Note: The real color is bgra here.
            ripple_paint.set_color_rgba8(64, 64, 255, (alpha * 128.0) as u8);
            ripple_paint.anti_alias = true;

            let mut ripple_pb = PathBuilder::new();
            ripple_pb.push_circle(ripple.x, ripple.y, radius);
            if let Some(path) = ripple_pb.finish() {
                pixmap.fill_path(
                    &path,
                    &ripple_paint,
                    FillRule::Winding,
                    Transform::identity(),
                    None,
                );
            }
        }

        for cursor in self.presentation.cursor_values() {
            let (x, y) = (cursor.x, cursor.y);
            let size = 1.5f32;

            let mut pb = PathBuilder::new();
            pb.move_to(x, y);
            pb.line_to(x, y + 16.0 * size);
            pb.line_to(x + 4.0 * size, y + 13.0 * size);
            pb.line_to(x + 7.0 * size, y + 20.0 * size);
            pb.line_to(x + 9.0 * size, y + 19.0 * size);
            pb.line_to(x + 6.0 * size, y + 12.0 * size);
            pb.line_to(x + 11.0 * size, y + 12.0 * size);
            pb.close();

            if let Some(path) = pb.finish() {
                let mut arrow_paint = Paint::default();
                let rgba = super::argb_to_rgba(cursor.argb);
                arrow_paint.set_color_rgba8(rgba.2, rgba.1, rgba.0, rgba.3);
                arrow_paint.anti_alias = true;
                pixmap.fill_path(
                    &path,
                    &arrow_paint,
                    FillRule::Winding,
                    Transform::identity(),
                    None,
                );

                let mut black_paint = Paint::default();
                black_paint.set_color_rgba8(0, 0, 0, 255);
                black_paint.anti_alias = true;
                let mut stroke = Stroke::default();
                stroke.width = 1.0f32;
                pixmap.stroke_path(&path, &black_paint, &stroke, Transform::identity(), None);

                face.as_ref().map(|face| {
                    draw_text(
                        &mut pixmap,
                        face,
                        &cursor.text,
                        x + 24.0 * size,
                        y + 24.0 * size,
                        &arrow_paint,
                        14.0f32,
                    );
                });
            }
        }

        self.window.pre_present_notify();

        if let Err(e) = buffer.present() {
            log::error!("Failed to present buffer: {}", e);
        }

        self.window.set_cursor_hittest(false).ok();

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use winit::platform::x11::EventLoopBuilderExtX11;
    use x11rb_listener::{
        errors::ReplyError,
        protocol::{xproto::ConnectionExt, ErrorKind},
    };

    struct NativeApplication(WhiteboardApplication, Option<u32>, usize);

    impl ApplicationHandler<(i32, CustomEvent)> for NativeApplication {
        fn resumed(&mut self, event_loop: &ActiveEventLoop) {
            self.0.resumed(event_loop);
            assert!(!self.0.close_requested);
            assert_eq!(self.0.windows.len(), 1);
            self.1 = Some(assert_presented_owners(&mut self.0));
        }

        fn user_event(&mut self, event_loop: &ActiveEventLoop, event: (i32, CustomEvent)) {
            assert_eq!(event.0, 0);
            assert!(matches!(&event.1, CustomEvent::Exit));
            self.2 += 1;
            assert_eq!(self.2, 1);
            self.0.user_event(event_loop, event);
        }

        fn window_event(
            &mut self,
            event_loop: &ActiveEventLoop,
            window_id: WindowId,
            event: WindowEvent,
        ) {
            self.0.window_event(event_loop, window_id, event);
        }

        fn exiting(&mut self, event_loop: &ActiveEventLoop) {
            self.0.exiting(event_loop);
        }

        fn about_to_wait(&mut self, event_loop: &ActiveEventLoop) {
            self.0.about_to_wait(event_loop);
        }
    }

    fn assert_presented_owners(app: &mut WhiteboardApplication) -> u32 {
        let state = &mut app.windows[0];
        let window_id = match state.window.window_handle().unwrap().as_raw() {
            RawWindowHandle::Xlib(handle) => handle.window as u32,
            _ => panic!("native whiteboard fixture is not X11"),
        };
        for (conn_id, x, y, argb) in [
            (7, 32.0, 32.0, 0xff00ff00),
            (8, 128.0, 96.0, 0xff0000ff),
        ] {
            assert!(state.presentation.update(
                conn_id,
                Cursor {
                    x,
                    y,
                    argb,
                    btns: 0,
                    text: String::new(),
                },
                None,
            ));
        }
        state.draw(&app.face).unwrap();
        let width = state.window.inner_size().width as usize;
        let pixels = state.surface.fetch().unwrap();
        assert_eq!(pixels[42 * width + 35] & 0x00ffffff, 0x0000ff00);
        assert_eq!(pixels[106 * width + 131] & 0x00ffffff, 0x000000ff);

        state.presentation.clear(7);
        state.draw(&app.face).unwrap();
        let pixels = state.surface.fetch().unwrap();
        assert_eq!(pixels[42 * width + 35] & 0x00ffffff, 0);
        assert_eq!(pixels[106 * width + 131] & 0x00ffffff, 0x000000ff);
        window_id
    }

    #[test]
    #[ignore = "requires an isolated X11 display"]
    fn r_s11hn_linux_whiteboard_retires_windows_before_event_loop_return() {
        assert!(std::env::var_os(crate::common::WHITEBOARD_LAUNCH_TOKEN_ENV).is_none());
        assert!(std::env::var_os(crate::common::WHITEBOARD_LAUNCH_PARENT_ENV).is_none());
        let worker = WhiteboardIpcWorker::spawn().unwrap();
        worker.stop_and_join().unwrap();

        let mut builder = EventLoop::<(i32, CustomEvent)>::with_user_event();
        builder.with_x11().with_any_thread(true);
        let event_loop = builder.build().unwrap();
        let _event_proxy = install_whiteboard_event_proxy(event_loop.create_proxy());
        let mut app = NativeApplication(
            WhiteboardApplication::new(&event_loop).unwrap(),
            None,
            0,
        );
        let (observer, _) = x11rb_listener::connect(None).unwrap();

        event_loop.run_app(&mut app).unwrap();
        let _: &Context<OwnedDisplayHandle> = &app.0.context;
        let window_id = app.1.expect("native whiteboard window was never created");
        match observer.get_window_attributes(window_id).unwrap().reply() {
            Err(ReplyError::X11Error(error)) if error.error_kind == ErrorKind::Window => (),
            result => panic!("whiteboard window survived event-loop return: {result:?}"),
        }
        assert!(app.0.windows.is_empty());
        assert!(app.0.close_requested);
        assert_eq!(app.2, 1);
    }
}
