use crate::{client::LoginConfigHandler, flutter::{sessions, FlutterSession}, flutter_ffi::SessionID};

fn save_reverse_mouse_wheel(handler: &mut LoginConfigHandler, value: String) {
    let mut config = handler.load_config();
    config.reverse_mouse_wheel = value;
    handler.save_config(config);
}

fn session_save_reverse_mouse_wheel(session: &FlutterSession, value: String) {
    save_reverse_mouse_wheel(&mut session.lc.write().unwrap(), value);
}

pub fn session_set_reverse_mouse_wheel(session_id: SessionID, value: String) {
    if let Some(session) = sessions::get_session_by_session_id(&session_id) {
        session_save_reverse_mouse_wheel(&session, value);
    }
}
