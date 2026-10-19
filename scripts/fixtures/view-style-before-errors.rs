use crate::{client::LoginConfigHandler, flutter::{sessions, FlutterSession}, flutter_ffi::SessionID};

fn save_view_style_handler(handler: &mut LoginConfigHandler, value: String) {
    let mut config = handler.load_config();
    config.view_style = value;
    handler.save_config(config);
}

fn save_view_style_session(session: &FlutterSession, value: String) {
    save_view_style_handler(&mut session.lc.write().unwrap(), value);
}

pub fn session_set_view_style(session_id: SessionID, value: String) {
    if let Some(session) = sessions::get_session_by_session_id(&session_id) {
        save_view_style_session(&session, value);
    }
}
