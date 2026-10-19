use crate::{client::LoginConfigHandler, flutter::{sessions, FlutterSession}, flutter_ffi::SessionID};

fn save_scroll_style(handler: &mut LoginConfigHandler, value: String) {
    let mut config = handler.load_config();
    config.scroll_style = value;
    handler.save_config(config);
}

fn save_edge_scroll_edge_thickness(handler: &mut LoginConfigHandler, value: i32) {
    let mut config = handler.load_config();
    config.edge_scroll_edge_thickness = value;
    handler.save_config(config);
}

fn session_save_scroll_style(session: &FlutterSession, value: String) {
    save_scroll_style(&mut session.lc.write().unwrap(), value);
}

fn session_save_edge_scroll_edge_thickness(session: &FlutterSession, value: i32) {
    save_edge_scroll_edge_thickness(&mut session.lc.write().unwrap(), value);
}

pub fn session_set_scroll_style(session_id: SessionID, value: String) {
    if let Some(session) = sessions::get_session_by_session_id(&session_id) {
        session_save_scroll_style(&session, value);
    }
}

pub fn session_set_edge_scroll_edge_thickness(session_id: SessionID, value: i32) {
    if let Some(session) = sessions::get_session_by_session_id(&session_id) {
        session_save_edge_scroll_edge_thickness(&session, value);
    }
}
