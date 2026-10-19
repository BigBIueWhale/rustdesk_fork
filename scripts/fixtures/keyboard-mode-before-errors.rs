use crate::{client::LoginConfigHandler, flutter::{sessions, try_sync_peer_option}, flutter_ffi::SessionID};

fn save_keyboard_mode(handler: &mut LoginConfigHandler, value: String) {
    let mut config = handler.load_config();
    config.keyboard_mode = value;
    handler.save_config(config);
}

pub fn session_set_keyboard_mode(session_id: SessionID, value: String) {
    let mut _mode_updated = false;
    if let Some(session) = sessions::get_session_by_session_id(&session_id) {
        save_keyboard_mode(&mut session.lc.write().unwrap(), value.clone());
        _mode_updated = true;
        try_sync_peer_option(&session, &session_id, "keyboard_mode", None);
    }
    #[cfg(windows)]
    if _mode_updated {
        crate::keyboard::update_grab_get_key_name(&value);
    }
}
