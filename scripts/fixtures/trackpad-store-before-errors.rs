use crate::{client::LoginConfigHandler, flutter::sessions, flutter_ffi::SessionID};

fn save_trackpad_speed(handler: &mut LoginConfigHandler, speed: i32) {
    let mut config = handler.load_config();
    config.trackpad_speed = speed;
    handler.save_config(config);
}

pub fn session_set_trackpad_speed(session_id: SessionID, value: i32) {
    if let Some(session) = sessions::get_session_by_session_id(&session_id) {
        save_trackpad_speed(&mut session.lc.write().unwrap(), value);
    }
}
