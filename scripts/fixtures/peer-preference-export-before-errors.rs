use super::*;

pub fn session_set_custom_image_quality(session_id: SessionID, value: i32) {
    if let Some(session) = sessions::get_session_by_session_id(&session_id) {
        session.save_custom_image_quality(value);
    }
}

pub fn session_set_custom_fps(session_id: SessionID, fps: i32) {
    if let Some(session) = sessions::get_session_by_session_id(&session_id) {
        session.set_custom_fps(fps);
    }
}
