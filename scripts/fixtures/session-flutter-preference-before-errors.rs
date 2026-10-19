use crate::{client::LoginConfigHandler, flutter::{sessions, FlutterSession}, flutter_ffi::SessionID};

fn save_ui_flutter(handler: &mut LoginConfigHandler, k: String, v: String) {
    let mut config = handler.load_config();
    if v.is_empty() {
        config.ui_flutter.remove(&k);
    } else {
        config.ui_flutter.insert(k, v);
    }
    handler.save_config(config);
}

fn save_flutter_option(session: &FlutterSession, k: String, v: String) {
    save_ui_flutter(&mut session.lc.write().unwrap(), k, v);
}

pub fn session_set_flutter_option(session_id: SessionID, k: String, v: String) {
    if let Some(session) = sessions::get_session_by_session_id(&session_id) {
        save_flutter_option(&session, k, v);
    }
}
