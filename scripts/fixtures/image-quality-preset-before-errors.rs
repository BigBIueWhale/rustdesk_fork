use super::{Data, Interface, LoginConfigHandler, Message, Misc, OptionMessage};
use crate::{flutter::{sessions, FlutterSession}, flutter_ffi::SessionID};
use hbb_common::log;

fn save_image_quality_handler(handler: &mut LoginConfigHandler, value: String) -> Option<Message> {
    let mut res = None;
    if let Some(q) = handler.get_image_quality_enum(&value, false) {
        let mut misc = Misc::new();
        misc.set_option(OptionMessage {
            image_quality: q.into(),
            ..Default::default()
        });
        let mut msg_out = Message::new();
        msg_out.set_misc(misc);
        res = Some(msg_out);
    }
    let mut config = handler.load_config();
    config.image_quality = value;
    handler.save_config(config);
    res
}

fn save_image_quality(session: &FlutterSession, value: String) {
    let msg = save_image_quality_handler(&mut session.lc.write().unwrap(), value.clone());
    if let Some(msg) = msg {
        session.send(Data::Message(msg));
    }
    if value != "custom" {
        let last_auto_fps = session.lc.read().unwrap().last_auto_fps;
        if last_auto_fps.unwrap_or(usize::MAX) >= 30 {
            // non custom quality use 30 fps
            let result = session.lc.write().unwrap().set_custom_fps(30, false);
            match result {
                Ok(msg) => session.send(Data::Message(msg)),
                Err(err) => log::error!("Failed to set automatic FPS: {err}"),
            }
        }
    }
}

pub fn session_set_image_quality(session_id: SessionID, value: String) {
    if let Some(session) = sessions::get_session_by_session_id(&session_id) {
        save_image_quality(&session, value);
    }
}
