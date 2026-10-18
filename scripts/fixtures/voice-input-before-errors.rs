pub fn set_voice_call_input_device(_is_cm: bool, _device: String) {
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    if _is_cm {
        let _ = crate::ipc::set_voice_call_input_device(_device);
    } else {
        crate::audio_service::set_voice_call_input_device(_device);
    }
}

pub fn get_voice_call_input_device(_is_cm: bool) -> String {
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    if _is_cm {
        match crate::ipc::get_config("voice-call-input") {
            Ok(Some(device)) => device,
            _ => "".to_owned(),
        }
    } else {
        crate::audio_service::get_voice_call_input_device().unwrap_or_default()
    }
    #[cfg(any(target_os = "android", target_os = "ios"))]
    "".to_owned()
}
