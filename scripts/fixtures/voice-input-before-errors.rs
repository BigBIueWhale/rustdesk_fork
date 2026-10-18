pub fn set_voice_call_input_device(_is_cm: bool, _device: String) {
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    if _is_cm {
        let _ = crate::ipc::set_voice_call_input_device(_device);
    } else {
        crate::audio_service::set_voice_call_input_device(_device);
    }
}
