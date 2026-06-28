#[cfg(target_os = "android")]
#[no_mangle]
pub unsafe extern "system" fn Java_com_carriez_flutter_1hbb_NativeClipboardSetService_nativeSelfTest(
    _env: jni::JNIEnv,
    _this: jni::objects::JObject,
) -> jni::sys::jboolean {
    if crate::clipboard::android_service_clipboard_self_test() {
        jni::sys::JNI_TRUE
    } else {
        jni::sys::JNI_FALSE
    }
}

#[cfg(target_os = "android")]
#[no_mangle]
pub unsafe extern "system" fn Java_com_carriez_flutter_1hbb_NativeClipboardSetService_nativeSanitize(
    env: jni::JNIEnv,
    _this: jni::objects::JObject,
    payload: jni::objects::JByteArray,
) -> jni::sys::jbyteArray {
    let response = (|| -> hbb_common::ResultType<Vec<u8>> {
        let payload = env.convert_byte_array(payload).map_err(|e| {
            hbb_common::anyhow::anyhow!("failed to copy Android clipboard payload from JNI: {e}")
        })?;
        crate::clipboard::android_service_clipboard_sanitize_payload(&payload)
    })();

    match response.and_then(|response| {
        env.byte_array_from_slice(&response).map_err(|e| {
            hbb_common::anyhow::anyhow!("failed to return Android clipboard response: {e}")
        })
    }) {
        Ok(array) => array.into_raw(),
        Err(err) => {
            hbb_common::log::debug!("Android isolated clipboard sanitizer failed: {err}");
            std::ptr::null_mut()
        }
    }
}
