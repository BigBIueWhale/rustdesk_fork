#[cfg(target_os = "android")]
#[no_mangle]
pub unsafe extern "system" fn Java_com_carriez_flutter_1hbb_NativeZstdDecoderService_nativeSelfTest(
    _env: jni::JNIEnv,
    _this: jni::objects::JObject,
) -> jni::sys::jboolean {
    if hbb_common::compress::android_service_zstd_self_test() {
        jni::sys::JNI_TRUE
    } else {
        jni::sys::JNI_FALSE
    }
}

#[cfg(target_os = "android")]
#[no_mangle]
pub unsafe extern "system" fn Java_com_carriez_flutter_1hbb_NativeZstdDecoderService_nativeDecompress(
    env: jni::JNIEnv,
    _this: jni::objects::JObject,
    payload: jni::objects::JByteArray,
) -> jni::sys::jbyteArray {
    let response = (|| -> hbb_common::ResultType<Vec<u8>> {
        let payload = env.convert_byte_array(payload).map_err(|e| {
            hbb_common::anyhow::anyhow!("failed to copy android zstd payload from JNI: {e}")
        })?;
        hbb_common::compress::android_service_zstd_decompress_response_bytes(&payload)
    })()
    .unwrap_or_default();

    match env.byte_array_from_slice(&response) {
        Ok(array) => array.into_raw(),
        Err(err) => {
            hbb_common::log::error!("failed to return android isolated zstd response: {err}");
            std::ptr::null_mut()
        }
    }
}
