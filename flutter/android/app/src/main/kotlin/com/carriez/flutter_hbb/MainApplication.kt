package com.carriez.flutter_hbb

import android.app.Application
import android.util.Log
import androidx.annotation.Keep
import ffi.FFI

class MainApplication : Application() {
    companion object {
        private const val TAG = "MainApplication"
    }

    override fun onCreate() {
        super.onCreate()
        Log.d(TAG, "App start")
        FFI.onAppStart(applicationContext)
    }

    @Keep
    fun rustIsNativeVideoDecoderReady(): Boolean {
        return NativeVideoDecoderClient.isReady(applicationContext)
    }

    @Keep
    fun rustDecodeNativeVideo(
        payload: ByteArray,
        codec: Int,
        imageFormat: Int,
        align: Int
    ): ByteArray? {
        return NativeVideoDecoderClient.decode(
            applicationContext,
            payload,
            codec,
            imageFormat,
            align
        )
    }
}
