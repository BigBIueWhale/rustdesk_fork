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

    @Keep
    fun rustIsNativeOpusDecoderReady(): Boolean {
        return NativeAudioDecoderClient.isReady(applicationContext)
    }

    @Keep
    fun rustDecodeNativeOpus(
        payload: ByteArray,
        sampleRate: Int,
        channels: Int,
        decodeFec: Boolean
    ): ByteArray? {
        return NativeAudioDecoderClient.decode(
            applicationContext,
            payload,
            sampleRate,
            channels,
            decodeFec
        )
    }

    @Keep
    fun rustIsNativeZstdDecoderReady(): Boolean {
        return NativeZstdDecoderClient.isReady(applicationContext)
    }

    @Keep
    fun rustDecompressNativeZstd(payload: ByteArray): ByteArray? {
        return NativeZstdDecoderClient.decompress(applicationContext, payload)
    }
}
