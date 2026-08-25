// ffi.kt

package ffi

import android.content.Context
import java.nio.ByteBuffer

import com.carriez.flutter_hbb.RdClipboardManager

object FFI {
    init {
        System.loadLibrary("rustdesk")
    }

    external fun init(service: Context, applicationContext: Context): Boolean
    external fun releaseService(service: Context): Boolean
    external fun setMobileAtRestStorageKey(key: ByteArray): Boolean
    external fun onAppStart(ctx: Context)
    external fun setClipboardManager(clipboardManager: RdClipboardManager)
    external fun startServer(service: Context, app_dir: String, custom_client_config: String): Long
    external fun activateServer(service: Context, generation: Long): Boolean
    external fun isServerGenerationActive(service: Context, generation: Long): Boolean
    external fun stopServer(service: Context, generation: Long): Boolean
    external fun beginClientSessionOwner(): Long
    external fun registerClientSessionOwner(generation: Long, sessionId: String): Boolean
    external fun resumeClientSessionOwner(generation: Long, sessionId: String): Long
    external fun retireClientSessions(generation: Long, sessionId: String): Int
    external fun rebuildDirectServerListener(generation: Long): Boolean
    external fun onVideoFrameUpdate(generation: Long, buf: ByteBuffer)
    external fun onAudioFrameUpdate(buf: ByteBuffer)
    external fun translateLocale(localeName: String, input: String): String
    external fun updateScreenInfo(generation: Long, width: Int, height: Int, scale: Int): Boolean
    external fun setVideoFrameRawEnable(generation: Long, value: Boolean): Boolean
    external fun setAudioFrameRawEnable(value: Boolean)
    external fun getLocalOption(key: String): String
    external fun getBuildinOption(key: String): String
    external fun onClipboardUpdate(clips: ByteBuffer)
    external fun isServiceClipboardEnabled(): Boolean
}
