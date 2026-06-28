package com.carriez.flutter_hbb

import android.app.Activity
import android.app.Instrumentation
import android.os.Build
import android.os.Bundle
import android.util.Log

private const val NIS_SMOKE_TAG = "NativeIsoSmoke"

class NativeIsolatedServicesSmokeInstrumentation : Instrumentation() {
    override fun onCreate(arguments: Bundle?) {
        super.onCreate(arguments)
        start()
    }

    override fun onStart() {
        val result = Bundle()
        val failures = mutableListOf<String>()

        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O_MR1) {
            failures += "Android API ${Build.VERSION.SDK_INT} lacks SharedMemory; isolated native services must fail closed"
        } else {
            val context = targetContext.applicationContext
            checkService("video", failures) { NativeVideoDecoderClient.isReady(context) }
            checkService("opus", failures) { NativeAudioDecoderClient.isReady(context) }
            checkService("zstd", failures) { NativeZstdDecoderClient.isReady(context) }
            checkService("clipboard", failures) { NativeClipboardSetClient.isReady(context) }
        }

        if (failures.isEmpty()) {
            result.putString("native_isolated_services", "video,opus,zstd,clipboard ready")
            finish(Activity.RESULT_OK, result)
        } else {
            val failureText = failures.joinToString("; ")
            Log.e(NIS_SMOKE_TAG, failureText)
            result.putString("native_isolated_services", failureText)
            result.putStringArray("failures", failures.toTypedArray())
            finish(Activity.RESULT_CANCELED, result)
        }
    }

    private fun checkService(
        name: String,
        failures: MutableList<String>,
        ready: () -> Boolean
    ) {
        try {
            if (!ready()) {
                failures += "$name isolated service readiness self-test returned false"
            }
        } catch (t: Throwable) {
            failures += "$name isolated service readiness threw ${t.javaClass.simpleName}: ${t.message ?: "no message"}"
        }
    }
}
