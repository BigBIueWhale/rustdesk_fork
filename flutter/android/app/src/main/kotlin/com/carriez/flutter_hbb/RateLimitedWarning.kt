package com.carriez.flutter_hbb

import android.os.SystemClock
import android.util.Log
import java.util.concurrent.atomic.AtomicLong

internal class RateLimitedWarning(
    private val tag: String,
    private val message: String,
    private val intervalMs: Long = DEFAULT_INTERVAL_MS
) {
    private val nextLogAtMs = AtomicLong(0)

    fun warn() {
        val now = SystemClock.elapsedRealtime()
        val next = nextLogAtMs.get()
        if (now < next) {
            return
        }
        if (nextLogAtMs.compareAndSet(next, now + intervalMs)) {
            Log.w(tag, message)
        }
    }

    private companion object {
        const val DEFAULT_INTERVAL_MS = 1_000L
    }
}
