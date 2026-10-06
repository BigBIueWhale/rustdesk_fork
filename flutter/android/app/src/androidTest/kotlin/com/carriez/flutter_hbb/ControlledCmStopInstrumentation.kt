package com.carriez.flutter_hbb

import android.app.Activity
import android.app.Application
import android.app.Instrumentation
import android.os.Bundle
import android.os.SystemClock
import android.util.Log

/** Test-only, same-process observation of a real CM admission racing production Service Stop. */
class ControlledCmStopInstrumentation : Instrumentation() {
    companion object {
        private const val TAG = "ControlledCmStopTest"
        private const val APP_PROCESS = "com.carriez.flutter_hbb"
    }

    private var requestedScenario: String? = null

    override fun onCreate(arguments: Bundle?) {
        super.onCreate(arguments)
        requestedScenario = arguments?.getString("scenario")
        start()
    }

    override fun onStart() {
        val outcome = Bundle()
        var result = Activity.RESULT_CANCELED
        try {
            check(Application.getProcessName() == APP_PROCESS) {
                "instrumentation did not enter the app's main process"
            }
            if (requestedScenario == "process-smoke") {
                Log.i(TAG, "PROCESS_SMOKE_PASS")
            } else {
                check(requestedScenario == "cm-stop-race") {
                    "unknown instrumentation scenario"
                }
                exerciseRace()
            }
            outcome.putString("result", "pass")
            result = Activity.RESULT_OK
        } catch (error: Throwable) {
            outcome.putString("result", "fail")
            outcome.putString("reason", error.message ?: error.javaClass.name)
            Log.e(TAG, "INSTRUMENTATION_FAILED", error)
        } finally {
            finish(result, outcome)
        }
    }

    private fun exerciseRace() {
        val monitor = addMonitor(MainActivity::class.java.name, null, false)
        Log.i(TAG, "READY")
        val activity = waitForMonitorWithTimeout(monitor, 90_000) as? MainActivity
            ?: error("production MainActivity did not launch")
        removeMonitor(monitor)
        val serviceField = MainActivity::class.java.getDeclaredField("mainService").apply {
            isAccessible = true
        }
        var service: MainService? = null
        var generation = 0L
        check(waitUntil(90_000) {
            val status = MainService.currentStatus()
            val bound = serviceField.get(activity) as? MainService
            if (status != null && status.mediaProjectionReady && bound != null) {
                generation = status.generation
                service = bound
                true
            } else {
                false
            }
        }) { "production Service did not become capture-ready and Activity-bound" }
        val owner = service ?: error("capture-ready Service object disappeared")
        synchronized(owner) {
            Log.i(TAG, "MONITOR_HELD generation=$generation")
            check(waitUntil(45_000) { overlappingStacks() }) {
                "Rust JNI admission and production Stop did not overlap"
            }
            Log.i(TAG, "OVERLAP_OBSERVED generation=$generation")
        }
        check(waitUntil(60_000) { MainService.currentStatus() == null }) {
            "production Stop did not retire the exact Service generation"
        }
        Log.i(TAG, "STOP_RETIRED generation=$generation")
        check(waitUntil(90_000) {
            val status = MainService.currentStatus()
            status != null && status.generation > generation && status.mediaProjectionReady
        }) { "same-process Service restart did not restore a fresh capture-ready generation" }
        Log.i(TAG, "RESTART_READY generation=${MainService.currentStatus()?.generation}")
    }

    private fun overlappingStacks(): Boolean {
        var admissionBlocked = false
        var stopWaiting = false
        for ((thread, stack) in Thread.getAllStackTraces()) {
            if (thread.state == Thread.State.BLOCKED && stack.any {
                    it.className == MainService::class.java.name &&
                        it.methodName == "rustAdmitControlledConnection"
                }) {
                admissionBlocked = true
            }
            if (thread.name == "main" && stack.any {
                    it.className == "ffi.FFI" && it.methodName == "deactivateServer"
                } && stack.any {
                    it.className == MainService::class.java.name &&
                        it.methodName == "quiesceControlledConnectionAdmission"
                }) {
                stopWaiting = true
            }
        }
        return admissionBlocked && stopWaiting
    }

    private fun waitUntil(timeoutMillis: Long, condition: () -> Boolean): Boolean {
        val deadline = SystemClock.elapsedRealtime() + timeoutMillis
        do {
            if (condition()) return true
            SystemClock.sleep(25)
        } while (SystemClock.elapsedRealtime() < deadline)
        return false
    }
}
