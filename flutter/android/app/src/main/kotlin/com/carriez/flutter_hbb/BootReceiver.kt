package com.carriez.flutter_hbb

import android.Manifest.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Build
import android.util.Log
import android.widget.Toast
import com.hjq.permissions.XXPermissions

class BootReceiver : BroadcastReceiver() {
    private val logTag = "tagBootReceiver"

    override fun onReceive(context: Context, intent: Intent) {
        Log.d(logTag, "onReceive ${intent.action}")

        if (Intent.ACTION_BOOT_COMPLETED == intent.action) {
            // R-G7 (§19): the user-settable "Start on boot" toggle is removed; boot-start is
            // re-homed on RECEIVE_BOOT_COMPLETED ALONE (no KEY_START_ON_BOOT_OPT gate) so the
            // hardened controlled box auto-starts unconditionally — one mode, no runtime knob
            // (R-D2). The only remaining gate is the legitimate battery-optimization exemption
            // (the kept onboarding, requested at service-start), which Android requires to
            // start a foreground service from boot; without it we must not attempt the start
            // (ForegroundServiceStartNotAllowedException) — that is a real OS constraint, not
            // a toggle, so this is "re-homed, not left silently broken".
            // (R-X6: the old SYSTEM_ALERT_WINDOW dependency was already severed with the
            // excised floating window.)
            if (!XXPermissions.isGranted(context, REQUEST_IGNORE_BATTERY_OPTIMIZATIONS)){
                Log.d(logTag, "REQUEST_IGNORE_BATTERY_OPTIMIZATIONS is not granted")
                return
            }

            val it = Intent(context, MainService::class.java).apply {
                action = ACT_INIT_MEDIA_PROJECTION_AND_SERVICE
                putExtra(EXT_INIT_FROM_BOOT, true)
            }
            Toast.makeText(context, "RustDesk is Open", Toast.LENGTH_LONG).show()
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(it)
            } else {
                context.startService(it)
            }
        }
    }
}
