package com.carriez.flutter_hbb

/**
 * Handle events from flutter
 * Request MediaProjection permission
 *
 * Inspired by [droidVNC-NG] https://github.com/bk138/droidVNC-NG
 */

import ffi.FFI

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.content.ClipboardManager
import android.os.Bundle
import android.os.Build
import android.os.IBinder
import android.util.Log
import android.view.WindowManager
import androidx.annotation.RequiresApi
import com.hjq.permissions.XXPermissions
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel
import java.util.Locale
import java.util.UUID


class MainActivity : FlutterActivity() {
    companion object {
        internal data class ClientSessionOwner(val generation: Long, val sessionId: String) {
            fun toVoiceCallOwner() = OutgoingVoiceCallOwner(generation, sessionId)
        }

        var flutterMethodChannel: MethodChannel? = null
        private var _rdClipboardManager: RdClipboardManager? = null
        private val stoppedClientSessionOwners = LinkedHashMap<Long, String>()
        val rdClipboardManager: RdClipboardManager?
            get() = _rdClipboardManager;

        @Synchronized
        private fun markClientSessionOwnerStopped(owner: ClientSessionOwner) {
            stoppedClientSessionOwners[owner.generation] = owner.sessionId
        }

        @Synchronized
        private fun markClientSessionOwnerStarted(owner: ClientSessionOwner) {
            stoppedClientSessionOwners.remove(owner.generation)
        }

        @Synchronized
        private fun forgetClientSessionOwner(owner: ClientSessionOwner) {
            stoppedClientSessionOwners.remove(owner.generation)
        }

        @Synchronized
        internal fun takeStoppedClientSessionOwners(): List<ClientSessionOwner> {
            val owners = stoppedClientSessionOwners.map { (generation, sessionId) ->
                ClientSessionOwner(generation, sessionId)
            }
            stoppedClientSessionOwners.clear()
            return owners
        }
    }

    private val channelTag = "mChannel"
    private val logTag = "mMainActivity"
    private var mainService: MainService? = null
    private var isServiceBound = false
    private var activityFlutterMethodChannel: MethodChannel? = null
    private var clientSessionOwnerGeneration = 0L
    private var clientSessionOwner: ClientSessionOwner? = null
    private var isActivityStopped = false

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        if (!VoiceCallAudioCoordinator.initialize(applicationContext)) {
            Log.e(logTag, "Failed to initialize process-wide audio capture ownership")
        }
        super.configureFlutterEngine(flutterEngine)
        if (MainService.currentStatus() != null) {
            bindMainService(createIfNeeded = false)
        }
        val channel = MethodChannel(
            flutterEngine.dartExecutor.binaryMessenger,
            channelTag
        )
        activityFlutterMethodChannel = channel
        flutterMethodChannel = channel
        initFlutterChannel(channel)
    }

    override fun onResume() {
        super.onResume()
        val inputPer = InputService.isOpen
        activity.runOnUiThread {
            flutterMethodChannel?.invokeMethod(
                "on_state_changed",
                mapOf("name" to "input", "value" to inputPer.toString())
            )
        }
    }

    private fun requestMediaProjection() {
        val intent = Intent(this, PermissionRequestTransparentActivity::class.java).apply {
            action = ACT_REQUEST_MEDIA_PROJECTION
        }
        startActivityForResult(intent, REQ_INVOKE_PERMISSION_ACTIVITY_MEDIA_PROJECTION)
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQ_INVOKE_PERMISSION_ACTIVITY_MEDIA_PROJECTION && resultCode == RES_FAILED) {
            flutterMethodChannel?.invokeMethod("on_media_projection_canceled", null)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        // Invalidate the previous Flutter engine's native admission before super.onCreate can
        // attach and run this Activity's engine. Dart binds this generation to its isolate-wide
        // UUID before the UI starts; delayed calls from an older engine then fail closed.
        if (!VoiceCallAudioCoordinator.invalidateOutgoingOwner()) {
            Log.e(logTag, "Failed to retire the previous outgoing voice-call owner")
        }
        clientSessionOwnerGeneration = FFI.beginClientSessionOwner()
        if (clientSessionOwnerGeneration == 0L) {
            Log.e(logTag, "Failed to allocate an Android client session owner generation")
        }
        super.onCreate(savedInstanceState)
        if (_rdClipboardManager == null) {
            _rdClipboardManager = RdClipboardManager(getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager)
            FFI.setClipboardManager(_rdClipboardManager!!)
        }
    }

    override fun onDestroy() {
        Log.e(logTag, "onDestroy")

        // Teardown is bound to this Activity generation and Flutter isolate UUID. A delayed
        // onDestroy from an obsolete Activity cannot close the replacement Activity's sessions.
        clientSessionOwner?.let { owner ->
            forgetClientSessionOwner(owner)
            if (!VoiceCallAudioCoordinator.unregisterOutgoingOwner(owner.toVoiceCallOwner())) {
                Log.e(logTag, "Failed to reconcile outgoing voice-call audio during Activity teardown")
            }
            val closedSessions = FFI.closeClientSessions(owner.generation, owner.sessionId)
            if (closedSessions > 0) {
                Log.i(logTag, "Closed $closedSessions outgoing client peer session(s) for Activity owner ${owner.generation}")
            }
        }
        clientSessionOwner = null

        activityFlutterMethodChannel?.setMethodCallHandler(null)
        if (flutterMethodChannel === activityFlutterMethodChannel) {
            flutterMethodChannel = null
        }
        activityFlutterMethodChannel = null

        unbindMainService()
        super.onDestroy()
    }

    private fun bindMainService(createIfNeeded: Boolean): Boolean {
        if (isServiceBound) {
            return true
        }
        val flags = if (createIfNeeded) Context.BIND_AUTO_CREATE else 0
        return try {
            bindService(
                Intent(this, MainService::class.java),
                serviceConnection,
                flags
            ).also { bound ->
                isServiceBound = bound
                if (!bound) {
                    Log.w(logTag, "Failed to bind MainService")
                }
            }
        } catch (e: SecurityException) {
            Log.e(logTag, "MainService binding was rejected", e)
            false
        }
    }

    private fun unbindMainService(): Boolean {
        if (!isServiceBound) {
            mainService = null
            return false
        }
        return try {
            unbindService(serviceConnection)
            true
        } catch (e: IllegalArgumentException) {
            Log.w(logTag, "MainService binding was already gone", e)
            false
        } finally {
            isServiceBound = false
            mainService = null
        }
    }

    private val serviceConnection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, service: IBinder?) {
            Log.d(logTag, "onServiceConnected")
            val binder = service as MainService.LocalBinder
            mainService = binder.getService()
            isServiceBound = true
        }

        override fun onServiceDisconnected(name: ComponentName?) {
            Log.d(logTag, "onServiceDisconnected")
            mainService = null
            isServiceBound = false
        }
    }

    private fun initFlutterChannel(flutterMethodChannel: MethodChannel) {
        flutterMethodChannel.setMethodCallHandler { call, result ->
            // make sure result will be invoked, otherwise flutter will await forever
            when (call.method) {
                "register_client_session_owner" -> {
                    val rawSessionId = call.arguments as? String
                    val canonicalSessionId = try {
                        rawSessionId?.let { UUID.fromString(it).toString() }
                    } catch (e: IllegalArgumentException) {
                        null
                    }
                    val isCanonical = rawSessionId != null &&
                        canonicalSessionId == rawSessionId.lowercase(Locale.ROOT)
                    val existingOwner = clientSessionOwner
                    if (!isCanonical || canonicalSessionId == null || clientSessionOwnerGeneration == 0L) {
                        Log.e(logTag, "Rejected invalid Flutter client session owner registration")
                        result.success(false)
                    } else if (existingOwner != null && existingOwner.sessionId != canonicalSessionId) {
                        Log.e(logTag, "Rejected a second Flutter client session owner for one Activity")
                        result.success(false)
                    } else if (!FFI.registerClientSessionOwner(clientSessionOwnerGeneration, canonicalSessionId)) {
                        Log.w(logTag, "Rejected stale Flutter client session owner generation $clientSessionOwnerGeneration")
                        result.success(false)
                    } else {
                        val owner = ClientSessionOwner(clientSessionOwnerGeneration, canonicalSessionId)
                        if (!VoiceCallAudioCoordinator.registerOutgoingOwner(owner.toVoiceCallOwner())) {
                            Log.e(logTag, "Rejected stale outgoing voice-call owner registration")
                            FFI.closeClientSessions(owner.generation, owner.sessionId)
                            result.success(false)
                        } else {
                            clientSessionOwner = owner
                            if (isActivityStopped) {
                                markClientSessionOwnerStopped(owner)
                            }
                            result.success(true)
                        }
                    }
                }
                "init_service" -> {
                    val status = MainService.currentStatus()
                    bindMainService(createIfNeeded = status == null)
                    if (status?.mediaProjectionReady == true) {
                        result.success(false)
                        return@setMethodCallHandler
                    }
                    requestMediaProjection()
                    result.success(true)
                }
                "stop_service" -> {
                    Log.d(logTag, "Stop service")
                    // A stopped service with a BIND_AUTO_CREATE client is not destroyed until the
                    // client unbinds. onDestroy is MainService's sole resource-teardown owner.
                    val stopped = stopService(Intent(this, MainService::class.java))
                    val unbound = unbindMainService()
                    result.success(stopped || unbound)
                }
                "check_permission" -> {
                    if (call.arguments is String) {
                        result.success(XXPermissions.isGranted(context, call.arguments as String))
                    } else {
                        result.success(false)
                    }
                }
                "request_permission" -> {
                    if (call.arguments is String) {
                        requestPermission(context, call.arguments as String)
                        result.success(true)
                    } else {
                        result.success(false)
                    }
                }
                START_ACTION -> {
                    if (call.arguments is String) {
                        startAction(context, call.arguments as String)
                        result.success(true)
                    } else {
                        result.success(false)
                    }
                }
                "check_video_permission" -> {
                    mainService?.let {
                        result.success(it.checkMediaPermission())
                    } ?: let {
                        result.success(
                            MainService.currentStatus()?.mediaProjectionReady == true
                        )
                    }
                }
                "check_service" -> {
                    Companion.flutterMethodChannel?.invokeMethod(
                        "on_state_changed",
                        mapOf("name" to "input", "value" to InputService.isOpen.toString())
                    )
                    Companion.flutterMethodChannel?.invokeMethod(
                        "on_state_changed",
                        mapOf(
                            "name" to "media",
                            "value" to (
                                MainService.currentStatus()?.mediaProjectionReady == true
                            ).toString(),
                        )
                    )
                    result.success(true)
                }
                "stop_input" -> {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                        InputService.ctx?.disableSelf()
                    }
                    InputService.ctx = null
                    Companion.flutterMethodChannel?.invokeMethod(
                        "on_state_changed",
                        mapOf("name" to "input", "value" to InputService.isOpen.toString())
                    )
                    result.success(true)
                }
                "cancel_notification" -> {
                    if (call.arguments is Int) {
                        val id = call.arguments as Int
                        mainService?.cancelNotification(id)
                    } else {
                        result.success(true)
                    }
                }
                "enable_soft_keyboard" -> {
                    // https://blog.csdn.net/hanye2020/article/details/105553780
                    if (call.arguments as Boolean) {
                        window.clearFlags(WindowManager.LayoutParams.FLAG_ALT_FOCUSABLE_IM)
                    } else {
                        window.addFlags(WindowManager.LayoutParams.FLAG_ALT_FOCUSABLE_IM)
                    }
                    result.success(true)

                }
                "try_sync_clipboard" -> {
                    rdClipboardManager?.syncClipboard(true)
                    result.success(true)
                }
                // R-G7 (§19): the get/set "Start on boot" platform-channel handlers are
                // removed with the toggle — boot-start is re-homed unconditionally in
                // BootReceiver (RECEIVE_BOOT_COMPLETED alone), so there is no opt to read/write.
                SYNC_APP_DIR_CONFIG_PATH -> {
                    if (call.arguments is String) {
                        val prefs = getSharedPreferences(KEY_SHARED_PREFERENCES, MODE_PRIVATE)
                        val edit = prefs.edit()
                        edit.putString(KEY_APP_DIR_CONFIG_PATH, call.arguments as String)
                        edit.apply()
                        result.success(true)
                    } else {
                        result.success(false)
                    }
                }
                GET_VALUE -> {
                    if (call.arguments is String) {
                        if (call.arguments == KEY_IS_SUPPORT_VOICE_CALL) {
                            result.success(isSupportVoiceCall())
                        } else {
                            result.error("-1", "No such key", null)
                        }
                    } else {
                        result.success(null)
                    }
                }
                "on_voice_call_started" -> {
                    result.success(setOutgoingVoiceCallActive(true))
                }
                "on_voice_call_closed" -> {
                    result.success(setOutgoingVoiceCallActive(false))
                }
                else -> {
                    result.error("-1", "No such method", null)
                }
            }
        }
    }

    private fun setOutgoingVoiceCallActive(active: Boolean): Boolean {
        val owner = clientSessionOwner
        if (owner == null) {
            Log.e(logTag, "Rejected voice-call event without an outgoing session owner")
            return false
        }
        val ok = VoiceCallAudioCoordinator.setOutgoingVoiceCallActive(
            owner.toVoiceCallOwner(),
            active,
        )
        if (!ok) {
            Log.e(logTag, "Failed to ${if (active) "start" else "stop"} outgoing voice-call audio")
            flutterMethodChannel?.invokeMethod("msgbox", mapOf(
                "type" to "custom-nook-nocancel-hasclose-error",
                "title" to "Voice call",
                "text" to "Failed to update voice-call audio."))
        } else {
            Log.d(logTag, "Outgoing voice-call audio active=$active")
        }
        return ok
    }

    override fun onStop() {
        isActivityStopped = true
        clientSessionOwner?.let { markClientSessionOwnerStopped(it) }
        super.onStop()
        // R-X6: the floating overlay window is cut — the controlled-status surface
        // is the mandatory foreground-service notification, not a
        // TYPE_APPLICATION_OVERLAY window (a tapjacking primitive a single-purpose
        // box does not need). SYSTEM_ALERT_WINDOW is dropped with it.
    }

    override fun onStart() {
        super.onStart()
        isActivityStopped = false
        val owner = clientSessionOwner ?: return
        val resumedGeneration = FFI.resumeClientSessionOwner(owner.generation, owner.sessionId)
        if (resumedGeneration == 0L) {
            Log.e(logTag, "Failed to resume Android client session ownership; closing stale Activity")
            val retiredRejectedOwner =
                VoiceCallAudioCoordinator.unregisterOutgoingOwner(owner.toVoiceCallOwner())
            if (!retiredRejectedOwner) {
                Log.d(logTag, "Rejected Activity did not own the current voice-call recorder")
            }
            forgetClientSessionOwner(owner)
            clientSessionOwner = null
            finish()
            return
        }

        // onStart can run without onCreate when Android restores an older Activity from the back
        // stack. Reconcile its recorded generation with the authoritative native generation acquired
        // above. Forgetting the old stopped marker first prevents a delayed task callback from
        // retaining dead metadata.
        forgetClientSessionOwner(owner)
        val resumedOwner = ClientSessionOwner(resumedGeneration, owner.sessionId)
        if (!VoiceCallAudioCoordinator.resumeOutgoingOwner(
                owner.toVoiceCallOwner(),
                resumedOwner.toVoiceCallOwner(),
            )
        ) {
            Log.e(logTag, "Failed to transfer outgoing voice-call ownership to resumed Activity")
            val retiredUnreconciledOwner =
                VoiceCallAudioCoordinator.unregisterOutgoingOwner(owner.toVoiceCallOwner())
            if (!retiredUnreconciledOwner) {
                Log.d(logTag, "Unreconciled Activity did not own the current voice-call recorder")
            }
            val closedUnreconciledSessions =
                FFI.closeClientSessions(owner.generation, owner.sessionId)
            if (closedUnreconciledSessions > 0) {
                Log.i(
                    logTag,
                    "Closed $closedUnreconciledSessions session(s) for the exact unreconciled Activity owner",
                )
            }
            clientSessionOwner = null
            finish()
            return
        }
        clientSessionOwner = resumedOwner
        markClientSessionOwnerStarted(resumedOwner)
    }
}
