package com.carriez.flutter_hbb

import ffi.FFI

/**
 * Capture screen,get video and audio,send to rust.
 * Dispatch notifications
 *
 * Inspired by [droidVNC-NG] https://github.com/bk138/droidVNC-NG
 */

import android.Manifest
import android.annotation.SuppressLint
import android.app.*
import android.app.PendingIntent.FLAG_IMMUTABLE
import android.app.PendingIntent.FLAG_UPDATE_CURRENT
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.res.Configuration
import android.content.res.Configuration.ORIENTATION_LANDSCAPE
import android.graphics.Color
import android.graphics.PixelFormat
import android.hardware.display.DisplayManager.VIRTUAL_DISPLAY_FLAG_AUTO_MIRROR
import android.hardware.display.VirtualDisplay
import android.media.*
import android.media.projection.MediaProjection
import android.media.projection.MediaProjectionManager
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkRequest
import android.os.*
import android.util.DisplayMetrics
import android.util.Log
import android.view.Surface
import android.view.WindowManager
import androidx.annotation.Keep
import androidx.annotation.RequiresApi
import androidx.core.app.ActivityCompat
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import io.flutter.embedding.android.FlutterActivity
import kotlin.concurrent.thread
import org.json.JSONException
import org.json.JSONObject
import java.nio.ByteBuffer
import kotlin.math.max
import kotlin.math.min

// R-G8 / R-SV9 (de-brand): the foreground-service notification title carries the fork identity,
// not the bare upstream brand. (The app label / accessibility-service name — the app's own
// identity, not marketing — is left intact; R-G8 names the notification title specifically.)
const val DEFAULT_NOTIFY_TITLE = "RustDesk Hardened Fork"
const val DEFAULT_NOTIFY_TEXT = "Service is running"
const val DEFAULT_NOTIFY_ID = 1
const val NOTIFY_ID_OFFSET = 100

// video const

const val MAX_SCREEN_SIZE = 1200

class MainService : Service() {

    @Keep
    @RequiresApi(Build.VERSION_CODES.N)
    fun rustPointerInput(kind: Int, mask: Int, x: Int, y: Int) {
        // turn on screen with LEFT_DOWN when screen off
        if (!powerManager.isInteractive && (kind == 0 || mask == LEFT_DOWN)) {
            if (wakeLock.isHeld) {
                Log.d(logTag, "Turn on Screen, WakeLock release")
                wakeLock.release()
            }
            Log.d(logTag,"Turn on Screen")
            wakeLock.acquire(5000)
        } else {
            when (kind) {
                0 -> { // touch
                    InputService.ctx?.onTouchInput(mask, x, y)
                }
                1 -> { // mouse
                    InputService.ctx?.onMouseInput(mask, x, y)
                }
                else -> {
                }
            }
        }
    }

    @Keep
    @RequiresApi(Build.VERSION_CODES.N)
    fun rustKeyEventInput(input: ByteArray) {
        InputService.ctx?.onKeyEvent(input)
    }

    @Keep
    fun rustGetByName(name: String): String {
        return when (name) {
            "screen_size" -> {
                JSONObject().apply {
                    put("width",SCREEN_INFO.width)
                    put("height",SCREEN_INFO.height)
                    put("scale",SCREEN_INFO.scale)
                }.toString()
            }
            "is_start" -> {
                isStart.toString()
            }
            else -> ""
        }
    }

    @Keep
    fun rustSetByName(name: String, arg1: String, arg2: String) {
        when (name) {
            "add_connection" -> {
                try {
                    val jsonObject = JSONObject(arg1)
                    val id = jsonObject["id"] as Int
                    val username = jsonObject["name"] as String
                    val peerId = jsonObject["peer_id"] as String
                    val authorized = jsonObject["authorized"] as Boolean
                    val connectionType = ControlledConnectionType.fromWireTag(
                        jsonObject.getJSONObject("conn_type").getString("t")
                    )
                    if (connectionType == null) {
                        Log.e(logTag, "Rejected unknown controlled connection type")
                        return
                    }
                    // R-S14/R-S19: resource authority comes from the exact AuthConnType carried
                    // by Rust, never by reconstructing Remote from parallel presentation fields.
                    if (connectionType.allowsVoiceCall &&
                        !VoiceCallAudioCoordinator.registerControlledConnection(id)
                    ) {
                        Log.e(logTag, "Rejected invalid controlled voice-call owner: $id")
                    }
                    val type = if (connectionType == ControlledConnectionType.FILE_TRANSFER) {
                        translate("Transfer file")
                    } else {
                        translate("Share screen")
                    }
                    if (authorized) {
                        if (connectionType.requiresDesktopCapture) {
                            requestCapture()
                        }
                        onClientAuthorizedNotification(id, type, username, peerId)
                    } else {
                        loginRequestNotification(id, type, username, peerId)
                    }
                } catch (e: JSONException) {
                    e.printStackTrace()
                }
            }
            "remove_connection" -> {
                val id = arg1.toIntOrNull()
                if (id == null ||
                    !VoiceCallAudioCoordinator.unregisterControlledConnection(id)
                ) {
                    Log.e(logTag, "Rejected invalid controlled connection removal: $arg1")
                } else {
                    cancelNotification(id)
                }
            }
            "update_voice_call_state" -> {
                try {
                    val jsonObject = JSONObject(arg1)
                    val id = jsonObject["id"] as Int
                    val username = jsonObject["name"] as String
                    val peerId = jsonObject["peer_id"] as String
                    val inVoiceCall = jsonObject["in_voice_call"] as Boolean
                    val incomingVoiceCall = jsonObject["incoming_voice_call"] as Boolean
                    if (!VoiceCallAudioCoordinator.setControlledVoiceCallActive(id, inVoiceCall)) {
                        Log.e(logTag, "Failed to reconcile controlled voice-call owner: $id")
                        MainActivity.flutterMethodChannel?.invokeMethod("msgbox", mapOf(
                            "type" to "custom-nook-nocancel-hasclose-error",
                            "title" to "Voice call",
                            "text" to "Failed to update voice-call audio."))
                    }
                    if (incomingVoiceCall) {
                        voiceCallRequestNotification(id, "Voice Call Request", username, peerId)
                    }
                } catch (e: JSONException) {
                    e.printStackTrace()
                }
            }
            "stop_capture" -> {
                Log.d(logTag, "from rust:stop_capture")
                stopCapture()
            }
            "half_scale" -> {
                val halfScale = arg1.toBoolean()
                if (isHalfScale != halfScale) {
                    isHalfScale = halfScale
                    updateScreenInfo(resources.configuration.orientation)
                }
                
            }
            else -> {
            }
        }
    }

    private var serviceLooper: Looper? = null
    private var serviceHandler: Handler? = null

    private val powerManager: PowerManager by lazy { applicationContext.getSystemService(Context.POWER_SERVICE) as PowerManager }
    private val wakeLock: PowerManager.WakeLock by lazy { powerManager.newWakeLock(PowerManager.ACQUIRE_CAUSES_WAKEUP or PowerManager.SCREEN_BRIGHT_WAKE_LOCK, "rustdesk:wakelock")}
    private val networkKeepaliveWakeLock: PowerManager.WakeLock by lazy {
        powerManager.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "rustdesk:network-keepalive").apply {
            setReferenceCounted(false)
        }
    }
    private val connectivityManager: ConnectivityManager by lazy {
        applicationContext.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
    }
    @Volatile
    private var networkCallbackRegistered = false
    private val networkCallback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
            requestDirectListenerRebuild("available:$network")
        }

        override fun onLost(network: Network) {
            requestDirectListenerRebuild("lost:$network")
        }
    }

    companion object {
        @Volatile
        private var _isReady = false // media permission ready status
        @Volatile
        private var _isStart = false // screen capture start status
        val isReady: Boolean
            get() = _isReady
        val isStart: Boolean
            get() = _isStart
    }

    private val logTag = "LOG_SERVICE"
    private val binder = LocalBinder()

    private var reuseVirtualDisplay = Build.VERSION.SDK_INT > 33

    // video
    private var mediaProjection: MediaProjection? = null
    private var mediaProjectionCallback: MediaProjection.Callback? = null
    @Volatile
    private var captureRequested = false
    private var surface: Surface? = null
    private var imageReader: ImageReader? = null
    private var virtualDisplay: VirtualDisplay? = null

    // notification
    private lateinit var notificationManager: NotificationManager
    private lateinit var notificationChannel: String
    private lateinit var notificationBuilder: NotificationCompat.Builder

    private fun requestDirectListenerRebuild(reason: String) {
        Log.i(logTag, "R-T13: Android network change ($reason); rebuilding direct listener")
        FFI.rebuildDirectServerListener()
    }

    @Synchronized
    private fun registerNetworkCallback() {
        if (networkCallbackRegistered) {
            return
        }
        try {
            val request = NetworkRequest.Builder().build()
            connectivityManager.registerNetworkCallback(request, networkCallback)
            networkCallbackRegistered = true
            Log.i(logTag, "R-T13: registered ConnectivityManager.NetworkCallback")
        } catch (e: Exception) {
            Log.w(logTag, "R-T13: failed to register network callback", e)
        }
    }

    @Synchronized
    private fun unregisterNetworkCallback() {
        if (!networkCallbackRegistered) {
            return
        }
        try {
            connectivityManager.unregisterNetworkCallback(networkCallback)
        } catch (e: Exception) {
            Log.w(logTag, "R-T13: failed to unregister network callback", e)
        } finally {
            networkCallbackRegistered = false
        }
    }

    @SuppressLint("WakelockTimeout")
    private fun acquireNetworkKeepaliveWakeLock() {
        if (!networkKeepaliveWakeLock.isHeld) {
            networkKeepaliveWakeLock.acquire()
            Log.i(logTag, "R-T13: acquired partial wakelock for TCP keepalive")
        }
    }

    private fun releaseNetworkKeepaliveWakeLock() {
        if (networkKeepaliveWakeLock.isHeld) {
            networkKeepaliveWakeLock.release()
            Log.i(logTag, "R-T13: released partial wakelock for TCP keepalive")
        }
    }

    override fun onCreate() {
        super.onCreate()
        Log.d(logTag,"MainService onCreate, sdk int:${Build.VERSION.SDK_INT} reuseVirtualDisplay:$reuseVirtualDisplay")
        if (!VoiceCallAudioCoordinator.initialize(applicationContext)) {
            Log.e(logTag, "Failed to initialize process-wide audio capture ownership")
        }
        FFI.init(this)
        HandlerThread("Service", Process.THREAD_PRIORITY_BACKGROUND).apply {
            start()
            serviceLooper = looper
            serviceHandler = Handler(looper)
        }
        updateScreenInfo(resources.configuration.orientation)
        initNotification()

        // keep the config dir same with flutter
        val prefs = applicationContext.getSharedPreferences(KEY_SHARED_PREFERENCES, FlutterActivity.MODE_PRIVATE)
        val configPath = prefs.getString(KEY_APP_DIR_CONFIG_PATH, "") ?: ""
        FFI.startServer(configPath, "")

        createForegroundNotification()
        acquireNetworkKeepaliveWakeLock()
        registerNetworkCallback()
    }

    override fun onDestroy() {
        releaseCaptureResources()
        if (!VoiceCallAudioCoordinator.clearControlledConnections()) {
            Log.e(logTag, "Failed to release controlled voice-call owners during service teardown")
        }
        serviceLooper?.quitSafely()
        serviceHandler = null
        serviceLooper = null
        checkMediaPermission()
        unregisterNetworkCallback()
        releaseNetworkKeepaliveWakeLock()
        // R-D7a: the direct listener is OWNED by this foreground service (started by FFI.startServer
        // in onCreate). Tear it down as the service is destroyed — stopServer supersedes the Rust
        // service-owned-listener generation, so the accept loop drops the TcpListener and the socket
        // closes. The user "Stop service" path reaches here via MainActivity.stop_service -> destroy()
        // -> stopSelf -> onDestroy; an OS/OEM/battery kill closes the socket by process death instead
        // (START_NOT_STICKY means no zombie auto-restart rebinds it).
        FFI.stopServer()
        super.onDestroy()
    }

    override fun onTaskRemoved(rootIntent: Intent?) {
        // Removing the Android task does not stop this foreground service, and therefore does not
        // kill the process that owns librustdesk's static outgoing-session table. Consume only
        // owner pairs recorded by stopped Activities. Generation + isolate UUID binding makes this
        // safe even when an obsolete task callback arrives after a replacement Activity starts.
        for (owner in MainActivity.takeStoppedClientSessionOwners()) {
            if (!VoiceCallAudioCoordinator.unregisterOutgoingOwner(owner.toVoiceCallOwner())) {
                Log.e(logTag, "Failed to reconcile removed-task voice-call owner ${owner.generation}")
            }
            val closedSessions = FFI.closeClientSessions(owner.generation, owner.sessionId)
            if (closedSessions > 0) {
                Log.i(logTag, "Closed $closedSessions outgoing client peer session(s) for removed task owner ${owner.generation}")
            }
        }
        super.onTaskRemoved(rootIntent)
    }

    private var isHalfScale: Boolean? = null;
    private fun updateScreenInfo(orientation: Int) {
        var w: Int
        var h: Int
        var dpi: Int
        val windowManager = getSystemService(Context.WINDOW_SERVICE) as WindowManager

        @Suppress("DEPRECATION")
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            val m = windowManager.maximumWindowMetrics
            w = m.bounds.width()
            h = m.bounds.height()
            dpi = resources.configuration.densityDpi
        } else {
            val dm = DisplayMetrics()
            windowManager.defaultDisplay.getRealMetrics(dm)
            w = dm.widthPixels
            h = dm.heightPixels
            dpi = dm.densityDpi
        }

        val max = max(w,h)
        val min = min(w,h)
        if (orientation == ORIENTATION_LANDSCAPE) {
            w = max
            h = min
        } else {
            w = min
            h = max
        }
        Log.d(logTag,"updateScreenInfo:w:$w,h:$h")
        var scale = 1
        if (w != 0 && h != 0) {
            if (isHalfScale == true && (w > MAX_SCREEN_SIZE || h > MAX_SCREEN_SIZE)) {
                scale = 2
                w /= scale
                h /= scale
                dpi /= scale
            }
            if (SCREEN_INFO.width != w) {
                SCREEN_INFO.width = w
                SCREEN_INFO.height = h
                SCREEN_INFO.scale = scale
                SCREEN_INFO.dpi = dpi
                if (isStart) {
                    stopCapturePipeline()
                    FFI.refreshScreen()
                    if (captureRequested) {
                        startCapture()
                    }
                } else {
                    FFI.refreshScreen()
                }
            }

        }
    }

    override fun onBind(intent: Intent): IBinder {
        Log.d(logTag, "service onBind")
        return binder
    }

    inner class LocalBinder : Binder() {
        init {
            Log.d(logTag, "LocalBinder init")
        }

        fun getService(): MainService = this@MainService
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        Log.d("whichService", "this service: ${Thread.currentThread()}")
        super.onStartCommand(intent, flags, startId)
        if (intent?.action == ACT_INIT_MEDIA_PROJECTION_AND_SERVICE) {
            createForegroundNotification()
            acquireNetworkKeepaliveWakeLock()

            Log.d(logTag, "service starting: ${startId}:${Thread.currentThread()}")
            val mediaProjectionManager =
                getSystemService(MEDIA_PROJECTION_SERVICE) as MediaProjectionManager

            intent.getParcelableExtra<Intent>(EXT_MEDIA_PROJECTION_RES_INTENT)?.let {
                val projection = try {
                    mediaProjectionManager.getMediaProjection(Activity.RESULT_OK, it)
                } catch (e: RuntimeException) {
                    Log.e(logTag, "Failed to obtain MediaProjection from fresh consent", e)
                    null
                }
                if (projection == null) {
                    Log.e(logTag, "Fresh MediaProjection consent returned no projection")
                    checkMediaPermission()
                } else {
                    installMediaProjection(projection)
                }
            } ?: let {
                // BR-17 / R-D7a: honor the boot/start split that was plumbed (EXT_INIT_FROM_BOOT,
                // set by BootReceiver) but never read. On BOOT, start the foreground service + the
                // password-gated direct listener ONLY (both already up from onCreate: FFI.startServer
                // + createForegroundNotification) — do NOT request MediaProjection. Requesting it here
                // popped the unprompted "Share your screen?" system dialog on unlock; capture consent
                // must be a per-session, human-tapped action (Android is attended-only, R-S14). A
                // deliberate foreground "Start screen sharing" tap arrives with the result extra
                // present (via PermissionRequestTransparentActivity) and so takes the branch above,
                // unaffected; file transfer needs only the listener (no capture) and also works.
                if (intent.getBooleanExtra(EXT_INIT_FROM_BOOT, false)) {
                    Log.d(logTag, "init from boot: foreground service + listener only, not requesting MediaProjection")
                } else {
                    Log.d(logTag, "getParcelableExtra intent null, invoke requestMediaProjection")
                    requestMediaProjection()
                }
            }
        }
        return START_NOT_STICKY // don't use sticky (auto restart), the new service (from auto restart) will lose control
    }

    override fun onConfigurationChanged(newConfig: Configuration) {
        super.onConfigurationChanged(newConfig)
        updateScreenInfo(newConfig.orientation)
    }

    private fun requestMediaProjection() {
        val intent = Intent(this, PermissionRequestTransparentActivity::class.java).apply {
            action = ACT_REQUEST_MEDIA_PROJECTION
            flags = Intent.FLAG_ACTIVITY_NEW_TASK
        }
        startActivity(intent)
    }

    @SuppressLint("WrongConstant")
    private fun createSurface(): Surface? {
        // R-D7a: useVP9 excised — the raw ImageReader is the single capture encoder.
        Log.d(logTag, "ImageReader.newInstance:INFO:$SCREEN_INFO")
        imageReader =
            ImageReader.newInstance(
                SCREEN_INFO.width,
                SCREEN_INFO.height,
                PixelFormat.RGBA_8888,
                4
            ).apply {
                setOnImageAvailableListener({ imageReader: ImageReader ->
                    try {
                        // If not call acquireLatestImage, listener will not be called again
                        imageReader.acquireLatestImage().use { image ->
                            if (image == null || !isStart) return@setOnImageAvailableListener
                            val planes = image.planes
                            val buffer = planes[0].buffer
                            buffer.rewind()
                            FFI.onVideoFrameUpdate(buffer)
                        }
                    } catch (ignored: java.lang.Exception) {
                    }
                }, serviceHandler)
            }
        Log.d(logTag, "ImageReader.setOnImageAvailableListener done")
        return imageReader?.surface
    }

    @Synchronized
    private fun requestCapture(): Boolean {
        captureRequested = true
        return startCapture()
    }

    @Synchronized
    fun startCapture(): Boolean {
        if (isStart) {
            return true
        }
        val projection = mediaProjection
        if (projection == null) {
            Log.w(logTag, "startCapture fail,mediaProjection is null")
            requestMediaProjection()
            return false
        }
        
        updateScreenInfo(resources.configuration.orientation)
        Log.d(logTag, "Start Capture")
        surface = createSurface()

        if (!startRawVideoRecorder(projection)) {
            Log.w(logTag, "startCapture failed before VirtualDisplay became active")
            releaseCaptureResources(clearCaptureRequest = false)
            requestMediaProjection()
            return false
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            try {
                if (!VoiceCallAudioCoordinator.setPlaybackCaptureProjection(projection)) {
                    Log.w(logTag, "Failed to start playback audio capture")
                }
            } catch (e: RuntimeException) {
                // Audio is optional. A device-specific audio failure must not leave an already
                // active VirtualDisplay recorded as an inactive screen-capture pipeline.
                Log.w(logTag, "Audio capture failed; continuing with screen capture", e)
            }
        }
        checkMediaPermission()
        _isStart = true
        FFI.setFrameRawEnable("video",true)
        MainActivity.rdClipboardManager?.setCaptureStarted(_isStart)
        return true
    }

    @Synchronized
    fun stopCapture() {
        captureRequested = false
        stopCapturePipeline()
    }

    @Synchronized
    private fun stopCapturePipeline(keepReusableDisplay: Boolean = reuseVirtualDisplay) {
        Log.d(logTag, "Stop Capture")
        FFI.setFrameRawEnable("video",false)
        _isStart = false
        MainActivity.rdClipboardManager?.setCaptureStarted(_isStart)
        if (keepReusableDisplay) {
            try {
                virtualDisplay?.setSurface(null)
            } catch (e: RuntimeException) {
                Log.w(logTag, "Failed to detach stopped VirtualDisplay; releasing it", e)
                virtualDisplay?.release()
                virtualDisplay = null
            }
        } else {
            virtualDisplay?.release()
            virtualDisplay = null
        }
        imageReader?.close()
        imageReader = null
        // The surface must be released after `imageReader.close()`.
        // https://github.com/rustdesk/rustdesk/issues/4118#issuecomment-1515666629
        surface?.release()
        surface = null

        if (!VoiceCallAudioCoordinator.setPlaybackCaptureProjection(null)) {
            Log.e(logTag, "Failed to reconcile audio after screen-capture stop")
        }
    }

    @Synchronized
    private fun releaseCaptureResources(clearCaptureRequest: Boolean = true) {
        if (clearCaptureRequest) {
            captureRequested = false
        }
        stopCapturePipeline(keepReusableDisplay = false)
        releaseMediaProjection()
    }

    @Synchronized
    private fun releaseMediaProjection() {
        val projection = mediaProjection
        val callback = mediaProjectionCallback
        mediaProjection = null
        mediaProjectionCallback = null
        _isReady = false
        if (projection != null && callback != null) {
            try {
                projection.unregisterCallback(callback)
            } catch (e: RuntimeException) {
                Log.w(logTag, "Failed to unregister MediaProjection callback during teardown", e)
            }
        }
        projection?.let {
            Log.d(logTag, "stopping MediaProjection")
            try {
                it.stop()
            } catch (e: RuntimeException) {
                Log.w(logTag, "Failed to stop MediaProjection during teardown", e)
            }
        }
    }

    @Synchronized
    private fun installMediaProjection(projection: MediaProjection) {
        releaseCaptureResources(clearCaptureRequest = false)
        val callback = object : MediaProjection.Callback() {
            override fun onStop() {
                onMediaProjectionStopped(projection, this)
            }
        }
        mediaProjection = projection
        mediaProjectionCallback = callback
        try {
            projection.registerCallback(
                callback,
                serviceHandler ?: Handler(Looper.getMainLooper())
            )
        } catch (e: RuntimeException) {
            Log.e(logTag, "Failed to register MediaProjection lifecycle callback", e)
            mediaProjection = null
            mediaProjectionCallback = null
            try {
                projection.stop()
            } catch (stopError: RuntimeException) {
                Log.w(logTag, "Failed to stop rejected MediaProjection", stopError)
            }
            checkMediaPermission()
            requestMediaProjection()
            return
        }
        _isReady = true
        checkMediaPermission()
        if (captureRequested) {
            startCapture()
        }
    }

    @Synchronized
    private fun onMediaProjectionStopped(
        projection: MediaProjection,
        callback: MediaProjection.Callback
    ) {
        if (mediaProjection !== projection || mediaProjectionCallback !== callback) {
            Log.d(logTag, "Ignoring stop callback from a replaced MediaProjection")
            return
        }
        Log.i(logTag, "MediaProjection stopped; invalidating capture state")
        mediaProjection = null
        mediaProjectionCallback = null
        _isReady = false
        stopCapturePipeline(keepReusableDisplay = false)
        checkMediaPermission()
    }

    fun destroy() {
        Log.d(logTag, "destroy service")
        _isReady = false

        releaseCaptureResources()
        checkMediaPermission()
        unregisterNetworkCallback()
        releaseNetworkKeepaliveWakeLock()
        stopForeground(true)
        stopSelf()
    }

    fun checkMediaPermission(): Boolean {
        Handler(Looper.getMainLooper()).post {
            MainActivity.flutterMethodChannel?.invokeMethod(
                "on_state_changed",
                mapOf("name" to "media", "value" to isReady.toString())
            )
        }
        Handler(Looper.getMainLooper()).post {
            MainActivity.flutterMethodChannel?.invokeMethod(
                "on_state_changed",
                mapOf("name" to "input", "value" to InputService.isOpen.toString())
            )
        }
        return isReady
    }

    private fun startRawVideoRecorder(mp: MediaProjection): Boolean {
        Log.d(logTag, "startRawVideoRecorder,screen info:$SCREEN_INFO")
        val targetSurface = surface
        if (targetSurface == null) {
            Log.d(logTag, "startRawVideoRecorder failed,surface is null")
            return false
        }
        return createOrSetVirtualDisplay(mp, targetSurface)
    }

    // https://github.com/bk138/droidVNC-NG/blob/b79af62db5a1c08ed94e6a91464859ffed6f4e97/app/src/main/java/net/christianbeier/droidvnc_ng/MediaProjectionService.java#L250
    // Reuse virtualDisplay if it exists, to avoid media projection confirmation dialog every connection.
    private fun createOrSetVirtualDisplay(mp: MediaProjection, s: Surface): Boolean {
        return try {
            virtualDisplay?.let {
                it.resize(SCREEN_INFO.width, SCREEN_INFO.height, SCREEN_INFO.dpi)
                it.setSurface(s)
            } ?: let {
                virtualDisplay = mp.createVirtualDisplay(
                    "RustDeskVD",
                    SCREEN_INFO.width, SCREEN_INFO.height, SCREEN_INFO.dpi, VIRTUAL_DISPLAY_FLAG_AUTO_MIRROR,
                    s, null, null
                )
            }
            virtualDisplay != null
        } catch (e: SecurityException) {
            Log.w(logTag, "MediaProjection was no longer authorized for capture", e)
            false
        } catch (e: IllegalStateException) {
            Log.w(logTag, "MediaProjection was no longer in a capturable state", e)
            false
        }
    }

    private fun initNotification() {
        notificationManager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        notificationChannel = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channelId = "RustDesk"
            val channelName = "RustDesk Service"
            val channel = NotificationChannel(
                channelId,
                channelName, NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = "RustDesk Service Channel"
            }
            channel.lightColor = Color.BLUE
            channel.lockscreenVisibility = Notification.VISIBILITY_PRIVATE
            notificationManager.createNotificationChannel(channel)
            channelId
        } else {
            ""
        }
        notificationBuilder = NotificationCompat.Builder(this, notificationChannel)
    }

    @SuppressLint("UnspecifiedImmutableFlag")
    private fun createForegroundNotification() {
        val intent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_RESET_TASK_IF_NEEDED
            action = Intent.ACTION_MAIN
            addCategory(Intent.CATEGORY_LAUNCHER)
            putExtra("type", type)
        }
        val pendingIntent = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            PendingIntent.getActivity(this, 0, intent, FLAG_UPDATE_CURRENT or FLAG_IMMUTABLE)
        } else {
            PendingIntent.getActivity(this, 0, intent, FLAG_UPDATE_CURRENT)
        }
        val notification = notificationBuilder
            .setOngoing(true)
            .setSmallIcon(R.mipmap.ic_stat_logo)
            .setDefaults(Notification.DEFAULT_ALL)
            .setAutoCancel(true)
            .setPriority(NotificationCompat.PRIORITY_DEFAULT)
            .setContentTitle(DEFAULT_NOTIFY_TITLE)
            .setContentText(translate(DEFAULT_NOTIFY_TEXT))
            .setOnlyAlertOnce(true)
            .setContentIntent(pendingIntent)
            .setColor(ContextCompat.getColor(this, R.color.primary))
            .setWhen(System.currentTimeMillis())
            .build()
        startForeground(DEFAULT_NOTIFY_ID, notification)
    }

    private fun loginRequestNotification(
        clientID: Int,
        type: String,
        username: String,
        peerId: String
    ) {
        val notification = notificationBuilder
            .setOngoing(false)
            .setPriority(NotificationCompat.PRIORITY_MAX)
            .setContentTitle(translate("Do you accept?"))
            .setContentText("$type:$username-$peerId")
            // .setStyle(MediaStyle().setShowActionsInCompactView(0, 1))
            // .addAction(R.drawable.check_blue, "check", genLoginRequestPendingIntent(true))
            // .addAction(R.drawable.close_red, "close", genLoginRequestPendingIntent(false))
            .build()
        notificationManager.notify(getClientNotifyID(clientID), notification)
    }

    private fun onClientAuthorizedNotification(
        clientID: Int,
        type: String,
        username: String,
        peerId: String
    ) {
        cancelNotification(clientID)
        val notification = notificationBuilder
            .setOngoing(false)
            .setPriority(NotificationCompat.PRIORITY_MAX)
            .setContentTitle("$type ${translate("Established")}")
            .setContentText("$username - $peerId")
            .build()
        notificationManager.notify(getClientNotifyID(clientID), notification)
    }

    private fun voiceCallRequestNotification(
        clientID: Int,
        type: String,
        username: String,
        peerId: String
    ) {
        val notification = notificationBuilder
            .setOngoing(false)
            .setPriority(NotificationCompat.PRIORITY_MAX)
            .setContentTitle(translate("Do you accept?"))
            .setContentText("$type:$username-$peerId")
            .build()
        notificationManager.notify(getClientNotifyID(clientID), notification)
    }

    private fun getClientNotifyID(clientID: Int): Int {
        return clientID + NOTIFY_ID_OFFSET
    }

    fun cancelNotification(clientID: Int) {
        notificationManager.cancel(getClientNotifyID(clientID))
    }

    @SuppressLint("UnspecifiedImmutableFlag")
    private fun genLoginRequestPendingIntent(res: Boolean): PendingIntent {
        val intent = Intent(this, MainService::class.java).apply {
            action = ACT_LOGIN_REQ_NOTIFY
            putExtra(EXT_LOGIN_REQ_NOTIFY, res)
        }
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            PendingIntent.getService(this, 111, intent, FLAG_IMMUTABLE)
        } else {
            PendingIntent.getService(this, 111, intent, FLAG_UPDATE_CURRENT)
        }
    }

    private fun setTextNotification(_title: String?, _text: String?) {
        val title = _title ?: DEFAULT_NOTIFY_TITLE
        val text = _text ?: translate(DEFAULT_NOTIFY_TEXT)
        val notification = notificationBuilder
            .clearActions()
            .setStyle(null)
            .setContentTitle(title)
            .setContentText(text)
            .build()
        notificationManager.notify(DEFAULT_NOTIFY_ID, notification)
    }
}
