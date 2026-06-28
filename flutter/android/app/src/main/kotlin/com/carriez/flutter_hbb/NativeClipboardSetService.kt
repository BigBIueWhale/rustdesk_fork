package com.carriez.flutter_hbb

import android.app.Service
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.HandlerThread
import android.os.IBinder
import android.os.Looper
import android.os.Message
import android.os.Messenger
import android.os.Process
import android.os.RemoteException
import android.os.SharedMemory
import android.system.OsConstants
import android.util.Log
import androidx.annotation.Keep
import androidx.annotation.RequiresApi
import ffi.FFI
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.locks.ReentrantLock

private const val NCS_LOG_TAG = "NativeClipboardSet"
private const val NCS_MSG_SELF_TEST = 1
private const val NCS_MSG_SANITIZE = 2
private const val NCS_MSG_REPLY = 3
private const val NCS_STATUS_OK = 0
private const val NCS_STATUS_ERROR = 1
private const val NCS_KEY_STATUS = "status"
private const val NCS_KEY_ERROR = "error"
private const val NCS_KEY_INPUT_SHM = "input_shm"
private const val NCS_KEY_INPUT_LEN = "input_len"
private const val NCS_KEY_OUTPUT_SHM = "output_shm"
private const val NCS_KEY_OUTPUT_LEN = "output_len"
private const val NCS_BIND_TIMEOUT_MS = 2_000L
private const val NCS_SANITIZE_TIMEOUT_MS = 5_000L
private const val NCS_MAX_REQUEST_BYTES = 64 * 1024 * 1024
private const val NCS_MAX_RESPONSE_BYTES = 64 * 1024 * 1024 + 64

object NativeClipboardSetClient {
    private val requestSeq = AtomicInteger()
    private val sanitizeLock = ReentrantLock()
    private val lock = Object()
    private val replyThread = HandlerThread("rd-native-clipboard-set-client").apply { start() }

    @Volatile
    private var messenger: Messenger? = null
    @Volatile
    private var bound = false
    private var bindLatch: CountDownLatch? = null

    private val connection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, service: IBinder?) {
            synchronized(lock) {
                messenger = if (service == null) null else Messenger(service)
                bound = messenger != null
                bindLatch?.countDown()
            }
        }

        override fun onServiceDisconnected(name: ComponentName?) {
            synchronized(lock) {
                messenger = null
                bound = false
                bindLatch?.countDown()
            }
        }
    }

    fun isReady(context: Context): Boolean {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O_MR1) {
            return false
        }
        if (Looper.myLooper() == Looper.getMainLooper()) {
            Log.w(NCS_LOG_TAG, "refusing to bind isolated clipboard SET service from the main thread")
            return false
        }
        return isReadyApi27(context.applicationContext)
    }

    fun sanitize(context: Context, payload: ByteArray): ByteArray? {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O_MR1) {
            return null
        }
        if (Looper.myLooper() == Looper.getMainLooper()) {
            Log.w(NCS_LOG_TAG, "refusing synchronous clipboard SET sanitize from the main thread")
            return null
        }
        if (payload.isEmpty() || payload.size > NCS_MAX_REQUEST_BYTES) {
            Log.w(NCS_LOG_TAG, "dropping oversized isolated clipboard SET request: ${payload.size}")
            return null
        }
        if (!sanitizeLock.tryLock()) {
            Log.w(NCS_LOG_TAG, "isolated clipboard SET sanitizer busy; refusing to queue peer request")
            return null
        }
        return try {
            sanitizeApi27(context.applicationContext, payload)
        } finally {
            sanitizeLock.unlock()
        }
    }

    @RequiresApi(Build.VERSION_CODES.O_MR1)
    private fun isReadyApi27(context: Context): Boolean {
        if (!ensureBound(context)) {
            return false
        }
        val reply = sendRequest(context, Message.obtain(null, NCS_MSG_SELF_TEST), NCS_BIND_TIMEOUT_MS)
        return reply?.first == NCS_STATUS_OK
    }

    @RequiresApi(Build.VERSION_CODES.O_MR1)
    private fun sanitizeApi27(context: Context, payload: ByteArray): ByteArray? {
        if (!ensureBound(context)) {
            return null
        }

        var inputMemory: SharedMemory? = null
        try {
            inputMemory = SharedMemory.create("rd-native-clipboard-set-input", payload.size)
            val inputMap = inputMemory.mapReadWrite()
            try {
                inputMap.put(payload)
            } finally {
                SharedMemory.unmap(inputMap)
            }
            inputMemory.setProtect(OsConstants.PROT_READ)

            val msg = Message.obtain(null, NCS_MSG_SANITIZE)
            msg.data = Bundle().apply {
                putParcelable(NCS_KEY_INPUT_SHM, inputMemory)
                putInt(NCS_KEY_INPUT_LEN, payload.size)
            }
            val reply = sendRequest(context, msg, NCS_SANITIZE_TIMEOUT_MS) ?: return null
            if (reply.first != NCS_STATUS_OK) {
                Log.w(NCS_LOG_TAG, "isolated clipboard SET sanitizer failed: ${reply.second}")
                return null
            }
            val data = reply.third ?: return null
            val outputMemory = data.first
            val outputLength = data.second
            if (outputLength <= 0 || outputLength > NCS_MAX_RESPONSE_BYTES) {
                outputMemory.close()
                Log.w(NCS_LOG_TAG, "isolated clipboard SET sanitizer returned invalid length: $outputLength")
                return null
            }
            val outputMap = outputMemory.mapReadOnly()
            return try {
                if (outputLength > outputMap.remaining()) {
                    Log.w(NCS_LOG_TAG, "isolated clipboard SET shared memory shorter than reply")
                    null
                } else {
                    ByteArray(outputLength).also { outputMap.get(it) }
                }
            } finally {
                SharedMemory.unmap(outputMap)
                outputMemory.close()
            }
        } catch (e: Exception) {
            Log.w(NCS_LOG_TAG, "isolated clipboard SET bridge failed", e)
            reset(context)
            return null
        } finally {
            inputMemory?.close()
        }
    }

    @RequiresApi(Build.VERSION_CODES.O_MR1)
    private fun ensureBound(context: Context): Boolean {
        messenger?.let { return true }
        val latch: CountDownLatch
        synchronized(lock) {
            messenger?.let { return true }
            latch = CountDownLatch(1)
            bindLatch = latch
            val intent = Intent(context, NativeClipboardSetService::class.java)
            if (!context.bindService(intent, connection, Context.BIND_AUTO_CREATE)) {
                bindLatch = null
                return false
            }
        }
        if (!latch.await(NCS_BIND_TIMEOUT_MS, TimeUnit.MILLISECONDS)) {
            Log.w(NCS_LOG_TAG, "timed out binding isolated clipboard SET service")
            reset(context)
            return false
        }
        return messenger != null
    }

    @RequiresApi(Build.VERSION_CODES.O_MR1)
    private fun sendRequest(
        context: Context,
        message: Message,
        timeoutMs: Long
    ): Triple<Int, String?, Pair<SharedMemory, Int>?>? {
        val current = messenger ?: return null
        val latch = CountDownLatch(1)
        var status = NCS_STATUS_ERROR
        var error: String? = null
        var output: Pair<SharedMemory, Int>? = null
        val replyHandler = Handler(replyThread.looper) { reply ->
            if (reply.what != NCS_MSG_REPLY) {
                return@Handler false
            }
            reply.data.classLoader = SharedMemory::class.java.classLoader
            status = reply.data.getInt(NCS_KEY_STATUS, NCS_STATUS_ERROR)
            error = reply.data.getString(NCS_KEY_ERROR)
            if (status == NCS_STATUS_OK && reply.data.containsKey(NCS_KEY_OUTPUT_SHM)) {
                @Suppress("DEPRECATION")
                val outputMemory = reply.data.getParcelable<SharedMemory>(NCS_KEY_OUTPUT_SHM)
                val outputLength = reply.data.getInt(NCS_KEY_OUTPUT_LEN, 0)
                if (outputMemory != null) {
                    output = Pair(outputMemory, outputLength)
                }
            }
            latch.countDown()
            true
        }
        message.replyTo = Messenger(replyHandler)
        message.arg1 = requestSeq.incrementAndGet()
        return try {
            current.send(message)
            if (!latch.await(timeoutMs, TimeUnit.MILLISECONDS)) {
                Log.w(NCS_LOG_TAG, "isolated clipboard SET request timed out")
                reset(context)
                null
            } else {
                Triple(status, error, output)
            }
        } catch (e: RemoteException) {
            Log.w(NCS_LOG_TAG, "isolated clipboard SET binder send failed", e)
            reset(context)
            null
        }
    }

    private fun reset(context: Context) {
        synchronized(lock) {
            if (bound) {
                try {
                    context.unbindService(connection)
                } catch (_: IllegalArgumentException) {
                }
            }
            messenger = null
            bound = false
            bindLatch?.countDown()
            bindLatch = null
        }
    }
}

class NativeClipboardSetService : Service() {
    private lateinit var handlerThread: HandlerThread
    private lateinit var messenger: Messenger

    override fun onCreate() {
        super.onCreate()
        FFI.onAppStart(applicationContext)
        handlerThread = HandlerThread("rd-native-clipboard-set-isolated").apply { start() }
        messenger = Messenger(IncomingHandler(handlerThread.looper))
    }

    override fun onBind(intent: Intent?): IBinder {
        return messenger.binder
    }

    override fun onDestroy() {
        handlerThread.quitSafely()
        super.onDestroy()
    }

    private inner class IncomingHandler(looper: Looper) : Handler(looper) {
        override fun handleMessage(msg: Message) {
            when (msg.what) {
                NCS_MSG_SELF_TEST -> handleSelfTest(msg)
                NCS_MSG_SANITIZE -> {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O_MR1) {
                        handleSanitizeApi27(msg)
                    } else {
                        replyError(msg, "SharedMemory is unavailable on this Android release")
                    }
                }
                else -> replyError(msg, "unsupported isolated clipboard SET operation")
            }
        }
    }

    private fun handleSelfTest(msg: Message) {
        val isolated = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            Process.isIsolated()
        } else {
            true
        }
        if (!isolated) {
            replyError(msg, "native clipboard SET service is not isolated")
            return
        }
        if (!nativeSelfTest()) {
            replyError(msg, "native clipboard SET self-test failed")
            return
        }
        replyOk(msg, null, 0)
    }

    @RequiresApi(Build.VERSION_CODES.O_MR1)
    private fun handleSanitizeApi27(msg: Message) {
        msg.data.classLoader = SharedMemory::class.java.classLoader
        @Suppress("DEPRECATION")
        val inputMemory = msg.data.getParcelable<SharedMemory>(NCS_KEY_INPUT_SHM)
        val inputLength = msg.data.getInt(NCS_KEY_INPUT_LEN, 0)
        if (inputMemory == null) {
            replyError(msg, "missing isolated clipboard SET input memory")
            return
        }
        if (inputLength <= 0 || inputLength > NCS_MAX_REQUEST_BYTES) {
            replyError(msg, "invalid isolated clipboard SET input length")
            return
        }

        var outputMemory: SharedMemory? = null
        try {
            val inputMap = inputMemory.mapReadOnly()
            val payload = try {
                if (inputLength > inputMap.remaining()) {
                    replyError(msg, "isolated clipboard SET input memory shorter than declared")
                    return
                }
                ByteArray(inputLength).also { inputMap.get(it) }
            } finally {
                SharedMemory.unmap(inputMap)
            }
            val response = nativeSanitize(payload)
            if (response == null || response.isEmpty() || response.size > NCS_MAX_RESPONSE_BYTES) {
                replyError(msg, "invalid native clipboard SET response length")
                return
            }
            outputMemory = SharedMemory.create("rd-native-clipboard-set-output", response.size)
            val outputMap = outputMemory.mapReadWrite()
            try {
                outputMap.put(response)
            } finally {
                SharedMemory.unmap(outputMap)
            }
            outputMemory.setProtect(OsConstants.PROT_READ)
            replyOk(msg, outputMemory, response.size)
        } catch (e: Exception) {
            replyError(msg, "isolated clipboard SET service failed: ${e.message}")
        } finally {
            outputMemory?.close()
            inputMemory.close()
        }
    }

    private fun replyOk(msg: Message, outputMemory: SharedMemory?, outputLength: Int) {
        val reply = Message.obtain(null, NCS_MSG_REPLY)
        reply.data = Bundle().apply {
            putInt(NCS_KEY_STATUS, NCS_STATUS_OK)
            if (outputMemory != null) {
                putParcelable(NCS_KEY_OUTPUT_SHM, outputMemory)
                putInt(NCS_KEY_OUTPUT_LEN, outputLength)
            }
        }
        sendReply(msg, reply)
    }

    private fun replyError(msg: Message, error: String) {
        val reply = Message.obtain(null, NCS_MSG_REPLY)
        reply.data = Bundle().apply {
            putInt(NCS_KEY_STATUS, NCS_STATUS_ERROR)
            putString(NCS_KEY_ERROR, error)
        }
        sendReply(msg, reply)
    }

    private fun sendReply(msg: Message, reply: Message) {
        try {
            msg.replyTo?.send(reply)
        } catch (e: RemoteException) {
            Log.w(NCS_LOG_TAG, "failed to reply from isolated clipboard SET service", e)
        }
    }

    @Keep
    private external fun nativeSelfTest(): Boolean

    @Keep
    private external fun nativeSanitize(payload: ByteArray): ByteArray?
}
