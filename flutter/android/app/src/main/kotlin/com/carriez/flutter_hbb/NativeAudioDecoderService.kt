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

private const val NAD_LOG_TAG = "NativeAudioDecoder"
private const val NAD_MSG_SELF_TEST = 1
private const val NAD_MSG_DECODE = 2
private const val NAD_MSG_REPLY = 3
private const val NAD_STATUS_OK = 0
private const val NAD_STATUS_ERROR = 1
private const val NAD_KEY_STATUS = "status"
private const val NAD_KEY_ERROR = "error"
private const val NAD_KEY_INPUT_SHM = "input_shm"
private const val NAD_KEY_INPUT_LEN = "input_len"
private const val NAD_KEY_OUTPUT_SHM = "output_shm"
private const val NAD_KEY_OUTPUT_LEN = "output_len"
private const val NAD_KEY_SAMPLE_RATE = "sample_rate"
private const val NAD_KEY_CHANNELS = "channels"
private const val NAD_KEY_DECODE_FEC = "decode_fec"
private const val NAD_BIND_TIMEOUT_MS = 2_000L
private const val NAD_DECODE_TIMEOUT_MS = 3_000L
private const val NAD_MAX_REQUEST_BYTES = 4 * 1024
private const val NAD_MAX_RESPONSE_BYTES = 512 * 1024

object NativeAudioDecoderClient {
    private val requestSeq = AtomicInteger()
    private val decodeLock = Object()
    private val lock = Object()
    private val replyThread = HandlerThread("rd-native-audio-client").apply { start() }

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
            Log.w(NAD_LOG_TAG, "refusing to bind isolated Opus decoder service from the main thread")
            return false
        }
        return isReadyApi27(context.applicationContext)
    }

    fun decode(
        context: Context,
        payload: ByteArray,
        sampleRate: Int,
        channels: Int,
        decodeFec: Boolean
    ): ByteArray? {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O_MR1) {
            return null
        }
        if (Looper.myLooper() == Looper.getMainLooper()) {
            Log.w(NAD_LOG_TAG, "refusing synchronous Opus decode from the main thread")
            return null
        }
        if (payload.isEmpty() || payload.size > NAD_MAX_REQUEST_BYTES) {
            Log.w(NAD_LOG_TAG, "dropping oversized isolated Opus decode request: ${payload.size}")
            return null
        }
        return synchronized(decodeLock) {
            decodeApi27(context.applicationContext, payload, sampleRate, channels, decodeFec)
        }
    }

    @RequiresApi(Build.VERSION_CODES.O_MR1)
    private fun isReadyApi27(context: Context): Boolean {
        if (!ensureBound(context)) {
            return false
        }
        val reply = sendRequest(context, Message.obtain(null, NAD_MSG_SELF_TEST), NAD_BIND_TIMEOUT_MS)
        return reply?.first == NAD_STATUS_OK
    }

    @RequiresApi(Build.VERSION_CODES.O_MR1)
    private fun decodeApi27(
        context: Context,
        payload: ByteArray,
        sampleRate: Int,
        channels: Int,
        decodeFec: Boolean
    ): ByteArray? {
        if (!ensureBound(context)) {
            return null
        }

        var inputMemory: SharedMemory? = null
        try {
            inputMemory = SharedMemory.create("rd-native-opus-input", payload.size)
            val inputMap = inputMemory.mapReadWrite()
            try {
                inputMap.put(payload)
            } finally {
                SharedMemory.unmap(inputMap)
            }
            inputMemory.setProtect(OsConstants.PROT_READ)

            val msg = Message.obtain(null, NAD_MSG_DECODE)
            msg.data = Bundle().apply {
                putParcelable(NAD_KEY_INPUT_SHM, inputMemory)
                putInt(NAD_KEY_INPUT_LEN, payload.size)
                putInt(NAD_KEY_SAMPLE_RATE, sampleRate)
                putInt(NAD_KEY_CHANNELS, channels)
                putBoolean(NAD_KEY_DECODE_FEC, decodeFec)
            }
            val reply = sendRequest(context, msg, NAD_DECODE_TIMEOUT_MS) ?: return null
            if (reply.first != NAD_STATUS_OK) {
                Log.w(NAD_LOG_TAG, "isolated Opus decoder failed: ${reply.second}")
                return null
            }
            val data = reply.third ?: return null
            val outputMemory = data.first
            val outputLength = data.second
            if (outputLength <= 0 || outputLength > NAD_MAX_RESPONSE_BYTES) {
                outputMemory.close()
                Log.w(NAD_LOG_TAG, "isolated Opus decoder returned invalid length: $outputLength")
                return null
            }
            val outputMap = outputMemory.mapReadOnly()
            return try {
                if (outputLength > outputMap.remaining()) {
                    Log.w(NAD_LOG_TAG, "isolated Opus decoder shared memory shorter than reply")
                    null
                } else {
                    ByteArray(outputLength).also { outputMap.get(it) }
                }
            } finally {
                SharedMemory.unmap(outputMap)
                outputMemory.close()
            }
        } catch (e: Exception) {
            Log.w(NAD_LOG_TAG, "isolated Opus decode bridge failed", e)
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
            val intent = Intent(context, NativeAudioDecoderService::class.java)
            if (!context.bindService(intent, connection, Context.BIND_AUTO_CREATE)) {
                bindLatch = null
                return false
            }
        }
        if (!latch.await(NAD_BIND_TIMEOUT_MS, TimeUnit.MILLISECONDS)) {
            Log.w(NAD_LOG_TAG, "timed out binding isolated Opus decoder service")
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
        var status = NAD_STATUS_ERROR
        var error: String? = null
        var output: Pair<SharedMemory, Int>? = null
        val replyHandler = Handler(replyThread.looper) { reply ->
            if (reply.what != NAD_MSG_REPLY) {
                return@Handler false
            }
            reply.data.classLoader = SharedMemory::class.java.classLoader
            status = reply.data.getInt(NAD_KEY_STATUS, NAD_STATUS_ERROR)
            error = reply.data.getString(NAD_KEY_ERROR)
            if (status == NAD_STATUS_OK && reply.data.containsKey(NAD_KEY_OUTPUT_SHM)) {
                @Suppress("DEPRECATION")
                val outputMemory = reply.data.getParcelable<SharedMemory>(NAD_KEY_OUTPUT_SHM)
                val outputLength = reply.data.getInt(NAD_KEY_OUTPUT_LEN, 0)
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
                Log.w(NAD_LOG_TAG, "isolated Opus decoder request timed out")
                reset(context)
                null
            } else {
                Triple(status, error, output)
            }
        } catch (e: RemoteException) {
            Log.w(NAD_LOG_TAG, "isolated Opus decoder binder send failed", e)
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

class NativeAudioDecoderService : Service() {
    private lateinit var handlerThread: HandlerThread
    private lateinit var messenger: Messenger

    override fun onCreate() {
        super.onCreate()
        FFI.onAppStart(applicationContext)
        handlerThread = HandlerThread("rd-native-audio-isolated").apply { start() }
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
                NAD_MSG_SELF_TEST -> handleSelfTest(msg)
                NAD_MSG_DECODE -> {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O_MR1) {
                        handleDecodeApi27(msg)
                    } else {
                        replyError(msg, "SharedMemory is unavailable on this Android release")
                    }
                }
                else -> replyError(msg, "unsupported isolated Opus decoder operation")
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
            replyError(msg, "native Opus decoder service is not isolated")
            return
        }
        if (!nativeSelfTest()) {
            replyError(msg, "native Opus decoder self-test failed")
            return
        }
        replyOk(msg, null, 0)
    }

    @RequiresApi(Build.VERSION_CODES.O_MR1)
    private fun handleDecodeApi27(msg: Message) {
        msg.data.classLoader = SharedMemory::class.java.classLoader
        @Suppress("DEPRECATION")
        val inputMemory = msg.data.getParcelable<SharedMemory>(NAD_KEY_INPUT_SHM)
        val inputLength = msg.data.getInt(NAD_KEY_INPUT_LEN, 0)
        val sampleRate = msg.data.getInt(NAD_KEY_SAMPLE_RATE, 0)
        val channels = msg.data.getInt(NAD_KEY_CHANNELS, 0)
        val decodeFec = msg.data.getBoolean(NAD_KEY_DECODE_FEC, false)
        if (inputMemory == null) {
            replyError(msg, "missing isolated Opus decoder input memory")
            return
        }
        if (inputLength <= 0 || inputLength > NAD_MAX_REQUEST_BYTES) {
            replyError(msg, "invalid isolated Opus decoder input length")
            return
        }

        var outputMemory: SharedMemory? = null
        try {
            val inputMap = inputMemory.mapReadOnly()
            val payload = try {
                if (inputLength > inputMap.remaining()) {
                    replyError(msg, "isolated Opus decoder input memory shorter than declared")
                    return
                }
                ByteArray(inputLength).also { inputMap.get(it) }
            } finally {
                SharedMemory.unmap(inputMap)
            }
            val response = nativeDecode(sampleRate, channels, decodeFec, payload)
            if (response == null || response.isEmpty() || response.size > NAD_MAX_RESPONSE_BYTES) {
                replyError(msg, "invalid native Opus decoder response length")
                return
            }
            outputMemory = SharedMemory.create("rd-native-opus-output", response.size)
            val outputMap = outputMemory.mapReadWrite()
            try {
                outputMap.put(response)
            } finally {
                SharedMemory.unmap(outputMap)
            }
            outputMemory.setProtect(OsConstants.PROT_READ)
            replyOk(msg, outputMemory, response.size)
        } catch (e: Exception) {
            replyError(msg, "isolated Opus decoder service failed: ${e.message}")
        } finally {
            outputMemory?.close()
            inputMemory.close()
        }
    }

    private fun replyOk(msg: Message, outputMemory: SharedMemory?, outputLength: Int) {
        val reply = Message.obtain(null, NAD_MSG_REPLY)
        reply.data = Bundle().apply {
            putInt(NAD_KEY_STATUS, NAD_STATUS_OK)
            if (outputMemory != null) {
                putParcelable(NAD_KEY_OUTPUT_SHM, outputMemory)
                putInt(NAD_KEY_OUTPUT_LEN, outputLength)
            }
        }
        sendReply(msg, reply)
    }

    private fun replyError(msg: Message, error: String) {
        val reply = Message.obtain(null, NAD_MSG_REPLY)
        reply.data = Bundle().apply {
            putInt(NAD_KEY_STATUS, NAD_STATUS_ERROR)
            putString(NAD_KEY_ERROR, error)
        }
        sendReply(msg, reply)
    }

    private fun sendReply(msg: Message, reply: Message) {
        try {
            msg.replyTo?.send(reply)
        } catch (e: RemoteException) {
            Log.w(NAD_LOG_TAG, "failed to reply from isolated Opus decoder service", e)
        }
    }

    @Keep
    private external fun nativeSelfTest(): Boolean

    @Keep
    private external fun nativeDecode(
        sampleRate: Int,
        channels: Int,
        decodeFec: Boolean,
        payload: ByteArray
    ): ByteArray?
}
