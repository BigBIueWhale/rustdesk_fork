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

private const val NVD_LOG_TAG = "NativeVideoDecoder"
private const val NVD_MSG_SELF_TEST = 1
private const val NVD_MSG_DECODE = 2
private const val NVD_MSG_REPLY = 3
private const val NVD_STATUS_OK = 0
private const val NVD_STATUS_ERROR = 1
private const val NVD_KEY_STATUS = "status"
private const val NVD_KEY_ERROR = "error"
private const val NVD_KEY_INPUT_SHM = "input_shm"
private const val NVD_KEY_INPUT_LEN = "input_len"
private const val NVD_KEY_OUTPUT_SHM = "output_shm"
private const val NVD_KEY_OUTPUT_LEN = "output_len"
private const val NVD_KEY_CODEC = "codec"
private const val NVD_KEY_IMAGE_FORMAT = "image_format"
private const val NVD_KEY_ALIGN = "align"
private const val NVD_BIND_TIMEOUT_MS = 2_000L
private const val NVD_DECODE_TIMEOUT_MS = 10_000L
private const val NVD_MAX_REQUEST_BYTES = 32 * 1024 * 1024
private const val NVD_MAX_RESPONSE_BYTES = 160 * 1024 * 1024 + 64 * 1024

object NativeVideoDecoderClient {
    private val requestSeq = AtomicInteger()
    private val decodeLock = Object()
    private val lock = Object()
    private val replyThread = HandlerThread("rd-native-video-client").apply { start() }

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
            Log.w(NVD_LOG_TAG, "refusing to bind isolated decoder service from the main thread")
            return false
        }
        return isReadyApi27(context.applicationContext)
    }

    fun decode(
        context: Context,
        payload: ByteArray,
        codec: Int,
        imageFormat: Int,
        align: Int
    ): ByteArray? {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O_MR1) {
            return null
        }
        if (Looper.myLooper() == Looper.getMainLooper()) {
            Log.w(NVD_LOG_TAG, "refusing synchronous video decode from the main thread")
            return null
        }
        if (payload.isEmpty() || payload.size > NVD_MAX_REQUEST_BYTES) {
            Log.w(NVD_LOG_TAG, "dropping oversized isolated video decode request: ${payload.size}")
            return null
        }
        return synchronized(decodeLock) {
            decodeApi27(context.applicationContext, payload, codec, imageFormat, align)
        }
    }

    @RequiresApi(Build.VERSION_CODES.O_MR1)
    private fun isReadyApi27(context: Context): Boolean {
        if (!ensureBound(context)) {
            return false
        }
        val reply = sendRequest(context, Message.obtain(null, NVD_MSG_SELF_TEST), NVD_BIND_TIMEOUT_MS)
        return reply?.first == NVD_STATUS_OK
    }

    @RequiresApi(Build.VERSION_CODES.O_MR1)
    private fun decodeApi27(
        context: Context,
        payload: ByteArray,
        codec: Int,
        imageFormat: Int,
        align: Int
    ): ByteArray? {
        if (!ensureBound(context)) {
            return null
        }

        var inputMemory: SharedMemory? = null
        try {
            inputMemory = SharedMemory.create("rd-native-video-input", payload.size)
            val inputMap = inputMemory.mapReadWrite()
            try {
                inputMap.put(payload)
            } finally {
                SharedMemory.unmap(inputMap)
            }
            inputMemory.setProtect(OsConstants.PROT_READ)

            val msg = Message.obtain(null, NVD_MSG_DECODE)
            msg.data = Bundle().apply {
                putParcelable(NVD_KEY_INPUT_SHM, inputMemory)
                putInt(NVD_KEY_INPUT_LEN, payload.size)
                putInt(NVD_KEY_CODEC, codec)
                putInt(NVD_KEY_IMAGE_FORMAT, imageFormat)
                putInt(NVD_KEY_ALIGN, align)
            }
            val reply = sendRequest(context, msg, NVD_DECODE_TIMEOUT_MS) ?: return null
            if (reply.first != NVD_STATUS_OK) {
                Log.w(NVD_LOG_TAG, "isolated video decoder failed: ${reply.second}")
                return null
            }
            val data = reply.third ?: return null
            val outputMemory = data.first
            val outputLength = data.second
            if (outputLength <= 0 || outputLength > NVD_MAX_RESPONSE_BYTES) {
                outputMemory.close()
                Log.w(NVD_LOG_TAG, "isolated video decoder returned invalid length: $outputLength")
                return null
            }
            val outputMap = outputMemory.mapReadOnly()
            return try {
                if (outputLength > outputMap.remaining()) {
                    Log.w(NVD_LOG_TAG, "isolated video decoder shared memory shorter than reply")
                    null
                } else {
                    ByteArray(outputLength).also { outputMap.get(it) }
                }
            } finally {
                SharedMemory.unmap(outputMap)
                outputMemory.close()
            }
        } catch (e: Exception) {
            Log.w(NVD_LOG_TAG, "isolated video decode bridge failed", e)
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
            val intent = Intent(context, NativeVideoDecoderService::class.java)
            if (!context.bindService(intent, connection, Context.BIND_AUTO_CREATE)) {
                bindLatch = null
                return false
            }
        }
        if (!latch.await(NVD_BIND_TIMEOUT_MS, TimeUnit.MILLISECONDS)) {
            Log.w(NVD_LOG_TAG, "timed out binding isolated video decoder service")
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
        var status = NVD_STATUS_ERROR
        var error: String? = null
        var output: Pair<SharedMemory, Int>? = null
        val replyHandler = Handler(replyThread.looper) { reply ->
            if (reply.what != NVD_MSG_REPLY) {
                return@Handler false
            }
            reply.data.classLoader = SharedMemory::class.java.classLoader
            status = reply.data.getInt(NVD_KEY_STATUS, NVD_STATUS_ERROR)
            error = reply.data.getString(NVD_KEY_ERROR)
            if (status == NVD_STATUS_OK && reply.data.containsKey(NVD_KEY_OUTPUT_SHM)) {
                @Suppress("DEPRECATION")
                val outputMemory = reply.data.getParcelable<SharedMemory>(NVD_KEY_OUTPUT_SHM)
                val outputLength = reply.data.getInt(NVD_KEY_OUTPUT_LEN, 0)
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
                Log.w(NVD_LOG_TAG, "isolated video decoder request timed out")
                reset(context)
                null
            } else {
                Triple(status, error, output)
            }
        } catch (e: RemoteException) {
            Log.w(NVD_LOG_TAG, "isolated video decoder binder send failed", e)
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

class NativeVideoDecoderService : Service() {
    private lateinit var handlerThread: HandlerThread
    private lateinit var messenger: Messenger

    override fun onCreate() {
        super.onCreate()
        FFI.onAppStart(applicationContext)
        handlerThread = HandlerThread("rd-native-video-isolated").apply { start() }
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
                NVD_MSG_SELF_TEST -> handleSelfTest(msg)
                NVD_MSG_DECODE -> {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O_MR1) {
                        handleDecodeApi27(msg)
                    } else {
                        replyError(msg, "SharedMemory is unavailable on this Android release")
                    }
                }
                else -> replyError(msg, "unsupported isolated video decoder operation")
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
            replyError(msg, "native video decoder service is not isolated")
            return
        }
        if (!nativeSelfTest()) {
            replyError(msg, "native video decoder self-test failed")
            return
        }
        replyOk(msg, null, 0)
    }

    @RequiresApi(Build.VERSION_CODES.O_MR1)
    private fun handleDecodeApi27(msg: Message) {
        msg.data.classLoader = SharedMemory::class.java.classLoader
        @Suppress("DEPRECATION")
        val inputMemory = msg.data.getParcelable<SharedMemory>(NVD_KEY_INPUT_SHM)
        val inputLength = msg.data.getInt(NVD_KEY_INPUT_LEN, 0)
        val codec = msg.data.getInt(NVD_KEY_CODEC, 0)
        val imageFormat = msg.data.getInt(NVD_KEY_IMAGE_FORMAT, 0)
        val align = msg.data.getInt(NVD_KEY_ALIGN, 0)
        if (inputMemory == null) {
            replyError(msg, "missing isolated video decoder input memory")
            return
        }
        if (inputLength <= 0 || inputLength > NVD_MAX_REQUEST_BYTES) {
            replyError(msg, "invalid isolated video decoder input length")
            return
        }

        var outputMemory: SharedMemory? = null
        try {
            val inputMap = inputMemory.mapReadOnly()
            val payload = try {
                if (inputLength > inputMap.remaining()) {
                    replyError(msg, "isolated video decoder input memory shorter than declared")
                    return
                }
                ByteArray(inputLength).also { inputMap.get(it) }
            } finally {
                SharedMemory.unmap(inputMap)
            }
            val response = nativeDecode(codec, imageFormat, align, payload)
            if (response == null || response.isEmpty() || response.size > NVD_MAX_RESPONSE_BYTES) {
                replyError(msg, "invalid native video decoder response length")
                return
            }
            outputMemory = SharedMemory.create("rd-native-video-output", response.size)
            val outputMap = outputMemory.mapReadWrite()
            try {
                outputMap.put(response)
            } finally {
                SharedMemory.unmap(outputMap)
            }
            outputMemory.setProtect(OsConstants.PROT_READ)
            replyOk(msg, outputMemory, response.size)
        } catch (e: Exception) {
            replyError(msg, "isolated video decoder service failed: ${e.message}")
        } finally {
            outputMemory?.close()
            inputMemory.close()
        }
    }

    private fun replyOk(msg: Message, outputMemory: SharedMemory?, outputLength: Int) {
        val reply = Message.obtain(null, NVD_MSG_REPLY)
        reply.data = Bundle().apply {
            putInt(NVD_KEY_STATUS, NVD_STATUS_OK)
            if (outputMemory != null) {
                putParcelable(NVD_KEY_OUTPUT_SHM, outputMemory)
                putInt(NVD_KEY_OUTPUT_LEN, outputLength)
            }
        }
        sendReply(msg, reply)
    }

    private fun replyError(msg: Message, error: String) {
        val reply = Message.obtain(null, NVD_MSG_REPLY)
        reply.data = Bundle().apply {
            putInt(NVD_KEY_STATUS, NVD_STATUS_ERROR)
            putString(NVD_KEY_ERROR, error)
        }
        sendReply(msg, reply)
    }

    private fun sendReply(msg: Message, reply: Message) {
        try {
            msg.replyTo?.send(reply)
        } catch (e: RemoteException) {
            Log.w(NVD_LOG_TAG, "failed to reply from isolated video decoder service", e)
        }
    }

    @Keep
    private external fun nativeSelfTest(): Boolean

    @Keep
    private external fun nativeDecode(
        codec: Int,
        imageFormat: Int,
        align: Int,
        payload: ByteArray
    ): ByteArray?
}
