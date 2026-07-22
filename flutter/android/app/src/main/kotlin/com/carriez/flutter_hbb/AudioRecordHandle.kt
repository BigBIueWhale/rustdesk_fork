package com.carriez.flutter_hbb

import ffi.FFI

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.media.AudioAttributes
import android.media.AudioFormat
import android.media.AudioPlaybackCaptureConfiguration
import android.media.AudioRecord
import android.media.MediaRecorder
import android.media.projection.MediaProjection
import android.os.Build
import android.util.Log
import androidx.core.app.ActivityCompat
import kotlin.concurrent.thread

const val AUDIO_ENCODING = AudioFormat.ENCODING_PCM_FLOAT
const val AUDIO_SAMPLE_RATE = 48000
const val AUDIO_CHANNEL_MASK = AudioFormat.CHANNEL_IN_STEREO

private enum class AudioCaptureMode {
    STOPPED,
    PLAYBACK,
    VOICE_CALL,
}

internal class AudioRecordHandle(private val context: Context) {
    private val logTag = "LOG_AUDIO_RECORD_HANDLE"

    @Volatile
    private var audioRecorder: AudioRecord? = null
    private var audioReader: AudioReader? = null
    private var minBufferSize = 0
    @Volatile
    private var audioRecordStat = false
    @Volatile
    private var captureMode = AudioCaptureMode.STOPPED
    @Volatile
    private var captureProjection: MediaProjection? = null
    private var audioThread: Thread? = null

    private fun createAudioRecorder(
        mode: AudioCaptureMode,
        mediaProjection: MediaProjection?,
    ): Boolean {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
            return false
        }
        if (ActivityCompat.checkSelfPermission(
                context,
                Manifest.permission.RECORD_AUDIO,
            ) != PackageManager.PERMISSION_GRANTED
        ) {
            Log.d(logTag, "createAudioRecorder failed, no RECORD_AUDIO permission")
            return false
        }

        val builder = AudioRecord.Builder().setAudioFormat(
            AudioFormat.Builder()
                .setEncoding(AUDIO_ENCODING)
                .setSampleRate(AUDIO_SAMPLE_RATE)
                .setChannelMask(AUDIO_CHANNEL_MASK)
                .build(),
        )
        when (mode) {
            AudioCaptureMode.VOICE_CALL -> {
                builder.setAudioSource(MediaRecorder.AudioSource.VOICE_COMMUNICATION)
            }
            AudioCaptureMode.PLAYBACK -> {
                val projection = mediaProjection
                if (projection == null) {
                    Log.d(logTag, "createAudioRecorder failed, mediaProjection null")
                    return false
                }
                val configuration = AudioPlaybackCaptureConfiguration.Builder(projection)
                    .addMatchingUsage(AudioAttributes.USAGE_MEDIA)
                    .addMatchingUsage(AudioAttributes.USAGE_ALARM)
                    .addMatchingUsage(AudioAttributes.USAGE_GAME)
                    .addMatchingUsage(AudioAttributes.USAGE_UNKNOWN)
                    .build()
                builder.setAudioPlaybackCaptureConfig(configuration)
            }
            AudioCaptureMode.STOPPED -> return false
        }

        val recorder = try {
            builder.build()
        } catch (e: Exception) {
            Log.e(logTag, "createAudioRecorder failed", e)
            return false
        }
        if (recorder.state != AudioRecord.STATE_INITIALIZED) {
            Log.e(logTag, "createAudioRecorder returned an uninitialized recorder")
            try {
                recorder.release()
            } catch (e: Exception) {
                Log.w(logTag, "release uninitialized audio recorder failed", e)
            }
            return false
        }
        audioRecorder = recorder
        captureProjection = if (mode == AudioCaptureMode.PLAYBACK) mediaProjection else null
        return true
    }

    private fun checkAudioReader(): Boolean {
        if (audioReader != null && minBufferSize > 0) {
            return true
        }
        val platformMinBufferSize = AudioRecord.getMinBufferSize(
            AUDIO_SAMPLE_RATE,
            AUDIO_CHANNEL_MASK,
            AUDIO_ENCODING,
        )
        if (platformMinBufferSize <= 0) {
            Log.e(logTag, "getMinBufferSize failed: $platformMinBufferSize")
            return false
        }
        val requestedBufferSize = platformMinBufferSize.toLong() * 2L * 4L
        if (requestedBufferSize > Int.MAX_VALUE) {
            Log.e(logTag, "audio buffer size overflow: $requestedBufferSize")
            return false
        }
        minBufferSize = requestedBufferSize.toInt()
        audioReader = try {
            AudioReader(minBufferSize, 4)
        } catch (e: OutOfMemoryError) {
            Log.e(logTag, "failed to allocate audio reader", e)
            minBufferSize = 0
            null
        } catch (e: Exception) {
            Log.e(logTag, "failed to allocate audio reader", e)
            minBufferSize = 0
            null
        }
        return audioReader != null
    }

    private fun startAudioRecorder(mode: AudioCaptureMode): Boolean {
        if (!checkAudioReader()) {
            stopAudioRecorder()
            return false
        }
        val reader = audioReader
        val recorder = audioRecorder
        if (reader == null || recorder == null || minBufferSize <= 0) {
            Log.e(logTag, "startAudioRecorder missing initialized resources")
            stopAudioRecorder()
            return false
        }
        return try {
            FFI.setFrameRawEnable("audio", true)
            recorder.startRecording()
            if (recorder.recordingState != AudioRecord.RECORDSTATE_RECORDING) {
                throw IllegalStateException("AudioRecord did not enter RECORDSTATE_RECORDING")
            }
            audioRecordStat = true
            captureMode = mode
            val worker = thread(
                start = false,
                name = "rustdesk-android-audio",
            ) {
                try {
                    while (audioRecordStat) {
                        val frame = reader.readSync(recorder) ?: break
                        FFI.onAudioFrameUpdate(frame)
                    }
                } catch (e: Exception) {
                    if (audioRecordStat) {
                        Log.e(logTag, "audio recorder thread failed", e)
                    }
                } finally {
                    try {
                        if (recorder.recordingState == AudioRecord.RECORDSTATE_RECORDING) {
                            recorder.stop()
                        }
                    } catch (e: IllegalStateException) {
                        Log.w(logTag, "stop completed audio recorder failed", e)
                    }
                    try {
                        recorder.release()
                    } catch (e: Exception) {
                        Log.w(logTag, "release audio recorder failed", e)
                    }
                    if (audioRecorder === recorder) {
                        audioRecordStat = false
                        audioRecorder = null
                        audioReader = null
                        minBufferSize = 0
                        captureMode = AudioCaptureMode.STOPPED
                        captureProjection = null
                        FFI.setFrameRawEnable("audio", false)
                    }
                    Log.d(logTag, "Exit audio thread")
                }
            }
            audioThread = worker
            worker.start()
            true
        } catch (e: Exception) {
            Log.e(logTag, "startAudioRecorder failed", e)
            stopAudioRecorder()
            false
        }
    }

    private fun stopAudioRecorder() {
        audioRecordStat = false
        val recorder = audioRecorder
        if (recorder != null) {
            try {
                if (recorder.recordingState == AudioRecord.RECORDSTATE_RECORDING) {
                    recorder.stop()
                }
            } catch (e: IllegalStateException) {
                Log.w(logTag, "stop audio recorder failed", e)
            }
        }

        val worker = audioThread
        if (worker != null && worker !== Thread.currentThread()) {
            var interrupted = false
            while (worker.isAlive) {
                try {
                    worker.join()
                } catch (e: InterruptedException) {
                    interrupted = true
                }
            }
            if (interrupted) {
                Thread.currentThread().interrupt()
            }
        }
        if (audioThread === worker) {
            audioThread = null
        }

        if ((worker == null || !worker.isAlive) && recorder != null && audioRecorder === recorder) {
            try {
                recorder.release()
            } catch (e: Exception) {
                Log.w(logTag, "release audio recorder failed", e)
            }
            audioRecorder = null
            audioReader = null
            minBufferSize = 0
            captureMode = AudioCaptureMode.STOPPED
            captureProjection = null
            FFI.setFrameRawEnable("audio", false)
        }
    }

    fun switchToVoiceCall(): Boolean {
        if (!isSupportVoiceCall()) {
            return false
        }
        val recorder = audioRecorder
        if (captureMode == AudioCaptureMode.VOICE_CALL &&
            recorder?.recordingState == AudioRecord.RECORDSTATE_RECORDING
        ) {
            return true
        }
        stopAudioRecorder()
        if (!createAudioRecorder(AudioCaptureMode.VOICE_CALL, null)) {
            return false
        }
        return startAudioRecorder(AudioCaptureMode.VOICE_CALL)
    }

    fun switchToPlaybackCapture(mediaProjection: MediaProjection): Boolean {
        val recorder = audioRecorder
        if (captureMode == AudioCaptureMode.PLAYBACK &&
            captureProjection === mediaProjection &&
            recorder?.recordingState == AudioRecord.RECORDSTATE_RECORDING
        ) {
            return true
        }
        stopAudioRecorder()
        if (!createAudioRecorder(AudioCaptureMode.PLAYBACK, mediaProjection)) {
            return false
        }
        return startAudioRecorder(AudioCaptureMode.PLAYBACK)
    }

    fun stopCapture() {
        stopAudioRecorder()
    }
}
