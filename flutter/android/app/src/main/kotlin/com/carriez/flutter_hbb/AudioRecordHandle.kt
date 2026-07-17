package com.carriez.flutter_hbb

import ffi.FFI

import android.Manifest
import android.content.Context
import android.media.*
import android.content.pm.PackageManager
import android.media.projection.MediaProjection
import androidx.annotation.RequiresApi
import androidx.core.app.ActivityCompat
import android.os.Build
import android.util.Log
import kotlin.concurrent.thread

const val AUDIO_ENCODING = AudioFormat.ENCODING_PCM_FLOAT //  ENCODING_OPUS need API 30
const val AUDIO_SAMPLE_RATE = 48000
const val AUDIO_CHANNEL_MASK = AudioFormat.CHANNEL_IN_STEREO

class AudioRecordHandle(private var context: Context, private var isVideoStart: ()->Boolean, private var isAudioStart: ()->Boolean) {
    private val logTag = "LOG_AUDIO_RECORD_HANDLE"

    private var audioRecorder: AudioRecord? = null
    private var audioReader: AudioReader? = null
    private var minBufferSize = 0
    @Volatile
    private var audioRecordStat = false
    private var audioThread: Thread? = null

    @RequiresApi(Build.VERSION_CODES.M)
    fun createAudioRecorder(inVoiceCall: Boolean, mediaProjection: MediaProjection?): Boolean {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
            return false
        }
        if (ActivityCompat.checkSelfPermission(
            context,
            Manifest.permission.RECORD_AUDIO
        ) != PackageManager.PERMISSION_GRANTED
        ) {
            Log.d(logTag, "createAudioRecorder failed, no RECORD_AUDIO permission")
            return false
        }

        var builder = AudioRecord.Builder()
        .setAudioFormat(
            AudioFormat.Builder()
                .setEncoding(AUDIO_ENCODING)
                .setSampleRate(AUDIO_SAMPLE_RATE)
                .setChannelMask(AUDIO_CHANNEL_MASK).build()
        );
        if (inVoiceCall) {
            builder.setAudioSource(MediaRecorder.AudioSource.VOICE_COMMUNICATION)
        } else {
            mediaProjection?.let {
                var apcc = AudioPlaybackCaptureConfiguration.Builder(it)
                .addMatchingUsage(AudioAttributes.USAGE_MEDIA)
                .addMatchingUsage(AudioAttributes.USAGE_ALARM)
                .addMatchingUsage(AudioAttributes.USAGE_GAME)
                .addMatchingUsage(AudioAttributes.USAGE_UNKNOWN).build();
                builder.setAudioPlaybackCaptureConfig(apcc);
            } ?: let {
                Log.d(logTag, "createAudioRecorder failed, mediaProjection null")
                return false
            }
        }
        val recorder = try {
            builder.build()
        } catch (e: Exception) {
            Log.e(logTag, "createAudioRecorder failed", e)
            return false
        }
        audioRecorder = recorder
        Log.d(logTag, "createAudioRecorder done,minBufferSize:$minBufferSize")
        return true
    }

    @RequiresApi(Build.VERSION_CODES.M)
    private fun checkAudioReader() {
        if (audioReader != null && minBufferSize != 0) {
            return
        }
        // read f32 to byte , length * 4
        minBufferSize = 2 * 4 * AudioRecord.getMinBufferSize(
            AUDIO_SAMPLE_RATE,
            AUDIO_CHANNEL_MASK,
            AUDIO_ENCODING
        )
        if (minBufferSize == 0) {
            Log.d(logTag, "get min buffer size fail!")
            return
        }
        audioReader = AudioReader(minBufferSize, 4)
        Log.d(logTag, "init audioData len:$minBufferSize")
    }

    @RequiresApi(Build.VERSION_CODES.M)
    fun startAudioRecorder() {
        checkAudioReader()
        val reader = audioReader
        val recorder = audioRecorder
        if (reader != null && recorder != null && minBufferSize != 0) {
            try {
                FFI.setFrameRawEnable("audio", true)
                recorder.startRecording()
                audioRecordStat = true
                audioThread = thread {
                    try {
                        while (audioRecordStat) {
                            reader.readSync(recorder)?.let {
                                FFI.onAudioFrameUpdate(it)
                            }
                        }
                    } catch (e: Exception) {
                        if (audioRecordStat) {
                            Log.e(logTag, "audio recorder thread failed", e)
                        }
                    } finally {
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
                            FFI.setFrameRawEnable("audio", false)
                        }
                        Log.d(logTag, "Exit audio thread")
                    }
                }
            } catch (e: Exception) {
                Log.e(logTag, "startAudioRecorder fail", e)
                stopAudioRecorder()
            }
        } else {
            Log.d(logTag, "startAudioRecorder fail")
        }
    }

    private fun stopAudioRecorder() {
        audioRecordStat = false
        val recorder = audioRecorder
        if (recorder != null) {
            try {
                if (recorder.recordingState == AudioRecord.RECORDSTATE_RECORDING) {
                    // Unblock AudioReader.readSync(..., READ_BLOCKING) before waiting for its thread.
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

        // startRecording() can fail before the worker exists, so that path must release here.
        if (worker == null && recorder != null && audioRecorder === recorder) {
            try {
                recorder.release()
            } catch (e: Exception) {
                Log.w(logTag, "release audio recorder failed", e)
            }
            audioRecorder = null
            audioReader = null
            minBufferSize = 0
            FFI.setFrameRawEnable("audio", false)
        }
    }

    fun onVoiceCallStarted(mediaProjection: MediaProjection?): Boolean {
        if (!isSupportVoiceCall()) {
            return false
        }
        // No need to check if video or audio is started here.
        if (!switchToVoiceCall(mediaProjection)) {
            return false
        }
        return true
    }

    fun onVoiceCallClosed(mediaProjection: MediaProjection?): Boolean {
        // Return true if not supported, because is was not started.
        if (!isSupportVoiceCall()) {
            return true
        }
        if (isVideoStart()) {
            switchOutVoiceCall(mediaProjection)
        }
        tryReleaseAudio()
        return true
    }

    @RequiresApi(Build.VERSION_CODES.M)
    fun switchToVoiceCall(mediaProjection: MediaProjection?): Boolean {
        audioRecorder?.let {
            if (it.getAudioSource() == MediaRecorder.AudioSource.VOICE_COMMUNICATION) {
                return true
            }
        }
        stopAudioRecorder()

        if (!createAudioRecorder(true, mediaProjection)) {
            Log.e(logTag, "createAudioRecorder fail")
            return false
        }
        startAudioRecorder()
        return true
    }

    @RequiresApi(Build.VERSION_CODES.M)
    fun switchOutVoiceCall(mediaProjection: MediaProjection?): Boolean {
        audioRecorder?.let {
            if (it.getAudioSource() != MediaRecorder.AudioSource.VOICE_COMMUNICATION) {
                return true
            }
        }
        stopAudioRecorder()

        if (!createAudioRecorder(false, mediaProjection)) {
            Log.e(logTag, "createAudioRecorder fail")
            return false
        }
        startAudioRecorder()
        return true
    }

    fun tryReleaseAudio() {
        if (isAudioStart() || isVideoStart()) {
            return
        }
        stopAudioRecorder()
    }

    fun destroy() {
        Log.d(logTag, "destroy audio record handle")

        stopAudioRecorder()
    }
}
