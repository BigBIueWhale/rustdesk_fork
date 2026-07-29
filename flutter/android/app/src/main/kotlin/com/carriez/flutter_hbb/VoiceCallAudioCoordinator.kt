package com.carriez.flutter_hbb

import android.content.Context
import android.media.projection.MediaProjection

internal object VoiceCallAudioCoordinator {
    private val owners = VoiceCallOwnerState()
    private var audioRecordHandle: AudioRecordHandle? = null
    private var playbackProjection: Pair<Long, MediaProjection>? = null

    @Synchronized
    fun initialize(context: Context): Boolean {
        if (audioRecordHandle == null) {
            audioRecordHandle = AudioRecordHandle(context.applicationContext)
        }
        return reconcileRecorder()
    }

    @Synchronized
    fun beginControlledServiceGeneration(generation: Long): Boolean {
        val alreadyCurrent = owners.isControlledServiceGeneration(generation)
        if (!owners.beginControlledServiceGeneration(generation)) {
            return false
        }
        if (!alreadyCurrent) {
            playbackProjection = null
        }
        return reconcileRecorder()
    }

    @Synchronized
    fun registerControlledConnection(generation: Long, connectionId: Int): Boolean {
        return owners.registerControlledConnection(generation, connectionId)
    }

    @Synchronized
    fun setControlledVoiceCallActive(
        generation: Long,
        connectionId: Int,
        active: Boolean,
    ): Boolean {
        if (!owners.setControlledVoiceCallActive(generation, connectionId, active)) {
            return false
        }
        return reconcileRecorder()
    }

    @Synchronized
    fun unregisterControlledConnection(generation: Long, connectionId: Int): Boolean {
        if (!owners.unregisterControlledConnection(generation, connectionId)) {
            return false
        }
        return reconcileRecorder()
    }

    @Synchronized
    fun clearControlledConnections(generation: Long): Boolean {
        if (!owners.clearControlledConnections(generation)) {
            return false
        }
        if (playbackProjection?.first == generation) {
            playbackProjection = null
        }
        return reconcileRecorder()
    }

    @Synchronized
    fun invalidateOutgoingOwner(): Boolean {
        owners.invalidateOutgoingOwner()
        return reconcileRecorder()
    }

    @Synchronized
    fun registerOutgoingOwner(owner: OutgoingVoiceCallOwner): Boolean {
        return owners.registerOutgoingOwner(owner)
    }

    @Synchronized
    fun resumeOutgoingOwner(
        previous: OutgoingVoiceCallOwner,
        replacement: OutgoingVoiceCallOwner,
    ): Boolean {
        return owners.resumeOutgoingOwner(previous, replacement)
    }

    @Synchronized
    fun setOutgoingVoiceCallActive(owner: OutgoingVoiceCallOwner, active: Boolean): Boolean {
        if (!owners.setOutgoingVoiceCallActive(owner, active)) {
            return false
        }
        return reconcileRecorder()
    }

    @Synchronized
    fun unregisterOutgoingOwner(owner: OutgoingVoiceCallOwner): Boolean {
        if (!owners.unregisterOutgoingOwner(owner)) {
            return false
        }
        return reconcileRecorder()
    }

    @Synchronized
    fun setPlaybackCaptureProjection(
        generation: Long,
        projection: MediaProjection?,
    ): Boolean {
        if (!owners.isControlledServiceGeneration(generation)) {
            return false
        }
        playbackProjection = projection?.let { generation to it }
        return reconcileRecorder()
    }

    private fun reconcileRecorder(): Boolean {
        val recorder = audioRecordHandle
        if (recorder == null) {
            return !owners.requiresVoiceCapture && playbackProjection == null
        }
        if (owners.requiresVoiceCapture) {
            return recorder.switchToVoiceCall()
        }
        val projection = playbackProjection?.second
        if (projection != null) {
            return recorder.switchToPlaybackCapture(projection)
        }
        recorder.stopCapture()
        return true
    }
}
