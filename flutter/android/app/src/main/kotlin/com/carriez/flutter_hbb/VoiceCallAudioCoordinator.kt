package com.carriez.flutter_hbb

import android.content.Context
import android.media.projection.MediaProjection

internal object VoiceCallAudioCoordinator {
    private val owners = VoiceCallOwnerState()
    private var audioRecordHandle: AudioRecordHandle? = null
    private var playbackProjection: MediaProjection? = null

    @Synchronized
    fun initialize(context: Context): Boolean {
        if (audioRecordHandle == null) {
            audioRecordHandle = AudioRecordHandle(context.applicationContext)
        }
        return reconcileRecorder()
    }

    @Synchronized
    fun registerControlledConnection(connectionId: Int): Boolean {
        return owners.registerControlledConnection(connectionId)
    }

    @Synchronized
    fun setControlledVoiceCallActive(connectionId: Int, active: Boolean): Boolean {
        if (!owners.setControlledVoiceCallActive(connectionId, active)) {
            return false
        }
        return reconcileRecorder()
    }

    @Synchronized
    fun unregisterControlledConnection(connectionId: Int): Boolean {
        if (!owners.unregisterControlledConnection(connectionId)) {
            return false
        }
        return reconcileRecorder()
    }

    @Synchronized
    fun clearControlledConnections(): Boolean {
        owners.clearControlledConnections()
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
    fun setPlaybackCaptureProjection(projection: MediaProjection?): Boolean {
        playbackProjection = projection
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
        val projection = playbackProjection
        if (projection != null) {
            return recorder.switchToPlaybackCapture(projection)
        }
        recorder.stopCapture()
        return true
    }
}
