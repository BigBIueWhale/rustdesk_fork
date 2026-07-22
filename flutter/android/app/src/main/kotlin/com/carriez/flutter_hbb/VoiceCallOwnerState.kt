package com.carriez.flutter_hbb

internal data class OutgoingVoiceCallOwner(
    val generation: Long,
    val sessionId: String,
) {
    fun isValid(): Boolean = generation > 0 && sessionId.isNotEmpty()
}

internal class VoiceCallOwnerState {
    private val controlledConnections = mutableSetOf<Int>()
    private val activeControlledConnections = mutableSetOf<Int>()
    private var outgoingOwner: OutgoingVoiceCallOwner? = null
    private var outgoingVoiceCallActive = false

    val requiresVoiceCapture: Boolean
        get() = activeControlledConnections.isNotEmpty() || outgoingVoiceCallActive

    fun registerControlledConnection(connectionId: Int): Boolean {
        if (connectionId <= 0) {
            return false
        }
        controlledConnections.add(connectionId)
        return true
    }

    fun setControlledVoiceCallActive(connectionId: Int, active: Boolean): Boolean {
        if (!controlledConnections.contains(connectionId)) {
            return false
        }
        if (active) {
            activeControlledConnections.add(connectionId)
        } else {
            activeControlledConnections.remove(connectionId)
        }
        return true
    }

    fun unregisterControlledConnection(connectionId: Int): Boolean {
        if (connectionId <= 0) {
            return false
        }
        controlledConnections.remove(connectionId)
        activeControlledConnections.remove(connectionId)
        return true
    }

    fun clearControlledConnections() {
        controlledConnections.clear()
        activeControlledConnections.clear()
    }

    fun invalidateOutgoingOwner() {
        outgoingOwner = null
        outgoingVoiceCallActive = false
    }

    fun registerOutgoingOwner(owner: OutgoingVoiceCallOwner): Boolean {
        if (!owner.isValid()) {
            return false
        }
        val current = outgoingOwner
        if (current != null && current != owner) {
            return false
        }
        outgoingOwner = owner
        return true
    }

    fun resumeOutgoingOwner(
        previous: OutgoingVoiceCallOwner,
        replacement: OutgoingVoiceCallOwner,
    ): Boolean {
        if (!previous.isValid() ||
            !replacement.isValid() ||
            replacement.sessionId != previous.sessionId ||
            replacement.generation < previous.generation
        ) {
            return false
        }
        val current = outgoingOwner
        if (current == replacement) {
            return true
        }
        if (current != previous) {
            return false
        }
        outgoingOwner = replacement
        return true
    }

    fun setOutgoingVoiceCallActive(owner: OutgoingVoiceCallOwner, active: Boolean): Boolean {
        if (outgoingOwner != owner) {
            return false
        }
        outgoingVoiceCallActive = active
        return true
    }

    fun unregisterOutgoingOwner(owner: OutgoingVoiceCallOwner): Boolean {
        if (outgoingOwner != owner) {
            return false
        }
        outgoingOwner = null
        outgoingVoiceCallActive = false
        return true
    }
}
