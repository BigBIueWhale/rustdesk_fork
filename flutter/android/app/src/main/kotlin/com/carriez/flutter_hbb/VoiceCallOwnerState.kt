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
    private var greatestControlledServiceGeneration = 0L
    private var activeControlledServiceGeneration: Long? = null
    private var outgoingOwner: OutgoingVoiceCallOwner? = null
    private var outgoingVoiceCallActive = false

    val requiresVoiceCapture: Boolean
        get() = activeControlledConnections.isNotEmpty() || outgoingVoiceCallActive

    fun beginControlledServiceGeneration(generation: Long): Boolean {
        if (generation <= 0 ||
            generation < greatestControlledServiceGeneration ||
            (generation == greatestControlledServiceGeneration &&
                activeControlledServiceGeneration != generation)
        ) {
            return false
        }
        if (activeControlledServiceGeneration == generation) {
            return true
        }
        greatestControlledServiceGeneration = generation
        activeControlledServiceGeneration = generation
        controlledConnections.clear()
        activeControlledConnections.clear()
        return true
    }

    fun isControlledServiceGeneration(generation: Long): Boolean {
        return generation > 0 && activeControlledServiceGeneration == generation
    }

    fun registerControlledConnection(generation: Long, connectionId: Int): Boolean {
        if (!isControlledServiceGeneration(generation) || connectionId <= 0) {
            return false
        }
        controlledConnections.add(connectionId)
        return true
    }

    fun setControlledVoiceCallActive(
        generation: Long,
        connectionId: Int,
        active: Boolean,
    ): Boolean {
        if (!isControlledServiceGeneration(generation) ||
            !controlledConnections.contains(connectionId)
        ) {
            return false
        }
        if (active) {
            activeControlledConnections.add(connectionId)
        } else {
            activeControlledConnections.remove(connectionId)
        }
        return true
    }

    fun unregisterControlledConnection(generation: Long, connectionId: Int): Boolean {
        if (!isControlledServiceGeneration(generation) || connectionId <= 0) {
            return false
        }
        controlledConnections.remove(connectionId)
        activeControlledConnections.remove(connectionId)
        return true
    }

    fun clearControlledConnections(generation: Long): Boolean {
        if (!isControlledServiceGeneration(generation)) {
            return false
        }
        controlledConnections.clear()
        activeControlledConnections.clear()
        activeControlledServiceGeneration = null
        return true
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
