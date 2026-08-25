package com.carriez.flutter_hbb

internal data class MainServiceGenerationRetirement(
    val generation: Long,
    val retireStatus: Boolean,
    val retireVoice: Boolean,
)

internal class MainServiceGenerationOwner {
    private enum class Phase {
        RESERVED,
        STATUS_ATTEMPTED,
        VOICE_ATTEMPTED,
        ACTIVATION_ATTEMPTED,
        COMMITTED,
    }

    private var greatestGeneration = 0L
    private var activeGeneration: Long? = null
    private var phase: Phase? = null

    @Synchronized
    fun beginReservation(generation: Long): Boolean {
        if (generation <= 0L ||
            activeGeneration != null ||
            generation <= greatestGeneration
        ) {
            return false
        }
        greatestGeneration = generation
        activeGeneration = generation
        phase = Phase.RESERVED
        return true
    }

    @Synchronized
    fun noteStatusAttempt(generation: Long): Boolean {
        if (activeGeneration != generation || phase != Phase.RESERVED) {
            return false
        }
        phase = Phase.STATUS_ATTEMPTED
        return true
    }

    @Synchronized
    fun noteVoiceAttempt(generation: Long): Boolean {
        if (activeGeneration != generation || phase != Phase.STATUS_ATTEMPTED) {
            return false
        }
        phase = Phase.VOICE_ATTEMPTED
        return true
    }

    @Synchronized
    fun noteActivationAttempt(generation: Long): Boolean {
        if (activeGeneration != generation || phase != Phase.VOICE_ATTEMPTED) {
            return false
        }
        phase = Phase.ACTIVATION_ATTEMPTED
        return true
    }

    @Synchronized
    fun commit(generation: Long): Boolean {
        if (activeGeneration != generation || phase != Phase.ACTIVATION_ATTEMPTED) {
            return false
        }
        phase = Phase.COMMITTED
        return true
    }

    @Synchronized
    fun isCommitted(generation: Long): Boolean {
        return generation > 0L &&
            activeGeneration == generation &&
            phase == Phase.COMMITTED
    }

    @Synchronized
    fun retire(generation: Long): MainServiceGenerationRetirement? {
        if (generation <= 0L || activeGeneration != generation) {
            return null
        }
        val currentPhase = phase ?: return null
        val retirement = MainServiceGenerationRetirement(
            generation = generation,
            retireStatus = currentPhase != Phase.RESERVED,
            retireVoice = currentPhase == Phase.VOICE_ATTEMPTED ||
                currentPhase == Phase.ACTIVATION_ATTEMPTED ||
                currentPhase == Phase.COMMITTED,
        )
        activeGeneration = null
        phase = null
        return retirement
    }
}
