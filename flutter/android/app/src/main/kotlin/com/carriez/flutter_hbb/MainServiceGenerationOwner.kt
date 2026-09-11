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
        RETIRING,
    }

    private var greatestGeneration = 0L
    private var activeGeneration: Long? = null
    private var phase: Phase? = null
    private var retirement: MainServiceGenerationRetirement? = null

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
        retirement = null
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
    fun beginRetirement(generation: Long): MainServiceGenerationRetirement? {
        if (generation <= 0L || activeGeneration != generation) {
            return null
        }
        retirement?.let { current ->
            return if (current.generation == generation && phase == Phase.RETIRING) {
                current
            } else {
                null
            }
        }
        val currentPhase = phase ?: return null
        if (currentPhase == Phase.RETIRING) {
            return null
        }
        val plan = MainServiceGenerationRetirement(
            generation = generation,
            retireStatus = currentPhase != Phase.RESERVED,
            retireVoice = currentPhase == Phase.VOICE_ATTEMPTED ||
                currentPhase == Phase.ACTIVATION_ATTEMPTED ||
                currentPhase == Phase.COMMITTED,
        )
        phase = Phase.RETIRING
        retirement = plan
        return plan
    }

    @Synchronized
    fun completeRetirement(generation: Long): Boolean {
        if (generation <= 0L ||
            activeGeneration != generation ||
            phase != Phase.RETIRING ||
            retirement?.generation != generation
        ) {
            return false
        }
        activeGeneration = null
        phase = null
        retirement = null
        return true
    }

    @Synchronized
    fun hasActiveGeneration(): Boolean {
        return activeGeneration != null
    }
}
