package com.carriez.flutter_hbb

internal data class MainServiceStatus(
    val generation: Long,
    val mediaProjectionReady: Boolean,
)

internal class MainServiceStatusOwner {
    private var greatestGeneration = 0L
    private var activeGeneration: Long? = null
    private var mediaProjectionReady = false

    @Synchronized
    fun begin(generation: Long): Boolean {
        if (generation <= 0L) {
            return false
        }
        if (activeGeneration == generation) {
            return true
        }
        if (activeGeneration != null || generation <= greatestGeneration) {
            return false
        }
        greatestGeneration = generation
        activeGeneration = generation
        mediaProjectionReady = false
        return true
    }

    @Synchronized
    fun setMediaProjectionReady(generation: Long, ready: Boolean): Boolean {
        if (generation <= 0L) {
            return false
        }
        if (activeGeneration != generation) {
            return !ready &&
                activeGeneration == null &&
                greatestGeneration == generation
        }
        mediaProjectionReady = ready
        return true
    }

    @Synchronized
    fun retireOrConfirmInactive(generation: Long): Boolean {
        if (generation <= 0L) {
            return false
        }
        if (activeGeneration == null) {
            return greatestGeneration == generation
        }
        if (activeGeneration != generation) {
            return false
        }
        activeGeneration = null
        mediaProjectionReady = false
        return true
    }

    @Synchronized
    fun snapshot(): MainServiceStatus? {
        val generation = activeGeneration ?: return null
        return MainServiceStatus(generation, mediaProjectionReady)
    }
}
