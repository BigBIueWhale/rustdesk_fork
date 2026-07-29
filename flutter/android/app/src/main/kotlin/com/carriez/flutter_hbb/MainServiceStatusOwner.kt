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
        if (generation <= 0L ||
            generation < greatestGeneration ||
            (generation == greatestGeneration && activeGeneration != generation)
        ) {
            return false
        }
        if (activeGeneration == generation) {
            return true
        }
        greatestGeneration = generation
        activeGeneration = generation
        mediaProjectionReady = false
        return true
    }

    @Synchronized
    fun setMediaProjectionReady(generation: Long, ready: Boolean): Boolean {
        if (generation <= 0L || activeGeneration != generation) {
            return false
        }
        mediaProjectionReady = ready
        return true
    }

    @Synchronized
    fun retire(generation: Long): Boolean {
        if (generation <= 0L || activeGeneration != generation) {
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
