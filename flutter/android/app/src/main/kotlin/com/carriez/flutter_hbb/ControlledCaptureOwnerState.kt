package com.carriez.flutter_hbb

internal class ControlledCaptureOwnerState {
    private data class Owner(
        val registryGeneration: Long,
        val requiresDesktopCapture: Boolean,
    )

    private val owners = mutableMapOf<Int, Owner>()

    val requiresDesktopCapture: Boolean
        get() = owners.values.any { it.requiresDesktopCapture }

    fun remoteInputRegistryGeneration(connectionId: Int): Long? =
        owners[connectionId]
            ?.takeIf { it.requiresDesktopCapture }
            ?.registryGeneration

    fun registryGeneration(connectionId: Int): Long? = owners[connectionId]?.registryGeneration

    fun isCurrent(connectionId: Int, registryGeneration: Long): Boolean =
        registryGeneration > 0 && owners[connectionId]?.registryGeneration == registryGeneration

    fun canUpsert(connectionId: Int, registryGeneration: Long): Boolean {
        if (connectionId <= 0 || registryGeneration <= 0) {
            return false
        }
        val current = owners[connectionId]
        return current == null || registryGeneration > current.registryGeneration
    }

    fun upsert(
        connectionId: Int,
        registryGeneration: Long,
        authorized: Boolean,
        connectionType: ControlledConnectionType,
    ): Boolean {
        if (!canUpsert(connectionId, registryGeneration)) {
            return false
        }
        owners[connectionId] = Owner(
            registryGeneration,
            authorized && connectionType.requiresDesktopCapture,
        )
        return true
    }

    fun unregister(connectionId: Int, registryGeneration: Long): Boolean {
        if (!isCurrent(connectionId, registryGeneration)) {
            return false
        }
        owners.remove(connectionId)
        return true
    }

    fun clear() {
        owners.clear()
    }
}
