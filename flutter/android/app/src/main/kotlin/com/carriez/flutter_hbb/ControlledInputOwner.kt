package com.carriez.flutter_hbb

internal data class ControlledInputOwner(
    val serviceGeneration: Long,
    val connectionId: Int,
    val registryGeneration: Long,
) {
    val isValid: Boolean
        get() = serviceGeneration > 0 && connectionId > 0 && registryGeneration > 0
}
