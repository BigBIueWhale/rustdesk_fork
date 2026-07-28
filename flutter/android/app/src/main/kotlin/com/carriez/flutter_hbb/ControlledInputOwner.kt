package com.carriez.flutter_hbb

internal data class ControlledInputOwner(
    val serviceGeneration: Long,
    val connectionId: Int,
) {
    val isValid: Boolean
        get() = serviceGeneration > 0 && connectionId > 0
}
