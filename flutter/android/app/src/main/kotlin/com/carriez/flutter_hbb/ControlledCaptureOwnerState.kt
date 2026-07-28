package com.carriez.flutter_hbb

internal class ControlledCaptureOwnerState {
    private val owners = mutableSetOf<Int>()

    val requiresDesktopCapture: Boolean
        get() = owners.isNotEmpty()

    fun ownsRemoteInput(connectionId: Int): Boolean = owners.contains(connectionId)

    fun upsert(
        connectionId: Int,
        authorized: Boolean,
        connectionType: ControlledConnectionType,
    ): Boolean {
        if (connectionId <= 0) {
            return false
        }
        if (authorized && connectionType.requiresDesktopCapture) {
            owners.add(connectionId)
        } else {
            owners.remove(connectionId)
        }
        return true
    }

    fun unregister(connectionId: Int): Boolean {
        if (connectionId <= 0) {
            return false
        }
        owners.remove(connectionId)
        return true
    }

    fun clear() {
        owners.clear()
    }
}
