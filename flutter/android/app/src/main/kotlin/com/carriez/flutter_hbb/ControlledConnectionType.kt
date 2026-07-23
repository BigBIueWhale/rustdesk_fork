package com.carriez.flutter_hbb

internal enum class ControlledConnectionType {
    REMOTE,
    FILE_TRANSFER,
    VIEW_CAMERA,
    TERMINAL,
    PORT_FORWARD;

    val requiresDesktopCapture: Boolean
        get() = this == REMOTE

    val allowsVoiceCall: Boolean
        get() = this == REMOTE || this == VIEW_CAMERA

    companion object {
        fun fromWireTag(tag: String): ControlledConnectionType? {
            return when (tag) {
                "Remote" -> REMOTE
                "FileTransfer" -> FILE_TRANSFER
                "ViewCamera" -> VIEW_CAMERA
                "Terminal" -> TERMINAL
                "PortForward" -> PORT_FORWARD
                else -> null
            }
        }
    }
}
