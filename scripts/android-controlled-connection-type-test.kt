package com.carriez.flutter_hbb

private fun requireState(condition: Boolean, message: String) {
    check(condition) { message }
}

fun main() {
    val expected = mapOf(
        "Remote" to ControlledConnectionType.REMOTE,
        "FileTransfer" to ControlledConnectionType.FILE_TRANSFER,
        "ViewCamera" to ControlledConnectionType.VIEW_CAMERA,
        "Terminal" to ControlledConnectionType.TERMINAL,
        "PortForward" to ControlledConnectionType.PORT_FORWARD,
    )
    for ((wireTag, connectionType) in expected) {
        requireState(
            ControlledConnectionType.fromWireTag(wireTag) == connectionType,
            "failed to parse exact connection type $wireTag",
        )
    }
    for (wireTag in listOf("", "remote", "REMOTE", "Portforward", "Unknown")) {
        requireState(
            ControlledConnectionType.fromWireTag(wireTag) == null,
            "accepted non-canonical connection type $wireTag",
        )
    }

    for (connectionType in ControlledConnectionType.values()) {
        requireState(
            connectionType.requiresDesktopCapture ==
                (connectionType == ControlledConnectionType.REMOTE),
            "desktop capture was not Remote-only for $connectionType",
        )
        requireState(
            connectionType.allowsVoiceCall ==
                (connectionType == ControlledConnectionType.REMOTE ||
                    connectionType == ControlledConnectionType.VIEW_CAMERA),
            "voice-call authority was incorrect for $connectionType",
        )
    }
}
