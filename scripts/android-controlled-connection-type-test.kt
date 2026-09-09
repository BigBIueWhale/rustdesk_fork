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

    val owners = ControlledCaptureOwnerState()
    requireState(!owners.requiresDesktopCapture, "fresh owner state requires capture")
    requireState(
        !owners.upsert(0, 1, true, ControlledConnectionType.REMOTE),
        "invalid capture owner was admitted",
    )
    requireState(
        !owners.upsert(11, 0, true, ControlledConnectionType.REMOTE),
        "invalid registry generation was admitted",
    )
    requireState(
        owners.upsert(11, 1, false, ControlledConnectionType.REMOTE),
        "unauthorized Remote owner update failed",
    )
    requireState(
        !owners.requiresDesktopCapture,
        "unauthorized Remote created capture demand",
    )
    requireState(
        owners.upsert(11, 2, true, ControlledConnectionType.REMOTE),
        "authorized Remote owner admission failed",
    )
    requireState(owners.requiresDesktopCapture, "authorized Remote did not require capture")
    requireState(
        owners.upsert(12, 3, true, ControlledConnectionType.REMOTE),
        "second Remote owner admission failed",
    )
    requireState(owners.unregister(11, 2), "first Remote owner removal failed")
    requireState(
        owners.requiresDesktopCapture,
        "one Remote teardown cleared another live owner",
    )
    requireState(
        owners.upsert(13, 4, true, ControlledConnectionType.FILE_TRANSFER),
        "FileTransfer owner update failed",
    )
    requireState(
        owners.requiresDesktopCapture,
        "non-capture connection altered a live Remote owner",
    )
    requireState(owners.unregister(12, 3), "last Remote owner removal failed")
    requireState(
        !owners.requiresDesktopCapture,
        "last Remote teardown retained capture demand",
    )

    // The two possible cross-connection delivery orders converge. No detached global
    // stop edge exists that can arrive after a newer Remote admission.
    requireState(
        owners.upsert(21, 5, true, ControlledConnectionType.REMOTE),
        "old Remote admission failed",
    )
    requireState(owners.unregister(21, 5), "old Remote removal failed")
    requireState(
        owners.upsert(22, 6, true, ControlledConnectionType.REMOTE),
        "new Remote admission after removal failed",
    )
    requireState(
        owners.requiresDesktopCapture,
        "remove-then-add ordering lost new Remote demand",
    )
    owners.clear()
    requireState(
        owners.upsert(31, 7, true, ControlledConnectionType.REMOTE),
        "old Remote readmission failed",
    )
    requireState(
        owners.upsert(32, 8, true, ControlledConnectionType.REMOTE),
        "new Remote admission before removal failed",
    )
    requireState(owners.unregister(31, 7), "old Remote late removal failed")
    requireState(
        owners.requiresDesktopCapture,
        "add-then-remove ordering lost new Remote demand",
    )
    requireState(
        owners.upsert(32, 9, true, ControlledConnectionType.VIEW_CAMERA),
        "newer same-ID connection-type replacement failed",
    )
    requireState(
        !owners.requiresDesktopCapture,
        "non-Remote replacement retained capture demand",
    )
    requireState(
        owners.registryGeneration(32) == 9L &&
            owners.remoteInputRegistryGeneration(32) == null,
        "non-Remote replacement retained Remote input authority",
    )
    requireState(
        owners.upsert(41, 10, true, ControlledConnectionType.REMOTE),
        "first same-ID generation admission failed",
    )
    requireState(
        owners.upsert(41, 11, true, ControlledConnectionType.REMOTE),
        "newer same-ID generation admission failed",
    )
    requireState(
        !owners.unregister(41, 10),
        "stale same-ID generation retired its replacement",
    )
    requireState(
        !owners.upsert(41, 11, true, ControlledConnectionType.VIEW_CAMERA),
        "duplicate same-ID generation was readmitted",
    )
    requireState(
        !owners.upsert(41, 9, true, ControlledConnectionType.VIEW_CAMERA),
        "stale same-ID generation replaced the current owner",
    )
    requireState(
        owners.isCurrent(41, 11) &&
            owners.remoteInputRegistryGeneration(41) == 11L &&
            owners.requiresDesktopCapture,
        "stale same-ID operations changed the current owner",
    )
    requireState(owners.unregister(41, 11), "current same-ID owner removal failed")
    owners.clear()
    requireState(!owners.requiresDesktopCapture, "owner clear retained capture demand")
}
