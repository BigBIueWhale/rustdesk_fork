package com.carriez.flutter_hbb

private fun requireState(condition: Boolean, message: String) {
    check(condition) { message }
}

fun main() {
    val state = VoiceCallOwnerState()
    requireState(!state.requiresVoiceCapture, "fresh state requires voice capture")
    requireState(
        !state.beginControlledServiceGeneration(0),
        "invalid controlled service generation was admitted",
    )
    requireState(
        !state.registerControlledConnection(10, 11, 1),
        "controlled owner without a live service generation was admitted",
    )
    requireState(
        state.beginControlledServiceGeneration(10),
        "first controlled service generation was rejected",
    )
    requireState(
        !state.registerControlledConnection(10, 0, 1),
        "invalid controlled owner was admitted",
    )
    requireState(
        !state.registerControlledConnection(10, 11, 0),
        "invalid controlled registry generation was admitted",
    )
    requireState(
        !state.setControlledVoiceCallActive(10, 11, 1, true),
        "unregistered controlled owner was activated",
    )

    requireState(
        state.registerControlledConnection(10, 11, 1),
        "first controlled owner registration failed",
    )
    requireState(
        state.registerControlledConnection(10, 12, 2),
        "second controlled owner registration failed",
    )
    requireState(
        state.setControlledVoiceCallActive(10, 11, 1, true),
        "first controlled owner activation failed",
    )
    requireState(
        state.setControlledVoiceCallActive(10, 12, 2, true),
        "second controlled owner activation failed",
    )
    requireState(state.requiresVoiceCapture, "controlled owners did not require voice capture")
    requireState(state.unregisterControlledConnection(10, 11, 1), "first controlled owner removal failed")
    requireState(state.requiresVoiceCapture, "one controlled teardown cleared another owner")
    requireState(state.unregisterControlledConnection(10, 12, 2), "final controlled owner removal failed")
    requireState(!state.requiresVoiceCapture, "final controlled teardown retained voice capture")

    requireState(
        state.registerControlledConnection(10, 13, 3),
        "same-ID predecessor registration failed",
    )
    requireState(
        state.setControlledVoiceCallActive(10, 13, 3, true),
        "same-ID predecessor activation failed",
    )
    requireState(
        !state.registerControlledConnection(10, 13, 3),
        "duplicate same-ID registry generation was admitted",
    )
    requireState(
        !state.registerControlledConnection(10, 13, 2),
        "stale same-ID registry generation was admitted",
    )
    requireState(
        state.registerControlledConnection(10, 13, 4),
        "same-ID replacement registration failed",
    )
    requireState(!state.requiresVoiceCapture, "same-ID replacement retained predecessor voice state")
    requireState(
        !state.setControlledVoiceCallActive(10, 13, 3, true),
        "stale same-ID owner changed replacement voice state",
    )
    requireState(
        !state.unregisterControlledConnection(10, 13, 3),
        "stale same-ID owner retired replacement voice state",
    )
    requireState(
        state.setControlledVoiceCallActive(10, 13, 4, true),
        "same-ID replacement activation failed",
    )
    requireState(
        state.unregisterControlledConnection(10, 13, 4),
        "same-ID replacement removal failed",
    )
    requireState(!state.requiresVoiceCapture, "same-ID replacement teardown retained voice capture")

    requireState(
        !state.registerOutgoingOwner(OutgoingVoiceCallOwner(0, "")),
        "invalid outgoing owner was admitted",
    )
    val first = OutgoingVoiceCallOwner(31, "session-a")
    val resumed = OutgoingVoiceCallOwner(32, "session-a")
    val stale = OutgoingVoiceCallOwner(30, "session-a")
    val wrongIsolate = OutgoingVoiceCallOwner(32, "session-b")
    val replacement = OutgoingVoiceCallOwner(40, "session-b")
    requireState(state.registerOutgoingOwner(first), "outgoing owner registration failed")
    requireState(state.setOutgoingVoiceCallActive(first, true), "outgoing owner activation failed")
    requireState(state.requiresVoiceCapture, "outgoing owner did not require voice capture")
    requireState(
        !state.setOutgoingVoiceCallActive(stale, false),
        "stale outgoing owner changed live state",
    )
    requireState(state.requiresVoiceCapture, "stale close retired the current outgoing owner")
    requireState(
        state.resumeOutgoingOwner(first, first),
        "same-generation resume was rejected",
    )
    requireState(state.requiresVoiceCapture, "idempotent resume lost active voice state")
    requireState(
        !state.resumeOutgoingOwner(first, stale),
        "older generation resumed outgoing owner",
    )
    requireState(
        !state.resumeOutgoingOwner(first, wrongIsolate),
        "different isolate resumed outgoing owner",
    )
    requireState(state.resumeOutgoingOwner(first, resumed), "outgoing owner resume failed")
    requireState(state.requiresVoiceCapture, "owner resume lost active voice state")
    requireState(
        state.resumeOutgoingOwner(first, resumed),
        "lost-response resume retry was rejected",
    )
    requireState(state.requiresVoiceCapture, "lost-response retry lost active voice state")
    requireState(
        !state.unregisterOutgoingOwner(first),
        "pre-resume owner retired the replacement generation",
    )
    requireState(state.unregisterOutgoingOwner(resumed), "resumed owner teardown failed")
    requireState(!state.requiresVoiceCapture, "resumed owner teardown retained voice capture")

    requireState(state.registerControlledConnection(10, 21, 5), "overlap controlled registration failed")
    requireState(state.setControlledVoiceCallActive(10, 21, 5, true), "overlap controlled activation failed")
    requireState(state.registerOutgoingOwner(replacement), "overlap outgoing registration failed")
    requireState(state.setOutgoingVoiceCallActive(replacement, true), "overlap outgoing activation failed")
    requireState(state.unregisterControlledConnection(10, 21, 5), "overlap controlled teardown failed")
    requireState(state.requiresVoiceCapture, "controlled teardown cleared an outgoing owner")
    state.invalidateOutgoingOwner()
    requireState(!state.requiresVoiceCapture, "outgoing invalidation retained voice capture")

    requireState(state.registerControlledConnection(10, 22, 6), "clear controlled registration failed")
    requireState(state.setControlledVoiceCallActive(10, 22, 6, true), "clear controlled activation failed")
    requireState(
        !state.beginControlledServiceGeneration(11),
        "replacement controlled service generation bypassed exact retirement",
    )
    requireState(
        state.requiresVoiceCapture,
        "rejected replacement changed the prior controlled voice owner",
    )
    requireState(
        state.clearControlledConnections(10),
        "predecessor controlled generation did not retire exactly",
    )
    requireState(
        state.beginControlledServiceGeneration(11),
        "replacement controlled service generation was rejected after retirement",
    )
    requireState(
        !state.requiresVoiceCapture,
        "replacement generation inherited prior controlled voice demand",
    )
    requireState(
        !state.registerControlledConnection(10, 22, 7),
        "stale generation registered a same-number controlled owner",
    )
    requireState(
        !state.setControlledVoiceCallActive(10, 22, 6, true),
        "stale generation changed controlled voice state",
    )
    requireState(
        state.registerControlledConnection(11, 22, 7),
        "replacement generation same-number owner registration failed",
    )
    requireState(
        state.setControlledVoiceCallActive(11, 22, 7, true),
        "replacement generation same-number owner activation failed",
    )
    requireState(
        !state.clearControlledConnections(10),
        "stale generation cleared replacement controlled owners",
    )
    requireState(
        state.requiresVoiceCapture,
        "stale generation teardown retired replacement voice capture",
    )
    requireState(
        state.beginControlledServiceGeneration(11),
        "current generation idempotent begin was rejected",
    )
    requireState(
        state.requiresVoiceCapture,
        "current generation idempotent begin cleared live owners",
    )
    requireState(
        state.registerOutgoingOwner(replacement),
        "replacement-overlap outgoing registration failed",
    )
    requireState(
        state.setOutgoingVoiceCallActive(replacement, true),
        "replacement-overlap outgoing activation failed",
    )
    requireState(
        !state.beginControlledServiceGeneration(12),
        "newer controlled service generation bypassed exact retirement",
    )
    requireState(
        state.requiresVoiceCapture,
        "rejected controlled-service replacement changed active demand",
    )
    requireState(
        state.clearControlledConnections(11),
        "current controlled generation did not retire before replacement",
    )
    requireState(
        state.beginControlledServiceGeneration(12),
        "newer controlled service generation was rejected after retirement",
    )
    requireState(
        state.requiresVoiceCapture,
        "controlled-service replacement cleared the outgoing owner",
    )
    requireState(
        state.setOutgoingVoiceCallActive(replacement, false),
        "controlled-service replacement invalidated the outgoing owner",
    )
    requireState(
        !state.requiresVoiceCapture,
        "controlled-service replacement retained predecessor controlled voice state",
    )
    requireState(
        state.unregisterOutgoingOwner(replacement),
        "replacement-overlap outgoing teardown failed",
    )
    requireState(
        !state.beginControlledServiceGeneration(11),
        "superseded controlled generation was reactivated",
    )
    requireState(
        state.clearControlledConnections(12),
        "current controlled generation teardown failed",
    )
    requireState(!state.requiresVoiceCapture, "controlled owner clear retained voice capture")
    requireState(
        state.clearControlledConnections(12),
        "exact controlled teardown retry was not idempotent",
    )
    requireState(
        state.mayClearControlledServiceResources(12),
        "retired controlled generation could not finish resource cleanup",
    )
    requireState(
        !state.beginControlledServiceGeneration(12),
        "retired generation was reactivated",
    )
    requireState(
        state.beginControlledServiceGeneration(13),
        "newer controlled service generation was rejected after retirement",
    )
    requireState(
        !state.clearControlledConnections(12),
        "retired predecessor cleanup changed its replacement",
    )
    requireState(
        !state.mayClearControlledServiceResources(12),
        "retired predecessor retained cleanup authority over its replacement",
    )
}
