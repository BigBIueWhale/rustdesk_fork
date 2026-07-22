package com.carriez.flutter_hbb

private fun requireState(condition: Boolean, message: String) {
    check(condition) { message }
}

fun main() {
    val state = VoiceCallOwnerState()
    requireState(!state.requiresVoiceCapture, "fresh state requires voice capture")
    requireState(!state.registerControlledConnection(0), "invalid controlled owner was admitted")
    requireState(
        !state.setControlledVoiceCallActive(11, true),
        "unregistered controlled owner was activated",
    )

    requireState(state.registerControlledConnection(11), "first controlled owner registration failed")
    requireState(state.registerControlledConnection(12), "second controlled owner registration failed")
    requireState(state.setControlledVoiceCallActive(11, true), "first controlled owner activation failed")
    requireState(state.setControlledVoiceCallActive(12, true), "second controlled owner activation failed")
    requireState(state.requiresVoiceCapture, "controlled owners did not require voice capture")
    requireState(state.unregisterControlledConnection(11), "first controlled owner removal failed")
    requireState(state.requiresVoiceCapture, "one controlled teardown cleared another owner")
    requireState(state.unregisterControlledConnection(12), "final controlled owner removal failed")
    requireState(!state.requiresVoiceCapture, "final controlled teardown retained voice capture")

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

    requireState(state.registerControlledConnection(21), "overlap controlled registration failed")
    requireState(state.setControlledVoiceCallActive(21, true), "overlap controlled activation failed")
    requireState(state.registerOutgoingOwner(replacement), "overlap outgoing registration failed")
    requireState(state.setOutgoingVoiceCallActive(replacement, true), "overlap outgoing activation failed")
    requireState(state.unregisterControlledConnection(21), "overlap controlled teardown failed")
    requireState(state.requiresVoiceCapture, "controlled teardown cleared an outgoing owner")
    state.invalidateOutgoingOwner()
    requireState(!state.requiresVoiceCapture, "outgoing invalidation retained voice capture")

    requireState(state.registerControlledConnection(22), "clear controlled registration failed")
    requireState(state.setControlledVoiceCallActive(22, true), "clear controlled activation failed")
    state.clearControlledConnections()
    requireState(!state.requiresVoiceCapture, "controlled owner clear retained voice capture")
}
