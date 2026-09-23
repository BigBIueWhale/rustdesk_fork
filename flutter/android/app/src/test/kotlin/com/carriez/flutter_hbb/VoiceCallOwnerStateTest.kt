package com.carriez.flutter_hbb

private var assertions = 0

private fun expect(value: Boolean, description: String) {
    assertions += 1
    check(value) { description }
}

private fun expectCapture(state: VoiceCallOwnerState, expected: Boolean, description: String) {
    expect(state.requiresVoiceCapture == expected, description)
}

private fun controlledServiceGenerationIsMonotonic() {
    val state = VoiceCallOwnerState()
    expect(!state.beginControlledServiceGeneration(0), "zero controlled generation was admitted")
    expect(!state.beginControlledServiceGeneration(-1), "negative controlled generation was admitted")
    expect(state.beginControlledServiceGeneration(1), "first controlled generation was refused")
    expect(state.beginControlledServiceGeneration(1), "current controlled generation was not idempotent")
    expect(!state.beginControlledServiceGeneration(2), "live controlled generation was replaced")
    expect(state.clearControlledConnections(1), "current controlled generation did not clear")
    expect(state.clearControlledConnections(1), "current controlled clear was not idempotent")
    expect(!state.beginControlledServiceGeneration(1), "retired controlled generation was resurrected")
    expect(state.beginControlledServiceGeneration(2), "monotonic controlled successor was refused")
    expect(!state.clearControlledConnections(1), "stale controlled generation cleared its successor")
    expect(state.isControlledServiceGeneration(2), "controlled successor was not retained")
}

private fun controlledRegistryGenerationPreventsConnectionAba() {
    val state = VoiceCallOwnerState()
    expect(state.beginControlledServiceGeneration(10), "controlled generation setup failed")
    expect(state.registerControlledConnection(10, 7, 100), "controlled connection registration failed")
    expect(state.setControlledVoiceCallActive(10, 7, 100, true), "controlled voice activation failed")
    expectCapture(state, true, "active controlled owner did not require capture")
    expect(!state.registerControlledConnection(10, 7, 100), "duplicate registry generation was admitted")
    expect(state.registerControlledConnection(10, 7, 101), "new registry generation was refused")
    expectCapture(state, false, "connection replacement retained predecessor activity")
    expect(!state.setControlledVoiceCallActive(10, 7, 100, true), "stale registry generation became active")
    expect(!state.unregisterControlledConnection(10, 7, 100), "stale registry generation retired successor")
    expect(state.setControlledVoiceCallActive(10, 7, 101, true), "replacement controlled owner did not activate")
    expectCapture(state, true, "replacement controlled owner did not require capture")
    expect(state.unregisterControlledConnection(10, 7, 101), "replacement controlled owner did not retire")
    expectCapture(state, false, "retired replacement still required capture")
    expect(state.unregisterControlledConnection(10, 7, 101), "exact controlled retirement was not idempotent")
}

private fun concurrentControlledOwnersRetireIndependently() {
    val state = VoiceCallOwnerState()
    expect(state.beginControlledServiceGeneration(20), "controlled generation setup failed")
    expect(state.registerControlledConnection(20, 1, 1), "first controlled owner registration failed")
    expect(state.registerControlledConnection(20, 2, 1), "second controlled owner registration failed")
    expect(state.setControlledVoiceCallActive(20, 1, 1, true), "first controlled owner activation failed")
    expect(state.setControlledVoiceCallActive(20, 2, 1, true), "second controlled owner activation failed")
    expectCapture(state, true, "concurrent controlled owners did not require capture")
    expect(state.setControlledVoiceCallActive(20, 1, 1, false), "first controlled owner deactivation failed")
    expectCapture(state, true, "first deactivation stopped the second controlled owner")
    expect(state.unregisterControlledConnection(20, 1, 1), "first controlled owner retirement failed")
    expectCapture(state, true, "first retirement stopped the second controlled owner")
    expect(state.unregisterControlledConnection(20, 2, 1), "second controlled owner retirement failed")
    expectCapture(state, false, "final controlled retirement retained capture")
}

private fun outgoingOwnerIsExact() {
    val state = VoiceCallOwnerState()
    val first = OutgoingVoiceCallOwner(1, "first-session")
    val replacement = OutgoingVoiceCallOwner(2, "second-session")
    expect(!state.registerOutgoingOwner(OutgoingVoiceCallOwner(0, "first-session")), "zero outgoing generation was admitted")
    expect(!state.registerOutgoingOwner(OutgoingVoiceCallOwner(1, "")), "empty outgoing session was admitted")
    expect(state.registerOutgoingOwner(first), "first outgoing owner registration failed")
    expect(state.registerOutgoingOwner(first), "exact outgoing registration was not idempotent")
    expect(!state.registerOutgoingOwner(replacement), "parallel outgoing owner was admitted")
    expect(state.setOutgoingVoiceCallActive(first, true), "outgoing owner activation failed")
    expectCapture(state, true, "active outgoing owner did not require capture")
    expect(!state.setOutgoingVoiceCallActive(replacement, false), "foreign outgoing owner changed activity")
    expectCapture(state, true, "foreign outgoing update stopped capture")
    expect(!state.unregisterOutgoingOwner(replacement), "foreign outgoing owner retired current owner")
    expectCapture(state, true, "foreign outgoing retirement stopped capture")
    expect(state.unregisterOutgoingOwner(first), "current outgoing owner retirement failed")
    expectCapture(state, false, "retired outgoing owner still required capture")
    expect(!state.setOutgoingVoiceCallActive(first, false), "retired outgoing owner changed activity")
}

private fun outgoingResumeTransfersOnlyToSameSessionAndNewerGeneration() {
    val state = VoiceCallOwnerState()
    val previous = OutgoingVoiceCallOwner(30, "same-session")
    val newer = OutgoingVoiceCallOwner(31, "same-session")
    expect(state.registerOutgoingOwner(previous), "outgoing resume setup failed")
    expect(state.setOutgoingVoiceCallActive(previous, true), "outgoing resume activation failed")
    expect(state.resumeOutgoingOwner(previous, previous), "same-generation resume was not idempotent")
    expectCapture(state, true, "same-generation resume lost active state")
    expect(!state.resumeOutgoingOwner(previous, OutgoingVoiceCallOwner(29, "same-session")), "older outgoing generation resumed")
    expect(!state.resumeOutgoingOwner(previous, OutgoingVoiceCallOwner(31, "other-session")), "cross-session outgoing owner resumed")
    expect(state.resumeOutgoingOwner(previous, newer), "newer same-session outgoing owner did not resume")
    expectCapture(state, true, "newer outgoing resume lost active state")
    expect(!state.setOutgoingVoiceCallActive(previous, false), "predecessor outgoing owner changed successor")
    expectCapture(state, true, "predecessor outgoing update stopped successor capture")
    expect(!state.unregisterOutgoingOwner(previous), "predecessor outgoing owner retired successor")
    expect(state.unregisterOutgoingOwner(newer), "resumed outgoing owner did not retire")
    expectCapture(state, false, "retired resumed owner still required capture")
}

private fun controlledAndOutgoingDomainsRetireIndependently() {
    val controlledSurvives = VoiceCallOwnerState()
    val outgoing = OutgoingVoiceCallOwner(40, "outgoing-session")
    expect(controlledSurvives.beginControlledServiceGeneration(40), "controlled setup failed")
    expect(controlledSurvives.registerControlledConnection(40, 1, 1), "controlled registration failed")
    expect(controlledSurvives.setControlledVoiceCallActive(40, 1, 1, true), "controlled activation failed")
    expect(controlledSurvives.registerOutgoingOwner(outgoing), "outgoing registration failed")
    expect(controlledSurvives.setOutgoingVoiceCallActive(outgoing, true), "outgoing activation failed")
    expectCapture(controlledSurvives, true, "overlapping owner domains did not require capture")
    expect(controlledSurvives.unregisterOutgoingOwner(outgoing), "outgoing retirement failed")
    expectCapture(controlledSurvives, true, "outgoing retirement stopped controlled capture")
    expect(controlledSurvives.clearControlledConnections(40), "controlled retirement failed")
    expectCapture(controlledSurvives, false, "final controlled retirement retained capture")

    val outgoingSurvives = VoiceCallOwnerState()
    expect(outgoingSurvives.beginControlledServiceGeneration(41), "second controlled setup failed")
    expect(outgoingSurvives.registerControlledConnection(41, 2, 1), "second controlled registration failed")
    expect(outgoingSurvives.setControlledVoiceCallActive(41, 2, 1, true), "second controlled activation failed")
    expect(outgoingSurvives.registerOutgoingOwner(outgoing), "second outgoing registration failed")
    expect(outgoingSurvives.setOutgoingVoiceCallActive(outgoing, true), "second outgoing activation failed")
    expect(outgoingSurvives.clearControlledConnections(41), "controlled generation did not clear")
    expectCapture(outgoingSurvives, true, "controlled teardown stopped outgoing capture")
    expect(outgoingSurvives.unregisterOutgoingOwner(outgoing), "surviving outgoing owner did not retire")
    expectCapture(outgoingSurvives, false, "final outgoing retirement retained capture")
}

private fun activityInvalidationPreservesControlledOwners() {
    val state = VoiceCallOwnerState()
    val outgoing = OutgoingVoiceCallOwner(50, "outgoing-session")
    expect(state.beginControlledServiceGeneration(50), "controlled setup failed")
    expect(state.registerControlledConnection(50, 1, 1), "controlled registration failed")
    expect(state.setControlledVoiceCallActive(50, 1, 1, true), "controlled activation failed")
    expect(state.registerOutgoingOwner(outgoing), "outgoing registration failed")
    expect(state.setOutgoingVoiceCallActive(outgoing, true), "outgoing activation failed")
    state.invalidateOutgoingOwner()
    expectCapture(state, true, "Activity invalidation stopped controlled capture")
    expect(!state.setOutgoingVoiceCallActive(outgoing, false), "invalidated outgoing owner changed state")
    expect(!state.unregisterOutgoingOwner(outgoing), "invalidated outgoing owner retired state")
    expect(state.unregisterControlledConnection(50, 1, 1), "controlled owner did not retire after Activity invalidation")
    expectCapture(state, false, "final controlled retirement retained capture")
}

fun main() {
    controlledServiceGenerationIsMonotonic()
    controlledRegistryGenerationPreventsConnectionAba()
    concurrentControlledOwnersRetireIndependently()
    outgoingOwnerIsExact()
    outgoingResumeTransfersOnlyToSameSessionAndNewerGeneration()
    controlledAndOutgoingDomainsRetireIndependently()
    activityInvalidationPreservesControlledOwners()
    check(assertions == 93) { "test assertion inventory changed: $assertions" }
    println("ANDROID_VOICE_OWNER_STATE_TEST=pass scenarios=7 assertions=$assertions kotlin=2.0.21")
}
