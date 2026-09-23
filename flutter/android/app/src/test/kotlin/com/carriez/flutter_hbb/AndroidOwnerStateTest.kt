package com.carriez.flutter_hbb

private var ownerAssertions = 0

private fun expectOwner(value: Boolean, description: String) {
    ownerAssertions += 1
    check(value) { description }
}

private fun expectOwnerFailure(description: String, action: () -> Unit) {
    ownerAssertions += 1
    check(runCatching(action).isFailure) { description }
}

private fun connectionTypePolicyIsClosedAndExact() {
    expectOwner(ControlledConnectionType.fromWireTag("Remote") == ControlledConnectionType.REMOTE, "Remote tag was not decoded")
    expectOwner(ControlledConnectionType.fromWireTag("FileTransfer") == ControlledConnectionType.FILE_TRANSFER, "FileTransfer tag was not decoded")
    expectOwner(ControlledConnectionType.fromWireTag("ViewCamera") == ControlledConnectionType.VIEW_CAMERA, "ViewCamera tag was not decoded")
    expectOwner(ControlledConnectionType.fromWireTag("Terminal") == ControlledConnectionType.TERMINAL, "Terminal tag was not decoded")
    expectOwner(ControlledConnectionType.fromWireTag("PortForward") == ControlledConnectionType.PORT_FORWARD, "PortForward tag was not decoded")
    expectOwner(ControlledConnectionType.fromWireTag("") == null, "empty connection tag was admitted")
    expectOwner(ControlledConnectionType.fromWireTag("remote") == null, "case-varied connection tag was admitted")
    expectOwner(ControlledConnectionType.fromWireTag(" Remote") == null, "whitespace-varied connection tag was admitted")
    expectOwner(ControlledConnectionType.fromWireTag("Future") == null, "unknown connection tag was admitted")
    expectOwner(ControlledConnectionType.REMOTE.requiresDesktopCapture, "Remote did not require desktop capture")
    expectOwner(!ControlledConnectionType.FILE_TRANSFER.requiresDesktopCapture, "FileTransfer required desktop capture")
    expectOwner(!ControlledConnectionType.VIEW_CAMERA.requiresDesktopCapture, "ViewCamera required desktop capture")
    expectOwner(!ControlledConnectionType.TERMINAL.requiresDesktopCapture, "Terminal required desktop capture")
    expectOwner(!ControlledConnectionType.PORT_FORWARD.requiresDesktopCapture, "PortForward required desktop capture")
    expectOwner(ControlledConnectionType.REMOTE.allowsVoiceCall, "Remote did not allow voice calls")
    expectOwner(!ControlledConnectionType.FILE_TRANSFER.allowsVoiceCall, "FileTransfer allowed voice calls")
    expectOwner(ControlledConnectionType.VIEW_CAMERA.allowsVoiceCall, "ViewCamera did not allow voice calls")
    expectOwner(!ControlledConnectionType.TERMINAL.allowsVoiceCall, "Terminal allowed voice calls")
    expectOwner(!ControlledConnectionType.PORT_FORWARD.allowsVoiceCall, "PortForward allowed voice calls")
}

private fun captureOwnersRejectStaleAndUnauthorizedDemand() {
    val state = ControlledCaptureOwnerState()
    expectOwner(!state.requiresDesktopCapture, "empty capture registry required capture")
    expectOwner(!state.upsert(0, 1, true, ControlledConnectionType.REMOTE), "zero connection ID was admitted")
    expectOwner(!state.upsert(1, 0, true, ControlledConnectionType.REMOTE), "zero registry generation was admitted")
    expectOwner(state.upsert(1, 1, false, ControlledConnectionType.REMOTE), "unauthorized owner was not recorded")
    expectOwner(!state.requiresDesktopCapture, "unauthorized Remote required capture")
    expectOwner(state.remoteInputRegistryGeneration(1) == null, "unauthorized Remote gained input authority")
    expectOwner(state.registryGeneration(1) == 1L, "unauthorized registry generation was not retained")
    expectOwner(!state.upsert(1, 1, true, ControlledConnectionType.REMOTE), "same registry generation replaced its owner")
    expectOwner(state.upsert(1, 2, true, ControlledConnectionType.FILE_TRANSFER), "new FileTransfer generation was refused")
    expectOwner(!state.requiresDesktopCapture, "FileTransfer required capture")
    expectOwner(state.remoteInputRegistryGeneration(1) == null, "FileTransfer gained input authority")
    expectOwner(state.registryGeneration(1) == 2L, "replacement registry generation was not retained")
    expectOwner(!state.isCurrent(1, 1), "stale registry generation remained current")
    expectOwner(state.isCurrent(1, 2), "replacement registry generation was not current")
    expectOwner(state.upsert(2, 1, true, ControlledConnectionType.REMOTE), "authorized Remote was refused")
    expectOwner(state.requiresDesktopCapture, "authorized Remote did not require capture")
    expectOwner(state.remoteInputRegistryGeneration(2) == 1L, "authorized Remote lacked input authority")
    expectOwner(state.upsert(3, 1, true, ControlledConnectionType.VIEW_CAMERA), "ViewCamera was refused")
    expectOwner(state.requiresDesktopCapture, "ViewCamera registration cleared Remote capture")
    expectOwner(state.remoteInputRegistryGeneration(3) == null, "ViewCamera gained Remote input authority")
    expectOwner(state.registryGeneration(3) == 1L, "ViewCamera registry generation was not retained")
    expectOwner(!state.unregister(2, 2), "wrong generation retired Remote owner")
    expectOwner(state.requiresDesktopCapture, "wrong retirement cleared Remote capture")
    expectOwner(state.unregister(2, 1), "exact Remote owner did not retire")
    expectOwner(!state.requiresDesktopCapture, "retired final Remote still required capture")
    state.clear()
    expectOwner(state.registryGeneration(1) == null, "clear retained FileTransfer owner")
    expectOwner(state.registryGeneration(3) == null, "clear retained ViewCamera owner")
    expectOwner(!state.requiresDesktopCapture, "clear retained capture demand")
}

private fun controlledInputOwnerIdentityIsExact() {
    val owner = ControlledInputOwner(1, 2, 3)
    expectOwner(owner.isValid, "positive input owner was invalid")
    expectOwner(!ControlledInputOwner(0, 2, 3).isValid, "zero service generation was valid")
    expectOwner(!ControlledInputOwner(1, 0, 3).isValid, "zero connection ID was valid")
    expectOwner(!ControlledInputOwner(1, 2, 0).isValid, "zero registry generation was valid")
    expectOwner(!ControlledInputOwner(-1, 2, 3).isValid, "negative service generation was valid")
    expectOwner(!ControlledInputOwner(1, -2, 3).isValid, "negative connection ID was valid")
    expectOwner(!ControlledInputOwner(1, 2, -3).isValid, "negative registry generation was valid")
    expectOwner(owner == ControlledInputOwner(1, 2, 3), "equal input owner identity differed")
    expectOwner(owner != ControlledInputOwner(2, 2, 3), "service replacement reused owner identity")
    expectOwner(owner != ControlledInputOwner(1, 3, 3), "connection replacement reused owner identity")
    expectOwner(owner != ControlledInputOwner(1, 2, 4), "registry replacement reused owner identity")
}

private fun boundedInputQueuePreservesFifoAndCapacity() {
    expectOwnerFailure("zero-capacity input queue was constructed") { ExactOwnerBoundedQueue<String>(0) }
    expectOwnerFailure("negative-capacity input queue was constructed") { ExactOwnerBoundedQueue<String>(-1) }
    val queue = ExactOwnerBoundedQueue<String>(2)
    val first = ControlledInputOwner(1, 1, 1)
    val second = ControlledInputOwner(1, 2, 1)
    expectOwner(queue.size == 0, "new input queue was not empty")
    expectOwner(queue.poll() == null, "new input queue returned an entry")
    expectOwner(!queue.offer(ControlledInputOwner(0, 1, 1), "invalid"), "invalid owner entered input queue")
    expectOwner(queue.offer(first, "first"), "first input entry was refused")
    expectOwner(queue.offer(second, "second"), "second input entry was refused")
    expectOwner(queue.size == 2, "input queue size did not reach capacity")
    expectOwner(!queue.offer(ControlledInputOwner(1, 3, 1), "overflow"), "input queue exceeded capacity")
    expectOwner(queue.size == 2, "overflow changed input queue size")
    expectOwner(queue.poll() == OwnedControlledInput(first, "first"), "input queue violated FIFO at first entry")
    expectOwner(queue.size == 1, "input queue did not subtract a dequeue")
    expectOwner(queue.offer(first, "third"), "input queue did not recover capacity")
    expectOwner(queue.poll() == OwnedControlledInput(second, "second"), "input queue violated FIFO at second entry")
    expectOwner(queue.poll() == OwnedControlledInput(first, "third"), "input queue violated FIFO after capacity recovery")
    expectOwner(queue.poll() == null, "drained input queue returned an entry")
}

private fun boundedInputQueueRetiresOnlyExactOwner() {
    val queue = ExactOwnerBoundedQueue<String>(5)
    val predecessor = ControlledInputOwner(7, 9, 10)
    val successor = ControlledInputOwner(7, 9, 11)
    val other = ControlledInputOwner(7, 10, 1)
    expectOwner(queue.offer(predecessor, "old-a"), "predecessor entry A was refused")
    expectOwner(queue.offer(other, "other"), "other-owner entry was refused")
    expectOwner(queue.offer(predecessor, "old-b"), "predecessor entry B was refused")
    expectOwner(queue.offer(successor, "new"), "successor entry was refused")
    queue.removeOwner(predecessor)
    expectOwner(queue.size == 2, "exact owner retirement removed the wrong count")
    expectOwner(queue.poll() == OwnedControlledInput(other, "other"), "exact owner retirement changed other owner order")
    expectOwner(queue.poll() == OwnedControlledInput(successor, "new"), "exact owner retirement removed ABA successor")
    expectOwner(queue.poll() == null, "exact owner retirement left predecessor entries")
    expectOwner(queue.offer(other, "clear-a"), "post-retirement queue admission failed")
    expectOwner(queue.offer(successor, "clear-b"), "post-retirement successor admission failed")
    queue.clear()
    expectOwner(queue.size == 0, "input queue clear retained entries")
    expectOwner(queue.poll() == null, "cleared input queue returned an entry")
}

private fun serviceStatusGenerationIsMonotonicAndIdempotent() {
    val state = MainServiceStatusOwner()
    expectOwner(state.snapshot() == null, "empty status owner published a snapshot")
    expectOwner(!state.begin(0), "zero status generation was admitted")
    expectOwner(!state.begin(-1), "negative status generation was admitted")
    expectOwner(state.begin(10), "first status generation was refused")
    expectOwner(state.snapshot() == MainServiceStatus(10, false), "first status snapshot differed")
    expectOwner(state.begin(10), "current status generation was not idempotent")
    expectOwner(!state.begin(11), "live status generation was replaced")
    expectOwner(!state.setMediaProjectionReady(9, true), "stale status generation became ready")
    expectOwner(!state.setMediaProjectionReady(9, false), "stale live status generation confirmed inactive")
    expectOwner(state.setMediaProjectionReady(10, true), "current status generation did not become ready")
    expectOwner(state.snapshot() == MainServiceStatus(10, true), "ready status snapshot differed")
    expectOwner(!state.retireOrConfirmInactive(9), "stale status generation retired current owner")
    expectOwner(state.retireOrConfirmInactive(10), "current status generation did not retire")
    expectOwner(state.snapshot() == null, "retired status generation remained published")
    expectOwner(state.setMediaProjectionReady(10, false), "retired exact status did not confirm inactive")
    expectOwner(!state.setMediaProjectionReady(10, true), "retired exact status resurrected ready state")
    expectOwner(state.retireOrConfirmInactive(10), "retired exact status was not idempotent")
    expectOwner(!state.begin(10), "retired status generation was reused")
    expectOwner(state.begin(11), "higher status generation was refused")
    expectOwner(state.snapshot() == MainServiceStatus(11, false), "replacement status snapshot differed")

    val exhausted = MainServiceStatusOwner()
    expectOwner(exhausted.begin(Long.MAX_VALUE), "maximum status generation was refused")
    expectOwner(exhausted.setMediaProjectionReady(Long.MAX_VALUE, true), "maximum status generation did not become ready")
    expectOwner(exhausted.retireOrConfirmInactive(Long.MAX_VALUE), "maximum status generation did not retire")
    expectOwner(!exhausted.begin(Long.MAX_VALUE), "maximum status generation was reused")
    expectOwner(!exhausted.begin(1), "status generation wrapped after exhaustion")
}

private fun serviceGenerationCommitsOnlyCompleteStartup() {
    val state = MainServiceGenerationOwner()
    expectOwner(!state.beginReservation(0), "zero service generation was reserved")
    expectOwner(!state.beginReservation(-1), "negative service generation was reserved")
    expectOwner(state.beginReservation(100), "first service generation was not reserved")
    expectOwner(state.hasActiveGeneration(), "reserved service generation was not active")
    expectOwner(!state.beginReservation(101), "parallel service generation was reserved")
    expectOwner(!state.isCommitted(100), "reserved service generation was already committed")
    expectOwner(!state.noteVoiceAttempt(100), "voice attempt skipped status attempt")
    expectOwner(state.noteStatusAttempt(100), "status attempt was refused")
    expectOwner(!state.noteStatusAttempt(100), "status attempt repeated")
    expectOwner(!state.noteActivationAttempt(100), "activation skipped voice attempt")
    expectOwner(state.noteVoiceAttempt(100), "voice attempt was refused")
    expectOwner(!state.commit(100), "commit skipped activation attempt")
    expectOwner(state.noteActivationAttempt(100), "activation attempt was refused")
    expectOwner(!state.noteVoiceAttempt(100), "voice attempt repeated after activation")
    expectOwner(state.commit(100), "complete service generation did not commit")
    expectOwner(state.isCommitted(100), "committed service generation was not observable")
    expectOwner(!state.commit(100), "service generation committed twice")
    expectOwner(!state.isCommitted(99), "stale service generation appeared committed")
}

private fun serviceGenerationRetirementPlansAreStableAndExact() {
    val phases = listOf(
        Triple(1L, false, false),
        Triple(2L, true, false),
        Triple(3L, true, true),
        Triple(4L, true, true),
        Triple(5L, true, true),
    )
    phases.forEachIndexed { index, (generation, retireStatus, retireVoice) ->
        val state = MainServiceGenerationOwner()
        expectOwner(state.beginReservation(generation), "phase $index reservation failed")
        if (index >= 1) {
            expectOwner(state.noteStatusAttempt(generation), "phase $index status attempt failed")
        }
        if (index >= 2) {
            expectOwner(state.noteVoiceAttempt(generation), "phase $index voice attempt failed")
        }
        if (index >= 3) {
            expectOwner(state.noteActivationAttempt(generation), "phase $index activation attempt failed")
        }
        if (index >= 4) {
            expectOwner(state.commit(generation), "phase $index commit failed")
        }
        expectOwner(state.beginRetirement(generation - 1) == null, "phase $index stale retirement was admitted")
        val plan = state.beginRetirement(generation)
        expectOwner(plan == MainServiceGenerationRetirement(generation, retireStatus, retireVoice), "phase $index retirement plan differed")
        expectOwner(state.beginRetirement(generation) === plan, "phase $index retirement plan was not stable")
        expectOwner(!state.beginReservation(generation + 100), "phase $index replacement overlapped retirement")
        expectOwner(!state.completeRetirement(generation - 1), "phase $index stale completion was admitted")
        expectOwner(state.completeRetirement(generation), "phase $index exact retirement did not complete")
        expectOwner(!state.hasActiveGeneration(), "phase $index remained active after retirement")
        expectOwner(!state.completeRetirement(generation), "phase $index retirement completed twice")
        expectOwner(!state.beginReservation(generation), "phase $index retired generation was reused")
        expectOwner(state.beginReservation(generation + 100), "phase $index higher generation was refused")
    }

    val exhausted = MainServiceGenerationOwner()
    expectOwner(exhausted.beginReservation(Long.MAX_VALUE), "maximum service generation was refused")
    expectOwner(
        exhausted.beginRetirement(Long.MAX_VALUE) == MainServiceGenerationRetirement(Long.MAX_VALUE, false, false),
        "maximum service generation retirement plan differed",
    )
    expectOwner(exhausted.completeRetirement(Long.MAX_VALUE), "maximum service generation did not retire")
    expectOwner(!exhausted.beginReservation(Long.MAX_VALUE), "maximum service generation was reused")
    expectOwner(!exhausted.beginReservation(1), "service generation wrapped after exhaustion")
    expectOwner(!exhausted.hasActiveGeneration(), "service generation exhaustion left an active owner")
}

fun main() {
    connectionTypePolicyIsClosedAndExact()
    captureOwnersRejectStaleAndUnauthorizedDemand()
    controlledInputOwnerIdentityIsExact()
    boundedInputQueuePreservesFifoAndCapacity()
    boundedInputQueueRetiresOnlyExactOwner()
    serviceStatusGenerationIsMonotonicAndIdempotent()
    serviceGenerationCommitsOnlyCompleteStartup()
    serviceGenerationRetirementPlansAreStableAndExact()
    check(ownerAssertions == 200) { "owner-state assertion inventory changed: $ownerAssertions" }
    println("ANDROID_OWNER_STATE_TEST=pass scenarios=8 assertions=$ownerAssertions kotlin=2.0.21")
}
