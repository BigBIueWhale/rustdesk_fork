package com.carriez.flutter_hbb

private fun requireGenerationOwner(condition: Boolean, message: String) {
    check(condition) { message }
}

fun main() {
    val owner = MainServiceGenerationOwner()
    requireGenerationOwner(!owner.beginReservation(0), "zero native generation was reserved")
    requireGenerationOwner(owner.beginReservation(7), "first native generation reservation was rejected")
    requireGenerationOwner(
        !owner.beginReservation(8),
        "a replacement generation was reserved while one transaction was active",
    )
    requireGenerationOwner(
        owner.retire(6) == null,
        "stale reservation retirement selected the active transaction",
    )
    requireGenerationOwner(
        owner.retire(7) == MainServiceGenerationRetirement(7, false, false),
        "reservation-only rollback selected unrelated authority",
    )
    requireGenerationOwner(
        !owner.beginReservation(7),
        "retired native generation was reserved again",
    )

    requireGenerationOwner(owner.beginReservation(8), "status-failure generation was rejected")
    requireGenerationOwner(owner.noteStatusAttempt(8), "status attempt was not recorded")
    requireGenerationOwner(
        owner.retire(8) == MainServiceGenerationRetirement(8, true, false),
        "status-failure rollback did not select exactly the attempted status owner",
    )

    requireGenerationOwner(owner.beginReservation(9), "voice-failure generation was rejected")
    requireGenerationOwner(owner.noteStatusAttempt(9), "voice predecessor stage was rejected")
    requireGenerationOwner(owner.noteVoiceAttempt(9), "voice attempt was not recorded")
    requireGenerationOwner(
        owner.retire(9) == MainServiceGenerationRetirement(9, true, true),
        "voice-failure rollback did not select every attempted exact owner",
    )

    requireGenerationOwner(owner.beginReservation(10), "activation-failure generation was rejected")
    requireGenerationOwner(owner.noteStatusAttempt(10), "activation status stage was rejected")
    requireGenerationOwner(owner.noteVoiceAttempt(10), "activation voice stage was rejected")
    requireGenerationOwner(
        owner.noteActivationAttempt(10),
        "listener activation attempt was not recorded",
    )
    requireGenerationOwner(
        owner.retire(10) == MainServiceGenerationRetirement(10, true, true),
        "activation-failure rollback did not select every attempted exact owner",
    )

    requireGenerationOwner(owner.beginReservation(11), "commit generation was rejected")
    requireGenerationOwner(!owner.commit(11), "generation committed before status and voice")
    requireGenerationOwner(owner.noteStatusAttempt(11), "commit status stage was rejected")
    requireGenerationOwner(!owner.commit(11), "generation committed before voice")
    requireGenerationOwner(owner.noteVoiceAttempt(11), "commit voice stage was rejected")
    requireGenerationOwner(!owner.commit(11), "generation committed before listener activation")
    requireGenerationOwner(
        owner.noteActivationAttempt(11),
        "commit listener activation stage was rejected",
    )
    requireGenerationOwner(owner.commit(11), "complete generation failed to commit")
    requireGenerationOwner(owner.isCommitted(11), "committed generation was not observable")
    requireGenerationOwner(!owner.isCommitted(10), "stale generation appeared committed")
    requireGenerationOwner(
        owner.retire(10) == null,
        "stale committed retirement selected its replacement",
    )
    requireGenerationOwner(
        owner.retire(11) == MainServiceGenerationRetirement(11, true, true),
        "committed retirement omitted an exact owner",
    )
    requireGenerationOwner(!owner.isCommitted(11), "retired generation remained committed")
    requireGenerationOwner(owner.beginReservation(12), "new generation after rollback was rejected")
}
