package com.carriez.flutter_hbb

private fun requireGenerationOwner(condition: Boolean, message: String) {
    check(condition) { message }
}

fun main() {
    val owner = MainServiceGenerationOwner()
    requireGenerationOwner(!owner.hasActiveGeneration(), "fresh owner reported an active generation")
    requireGenerationOwner(!owner.beginReservation(0), "zero native generation was reserved")
    requireGenerationOwner(owner.beginReservation(7), "first native generation reservation was rejected")
    requireGenerationOwner(
        !owner.beginReservation(8),
        "a replacement generation was reserved while one transaction was active",
    )
    requireGenerationOwner(
        owner.beginRetirement(6) == null,
        "stale reservation retirement selected the active transaction",
    )
    val reservationPlan = MainServiceGenerationRetirement(7, false, false)
    requireGenerationOwner(
        owner.beginRetirement(7) == reservationPlan,
        "reservation-only rollback selected unrelated authority",
    )
    requireGenerationOwner(
        owner.beginRetirement(7) == reservationPlan,
        "retirement retry did not retain the exact cleanup plan",
    )
    requireGenerationOwner(
        !owner.beginReservation(8),
        "cleanup failure released authority for a replacement generation",
    )
    requireGenerationOwner(owner.hasActiveGeneration(), "cleanup failure discarded exact authority")
    requireGenerationOwner(!owner.completeRetirement(6), "stale cleanup completed retirement")
    requireGenerationOwner(owner.completeRetirement(7), "exact reservation retirement did not complete")
    requireGenerationOwner(!owner.hasActiveGeneration(), "completed retirement retained authority")
    requireGenerationOwner(
        !owner.beginReservation(7),
        "retired native generation was reserved again",
    )

    requireGenerationOwner(owner.beginReservation(8), "status-failure generation was rejected")
    requireGenerationOwner(owner.noteStatusAttempt(8), "status attempt was not recorded")
    requireGenerationOwner(
        owner.beginRetirement(8) == MainServiceGenerationRetirement(8, true, false),
        "status-failure rollback did not select exactly the attempted status owner",
    )
    requireGenerationOwner(owner.completeRetirement(8), "status-failure retirement did not complete")

    requireGenerationOwner(owner.beginReservation(9), "voice-failure generation was rejected")
    requireGenerationOwner(owner.noteStatusAttempt(9), "voice predecessor stage was rejected")
    requireGenerationOwner(owner.noteVoiceAttempt(9), "voice attempt was not recorded")
    requireGenerationOwner(
        owner.beginRetirement(9) == MainServiceGenerationRetirement(9, true, true),
        "voice-failure rollback did not select every attempted exact owner",
    )
    requireGenerationOwner(owner.completeRetirement(9), "voice-failure retirement did not complete")

    requireGenerationOwner(owner.beginReservation(10), "activation-failure generation was rejected")
    requireGenerationOwner(owner.noteStatusAttempt(10), "activation status stage was rejected")
    requireGenerationOwner(owner.noteVoiceAttempt(10), "activation voice stage was rejected")
    requireGenerationOwner(
        owner.noteActivationAttempt(10),
        "listener activation attempt was not recorded",
    )
    requireGenerationOwner(
        owner.beginRetirement(10) == MainServiceGenerationRetirement(10, true, true),
        "activation-failure rollback did not select every attempted exact owner",
    )
    requireGenerationOwner(owner.completeRetirement(10), "activation-failure retirement did not complete")

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
        owner.beginRetirement(10) == null,
        "stale committed retirement selected its replacement",
    )
    val committedPlan = MainServiceGenerationRetirement(11, true, true)
    requireGenerationOwner(
        owner.beginRetirement(11) == committedPlan,
        "committed retirement omitted an exact owner",
    )
    requireGenerationOwner(!owner.isCommitted(11), "retiring generation remained committed")
    requireGenerationOwner(
        owner.beginRetirement(11) == committedPlan,
        "committed cleanup retry lost its exact retirement plan",
    )
    requireGenerationOwner(
        !owner.beginReservation(12),
        "replacement started before committed cleanup completed",
    )
    requireGenerationOwner(owner.completeRetirement(11), "committed retirement did not complete")
    requireGenerationOwner(owner.beginReservation(12), "new generation after rollback was rejected")
}
