package com.carriez.flutter_hbb

private fun requireStatus(condition: Boolean, message: String) {
    check(condition) { message }
}

fun main() {
    val owner = MainServiceStatusOwner()
    requireStatus(owner.snapshot() == null, "fresh status owner published a service")
    requireStatus(!owner.begin(0), "zero service generation was admitted")
    requireStatus(
        !owner.setMediaProjectionReady(7, true),
        "unbound generation published MediaProjection readiness",
    )

    requireStatus(owner.begin(7), "first service generation was rejected")
    requireStatus(
        owner.snapshot() == MainServiceStatus(7, false),
        "new service generation did not begin unready",
    )
    requireStatus(
        !owner.setMediaProjectionReady(6, true),
        "stale generation changed MediaProjection readiness",
    )
    requireStatus(
        owner.snapshot() == MainServiceStatus(7, false),
        "stale readiness changed current status",
    )
    requireStatus(
        owner.setMediaProjectionReady(7, true),
        "current generation readiness was rejected",
    )
    requireStatus(owner.begin(7), "current generation idempotent begin was rejected")
    requireStatus(
        owner.snapshot() == MainServiceStatus(7, true),
        "idempotent begin cleared current readiness",
    )

    requireStatus(
        !owner.begin(8),
        "replacement service generation bypassed exact predecessor retirement",
    )
    requireStatus(
        owner.snapshot() == MainServiceStatus(7, true),
        "rejected replacement changed predecessor readiness",
    )
    requireStatus(
        owner.retireOrConfirmInactive(7),
        "predecessor status did not retire exactly",
    )
    requireStatus(owner.begin(8), "replacement service generation was rejected after retirement")
    requireStatus(
        owner.snapshot() == MainServiceStatus(8, false),
        "replacement generation inherited predecessor readiness",
    )
    requireStatus(
        !owner.retireOrConfirmInactive(7),
        "stale generation retired its replacement",
    )
    requireStatus(
        owner.snapshot() == MainServiceStatus(8, false),
        "stale retirement changed replacement status",
    )
    requireStatus(
        owner.setMediaProjectionReady(8, true),
        "retained projection readiness was not republished to the replacement generation",
    )
    requireStatus(
        owner.retireOrConfirmInactive(8),
        "exact service generation retirement failed",
    )
    requireStatus(owner.snapshot() == null, "retired service status remained published")
    requireStatus(
        owner.retireOrConfirmInactive(8),
        "exact status retirement retry was not idempotent",
    )
    requireStatus(
        owner.setMediaProjectionReady(8, false),
        "exact retired generation could not confirm readiness cleanup",
    )
    requireStatus(
        !owner.setMediaProjectionReady(8, true),
        "retired generation republished MediaProjection readiness",
    )
    requireStatus(!owner.begin(8), "retired generation was reactivated")
    requireStatus(owner.begin(9), "new generation after retirement was rejected")
    requireStatus(
        !owner.retireOrConfirmInactive(8),
        "retired predecessor cleanup changed its replacement",
    )
    requireStatus(
        owner.snapshot() == MainServiceStatus(9, false),
        "new generation after retirement did not begin unready",
    )
}
