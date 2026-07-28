package com.carriez.flutter_hbb

private fun requireState(condition: Boolean, message: String) {
    check(condition) { message }
}

fun main() {
    val first = ControlledInputOwner(serviceGeneration = 7, connectionId = 11)
    val second = ControlledInputOwner(serviceGeneration = 7, connectionId = 12)
    val replacement = ControlledInputOwner(serviceGeneration = 8, connectionId = 11)
    requireState(first.isValid, "valid exact Android input owner was rejected")
    requireState(
        !ControlledInputOwner(serviceGeneration = 0, connectionId = 11).isValid,
        "zero service generation was admitted",
    )
    requireState(
        !ControlledInputOwner(serviceGeneration = 7, connectionId = 0).isValid,
        "nonpositive connection ID was admitted",
    )

    val queue = ExactOwnerBoundedQueue<String>(3)
    requireState(queue.offer(first, "first-1"), "first owner input was rejected")
    requireState(queue.offer(second, "second-1"), "second owner input was rejected")
    requireState(queue.offer(first, "first-2"), "second first-owner input was rejected")
    requireState(!queue.offer(second, "overflow"), "queue capacity was not enforced")
    requireState(queue.size == 3, "rejected queue input altered the exact capacity")

    queue.removeOwner(first)
    requireState(queue.size == 1, "exact owner retirement did not remove all owned work")
    requireState(
        queue.poll() == OwnedControlledInput(second, "second-1"),
        "one owner retirement removed or reordered another owner's work",
    )
    requireState(queue.poll() == null, "queue retained work after exact drain")

    requireState(queue.offer(first, "old-generation"), "old generation enqueue failed")
    requireState(queue.offer(replacement, "replacement"), "replacement enqueue failed")
    queue.removeOwner(first)
    requireState(
        queue.poll() == OwnedControlledInput(replacement, "replacement"),
        "old generation retirement selected the replacement owner",
    )

    requireState(
        !queue.offer(
            ControlledInputOwner(serviceGeneration = 0, connectionId = 1),
            "invalid",
        ),
        "invalid owner reached the bounded queue",
    )
    queue.clear()
    requireState(queue.size == 0, "queue clear retained controlled input")
}
