package com.carriez.flutter_hbb

import java.util.ArrayDeque

internal data class OwnedControlledInput<T>(
    val owner: ControlledInputOwner,
    val value: T,
)

internal class ExactOwnerBoundedQueue<T>(private val capacity: Int) {
    private val entries = ArrayDeque<OwnedControlledInput<T>>()

    init {
        require(capacity > 0)
    }

    val size: Int
        get() = entries.size

    fun offer(owner: ControlledInputOwner, value: T): Boolean {
        if (!owner.isValid || entries.size >= capacity) {
            return false
        }
        entries.addLast(OwnedControlledInput(owner, value))
        return true
    }

    fun poll(): OwnedControlledInput<T>? = entries.pollFirst()

    fun removeOwner(owner: ControlledInputOwner) {
        val iterator = entries.iterator()
        while (iterator.hasNext()) {
            if (iterator.next().owner == owner) {
                iterator.remove()
            }
        }
    }

    fun clear() {
        entries.clear()
    }
}
