package com.carriez.flutter_hbb

import com.hjq.permissions.OnPermissionCallback

fun main() {
    val permissions = listOf("android.permission.RECORD_AUDIO")
    val cases = listOf<Triple<String, Boolean, (OnPermissionCallback) -> Unit>>(
        Triple("grant", true) { it.onGranted(permissions, true) },
        Triple("partial-grant", false) { it.onGranted(permissions, false) },
        Triple("deny", false) { it.onDenied(permissions, false) },
        Triple("permanent-deny", false) { it.onDenied(permissions, true) },
    )
    var failures = 0
    for ((name, expected, deliver) in cases) {
        val results = mutableListOf<Boolean>()
        val callback = androidPermissionCallback { results.add(it) }
        deliver(callback)
        if (results != listOf(expected)) {
            failures += 1
            println("ANDROID_PERMISSION_CALLBACK_CASE=fail name=$name expected=$expected observed=$results")
        } else {
            println("ANDROID_PERMISSION_CALLBACK_CASE=pass name=$name")
        }
    }
    check(failures == 0) { "$failures Android permission callbacks did not report their result" }
    println("ANDROID_PERMISSION_CALLBACK_TEST=pass scenarios=4 assertions=4 xxpermissions=18.5")
}
