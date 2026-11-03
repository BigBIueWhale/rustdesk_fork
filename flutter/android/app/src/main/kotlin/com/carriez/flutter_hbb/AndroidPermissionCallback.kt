package com.carriez.flutter_hbb

import com.hjq.permissions.OnPermissionCallback

internal fun androidPermissionCallback(onResult: (Boolean) -> Unit): OnPermissionCallback =
    object : OnPermissionCallback {
        override fun onGranted(permissions: List<String>, allGranted: Boolean) {
            onResult(allGranted)
        }

        override fun onDenied(permissions: List<String>, doNotAskAgain: Boolean) {
            onResult(false)
        }
    }
