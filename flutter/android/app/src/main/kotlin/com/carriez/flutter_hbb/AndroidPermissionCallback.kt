package com.carriez.flutter_hbb

import com.hjq.permissions.OnPermissionCallback

internal fun androidPermissionCallback(onResult: (Boolean) -> Unit): OnPermissionCallback =
    OnPermissionCallback { _, allGranted -> onResult(allGranted) }
