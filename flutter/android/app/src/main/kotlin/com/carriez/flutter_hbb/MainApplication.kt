package com.carriez.flutter_hbb

import android.app.Application
import android.util.Log
import ffi.FFI

class MainApplication : Application() {
    companion object {
        private const val TAG = "MainApplication"
    }

    override fun onCreate() {
        super.onCreate()
        Log.d(TAG, "App start")
        val storageKey = MobileAtRestStorageKey.getOrCreate(applicationContext)
        if (storageKey == null || !FFI.setMobileAtRestStorageKey(storageKey)) {
            Log.e(TAG, "Mobile at-rest storage key was not installed; encrypted config reads fail closed")
        }
        FFI.onAppStart(applicationContext)
    }
}
