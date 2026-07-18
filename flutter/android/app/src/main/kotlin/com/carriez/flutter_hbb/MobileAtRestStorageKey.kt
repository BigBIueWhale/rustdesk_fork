package com.carriez.flutter_hbb

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

object MobileAtRestStorageKey {
    private const val TAG = "MobileAtRestStorageKey"
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val WRAPPING_KEY_ALIAS = "rustdesk_mobile_at_rest_wrapping_v1"
    private const val PREFS = "rustdesk_mobile_at_rest_storage"
    private const val PREF_CIPHERTEXT = "storage_key_ciphertext_v1"
    private const val PREF_IV = "storage_key_iv_v1"
    private const val CIPHER = "AES/GCM/NoPadding"
    private const val GCM_TAG_BITS = 128
    private const val STORAGE_KEY_BYTES = 32

    @Synchronized
    fun getOrCreate(context: Context): ByteArray? {
        return try {
            val appContext = context.applicationContext
            val prefs = appContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            val wrappingKey = getOrCreateWrappingKey()
            val storedCiphertext = prefs.getString(PREF_CIPHERTEXT, null)
            val storedIv = prefs.getString(PREF_IV, null)

            if (storedCiphertext != null || storedIv != null) {
                if (storedCiphertext == null || storedIv == null) {
                    Log.e(TAG, "Refusing partial Android at-rest key envelope")
                    return null
                }
                val plaintext = unwrapStorageKey(wrappingKey, storedCiphertext, storedIv)
                if (plaintext == null || plaintext.size != STORAGE_KEY_BYTES) {
                    Log.e(TAG, "Refusing invalid Android at-rest key envelope")
                    return null
                }
                return plaintext
            }

            val generated = ByteArray(STORAGE_KEY_BYTES)
            SecureRandom().nextBytes(generated)
            val wrapped = wrapStorageKey(wrappingKey, generated) ?: return null
            val stored = prefs.edit()
                .putString(PREF_CIPHERTEXT, wrapped.first)
                .putString(PREF_IV, wrapped.second)
                .commit()
            if (!stored) {
                Log.e(TAG, "Failed to persist Android at-rest key envelope")
                return null
            }

            val rereadCiphertext = prefs.getString(PREF_CIPHERTEXT, null)
            val rereadIv = prefs.getString(PREF_IV, null)
            if (rereadCiphertext == null || rereadIv == null) {
                Log.e(TAG, "Android at-rest key envelope disappeared after commit")
                return null
            }
            val reread = unwrapStorageKey(wrappingKey, rereadCiphertext, rereadIv)
            if (reread == null || !generated.contentEquals(reread)) {
                Log.e(TAG, "Android at-rest key round-trip self-test failed")
                return null
            }
            generated
        } catch (e: Exception) {
            Log.e(TAG, "Failed to prepare Android at-rest storage key", e)
            null
        }
    }

    private fun getOrCreateWrappingKey(): SecretKey {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        (keyStore.getKey(WRAPPING_KEY_ALIAS, null) as? SecretKey)?.let { return it }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            try {
                return generateWrappingKey(strongBox = true)
            } catch (e: Exception) {
                Log.i(TAG, "StrongBox AndroidKeyStore key unavailable; using ordinary AndroidKeyStore", e)
                runCatching { keyStore.deleteEntry(WRAPPING_KEY_ALIAS) }
            }
        }
        return generateWrappingKey(strongBox = false)
    }

    private fun generateWrappingKey(strongBox: Boolean): SecretKey {
        val keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES,
            ANDROID_KEYSTORE
        )
        val builder = KeyGenParameterSpec.Builder(
            WRAPPING_KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setKeySize(256)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setRandomizedEncryptionRequired(true)
            .setUserAuthenticationRequired(false)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            builder.setUnlockedDeviceRequired(false)
            if (strongBox) {
                builder.setIsStrongBoxBacked(true)
            }
        }
        keyGenerator.init(builder.build())
        return keyGenerator.generateKey()
    }

    private fun wrapStorageKey(key: SecretKey, plaintext: ByteArray): Pair<String, String>? {
        return try {
            val cipher = Cipher.getInstance(CIPHER)
            cipher.init(Cipher.ENCRYPT_MODE, key)
            val ciphertext = cipher.doFinal(plaintext)
            Pair(encode(ciphertext), encode(cipher.iv))
        } catch (e: Exception) {
            Log.e(TAG, "Failed to wrap Android at-rest storage key", e)
            null
        }
    }

    private fun unwrapStorageKey(
        key: SecretKey,
        ciphertext: String,
        iv: String
    ): ByteArray? {
        return try {
            val cipher = Cipher.getInstance(CIPHER)
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, decode(iv)))
            cipher.doFinal(decode(ciphertext))
        } catch (e: Exception) {
            Log.e(TAG, "Failed to unwrap Android at-rest storage key", e)
            null
        }
    }

    private fun encode(bytes: ByteArray): String =
        Base64.encodeToString(bytes, Base64.NO_WRAP)

    private fun decode(value: String): ByteArray =
        Base64.decode(value, Base64.NO_WRAP)
}
