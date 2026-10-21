package com.rustdesk.harness.storage;

import android.app.Activity;
import android.app.Instrumentation;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import com.carriez.flutter_hbb.MobileAtRestStorageKey;
import java.security.Key;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/** Executes the complete production Kotlin object against this probe app's real AndroidKeyStore. */
public final class AndroidStorageKeyInstrumentation extends Instrumentation {
    private static final String ALIAS = "rustdesk_mobile_at_rest_wrapping_v1";
    private static final String PREFS = "rustdesk_mobile_at_rest_storage";
    private static final String CIPHERTEXT = "storage_key_ciphertext_v1";
    private static final String IV = "storage_key_iv_v1";
    private SharedPreferences prefs;
    private SharedPreferences proof;
    private Context context;
    private String phase;
    private final StringBuilder results = new StringBuilder();
    private int failures;
    private int cases;

    @Override public void onCreate(Bundle arguments) {
        super.onCreate(arguments);
        phase = arguments.getString("phase", "cases");
        start();
    }

    private interface Case { void run() throws Exception; }

    private void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }

    private void runCase(String name, boolean preserve, Case body) {
        cases++;
        try {
            if (!preserve) reset();
            body.run();
            results.append("ANDROID_STORAGE_KEY_CASE=pass name=").append(name).append('\n');
        } catch (Throwable error) {
            failures++;
            results.append("ANDROID_STORAGE_KEY_CASE=fail name=").append(name)
                .append(" error=").append(error.getClass().getSimpleName()).append('\n');
        }
    }

    private KeyStore keyStore() throws Exception {
        KeyStore store = KeyStore.getInstance("AndroidKeyStore");
        store.load(null);
        return store;
    }

    private byte[] current() { return MobileAtRestStorageKey.INSTANCE.getOrCreate(context); }
    private Map<String, ?> envelope() { return new HashMap<>(prefs.getAll()); }
    private String encode(byte[] data) { return Base64.encodeToString(data, Base64.NO_WRAP); }

    private void reset() throws Exception {
        keyStore().deleteEntry(ALIAS);
        check(prefs.edit().clear().commit(), "fixture preferences clear failed");
        check(proof.edit().clear().commit(), "fixture proof clear failed");
        check(!keyStore().containsAlias(ALIAS) && prefs.getAll().isEmpty(), "fixture reset incomplete");
    }

    private void refusesWithoutCreatingKey() throws Exception {
        Map<String, ?> before = envelope();
        check(current() == null, "unavailable key accepted");
        check(!keyStore().containsAlias(ALIAS), "refusal created a wrapping key");
        check(before.equals(envelope()), "refusal rewrote the envelope");
    }

    private byte[] decrypt(SecretKey key, byte[] ciphertext, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
        return cipher.doFinal(ciphertext);
    }

    @Override public void onStart() {
        context = getTargetContext();
        prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
        proof = context.getSharedPreferences("storage_key_probe", Context.MODE_PRIVATE);
        try {
            check(android.os.Process.myUid() >= 10000, "probe must run as an application UID");
            if (phase.equals("reload")) {
                runCase("new_process_reload", true, () -> {
                    Map<String, ?> before = envelope();
                    String expected = proof.getString("digest", null);
                    byte[] value = current();
                    check(expected != null && value != null && value.length == 32, "reload unavailable");
                    check(expected.equals(encode(MessageDigest.getInstance("SHA-256").digest(value))), "reload key changed");
                    check(before.equals(envelope()), "reload rewrote envelope");
                    reset();
                    check(proof.getAll().isEmpty(), "proof retained after cleanup");
                });
            } else if (phase.equals("cases")) {
                runCase("partial_ciphertext", false, () -> {
                    check(prefs.edit().putString(CIPHERTEXT, "present").commit(), "fixture commit failed");
                    refusesWithoutCreatingKey();
                });
                runCase("partial_iv", false, () -> {
                    check(prefs.edit().putString(IV, "present").commit(), "fixture commit failed");
                    refusesWithoutCreatingKey();
                });
                runCase("envelope_missing_key", false, () -> {
                    check(prefs.edit().putString(CIPHERTEXT, encode(new byte[48]))
                        .putString(IV, encode(new byte[12])).commit(), "fixture commit failed");
                    refusesWithoutCreatingKey();
                });
                runCase("occupied_rsa_alias", false, () -> {
                    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "AndroidKeyStore");
                    generator.initialize(new KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_SIGN)
                        .setKeySize(2048).setDigests(KeyProperties.DIGEST_SHA256)
                        .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1).build());
                    generator.generateKeyPair();
                    byte[] before = keyStore().getCertificate(ALIAS).getEncoded();
                    check(current() == null, "occupied alias replaced");
                    check(Arrays.equals(before, keyStore().getCertificate(ALIAS).getEncoded()), "RSA authority changed");
                    check(prefs.getAll().isEmpty(), "occupied alias created envelope");
                });
                runCase("denied_decrypt_preserves_key", false, () -> {
                    KeyGenerator generator = KeyGenerator.getInstance("AES", "AndroidKeyStore");
                    generator.init(new KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT)
                        .setKeySize(256).setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                        .setRandomizedEncryptionRequired(false).build());
                    SecretKey key = generator.generateKey();
                    byte[] iv = new byte[12];
                    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                    cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
                    byte[] wrapped = cipher.doFinal(new byte[32]);
                    check(prefs.edit().putString(CIPHERTEXT, encode(wrapped)).putString(IV, encode(iv)).commit(), "fixture commit failed");
                    Map<String, ?> before = envelope();
                    check(current() == null && before.equals(envelope()), "denied decrypt changed envelope");
                    Cipher oracle = Cipher.getInstance("AES/GCM/NoPadding");
                    oracle.init(Cipher.ENCRYPT_MODE, keyStore().getKey(ALIAS, null), new GCMParameterSpec(128, iv));
                    check(Arrays.equals(wrapped, oracle.doFinal(new byte[32])), "denial replaced the AES key");
                });
                runCase("corrupt_envelope_preserves_authority", false, () -> {
                    byte[] value = current();
                    check(value != null && value.length == 32, "control creation unavailable");
                    SecretKey key = (SecretKey) keyStore().getKey(ALIAS, null);
                    byte[] wrapped = Base64.decode(prefs.getString(CIPHERTEXT, null), Base64.NO_WRAP);
                    byte[] iv = Base64.decode(prefs.getString(IV, null), Base64.NO_WRAP);
                    byte[] changed = wrapped.clone();
                    changed[0] ^= 1;
                    check(prefs.edit().putString(CIPHERTEXT, encode(changed)).commit(), "fixture commit failed");
                    Map<String, ?> before = envelope();
                    check(current() == null && before.equals(envelope()), "corrupt envelope rewritten");
                    check(Arrays.equals(value, decrypt(key, wrapped, iv)), "original authority lost");
                    check(Arrays.equals(value, decrypt((SecretKey) keyStore().getKey(ALIAS, null), wrapped, iv)), "key replaced");
                });
                runCase("fresh_create_and_warm_reload", false, () -> {
                    byte[] value = current();
                    check(value != null && value.length == 32, "fresh key unavailable");
                    Map<String, ?> before = envelope();
                    check(before.size() == 2, "fresh envelope incomplete");
                    Key wrappingKey = keyStore().getKey(ALIAS, null);
                    check(wrappingKey instanceof SecretKey && wrappingKey.getEncoded() == null, "key not OS-owned");
                    for (int i = 0; i < 32; i++) {
                        check(Arrays.equals(value, current()) && before.equals(envelope()), "warm reload changed state");
                    }
                    check(proof.edit().putString("digest", encode(MessageDigest.getInstance("SHA-256").digest(value)))
                        .commit(), "reload proof commit failed");
                });
            } else {
                throw new AssertionError("invalid probe phase");
            }
            if (failures != 0) reset();
        } catch (Throwable error) {
            failures++;
            results.append("ANDROID_STORAGE_KEY_FATAL=").append(error.getClass().getSimpleName()).append('\n');
        }
        results.append("ANDROID_STORAGE_KEY_PHASE=").append(phase).append(" cases=").append(cases)
            .append(" failures=").append(failures).append(" uid=").append(android.os.Process.myUid())
            .append(" pid=").append(android.os.Process.myPid()).append('\n');
        Bundle output = new Bundle();
        output.putString("stream", results.toString());
        finish(failures == 0 ? Activity.RESULT_OK : Activity.RESULT_CANCELED, output);
    }
}
