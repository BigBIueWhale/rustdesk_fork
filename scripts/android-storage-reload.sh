# Sourced only by the owned Android emulator after real UI password provisioning.
storage_reload_authenticate() {
    local phase=$1 output
    wait_ui_center text 'Reachable on :21118' >/dev/null \
        || fail "Android listener did not become ready: $phase"
    create_android_control_forward
    output="$(printf '%s\n' "$TEST_PASSWORD" \
        | timeout --signal=TERM --kill-after=2s 60s \
            "$PEER_TARGET/debug/examples/probe_client" \
            127.0.0.1:22119 --password-stdin ok)" \
        || fail "stored Android credential did not authenticate: $phase"
    [ "$output" = $'probe_client: keying ok=true (expected=ok)\nprobe_client: PASS' ] \
        || fail "Android storage authentication receipt differs: $phase"
    remove_android_control_forward || fail 'storage probe forward did not retire'
    printf 'ANDROID_STORAGE_AUTH=pass phase=%s process=%s forward_cleanup=removed\n' "$phase" "$APP_PID"
}

storage_reload_snapshot() {
    local phase=$1
    timeout --signal=TERM --kill-after=2s 30s \
        python3 -I -B -S "$SCRIPT_DIR/android-storage-snapshot.py" \
        "$ADB" "$SERIAL" "$APP_PID" "$WORK_ROOT/storage-baseline.json" "$phase" \
        || fail "Android encrypted storage changed or was unavailable: $phase"
}

exercise_android_storage_reload() {
    local previous_pid=$APP_PID stopped=0 consent= logs consent_x consent_y
    storage_reload_authenticate before
    timeout --signal=TERM --kill-after=2s 30s "$ADB" -s "$SERIAL" root >/dev/null \
        || fail 'cannot enable the disposable emulator storage observer'
    timeout --signal=TERM --kill-after=2s 30s "$ADB" -s "$SERIAL" wait-for-device \
        || fail 'the emulator storage observer did not become ready'
    [ "$(adb_shell_value id -u)" = 0 ] && [ "$(adb_shell_value getenforce)" = Enforcing ] \
        || fail 'the disposable emulator observer authority differs'
    storage_reload_snapshot before

    adb_shell_value am force-stop "$APP_PACKAGE" >/dev/null \
        || fail 'cannot retire the provisioned application process'
    for _ in $(seq 1 120); do
        if [ -z "$(adb_shell_value pidof "$APP_PACKAGE" 2>/dev/null || true)" ] \
           && assert_no_main_service; then
            stopped=1
            break
        fi
        sleep 0.25
    done
    [ "$stopped" -eq 1 ] || fail 'the first application generation did not retire'
    timeout --signal=TERM --kill-after=2s 60s \
        "$ADB" -s "$SERIAL" shell am start -W -n "$APP_ACTIVITY" >/dev/null \
        || fail 'fresh application launch failed'
    wait_resumed_activity || fail 'fresh MainActivity did not resume'
    APP_PID="$(adb_shell_value pidof "$APP_PACKAGE")"
    [[ "$APP_PID" =~ ^[1-9][0-9]*$ ]] && [ "$APP_PID" != "$previous_pid" ] \
        || fail 'encrypted storage reload did not use a new process'
    assert_no_main_service || fail 'application launch silently started MainService'
    storage_reload_snapshot relaunched

    tap_ui text 'Share screen' || fail 'fresh process cannot select Share screen'
    tap_ui text 'Start screen sharing' || fail 'fresh process cannot start sharing'
    wait_ui_center text 'Warning' >/dev/null \
        && capture_unobscured_ui_hierarchy complete \
        && [[ "$(ui_center text "$SERVICE_START_WARNING_TEXT" 2>/dev/null || true)" =~ ^[0-9]+\ [0-9]+$ ]] \
        || fail 'fresh service start warning differs'
    tap_ui text 'OK' || fail 'cannot confirm fresh service startup'
    for _ in $(seq 1 12); do
        capture_unobscured_ui_hierarchy complete || continue
        [ -z "$(ui_center text 'Set password' 2>/dev/null || true)" ] \
            || fail 'fresh process lost the persisted credential'
        consent="$(ui_center resource android:id/button1 2>/dev/null || true)"
        if [[ "$consent" =~ ^[0-9]+\ [0-9]+$ ]]; then
            read -r consent_x consent_y <<<"$consent"
            adb_shell_value input tap "$consent_x" "$consent_y" >/dev/null
            break
        fi
        sleep 0.5
    done
    [[ "$consent" =~ ^[0-9]+\ [0-9]+$ ]] || fail 'fresh capture consent was not requested'
    wait_ui_center text 'Screen capture ready' >/dev/null \
        || fail 'fresh service did not become capture-ready'
    assert_main_service || fail 'fresh service is not foreground'
    storage_reload_authenticate after
    storage_reload_snapshot after
    logs="$(adb_shell_value logcat -d -v brief)"
    ! grep -Eq 'FATAL EXCEPTION|Mobile at-rest storage key was not installed|Failed to prepare Android at-rest storage key|Android application context or app directory initialization failed' <<<"$logs" \
        || fail 'application restart reported a storage/bootstrap failure'
    timeout --signal=TERM --kill-after=2s 30s "$ADB" -s "$SERIAL" unroot >/dev/null \
        || fail 'cannot retire the disposable storage observer'
    timeout --signal=TERM --kill-after=2s 30s "$ADB" -s "$SERIAL" wait-for-device
    [ "$(adb_shell_value id -u)" = 2000 ] || fail 'adbd did not return to its shell UID'
    sleep 5
    [ "$(adb_shell_value pidof "$APP_PACKAGE")" = "$APP_PID" ] \
        || fail 'the reloaded application process changed'
    printf 'ANDROID_STORAGE_RELOAD=pass generations=2 auth=before-after envelope=unchanged credential=unchanged restart=force-stop-and-ui-start observer=retired apk_sha256=%s\n' "$APK_SHA256"
}
