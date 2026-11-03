#!/usr/bin/env bash
# Runs only in the admitted Android-builder container; output is its private RAM bind.
set -euo pipefail
[ "$#" -eq 3 ] || exit 2
readonly SOURCE=$1 SDK=$2 OUTPUT=$3
readonly TOOLS=$SDK/build-tools/34.0.0
readonly PLATFORM_INPUT=$SDK/platforms/android-34/android.jar
WORK=$(mktemp -d /tmp/android-backup-control.XXXXXXXXXX)
readonly WORK
trap 'rm -rf -- "$WORK"' EXIT
[ ! -e "$OUTPUT" ] && [ ! -L "$OUTPUT" ] || exit 1
readonly PLATFORM=$WORK/android.jar
# AAPT2 needs mmap; the sealed input projection supports reads, not file mappings.
cp --reflink=never -- "$PLATFORM_INPUT" "$PLATFORM"
cmp -- "$PLATFORM_INPUT" "$PLATFORM"
mkdir "$WORK/classes" "$WORK/dex"
cat >"$WORK/AndroidManifest.xml" <<'XML'
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="org.rustdesk.backupcontrol">
  <uses-sdk android:minSdkVersion="24" android:targetSdkVersion="33"/>
  <application android:allowBackup="false" android:label="Backup control">
    <activity android:name=".AndroidBackupControl" android:exported="true"/>
  </application>
</manifest>
XML
javac -encoding UTF-8 -source 8 -target 8 -classpath "$PLATFORM" \
    -d "$WORK/classes" "$SOURCE/scripts/AndroidBackupControl.java"
"$TOOLS/d8" --release --min-api 24 --lib "$PLATFORM" --output "$WORK/dex" \
    "$WORK/classes/org/rustdesk/backupcontrol/AndroidBackupControl.class"
"$TOOLS/aapt2" link -I "$PLATFORM" --manifest "$WORK/AndroidManifest.xml" -o "$WORK/unsigned.apk"
(cd "$WORK/dex" && zip -q -X "$WORK/unsigned.apk" classes.dex)
"$TOOLS/zipalign" 4 "$WORK/unsigned.apk" "$WORK/aligned.apk"
keytool -genkeypair -noprompt -alias control -keyalg RSA -keysize 2048 -validity 2 \
    -dname CN=DisposableBackupControl -keystore "$WORK/control.p12" \
    -storepass disposable -keypass disposable >/dev/null 2>&1
"$TOOLS/apksigner" sign --ks "$WORK/control.p12" --ks-pass pass:disposable \
    --out "$WORK/control.apk" "$WORK/aligned.apk"
"$TOOLS/apksigner" verify "$WORK/control.apk"
install -m 0400 "$WORK/control.apk" "$OUTPUT"
printf 'ANDROID_BACKUP_CONTROL_BUILD=pass sha256=%s source_sha256=%s target_sdk=33 allow_backup=false\n' \
    "$(sha256sum "$OUTPUT" | cut -d ' ' -f 1)" \
    "$(sha256sum "$SOURCE/scripts/AndroidBackupControl.java" | cut -d ' ' -f 1)"
