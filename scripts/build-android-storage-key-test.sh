#!/usr/bin/env bash
set -euo pipefail
umask 077
export PATH=/usr/bin:/bin
[ "$#" -eq 0 ] && [ "$(id -u):$(id -g)" = 1000:1000 ] || exit 2
readonly SOURCE=/source
readonly ONLINE=/online
readonly OUTPUT=/artifact
readonly WORK=/tmp/android-storage-key-build
source "$SOURCE/scripts/pins.env"
[ ! -e "$WORK" ] && [ ! -L "$WORK" ] && [ -d "$OUTPUT" ] && [ -z "$(ls -A "$OUTPUT")" ] || exit 1
mkdir -m 0700 "$WORK" "$WORK/classes" "$WORK/dex" "$WORK/jars"
export TMPDIR="$WORK"
ulimit -f 65536

python3 -I -S "$SOURCE/scripts/online-android-sdk-output.py" check-complete \
    --online "$ONLINE" --cmdline-archive "$ONLINE/android-cmdline-tools.zip" \
    --uid 1000 --gid 1000 --builder "$ANDROID_BUILDER_CONFIG_ID" \
    --package-pin "cmdline-tools=$SHA256_ANDROID_CMDLINE_TOOLS" \
    --package-pin "platform-tools=$SHA256_ANDROID_PLATFORM_TOOLS_37_0_1" \
    --package-pin "build-tools-30.0.3=$SHA256_ANDROID_BUILD_TOOLS_30_0_3" \
    --package-pin "build-tools-34.0.0=$SHA256_ANDROID_BUILD_TOOLS_34_0_0" \
    --package-pin "platform-31=$SHA256_ANDROID_PLATFORM_31" \
    --package-pin "platform-32=$SHA256_ANDROID_PLATFORM_32" \
    --package-pin "platform-33=$SHA256_ANDROID_PLATFORM_33" \
    --package-pin "platform-34=$SHA256_ANDROID_PLATFORM_34"

resolve_jar() {
    local group=$1 artifact=$2 version=$3 size=$4 digest=$5
    local -a matches=()
    mapfile -t matches < <(find "$ONLINE/gradle-home/caches/modules-2/files-2.1/$group/$artifact/$version" \
        -mindepth 2 -maxdepth 2 -type f -name "$artifact-$version.jar" -print | LC_ALL=C sort)
    [ "${#matches[@]}" -eq 1 ] || exit 1
    [ "$(stat -c '%u:%g:%a:%h:%s' "${matches[0]}")" = "1000:1000:400:1:$size" ] || exit 1
    [ "$(sha256sum "${matches[0]}" | cut -d ' ' -f 1)" = "$digest" ] || exit 1
    # Kotlin's jar filesystem needs mmap; the sealed virtiofs input is noexec/no-DAX.
    local staged="$WORK/jars/$artifact-$version.jar"
    cp -p "${matches[0]}" "$staged"
    [ "$(sha256sum "$staged" | cut -d ' ' -f 1)" = "$digest" ] || exit 1
    printf '%s\n' "$staged"
}
compiler=$(resolve_jar org.jetbrains.kotlin kotlin-compiler-embeddable "$ANDROID_KOTLIN_VERSION" "$SIZE_ANDROID_KOTLIN_COMPILER_EMBEDDABLE" "$SHA256_ANDROID_KOTLIN_COMPILER_EMBEDDABLE")
stdlib=$(resolve_jar org.jetbrains.kotlin kotlin-stdlib "$ANDROID_KOTLIN_STDLIB_VERSION" "$SIZE_ANDROID_KOTLIN_STDLIB" "$SHA256_ANDROID_KOTLIN_STDLIB")
script_runtime=$(resolve_jar org.jetbrains.kotlin kotlin-script-runtime "$ANDROID_KOTLIN_VERSION" "$SIZE_ANDROID_KOTLIN_SCRIPT_RUNTIME" "$SHA256_ANDROID_KOTLIN_SCRIPT_RUNTIME")
reflect=$(resolve_jar org.jetbrains.kotlin kotlin-reflect "$ANDROID_KOTLIN_COMPILER_REFLECT_VERSION" "$SIZE_ANDROID_KOTLIN_REFLECT" "$SHA256_ANDROID_KOTLIN_REFLECT")
daemon=$(resolve_jar org.jetbrains.kotlin kotlin-daemon-embeddable "$ANDROID_KOTLIN_VERSION" "$SIZE_ANDROID_KOTLIN_DAEMON_EMBEDDABLE" "$SHA256_ANDROID_KOTLIN_DAEMON_EMBEDDABLE")
trove=$(resolve_jar org.jetbrains.intellij.deps trove4j "$ANDROID_KOTLIN_COMPILER_TROVE_VERSION" "$SIZE_ANDROID_KOTLIN_COMPILER_TROVE" "$SHA256_ANDROID_KOTLIN_COMPILER_TROVE")
coroutines=$(resolve_jar org.jetbrains.kotlinx kotlinx-coroutines-core-jvm "$ANDROID_KOTLIN_COMPILER_COROUTINES_VERSION" "$SIZE_ANDROID_KOTLIN_COMPILER_COROUTINES" "$SHA256_ANDROID_KOTLIN_COMPILER_COROUTINES")
annotations=$(resolve_jar org.jetbrains annotations "$ANDROID_KOTLIN_COMPILER_ANNOTATIONS_VERSION" "$SIZE_ANDROID_KOTLIN_COMPILER_ANNOTATIONS" "$SHA256_ANDROID_KOTLIN_COMPILER_ANNOTATIONS")
readonly KOTLIN_SOURCE=$SOURCE/flutter/android/app/src/main/kotlin/com/carriez/flutter_hbb/MobileAtRestStorageKey.kt
readonly JAVA_SOURCE=$SOURCE/scripts/AndroidStorageKeyInstrumentation.java
readonly ANDROID_JAR=$WORK/android.jar
cp -p "$ONLINE/android-sdk/platforms/android-${ANDROID_COMPILE_SDK}/android.jar" "$ANDROID_JAR"
source_before=$(sha256sum "$KOTLIN_SOURCE" "$JAVA_SOURCE" "$SOURCE/scripts/build-android-storage-key-test.sh" "$ANDROID_JAR" "$stdlib")
# The sealed SDK is noexec. Copy only the authenticated build-tools into private RAM.
mkdir -m 0700 "$WORK/tools" "$WORK/tools/lib" "$WORK/tools/lib64"
for relative in aapt2 d8 apksigner zipalign lib/d8.jar lib/apksigner.jar lib64/libc++.so lib64/libc++.so.1; do
    cp -p "$ONLINE/android-sdk/build-tools/$ANDROID_BUILD_TOOLS/$relative" "$WORK/tools/$relative"
done
timeout --signal=TERM --kill-after=5s 90s java -Xms32m -Xmx512m \
    -Djava.io.tmpdir="$WORK" -cp "$compiler:$stdlib:$script_runtime:$reflect:$daemon:$trove:$coroutines:$annotations" \
    org.jetbrains.kotlin.cli.jvm.K2JVMCompiler -no-stdlib -no-reflect -jvm-target 1.8 \
    -classpath "$ANDROID_JAR:$stdlib:$annotations" -d "$WORK/classes" "$KOTLIN_SOURCE"
javac -encoding UTF-8 -source 8 -target 8 -classpath "$ANDROID_JAR:$stdlib:$WORK/classes" \
    -d "$WORK/classes" "$JAVA_SOURCE"
jar cf "$WORK/probe.jar" -C "$WORK/classes" .
timeout --signal=TERM --kill-after=5s 90s "$WORK/tools/d8" --release --min-api 23 \
    --lib "$ANDROID_JAR" --output "$WORK/dex" "$WORK/probe.jar" "$stdlib"
cat >"$WORK/AndroidManifest.xml" <<'XML'
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.rustdesk.harness.storage">
  <uses-sdk android:minSdkVersion="23" android:targetSdkVersion="34" />
  <application android:label="Storage key probe" android:allowBackup="false" android:debuggable="true" />
  <instrumentation android:name="com.rustdesk.harness.storage.AndroidStorageKeyInstrumentation"
      android:targetPackage="com.rustdesk.harness.storage" />
</manifest>
XML
"$WORK/tools/aapt2" link -I "$ANDROID_JAR" --manifest "$WORK/AndroidManifest.xml" -o "$WORK/unsigned.apk"
python3 -I -S - "$WORK" <<'PY'
import sys,zipfile
from pathlib import Path
work=Path(sys.argv[1]);dex=work/'dex/classes.dex'
assert dex.is_file() and 0<dex.stat().st_size<4*1024**2
assert sorted(p.name for p in (work/'dex').iterdir())==['classes.dex']
with zipfile.ZipFile(work/'unsigned.apk','a') as apk:apk.write(dex,'classes.dex')
PY
keytool -genkeypair -noprompt -alias probe -keyalg RSA -keysize 2048 -validity 2 \
    -dname CN=RustDeskStorageKeyProbe -keystore "$WORK/probe.p12" \
    -storepass probe-test-only -keypass probe-test-only
"$WORK/tools/zipalign" -f 4 "$WORK/unsigned.apk" "$WORK/aligned.apk"
"$WORK/tools/apksigner" sign --ks "$WORK/probe.p12" --ks-key-alias probe \
    --ks-pass pass:probe-test-only --key-pass pass:probe-test-only \
    --out "$OUTPUT/storage-key-probe.apk" "$WORK/aligned.apk"
"$WORK/tools/apksigner" verify --verbose "$OUTPUT/storage-key-probe.apk"
[ "$(stat -c %s "$OUTPUT/storage-key-probe.apk")" -lt 4194304 ] || exit 1
chmod 0400 "$OUTPUT/storage-key-probe.apk"
[ "$source_before" = "$(sha256sum "$KOTLIN_SOURCE" "$JAVA_SOURCE" "$SOURCE/scripts/build-android-storage-key-test.sh" "$ANDROID_JAR" "$stdlib")" ] || exit 1
printf 'ANDROID_STORAGE_KEY_BUILD=pass apk_sha256=%s kotlin_sha256=%s fixture_sha256=%s android_jar_sha256=%s kotlin=2.0.21 target=api34 uid=1000 network=none\n' \
    "$(sha256sum "$OUTPUT/storage-key-probe.apk" | cut -d ' ' -f 1)" \
    "$(sha256sum "$KOTLIN_SOURCE" | cut -d ' ' -f 1)" \
    "$(sha256sum "$JAVA_SOURCE" | cut -d ' ' -f 1)" \
    "$(sha256sum "$ANDROID_JAR" | cut -d ' ' -f 1)"
