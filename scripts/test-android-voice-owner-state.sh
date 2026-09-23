#!/usr/bin/env bash
set -euo pipefail
umask 077
export PATH=/usr/bin:/bin

[ "$#" -eq 2 ] \
    || { echo 'usage: test-android-voice-owner-state.sh GRADLE_HOME WORK_ROOT' >&2; exit 2; }
[ "$(/usr/bin/id -u)" -ne 0 ] && [ "$(/usr/bin/id -g)" -ne 0 ] \
    || { echo 'Android voice owner-state test refuses root' >&2; exit 1; }

readonly SCRIPT_DIR="$(cd "$(/usr/bin/dirname -- "${BASH_SOURCE[0]}")" && /usr/bin/pwd -P)"
readonly REPO_ROOT="$(cd "$SCRIPT_DIR/.." && /usr/bin/pwd -P)"
# shellcheck source=scripts/pins.env
source "$SCRIPT_DIR/pins.env"

readonly GRADLE_HOME="$1"
readonly WORK_ROOT="$2"
readonly PRODUCTION_SOURCE="$REPO_ROOT/flutter/android/app/src/main/kotlin/com/carriez/flutter_hbb/VoiceCallOwnerState.kt"
readonly TEST_SOURCE="$REPO_ROOT/flutter/android/app/src/test/kotlin/com/carriez/flutter_hbb/VoiceCallOwnerStateTest.kt"

[ -d "$GRADLE_HOME" ] && [ ! -L "$GRADLE_HOME" ] \
    || { echo 'Gradle seed root is absent or ambiguous' >&2; exit 1; }
[ ! -e "$WORK_ROOT" ] && [ ! -L "$WORK_ROOT" ] \
    || { echo 'test work root must be freshly absent' >&2; exit 1; }
for source in "$PRODUCTION_SOURCE" "$TEST_SOURCE"; do
    [ -f "$source" ] && [ ! -L "$source" ] \
        || { echo "test source is absent or ambiguous: $source" >&2; exit 1; }
done

resolve_jar() {
    local group=$1 artifact=$2 version=$3 size=$4 digest=$5 root
    local -a matches=()
    root="$GRADLE_HOME/caches/modules-2/files-2.1/$group/$artifact/$version"
    [ -d "$root" ] && [ ! -L "$root" ] \
        || { echo "Kotlin compiler artifact root is absent: $group:$artifact:$version" >&2; return 1; }
    mapfile -t matches < <(/usr/bin/find "$root" -mindepth 2 -maxdepth 2 -type f \
        -name "$artifact-$version.jar" -print | LC_ALL=C /usr/bin/sort)
    [ "${#matches[@]}" -eq 1 ] \
        || { echo "expected one Kotlin compiler artifact: $group:$artifact:$version" >&2; return 1; }
    [ "$(/usr/bin/stat -c '%u:%g:%a:%h:%s' -- "${matches[0]}")" = \
      "$(/usr/bin/id -u):$(/usr/bin/id -g):400:1:$size" ] \
        || { echo "Kotlin compiler artifact metadata differs: $group:$artifact:$version" >&2; return 1; }
    [ "$(/usr/bin/sha256sum -- "${matches[0]}" | /usr/bin/awk '{print $1}')" = "$digest" ] \
        || { echo "Kotlin compiler artifact digest differs: $group:$artifact:$version" >&2; return 1; }
    printf '%s\n' "${matches[0]}"
}

compiler="$(resolve_jar org.jetbrains.kotlin kotlin-compiler-embeddable \
    "$ANDROID_KOTLIN_VERSION" "$SIZE_ANDROID_KOTLIN_COMPILER_EMBEDDABLE" \
    "$SHA256_ANDROID_KOTLIN_COMPILER_EMBEDDABLE")"
stdlib="$(resolve_jar org.jetbrains.kotlin kotlin-stdlib \
    "$ANDROID_KOTLIN_STDLIB_VERSION" "$SIZE_ANDROID_KOTLIN_STDLIB" \
    "$SHA256_ANDROID_KOTLIN_STDLIB")"
script_runtime="$(resolve_jar org.jetbrains.kotlin kotlin-script-runtime \
    "$ANDROID_KOTLIN_VERSION" "$SIZE_ANDROID_KOTLIN_SCRIPT_RUNTIME" \
    "$SHA256_ANDROID_KOTLIN_SCRIPT_RUNTIME")"
reflect="$(resolve_jar org.jetbrains.kotlin kotlin-reflect \
    "$ANDROID_KOTLIN_COMPILER_REFLECT_VERSION" "$SIZE_ANDROID_KOTLIN_REFLECT" \
    "$SHA256_ANDROID_KOTLIN_REFLECT")"
daemon="$(resolve_jar org.jetbrains.kotlin kotlin-daemon-embeddable \
    "$ANDROID_KOTLIN_VERSION" "$SIZE_ANDROID_KOTLIN_DAEMON_EMBEDDABLE" \
    "$SHA256_ANDROID_KOTLIN_DAEMON_EMBEDDABLE")"
trove="$(resolve_jar org.jetbrains.intellij.deps trove4j \
    "$ANDROID_KOTLIN_COMPILER_TROVE_VERSION" "$SIZE_ANDROID_KOTLIN_COMPILER_TROVE" \
    "$SHA256_ANDROID_KOTLIN_COMPILER_TROVE")"
coroutines="$(resolve_jar org.jetbrains.kotlinx kotlinx-coroutines-core-jvm \
    "$ANDROID_KOTLIN_COMPILER_COROUTINES_VERSION" "$SIZE_ANDROID_KOTLIN_COMPILER_COROUTINES" \
    "$SHA256_ANDROID_KOTLIN_COMPILER_COROUTINES")"
annotations="$(resolve_jar org.jetbrains annotations \
    "$ANDROID_KOTLIN_COMPILER_ANNOTATIONS_VERSION" "$SIZE_ANDROID_KOTLIN_COMPILER_ANNOTATIONS" \
    "$SHA256_ANDROID_KOTLIN_COMPILER_ANNOTATIONS")"

/usr/bin/install -d -m 0700 -- "$WORK_ROOT" "$WORK_ROOT/classes"
readonly COMPILER_CLASSPATH="$compiler:$stdlib:$script_runtime:$reflect:$daemon:$trove:$coroutines:$annotations"
readonly TEST_CLASSPATH="$stdlib:$annotations"

compile_status=0
/usr/bin/timeout --signal=TERM --kill-after=5s 60s \
    /usr/bin/java -Xms32m -Xmx512m -Djava.io.tmpdir="$WORK_ROOT" \
        -cp "$COMPILER_CLASSPATH" org.jetbrains.kotlin.cli.jvm.K2JVMCompiler \
        -no-stdlib -no-reflect -Werror -jvm-target 1.8 -Xjdk-release=8 \
        -module-name rustdesk_android_voice_owner_state_test \
        -classpath "$TEST_CLASSPATH" -d "$WORK_ROOT/classes" \
        "$PRODUCTION_SOURCE" "$TEST_SOURCE" \
        >"$WORK_ROOT/compiler.out" 2>"$WORK_ROOT/compiler.err" || compile_status=$?
if [ "$compile_status" -ne 0 ]; then
    /usr/bin/tail -n 120 "$WORK_ROOT/compiler.out" "$WORK_ROOT/compiler.err" >&2
    exit "$compile_status"
fi
[ "$(/usr/bin/stat -c '%s' -- "$WORK_ROOT/compiler.out")" -le 65536 ] \
    && [ "$(/usr/bin/stat -c '%s' -- "$WORK_ROOT/compiler.err")" -le 65536 ] \
    || { echo 'Kotlin compiler output exceeded its bound' >&2; exit 1; }

/usr/bin/timeout --signal=TERM --kill-after=2s 10s \
    /usr/bin/java -ea -Xms16m -Xmx64m -Djava.io.tmpdir="$WORK_ROOT" \
        -cp "$WORK_ROOT/classes:$TEST_CLASSPATH" \
        com.carriez.flutter_hbb.VoiceCallOwnerStateTestKt
