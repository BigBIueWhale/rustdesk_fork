#!/usr/bin/env bash
# Acquisition-VM diagnostic: compile the actual SDK Gradle plugin, then resolve
# the candidate application build plugins. Retain observations, never a cache.
set -euo pipefail
umask 077
[ "$#" -eq 0 ] && [ "$(id -u)" -ne 0 ] && [ "$(id -g)" -ne 0 ] \
    || { echo 'candidate Gradle probe requires an ordinary container principal and no arguments' >&2; exit 1; }
# shellcheck source=scripts/pins.env
source /authority/pins.env

verify_input() {
    local path=$1 size=$2 digest=$3
    [ -f "$path" ] && [ ! -L "$path" ] \
        && [ "$(stat -c '%u:%g:%a:%h:%s' -- "$path")" = "$(id -u):$(id -g):400:1:$size" ] \
        && [ "$(sha256sum -- "$path" | awk '{print $1}')" = "$digest" ] \
        || { echo "candidate Gradle input differs: $path" >&2; exit 1; }
}
verify_input /inputs/flutter-sdk.tar.xz "$SIZE_FLUTTER_PRESENTATION_CANDIDATE" "$SHA256_FLUTTER_PRESENTATION_CANDIDATE"
verify_input /inputs/gradle.zip "$SIZE_ANDROID_CANDIDATE_GRADLE_BIN" "$SHA256_ANDROID_CANDIDATE_GRADLE_BIN"

work=$(mktemp -d /tmp/android-candidate-gradle.XXXXXXXXXX)
readonly work
ulimit -f 524288
mkdir -m 0700 "$work/user-home" "$work/plugin-consumer"
export GRADLE_USER_HOME="$work/gradle-home"
unzip -q /inputs/gradle.zip -d "$work"
tar -xJf /inputs/flutter-sdk.tar.xz -C "$work" --no-same-owner --no-same-permissions \
    flutter/packages/flutter_tools/gradle
readonly gradle="$work/gradle-$ANDROID_CANDIDATE_GRADLE_VERSION/bin/gradle"
readonly plugin="$work/flutter/packages/flutter_tools/gradle"
[ -z "$(find "$plugin" \( -type l -o \( ! -type d -a ! -type f \) \) -print -quit)" ] \
    || { echo 'candidate Flutter Gradle source has a non-file edge' >&2; exit 1; }
find "$plugin" -type f -print0 | sort -z | xargs -0 sha256sum >"$work/source.sha256"
java -version
"$gradle" --version

readonly -a options=(--no-daemon --max-workers=2 --console=plain --no-configuration-cache
    -Dorg.gradle.vfs.watch=false -Dorg.gradle.java.installations.auto-download=false
    "-Dorg.gradle.jvmargs=-Xmx2g -XX:MaxMetaspaceSize=768m -Duser.home=$work/user-home"
    "-Duser.home=$work/user-home" -Pkotlin.compiler.execution.strategy=in-process)

flutter_status=0
timeout --signal=TERM --kill-after=10s 300 "$gradle" "${options[@]}" -p "$plugin" jar \
    >"$work/flutter.log" 2>&1 || flutter_status=$?
[ "$(stat -c '%s' "$work/flutter.log")" -le 2097152 ] \
    || { echo 'Flutter Gradle diagnostics exceed their bound' >&2; exit 1; }
cat "$work/flutter.log"
consumer_status=not-run
if [ "$flutter_status" -eq 0 ]; then
    cat >"$work/plugin-consumer/settings.gradle" <<EOF
pluginManagement {
    includeBuild('$plugin')
    repositories { google(); mavenCentral(); gradlePluginPortal() }
}
rootProject.name = 'candidate-android-build-plugins'
EOF
    cat >"$work/plugin-consumer/build.gradle" <<EOF
plugins {
    id 'dev.flutter.flutter-gradle-plugin' apply false
    id 'com.android.application' version '$ANDROID_CANDIDATE_AGP_VERSION' apply false
    id 'org.jetbrains.kotlin.android' version '$ANDROID_CANDIDATE_KOTLIN_VERSION' apply false
}
EOF
    consumer_status=0
    timeout --signal=TERM --kill-after=10s 300 "$gradle" "${options[@]}" \
        -p "$work/plugin-consumer" help >"$work/consumer.log" 2>&1 || consumer_status=$?
    [ "$(stat -c '%s' "$work/consumer.log")" -le 2097152 ] \
        || { echo 'Android plugin diagnostics exceed their bound' >&2; exit 1; }
    cat "$work/consumer.log"
fi
sha256sum --check --status "$work/source.sha256"

# A completed diagnostic may observe a failed compile/resolution. Its receipt
# reports those actual exit statuses; it never substitutes for an APK acceptance.
python3 -I -S - "$work" "$flutter_status" "$consumer_status" <<'PY'
import hashlib,json,pathlib,stat,sys,zipfile
root=pathlib.Path(sys.argv[1]);flutter_status=int(sys.argv[2])
consumer_status=None if sys.argv[3]=='not-run' else int(sys.argv[3])
artifacts=[];total=0
cache=root/'gradle-home/caches/modules-2/files-2.1'
if cache.exists():
    for path in sorted(cache.rglob('*')):
        metadata=path.lstat()
        if stat.S_ISDIR(metadata.st_mode):
            continue
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink!=1:
            raise ValueError('Gradle module cache contains a nonregular or multiply linked file')
        parts=path.relative_to(cache).parts
        if len(parts)!=5 or len(artifacts)>=2000 or metadata.st_size>256*1024**2:
            raise ValueError('Gradle module inventory exceeds its bounds')
        total+=metadata.st_size
        if total>2*1024**3:
            raise ValueError('Gradle module bytes exceed their bound')
        with path.open('rb') as stream:
            digest=hashlib.file_digest(stream,'sha256').hexdigest()
        artifacts.append({'group':parts[0],'artifact':parts[1],'version':parts[2],
                          'file':parts[4],'bytes':metadata.st_size,'sha256':digest})
jars=[]
if flutter_status==0:
    for path in sorted((root/'flutter/packages/flutter_tools/gradle/build/libs').glob('*.jar')):
        with zipfile.ZipFile(path) as archive:
            if 'com/flutter/gradle/FlutterPlugin.class' not in archive.namelist():
                continue
            if archive.testzip() is not None:
                raise ValueError('compiled Flutter plugin JAR CRC differs')
        jars.append({'name':path.name,'bytes':path.stat().st_size,
                     'sha256':hashlib.sha256(path.read_bytes()).hexdigest()})
    if len(jars)!=1:
        raise ValueError('successful compilation did not produce exactly one Flutter plugin JAR')
result={'flutter_jar_exit':flutter_status,'consumer_exit':consumer_status,
        'compiled_plugin':jars,'artifacts':artifacts,'artifact_bytes':total,
        'source_unchanged':True,'cache_published':False,'apk_built':False,
        'provenance':'observed downloads only; independent authentication remains required'}
encoded=json.dumps(result,sort_keys=True,separators=(',',':'))
if len(encoded)>512*1024:
    raise ValueError('dependency observation receipt exceeds its bound')
print('ANDROID_CANDIDATE_GRADLE_PROBE='+encoded)
PY
