#!/usr/bin/env bash
set -euo pipefail
umask 077
export PATH=/usr/bin:/bin

die() {
    printf 'Android emulator frame observer setup: %s\n' "$*" >&2
    exit 1
}

[ "$#" -eq 3 ] \
    || die 'usage: android-emulator-frame-observer.sh EMULATOR_ZIP GRADLE_HOME OUTPUT_ROOT'
readonly EMULATOR_ZIP=$1
readonly GRADLE_HOME=$2
readonly OUTPUT_ROOT=$3
readonly SCRIPT_DIR="$(cd "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly OBSERVER_SOURCE=$SCRIPT_DIR/AndroidEmulatorFrameObserver.java
readonly FRAME_DECODER=$SCRIPT_DIR/android-emulator-frame.py
readonly WORK_ROOT=/tmp/android-emulator-frame-observer
readonly PROTO_ROOT=$WORK_ROOT/proto
readonly GENERATED_ROOT=$WORK_ROOT/generated
readonly CLASS_ROOT=$WORK_ROOT/classes

[ "$(id -u):$(id -g)" = 1000:1000 ] \
    || die 'the observer setup requires numeric uid/gid 1000:1000'
[ -f "$EMULATOR_ZIP" ] && [ ! -L "$EMULATOR_ZIP" ] \
    || die 'the emulator archive is absent or ambiguous'
[ -d "$GRADLE_HOME" ] && [ ! -L "$GRADLE_HOME" ] \
    || die 'the sealed Gradle input is absent or ambiguous'
[ -d "$OUTPUT_ROOT" ] && [ ! -L "$OUTPUT_ROOT" ] \
    && [ "$(stat -c '%u:%g:%a' -- "$OUTPUT_ROOT")" = 1000:1000:700 ] \
    || die 'the observer exchange root metadata differs'
[ -f "$OBSERVER_SOURCE" ] && [ ! -L "$OBSERVER_SOURCE" ] \
    && [ -f "$FRAME_DECODER" ] && [ ! -L "$FRAME_DECODER" ] \
    || die 'the observer sources are absent or ambiguous'
[ ! -e "$WORK_ROOT" ] && [ ! -L "$WORK_ROOT" ] \
    || die 'the private observer build root is occupied'
install -d -m 0700 -- "$PROTO_ROOT/google/protobuf" "$GENERATED_ROOT" "$CLASS_ROOT"

one_file() {
    local root=$1 pattern=$2 label=$3
    local -a matches=()
    mapfile -d '' -t matches < <(
        find "$root" -mindepth 1 -maxdepth 2 -type f -name "$pattern" -print0
    )
    [ "${#matches[@]}" -eq 1 ] \
        || die "$label is absent or ambiguous"
    [ ! -L "${matches[0]}" ] || die "$label is a symbolic link"
    printf '%s\n' "${matches[0]}"
}

jar_file() {
    local group=$1 artifact=$2 version=$3
    local group_path=${group//./\/}
    one_file \
        "$GRADLE_HOME/caches/modules-2/files-2.1/$group_path/$artifact/$version" \
        "$artifact-$version.jar" "$group:$artifact:$version"
}

readonly PROTOC="$(one_file \
    "$GRADLE_HOME/caches/modules-2/files-2.1/com.google.protobuf/protoc/3.20.1" \
    'protoc-3.20.1-linux-x86_64.exe' 'protoc 3.20.1')"
[ -x "$PROTOC" ] || die 'the pinned protoc input is not executable'

readonly PROTOBUF_JAVA="$(jar_file com.google.protobuf protobuf-java 3.22.3)"
readonly -a JARS=(
    "$PROTOBUF_JAVA"
    "$(jar_file io.grpc grpc-api 1.57.0)"
    "$(jar_file io.grpc grpc-context 1.57.0)"
    "$(jar_file io.grpc grpc-core 1.57.0)"
    "$(jar_file io.grpc grpc-netty 1.57.0)"
    "$(jar_file io.grpc grpc-protobuf 1.57.0)"
    "$(jar_file io.grpc grpc-protobuf-lite 1.57.0)"
    "$(jar_file io.grpc grpc-stub 1.57.0)"
    "$(jar_file com.google.api.grpc proto-google-common-protos 2.17.0)"
    "$(jar_file io.netty netty-buffer 4.1.93.Final)"
    "$(jar_file io.netty netty-codec 4.1.93.Final)"
    "$(jar_file io.netty netty-codec-http 4.1.93.Final)"
    "$(jar_file io.netty netty-codec-http2 4.1.93.Final)"
    "$(jar_file io.netty netty-codec-socks 4.1.93.Final)"
    "$(jar_file io.netty netty-common 4.1.93.Final)"
    "$(jar_file io.netty netty-handler 4.1.93.Final)"
    "$(jar_file io.netty netty-handler-proxy 4.1.93.Final)"
    "$(jar_file io.netty netty-resolver 4.1.93.Final)"
    "$(jar_file io.netty netty-transport 4.1.93.Final)"
    "$(jar_file io.netty netty-transport-native-unix-common 4.1.93.Final)"
    "$(jar_file com.google.guava guava 32.0.1-jre)"
    "$(jar_file com.google.guava failureaccess 1.0.1)"
    "$(jar_file com.google.guava listenablefuture 9999.0-empty-to-avoid-conflict-with-guava)"
    "$(jar_file com.google.code.findbugs jsr305 3.0.2)"
    "$(jar_file com.google.code.gson gson 2.10.1)"
    "$(jar_file com.google.android annotations 4.1.1.4)"
    "$(jar_file com.google.errorprone error_prone_annotations 2.18.0)"
    "$(jar_file com.google.j2objc j2objc-annotations 2.8)"
    "$(jar_file org.checkerframework checker-qual 3.33.0)"
    "$(jar_file org.codehaus.mojo animal-sniffer-annotations 1.23)"
    "$(jar_file io.perfmark perfmark-api 0.26.0)"
)

classpath=
for dependency in "${JARS[@]}"; do
    if [ -z "$classpath" ]; then
        classpath=$dependency
    else
        classpath=$classpath:$dependency
    fi
done
readonly classpath

/usr/bin/unzip -p "$EMULATOR_ZIP" emulator/lib/emulator_controller.proto \
    >"$PROTO_ROOT/emulator_controller.proto" \
    || die 'cannot extract the authenticated emulator controller schema'
/usr/bin/unzip -p "$PROTOBUF_JAVA" google/protobuf/empty.proto \
    >"$PROTO_ROOT/google/protobuf/empty.proto" \
    || die 'cannot extract the pinned protobuf Empty schema'
[ -s "$PROTO_ROOT/emulator_controller.proto" ] \
    && [ -s "$PROTO_ROOT/google/protobuf/empty.proto" ] \
    || die 'an extracted protobuf schema is empty'

"$PROTOC" --proto_path="$PROTO_ROOT" --java_out="$GENERATED_ROOT" \
    "$PROTO_ROOT/emulator_controller.proto" \
    || die 'pinned protoc could not generate the emulator message classes'
mapfile -d '' -t generated_sources < <(
    find "$GENERATED_ROOT" -type f -name '*.java' -print0 | sort -z
)
[ "${#generated_sources[@]}" -ge 2 ] \
    || die 'the generated emulator message closure is incomplete'
/usr/bin/javac --release 17 -encoding UTF-8 -cp "$classpath" -d "$CLASS_ROOT" \
    "${generated_sources[@]}" "$OBSERVER_SOURCE" \
    || die 'the emulator frame observer did not compile'

python3 -I -S "$FRAME_DECODER" self-test
/usr/bin/java -cp "$CLASS_ROOT:$classpath" AndroidEmulatorFrameObserver --self-test
printf 'ANDROID_EMULATOR_FRAME_OBSERVER_BUILD=pass protoc=3.20.1 protobuf=3.22.3 grpc=1.57.0 jars=%s generated_sources=%s network=container-loopback output=private-bind\n' \
    "${#JARS[@]}" "${#generated_sources[@]}"
exec /usr/bin/java -cp "$CLASS_ROOT:$classpath" AndroidEmulatorFrameObserver \
    127.0.0.1 8554 "$OUTPUT_ROOT"
