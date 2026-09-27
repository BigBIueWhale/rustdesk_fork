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
readonly DEPENDENCY_MANIFEST=$SCRIPT_DIR/android-emulator-frame-observer-dependencies.tsv
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
    && [ -f "$DEPENDENCY_MANIFEST" ] && [ ! -L "$DEPENDENCY_MANIFEST" ] \
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

PROTOC=
PROTOBUF_JAVA=
JARS=()
declare -A dependency_coordinates=()
declare -A dependency_paths=()
dependency_records=0
while IFS=$'\t' read -r kind group artifact version filename size digest mode extra; do
    [ -n "$kind" ] && [ -z "$extra" ] \
        && [[ "$group" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]] \
        && [[ "$artifact" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]] \
        && [[ "$version" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]] \
        && [[ "$filename" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]] \
        && [[ "$size" =~ ^[1-9][0-9]*$ ]] \
        && [[ "$digest" =~ ^[0-9a-f]{64}$ ]] \
        || die 'the observer dependency manifest is malformed'
    dependency_path="$(one_file \
        "$GRADLE_HOME/caches/modules-2/files-2.1/$group/$artifact/$version" \
        "$filename" "$group:$artifact:$version")" \
        || exit $?
    dependency_coordinate="$kind:$group:$artifact:$version:$filename"
    [ -z "${dependency_coordinates[$dependency_coordinate]+present}" ] \
        && [ -z "${dependency_paths[$dependency_path]+present}" ] \
        || die "observer dependency manifest entry is duplicated: $group:$artifact:$version"
    dependency_coordinates[$dependency_coordinate]=1
    dependency_paths[$dependency_path]=1
    [ "$(stat -c '%u:%g:%a:%h:%s' -- "$dependency_path")" = \
      "1000:1000:$mode:1:$size" ] \
        || die "observer dependency metadata differs: $group:$artifact:$version"
    [ "$(sha256sum "$dependency_path" | awk '{ print $1 }')" = "$digest" ] \
        || die "observer dependency digest differs: $group:$artifact:$version"
    case "$kind" in
        protoc)
            [ "$artifact:$version:$filename:$mode" = \
              'protoc:3.20.1:protoc-3.20.1-linux-x86_64.exe:500' ] \
                && [ -z "$PROTOC" ] \
                || die 'the observer protoc manifest entry differs'
            PROTOC=$dependency_path
            ;;
        jar)
            [ "$filename:$mode" = "$artifact-$version.jar:400" ] \
                || die "observer JAR manifest entry differs: $group:$artifact:$version"
            JARS+=("$dependency_path")
            if [ "$group:$artifact:$version" = \
                 com.google.protobuf:protobuf-java:3.22.3 ]; then
                [ -z "$PROTOBUF_JAVA" ] \
                    || die 'the observer protobuf-java entry is duplicated'
                PROTOBUF_JAVA=$dependency_path
            fi
            ;;
        *) die "the observer dependency kind is unsupported: $kind" ;;
    esac
    dependency_records=$((dependency_records + 1))
done <"$DEPENDENCY_MANIFEST"
[ "$dependency_records:${#JARS[@]}" = 32:31 ] \
    && [ -n "$PROTOC" ] && [ -n "$PROTOBUF_JAVA" ] \
    || die 'the observer dependency closure is incomplete'
[ -x "$PROTOC" ] || die 'the pinned protoc input is not executable'
readonly PROTOC PROTOBUF_JAVA
readonly -a JARS
DEPENDENCY_MANIFEST_SHA256="$(sha256sum "$DEPENDENCY_MANIFEST" \
    | awk '{ print $1 }')" \
    || die 'cannot digest the observer dependency manifest'
[[ "$DEPENDENCY_MANIFEST_SHA256" =~ ^[0-9a-f]{64}$ ]] \
    || die 'the observer dependency manifest digest is malformed'
readonly DEPENDENCY_MANIFEST_SHA256

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
printf 'ANDROID_EMULATOR_FRAME_OBSERVER_BUILD=pass protoc=3.20.1 protobuf=3.22.3 grpc=1.57.0 jars=%s generated_sources=%s dependency_manifest_sha256=%s network=container-loopback output=private-bind\n' \
    "${#JARS[@]}" "${#generated_sources[@]}" "$DEPENDENCY_MANIFEST_SHA256"
exec /usr/bin/java -cp "$CLASS_ROOT:$classpath" AndroidEmulatorFrameObserver \
    127.0.0.1 8554 "$OUTPUT_ROOT"
