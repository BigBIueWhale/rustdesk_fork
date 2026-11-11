#!/usr/bin/env bash
# Candidate-only dependency discovery. /work belongs to this disposable VM;
# neither the source checkout nor a persistent Pub cache is writable here.
set -euo pipefail
umask 077
[ "$#" -eq 1 ] && [ "$(id -u)" -ne 0 ] && [ "$(id -g)" -ne 0 ] \
    || { echo 'plugin migration probe requires one phase and an ordinary principal' >&2; exit 1; }
case "$1" in resolve|replay) ;; *) exit 1 ;; esac
source /authority/pins.env
readonly work=/work
[ "$(stat -c '%u:%g:%a' "$work")" = "$(id -u):$(id -g):700" ]
[ "$(stat -c '%u:%g:%a:%h:%s' /inputs/flutter.tar.xz)" = \
    "$(id -u):$(id -g):400:1:$SIZE_FLUTTER_PRESENTATION_CANDIDATE" ]
[ "$(sha256sum /inputs/flutter.tar.xz | awk '{print $1}')" = \
    "$SHA256_FLUTTER_PRESENTATION_CANDIDATE" ]
[ "$(sha256sum /authority/pubspec.lock | awk '{print $1}')" = \
    "$SHA256_FLUTTER_PRESENTATION_CANDIDATE_PROJECT_LOCK" ]
ulimit -f 524288
export FLUTTER_ROOT="$work/toolchain/flutter" PUB_CACHE="$work/pub-cache"
export PUB_HOSTED_URL=https://pub.dev CI=true FLUTTER_SUPPRESS_ANALYTICS=true
export DART_SUPPRESS_ANALYTICS=true
export ANALYZER_STATE_LOCATION_OVERRIDE=/tmp/analyzer-state
export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_OPTIONAL_LOCKS=0
export PATH="$FLUTTER_ROOT/bin/cache/dart-sdk/bin:/usr/bin:/bin"

run_logged() {
    local log=$1 status=0
    shift
    "$@" >"$log" 2>&1 || status=$?
    [ "$(stat -c '%s' "$log")" -le 2097152 ] \
        || { echo 'plugin migration diagnostics exceed their bound' >&2; return 1; }
    cat "$log"
    return "$status"
}

if [ "$1" = resolve ]; then
    [ -z "$(find "$work" -mindepth 1 -maxdepth 1 -print -quit)" ]
    mkdir "$work/toolchain" "$work/project" "$work/pub-cache"
    tar -xJf /inputs/flutter.tar.xz -C "$work/toolchain" --no-same-owner --no-same-permissions
    cp -a /project-source/. "$work/project/"
    chmod -R u+rwX "$work/project"
    cp /authority/pubspec.lock "$work/project/pubspec.lock"
    python3 -I -S - <<'PY'
import pathlib
p=pathlib.Path('/work/project/pubspec.yaml');text=p.read_text()
for old,new in [('  file_picker: ^5.1.0\n','  file_selector: 1.1.0\n'),
                ('  sqflite: 2.2.8+4\n','  sqflite: 2.4.6\n'),
                ('  flutter_plugin_android_lifecycle: 2.0.17\n','')]:
    if text.count(old)!=1:
        raise ValueError('candidate manifest precondition differs: '+old.strip())
    text=text.replace(old,new)
p.write_text(text)
PY
    cd "$work/project"
    dart --version
    run_logged "$work/resolve.log" timeout --signal=TERM --kill-after=10s 300 \
        dart pub get --no-example
    sha256sum pubspec.yaml pubspec.lock >"$work/resolved.sha256"
    printf 'FLUTTER_PLUGIN_MIGRATION_RESOLVE=pass\n'
else
    cd "$work/project"
    sha256sum --check --status "$work/resolved.sha256"
    # A fresh project configuration must be produced with the container NIC absent.
    python3 -I -S - <<'PY'
import pathlib,shutil
root=pathlib.Path('/work/project');dest=pathlib.Path('/tmp/replay')
shutil.copytree(root,dest,ignore=shutil.ignore_patterns('.dart_tool','build'))
PY
    cd /tmp/replay
    run_logged "$work/replay.log" timeout --signal=TERM --kill-after=10s 180 \
        dart pub get --offline --enforce-lockfile --no-example
    sha256sum --check --status "$work/resolved.sha256"
    mkdir -p tool
    cat >tool/plugin_migration_contract.dart <<'DART'
import 'package:file_selector/file_selector.dart';
import 'package:sqflite/sqflite.dart';

Future<String?> screenshotDestination(String name) async {
  final location = await getSaveLocation(
    suggestedName: name,
    confirmButtonText: 'Save',
    acceptedTypeGroups: const [XTypeGroup(
      label: 'PNG', extensions: ['png'], uniformTypeIdentifiers: ['public.png'],
    )],
  );
  return location?.path;
}

Future<String?> recordingDirectory(String initial) =>
    getDirectoryPath(initialDirectory: initial);

Future<Database> cacheDatabase(String path) => openDatabase(path);
DART
    run_logged "$work/analyze.log" timeout --signal=TERM --kill-after=10s 180 \
        dart analyze tool/plugin_migration_contract.dart
    python3 -I -S - <<'PY'
import hashlib,json,pathlib,urllib.parse
root=pathlib.Path('/tmp/replay');lock=(root/'pubspec.lock').read_bytes()
if not 0<len(lock)<=128*1024:
    raise ValueError('candidate lock exceeds evidence bound')
config=root/'.dart_tool/package_config.json'
packages=json.loads(config.read_text())['packages']
selected=[]
for package in packages:
    name=package['name']
    if not name.startswith(('file_selector','sqflite','flutter_plugin_android_lifecycle')):
        continue
    uri=urllib.parse.urljoin(config.as_uri(),package['rootUri'])
    parsed=urllib.parse.urlsplit(uri)
    if parsed.scheme!='file' or parsed.netloc:
        raise ValueError('selected package is not a local cache entry')
    path=pathlib.Path(urllib.parse.unquote(parsed.path)).resolve()
    if not path.is_relative_to('/work/pub-cache/hosted/pub.dev'):
        raise ValueError('selected package is outside the private hosted cache')
    manifest=(path/'pubspec.yaml').read_bytes()
    if len(manifest)>64*1024:
        raise ValueError('package manifest exceeds evidence bound')
    selected.append({'name':name,'directory':path.name,'pubspec':manifest.decode(),
                     'pubspec_sha256':hashlib.sha256(manifest).hexdigest()})
result={'package_count':len(packages),'selected_packages':selected,
        'pubspec':(root/'pubspec.yaml').read_text(),'lock':lock.decode(),
        'lock_sha256':hashlib.sha256(lock).hexdigest(),
        'offline_replay':True,'api_analysis':True,'apk_built':False,
        'cache_published':False,'application_changed':False,
        'provenance':'discovery only; independent package authentication remains required'}
encoded=json.dumps(result,sort_keys=True,separators=(',',':'))
if len(encoded)>512*1024:
    raise ValueError('migration receipt exceeds evidence bound')
print('FLUTTER_PLUGIN_MIGRATION_PROBE='+encoded)
PY
fi
