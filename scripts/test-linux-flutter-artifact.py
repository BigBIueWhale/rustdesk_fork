#!/usr/bin/env python3
"""Run real filesystem/ELF capsule cases only inside the authenticated verifier VM."""

import copy
import fcntl
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest
from contextlib import ExitStack

sys.dont_write_bytecode = True
SCRIPT_DIR = Path(__file__).resolve().parent
subprocess.run(["/bin/bash", str(SCRIPT_DIR / "verify-vm-entry-preflight.sh")],
               check=True, stdout=subprocess.DEVNULL)
spec = importlib.util.spec_from_file_location("linux_flutter_artifact", SCRIPT_DIR / "linux-flutter-artifact.py")
if spec is None or spec.loader is None:
    raise SystemExit("cannot load the Linux Flutter artifact implementation")
app = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = app
spec.loader.exec_module(app)
CONTEXT = {
    "source_commit": "1" * 40, "source_tree": "2" * 40,
    "builder_config": "sha256:" + "3" * 64, "build_recipe_sha256": "4" * 64,
    "rust_toolchain": "1.75.0-x86_64-unknown-linux-gnu", "flutter_version": "3.47.5",
    "source_date_epoch": "1700000000", "inputs": {key: "5" * 64 for key in app.INPUTS},
}
ELF = Path("/usr/bin/true").read_bytes()
CONTEXT["engine"] = {
    "source_commit": "6" * 40, "source_tree": "7" * 40,
    "framework_revision": "8" * 40, "patch_sha256": "9" * 64,
    "archive_sha256": "a" * 64, "manifest_sha256": "b" * 64,
    "core": {"bytes": len(ELF), "sha256": hashlib.sha256(ELF).hexdigest()},
    "icu": {"bytes": len(b"asset bytes"), "sha256": hashlib.sha256(b"asset bytes").hexdigest()},
}
WORKSPACE = Path(tempfile.mkdtemp(prefix="linux-flutter-artifact-test."))
WORKSPACE.chmod(0o700)
WORKSPACE_ID = app.publication.identity(WORKSPACE.stat())


def identity(path):
    return app.publication.identity(path.lstat())


def directory(path):
    path.mkdir(mode=0o700)
    return path


def write(path, data):
    with path.open("xb") as stream:
        stream.write(data)
    path.chmod(0o400)


class LinuxFlutterArtifactTests(unittest.TestCase):
    def setUp(self):
        self.case = directory(WORKSPACE / self.id().rsplit(".", 1)[-1])
        self.source = directory(self.case / "source")
        for relative in (*app.REQUIRED_FILES, "bundle/data/flutter_assets/empty asset",
                         "bundle/data/flutter_assets/packages/example/asset"):
            path = self.source / relative
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            write(path, ELF if app.executable(relative) else b"" if path.name == "empty asset" else b"asset bytes")
        for path in sorted(self.source.rglob("*"), reverse=True):
            if path.is_dir():
                path.chmod(0o500)
        self.source.chmod(0o500)
        self.parent = directory(self.case / "publication")
        self.execution = directory(self.case / "execution")

    def prepare(self):
        return app.prepare(str(self.source), identity(self.source), str(self.parent), identity(self.parent), CONTEXT)

    def published(self):
        pending, expected, digest = self.prepare()
        return Path(app.commit(str(self.parent), identity(self.parent), pending, expected, CONTEXT, digest)), digest

    def materialize(self, root, digest, context=CONTEXT):
        return Path(app.materialize(str(root), identity(root), str(self.execution), identity(self.execution), context, digest))

    def admit(self, root, digest, context=CONTEXT):
        with ExitStack() as stack:
            descriptor = app.open_root(str(root), identity(root), 0o500, stack)
            return app.admit(descriptor, context, digest, stack)[1]

    def rejected(self, operation):
        with self.assertRaises((app.publication.PublicationError, OSError, ValueError)):
            operation()

    def change_manifest(self, root, change):
        path = root / app.MANIFEST
        value = json.loads(path.read_bytes())
        raw = change(value)
        path.chmod(0o600)
        path.write_bytes(raw)
        path.chmod(0o400)
        return hashlib.sha256(raw).hexdigest()

    def cli(self, action, *arguments):
        return subprocess.run([
            "/usr/bin/python3", "-I", "-S", str(SCRIPT_DIR / "linux-flutter-artifact.py"), action,
            "--context", json.dumps(CONTEXT), "--parent", str(self.parent if action != "materialize" else self.execution),
            "--parent-identity", ":".join(map(str, identity(self.parent if action != "materialize" else self.execution))),
            *arguments,
        ], check=True, timeout=15, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout.strip()

    def test_actual_cli_publication_materialization_and_elf_execution(self):
        pending, expected, digest = self.cli("prepare", "--root", str(self.source),
            "--root-identity", ":".join(map(str, identity(self.source)))).split()
        root = Path(self.cli("commit", "--pending", pending, "--pending-identity", expected,
                             "--manifest-sha256", digest))
        manifest = self.admit(root, digest)
        for relative in manifest["files"]:
            self.assertEqual(stat.S_IMODE((root / relative).stat().st_mode), 0o400)
        target = Path(self.cli("materialize", "--root", str(root),
            "--root-identity", ":".join(map(str, identity(root))), "--manifest-sha256", digest))
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o500)
        self.assertFalse((target / app.MANIFEST).exists())
        for relative in manifest["files"]:
            output = target / relative
            self.assertEqual(output.read_bytes(), (root / relative).read_bytes())
            self.assertEqual((stat.S_IMODE(output.stat().st_mode), output.stat().st_nlink),
                             (0o500 if app.executable(relative) else 0o400, 1))
            if app.executable(relative):
                subprocess.run([str(output)], check=True, timeout=5, stdin=subprocess.DEVNULL,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def test_wrong_context_refuses_before_execution_copy(self):
        root, digest = self.published()
        for key in CONTEXT:
            context = copy.deepcopy(CONTEXT)
            if key == "inputs":
                context[key]["flutter_archive"] = "a" * 64
            elif key == "engine":
                context[key]["archive_sha256"] = "c" * 64
            elif key == "source_date_epoch":
                context[key] = "unset"
            elif key == "flutter_version":
                context[key] = "3.24.5"
            elif key == "rust_toolchain":
                context[key] = "1.76.0-x86_64-unknown-linux-gnu"
            else:
                context[key] = ("sha256:" if key == "builder_config" else "") + "a" * (40 if key in ("source_commit", "source_tree") else 64)
            self.rejected(lambda: self.materialize(root, digest, context))
            self.assertEqual(list(self.execution.iterdir()), [])

    def test_wrong_manifest_digest(self):
        root, _ = self.published()
        descriptors = set(os.listdir("/proc/self/fd"))
        with self.assertRaisesRegex(app.publication.PublicationError,
                                    "^Linux app manifest digest differs$"):
            self.materialize(root, "0" * 64)
        self.assertEqual(set(os.listdir("/proc/self/fd")), descriptors)
        self.assertEqual(list(self.execution.iterdir()), [])

    def test_closed_context_and_input_roles(self):
        for context in (dict(CONTEXT, unknown="x"), dict(CONTEXT, inputs={}),
                        dict(CONTEXT, source_commit="HEAD"), dict(CONTEXT, rust_toolchain="stable")):
            self.rejected(lambda: app.validate_context(context))
        for key in app.APP_ENGINE_FIELDS:
            context = copy.deepcopy(CONTEXT)
            del context["engine"][key]
            self.rejected(lambda: app.validate_context(context))
        for role in app.APP_ENGINE_ROLES:
            for value in (True, 0, app.MAX_FILE_BYTES + 1):
                context = copy.deepcopy(CONTEXT)
                context["engine"][role]["bytes"] = value
                self.rejected(lambda: app.validate_context(context))

    def test_stock_engine_refuses_before_publication(self):
        for role in app.APP_ENGINE_ROLES:
            context = copy.deepcopy(CONTEXT)
            context["engine"][role]["sha256"] = "f" * 64
            self.rejected(lambda: app.prepare(str(self.source), identity(self.source),
                str(self.parent), identity(self.parent), context))
            self.assertEqual(list(self.parent.iterdir()), [])

    def test_self_consistent_capsule_cannot_choose_its_engine(self):
        root, digest = self.published()
        for role, relative in app.APP_ENGINE_ROLES.items():
            original = (root / relative).read_bytes()
            replacement = original + b"self-consistent but not the selected engine"
            path = root / relative
            path.chmod(0o600)
            path.write_bytes(replacement)
            path.chmod(0o400)
            def substitute(value):
                value["files"][relative] = {
                    "bytes": len(replacement), "sha256": hashlib.sha256(replacement).hexdigest(),
                }
                return json.dumps(value).encode()
            digest = self.change_manifest(root, substitute)
            self.rejected(lambda: self.materialize(root, digest))
            self.assertEqual(list(self.execution.iterdir()), [])
            path.chmod(0o600)
            path.write_bytes(original)
            path.chmod(0o400)
            digest = self.change_manifest(root, lambda value: json.dumps({
                **value, "files": {**value["files"], relative: CONTEXT["engine"][role]},
            }).encode())

    def test_schema_one_has_no_patched_engine_authority(self):
        root, _ = self.published()
        digest = self.change_manifest(root, lambda value: json.dumps({**value, "schema": 1}).encode())
        self.rejected(lambda: self.materialize(root, digest))
        self.assertEqual(list(self.execution.iterdir()), [])

    def test_changed_asset_bytes(self):
        root, digest = self.published()
        path = root / "bundle/data/icudtl.dat"
        path.chmod(0o600)
        path.write_bytes(b"changed")
        path.chmod(0o400)
        self.rejected(lambda: self.admit(root, digest))

    def test_symlink_payload(self):
        root, digest = self.published()
        path = root / "bundle/rustdesk"
        path.parent.chmod(0o700)
        path.unlink()
        path.symlink_to(self.source / "bundle/rustdesk")
        path.parent.chmod(0o500)
        self.rejected(lambda: self.admit(root, digest))

    def test_external_hardlink(self):
        root, digest = self.published()
        os.link(root / "bundle/rustdesk", self.case / "external")
        self.rejected(lambda: self.admit(root, digest))

    def test_executable_cached_payload(self):
        root, digest = self.published()
        (root / "bundle/rustdesk").chmod(0o500)
        self.rejected(lambda: self.admit(root, digest))

    def test_extra_test_driver(self):
        self.source.chmod(0o700)
        write(self.source / "flutter-peer-presentation-x11", ELF)
        self.source.chmod(0o500)
        self.rejected(self.prepare)
        self.assertEqual(list(self.parent.iterdir()), [])

    def test_extra_empty_directory_is_manifest_bound(self):
        root, digest = self.published()
        parent = root / "bundle/data/flutter_assets"
        parent.chmod(0o700)
        directory(parent / "unrecorded").chmod(0o500)
        parent.chmod(0o500)
        self.rejected(lambda: self.admit(root, digest))

    def test_missing_required_product_file(self):
        path = self.source / "bundle/lib/libapp.so"
        path.parent.chmod(0o700)
        path.unlink()
        path.parent.chmod(0o500)
        self.rejected(self.prepare)
        self.assertEqual(list(self.parent.iterdir()), [])

    def test_non_elf_library(self):
        path = self.source / "bundle/lib/libapp.so"
        path.chmod(0o600)
        path.write_bytes(b"not an ELF image")
        path.chmod(0o400)
        descriptors = set(os.listdir("/proc/self/fd"))
        with self.assertRaisesRegex(app.publication.PublicationError,
                                    "^Linux app executable is not an x86_64 ELF image$"):
            self.prepare()
        self.assertEqual(set(os.listdir("/proc/self/fd")), descriptors)
        self.assertFalse((self.parent / app.DESTINATION).exists())
        pending, = self.parent.iterdir()
        self.assertIsNotNone(app.PENDING_RE.fullmatch(pending.name))
        expected = identity(pending)
        with self.assertRaisesRegex(app.publication.PublicationError,
                                    "^an earlier Linux app artifact remains; reuse or explicitly reconcile it$"):
            self.prepare()
        self.assertEqual(set(os.listdir("/proc/self/fd")), descriptors)
        self.assertEqual(list(self.parent.iterdir()), [pending])
        self.assertEqual(identity(pending), expected)

    def test_duplicate_manifest_key(self):
        root, _ = self.published()
        digest = self.change_manifest(root, lambda value: b'{"schema":2,' + json.dumps(value).encode()[1:])
        self.rejected(lambda: self.admit(root, digest))

    def test_boolean_manifest_size(self):
        root, _ = self.published()
        def change(value):
            value["files"]["bundle/rustdesk"]["bytes"] = True
            return json.dumps(value).encode()
        digest = self.change_manifest(root, change)
        self.rejected(lambda: self.admit(root, digest))

    def test_retained_pending_refuses_new_preparation(self):
        pending, expected, _ = self.prepare()
        self.rejected(self.prepare)
        self.assertEqual(names := [path.name for path in self.parent.iterdir()], [pending])
        self.assertEqual(identity(self.parent / names[0]), expected)

    def test_wrong_pending_identity(self):
        pending, expected, digest = self.prepare()
        self.rejected(lambda: app.commit(str(self.parent), identity(self.parent), pending,
            (expected[0], expected[1] + 1), CONTEXT, digest))
        self.assertFalse((self.parent / app.DESTINATION).exists())

    def test_late_publication_collision_does_not_clobber(self):
        pending, expected, digest = self.prepare()
        original = app.publication.rename_noreplace
        def collide(parent, source, destination):
            os.mkdir(destination, 0o700, dir_fd=parent)
            return original(parent, source, destination)
        app.publication.rename_noreplace = collide
        try:
            self.rejected(lambda: app.commit(str(self.parent), identity(self.parent), pending, expected, CONTEXT, digest))
        finally:
            app.publication.rename_noreplace = original
        self.assertEqual(identity(self.parent / pending), expected)
        self.assertEqual(list((self.parent / app.DESTINATION).iterdir()), [])

    def test_held_publication_lock(self):
        descriptor = os.open(self.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.rejected(self.prepare)
            self.assertEqual(list(self.parent.iterdir()), [])
        finally:
            os.close(descriptor)

    def test_posix_acl_even_with_owner_only_mode(self):
        root, digest = self.published()
        path = root / "bundle/rustdesk"
        entries = ((1, 4, 0xffffffff), (2, 0, 4001), (4, 0, 0xffffffff), (16, 0, 0xffffffff), (32, 0, 0xffffffff))
        os.setxattr(path, "system.posix_acl_access", struct.pack("<I", 2) + b"".join(
            struct.pack("<HHI", *entry) for entry in entries))
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o400)
        self.rejected(lambda: self.admit(root, digest))

    def test_materialization_success_failure_and_retry_descriptor_finality(self):
        root, digest = self.published()
        descriptors = set(os.listdir("/proc/self/fd"))
        target = self.materialize(root, digest)
        self.assertEqual(set(os.listdir("/proc/self/fd")), descriptors)
        expected = identity(target)
        for _ in range(3):
            with self.assertRaisesRegex(app.publication.PublicationError,
                                        "^Linux app execution workspace is occupied$"):
                self.materialize(root, digest)
            self.assertEqual(set(os.listdir("/proc/self/fd")), descriptors)
            self.assertEqual(list(self.execution.iterdir()), [target])
            self.assertEqual(identity(target), expected)
            self.assertEqual((target / "bundle/rustdesk").read_bytes(), ELF)

        failed_parent = directory(self.case / "failed-execution")
        original = app.publication.write_all
        writes = []

        def interrupt_copy(descriptor, data, label):
            self.assertEqual(label, "Linux app file")
            if os.readlink(f"/proc/self/fd/{descriptor}") != str(
                    failed_parent / app.MATERIALIZED / "bundle/rustdesk"):
                return original(descriptor, data, label)
            original(descriptor, data[:1], label)
            writes.append(descriptor)
            raise OSError("injected materialization write failure")

        app.publication.write_all = interrupt_copy
        try:
            with self.assertRaisesRegex(OSError, "^injected materialization write failure$"):
                app.materialize(str(root), identity(root), str(failed_parent),
                                identity(failed_parent), CONTEXT, digest)
        finally:
            app.publication.write_all = original
        self.assertEqual(len(writes), 1)
        self.assertEqual(set(os.listdir("/proc/self/fd")), descriptors)
        partial = failed_parent / app.MATERIALIZED
        partial_identity = identity(partial)
        copied = partial / "bundle/rustdesk"
        self.assertEqual(copied.read_bytes(), ELF[:1])

        def snapshot():
            return {str(path.relative_to(partial)): (app.publication.stable_file(path.lstat()),
                    path.read_bytes() if path.is_file() else None)
                    for path in [partial, *partial.rglob("*")]}

        retained = snapshot()
        for relative, (_, payload) in retained.items():
            if payload is not None and relative != "bundle/rustdesk":
                self.assertEqual(payload, (root / relative).read_bytes())
        for _ in range(3):
            with self.assertRaisesRegex(app.publication.PublicationError,
                                        "^Linux app execution workspace is occupied$"):
                app.materialize(str(root), identity(root), str(failed_parent),
                                identity(failed_parent), CONTEXT, digest)
            self.assertEqual(set(os.listdir("/proc/self/fd")), descriptors)
            self.assertEqual(list(failed_parent.iterdir()), [partial])
            self.assertEqual(identity(partial), partial_identity)
            self.assertEqual(snapshot(), retained)
        print("LINUX_FLUTTER_MATERIALIZATION_FINALITY=pass success=closed early-refusal=closed "
              "partial-write=observed failure=closed retry=refused retained=unchanged", file=sys.stderr)


class EngineSdkRoleTests(unittest.TestCase):
    def setUp(self):
        self.case = directory(WORKSPACE / self.id().rsplit(".", 1)[-1])
        self.sdk = directory(self.case / "sdk")
        directory(self.sdk / "packages")
        self.context = {"source_commit": "1" * 40, "source_tree": "2" * 40,
                        "framework_revision": "3" * 40, "patch_sha256": "4" * 64,
                        "bootstrap_sdk_archive_sha256": "5" * 64}
        self.values = {
            "bin/cache/pkg/sky_engine/pubspec.yaml": b"name: sky_engine\n",
            "bin/cache/pkg/sky_engine/lib/_embedder.yaml": b"embedded_libs:\n",
            "bin/cache/pkg/sky_engine/lib/ui/ui.dart": b"library dart.ui;\n",
            "bin/cache/pkg/sky_engine/README.md": b"package fixture\n",
            "bin/cache/dart-sdk/bin/snapshots/frontend_server_aot.dart.snapshot": ELF,
        }
        files = {}
        for relative, data in self.values.items():
            path = self.sdk / relative
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            write(path, data)
            key = relative.replace("bin/cache/pkg/sky_engine/", "gen/dart-pkg/sky_engine/") \
                          .replace("bin/cache/dart-sdk/bin/snapshots/", "gen/")
            files[key] = {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        self.manifest = dict(self.context, format="rustdesk-flutter-linux-engine-artifact-v2",
                             profile="linux-x64-release-toolkit", files=files)
        self.raw = json.dumps(self.manifest, sort_keys=True).encode()
        self.digest = hashlib.sha256(self.raw).hexdigest()

    def verify(self, raw=None, digest=None, context=None):
        return app.verify_engine_sdk_roles(str(self.sdk), identity(self.sdk),
            self.raw if raw is None else raw, self.digest if digest is None else digest,
            self.context if context is None else context)

    def reject(self, operation):
        with self.assertRaises((app.publication.PublicationError, OSError, ValueError)):
            operation()

    def test_sdk_role_match_is_read_only(self):
        def snapshot():
            return {str(path.relative_to(self.sdk)): (app.publication.stable_file(path.lstat()),
                    path.read_bytes() if path.is_file() else None)
                    for path in [self.sdk, *self.sdk.rglob("*")]}
        before = snapshot()
        self.assertEqual(self.verify(), 4)
        self.assertEqual(snapshot(), before)

    def test_sdk_role_manifest_and_source_authority(self):
        self.reject(lambda: self.verify(digest="0" * 64))
        self.reject(lambda: self.verify(raw=b"{"))
        for key in self.context:
            context = dict(self.context)
            context[key] = "a" * len(context[key])
            self.reject(lambda: self.verify(context=context))
        for change in (lambda value: value.update(profile="core-only"),
                       lambda value: value["files"].pop("gen/dart-pkg/sky_engine/lib/ui/ui.dart"),
                       lambda value: value["files"].update({"gen/dart-pkg/sky_engine/../escape":
                           {"bytes": 0, "sha256": "0" * 64}}),
                       lambda value: value["files"]["gen/frontend_server_aot.dart.snapshot"].update(bytes=True)):
            manifest = copy.deepcopy(self.manifest)
            change(manifest)
            raw = json.dumps(manifest).encode()
            self.reject(lambda: self.verify(raw=raw, digest=hashlib.sha256(raw).hexdigest()))

    def test_sdk_role_content_and_missing_file_refuse(self):
        for relative, data in self.values.items():
            path = self.sdk / relative
            path.chmod(0o600)
            path.write_bytes(b"x" * len(data))
            path.chmod(0o400)
            self.reject(self.verify)
            path.unlink()
            self.reject(self.verify)
            write(path, data)

    def test_sdk_role_extra_file_or_empty_subtree_refuses(self):
        shadow = directory(self.sdk / "packages/sky_engine")
        with self.assertRaisesRegex(app.publication.PublicationError, "higher-priority shadow"):
            self.verify()
        shadow.rmdir()
        parent = self.sdk / "bin/cache/pkg/sky_engine"
        write(parent / "unrecorded", b"extra")
        self.reject(self.verify)
        (parent / "unrecorded").unlink()
        directory(parent / "unrecorded")
        self.reject(self.verify)

    def test_sdk_role_links_and_special_objects_refuse(self):
        path = self.sdk / "bin/cache/pkg/sky_engine/lib/ui/ui.dart"
        data = path.read_bytes()
        path.unlink()
        path.symlink_to(self.sdk / "bin/cache/pkg/sky_engine/README.md")
        self.reject(self.verify)
        path.unlink()
        os.mkfifo(path, 0o600)
        self.reject(self.verify)
        path.unlink()
        write(path, data)
        os.link(path, self.case / "external")
        self.reject(self.verify)

    def test_sdk_role_identity_modes_and_acl_refuse(self):
        expected = identity(self.sdk)
        self.reject(lambda: app.verify_engine_sdk_roles(str(self.sdk),
            (expected[0], expected[1] + 1), self.raw, self.digest, self.context))
        self.sdk.chmod(0o702)
        self.reject(self.verify)
        self.sdk.chmod(0o700)
        path = self.sdk / "bin/cache/pkg/sky_engine/pubspec.yaml"
        path.chmod(0o646)
        self.reject(self.verify)
        path.chmod(0o400)
        entries = ((1, 4, 0xffffffff), (2, 0, 4001), (4, 0, 0xffffffff),
                   (16, 0, 0xffffffff), (32, 0, 0xffffffff))
        os.setxattr(path, "system.posix_acl_access", struct.pack("<I", 2) + b"".join(
            struct.pack("<HHI", *entry) for entry in entries))
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o400)
        self.reject(self.verify)


class EngineMaterializationTests(unittest.TestCase):
    def setUp(self):
        EngineSdkRoleTests.setUp(self)
        self.capsule = directory(self.case / "engine-capsule")
        self.execution = directory(self.case / "engine-execution")
        self.payloads = {key: ELF if key in app.ENGINE_ELFS else b"toolkit fixture\n"
                         for key in app.ENGINE_ELFS | app.ENGINE_HEADERS | app.ENGINE_DATA | app.ENGINE_SHADERS}
        self.payloads.update({relative.replace("bin/cache/pkg/sky_engine/", "gen/dart-pkg/sky_engine/")
            .replace("bin/cache/dart-sdk/bin/snapshots/", "gen/"): data
            for relative, data in self.values.items()})
        self.reseal()

    def reseal(self, change=None, extra=None, suffix=b""):
        self.manifest["files"] = {key: {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
                                  for key, data in self.payloads.items()}
        self.raw = json.dumps(self.manifest, sort_keys=True).encode()
        self.digest = hashlib.sha256(self.raw).hexdigest()
        data = io.BytesIO()
        with tarfile.open(fileobj=data, mode="w") as archive:
            for name, payload in [*sorted(self.payloads.items()), (app.ENGINE_MANIFEST, self.raw)]:
                member = tarfile.TarInfo(name)
                member.size, member.mode = len(payload), 0o400
                if change is not None:
                    change(member)
                archive.addfile(member, io.BytesIO(payload))
            if extra is not None:
                member = tarfile.TarInfo(extra)
                member.size, member.mode = 1, 0o400
                archive.addfile(member, io.BytesIO(b"x"))
        raw = data.getvalue() + suffix
        self.archive_digest = hashlib.sha256(raw).hexdigest()
        for name, payload in ((app.ENGINE_ARCHIVE, raw),
                (app.ENGINE_ARCHIVE + ".sha256", (self.archive_digest + "  " + app.ENGINE_ARCHIVE + "\n").encode())):
            path = self.capsule / name
            if path.exists():
                path.unlink()
            write(path, payload)

    def materialize(self, **changes):
        arguments = dict(path=str(self.capsule), root_identity=identity(self.capsule),
            parent_path=str(self.execution), parent_identity=identity(self.execution),
            sdk_path=str(self.sdk), sdk_identity=identity(self.sdk), context=self.context,
            archive_digest=self.archive_digest, manifest_digest=self.digest)
        arguments.update(changes)
        return Path(app.materialize_engine(**arguments))

    def reject(self, operation, *, empty=True):
        with self.assertRaises((app.publication.PublicationError, OSError, ValueError, tarfile.TarError)):
            operation()
        if empty:
            self.assertEqual(list(self.execution.iterdir()), [])

    def test_engine_cli_complete_projection_reuses_unchanged_sdk(self):
        def snapshot(root):
            return {str(path.relative_to(root)): (app.publication.stable_file(path.lstat()),
                    path.read_bytes() if path.is_file() else None) for path in [root, *root.rglob("*")]}
        before = snapshot(self.capsule), snapshot(self.sdk)
        result = subprocess.run([
            "/usr/bin/python3", "-I", "-S", str(SCRIPT_DIR / "linux-flutter-artifact.py"),
            "materialize-engine", "--context", json.dumps(self.context),
            "--root", str(self.capsule), "--root-identity", ":".join(map(str, identity(self.capsule))),
            "--parent", str(self.execution), "--parent-identity", ":".join(map(str, identity(self.execution))),
            "--sdk", str(self.sdk), "--sdk-identity", ":".join(map(str, identity(self.sdk))),
            "--archive-sha256", self.archive_digest, "--manifest-sha256", self.digest,
        ], check=True, timeout=15, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        source = Path(result.stdout.strip())
        self.assertEqual(source, self.execution / app.ENGINE_MATERIALIZED / "src")
        host = source / "out/host_release"
        for relative, data in self.payloads.items():
            path = host / relative
            self.assertEqual(path.read_bytes(), data)
            self.assertEqual((stat.S_IMODE(path.stat().st_mode), path.stat().st_nlink),
                             (0o500 if relative in app.ENGINE_ELFS else 0o400, 1))
            if relative in app.ENGINE_ELFS:
                subprocess.run([str(path)], check=True, timeout=5, stdin=subprocess.DEVNULL,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        alias = host / "dart-sdk"
        self.assertTrue(alias.is_symlink())
        self.assertEqual(os.readlink(alias), str(self.sdk / "bin/cache/dart-sdk"))
        self.assertEqual(identity(alias.resolve()), identity(self.sdk / "bin/cache/dart-sdk"))
        self.assertEqual((snapshot(self.capsule), snapshot(self.sdk)), before)
        self.assertEqual({str(path.relative_to(host)) for path in host.rglob("*") if not path.is_dir()},
                         set(self.payloads))
        self.assertFalse((host / app.ENGINE_MANIFEST).exists())
        self.assertFalse((host / "flutter_patched_sdk_product").exists())

    def test_engine_external_digest_context_and_identity_refuse(self):
        for changes in (dict(archive_digest="0" * 64), dict(manifest_digest="0" * 64),
                dict(context=dict(self.context, patch_sha256="0" * 64)),
                dict(root_identity=(1, 1)), dict(sdk_identity=(1, 1)),
                dict(parent_identity=(1, 1))):
            self.reject(lambda: self.materialize(**changes))

    def test_engine_capsule_links_special_objects_and_modes_refuse(self):
        path = self.capsule / app.ENGINE_ARCHIVE
        data = path.read_bytes()
        path.unlink()
        path.symlink_to(self.sdk / "bin/cache/dart-sdk/bin/snapshots/frontend_server_aot.dart.snapshot")
        self.reject(self.materialize)
        path.unlink()
        os.mkfifo(path, 0o400)
        self.reject(self.materialize)
        path.unlink()
        write(path, data)
        outside = self.case / "external-engine"
        os.link(path, outside)
        self.reject(self.materialize)
        outside.unlink()
        path.chmod(0o500)
        self.reject(self.materialize)
        path.chmod(0o400)
        self.capsule.chmod(0o755)
        self.reject(self.materialize)

    def test_engine_archive_contract_and_trailing_data_refuse(self):
        for change in (lambda member: setattr(member, "mode", 0o500),
                       lambda member: setattr(member, "uid", 1000),
                       lambda member: setattr(member, "mtime", 1),
                       lambda member: setattr(member, "name", "../escape"),
                       lambda member: setattr(member, "type", tarfile.SYMTYPE)):
            self.reseal(change=change)
            self.reject(self.materialize)
        for extra in ("gen_snapshot", "unrecorded"):
            self.reseal(extra=extra)
            self.reject(self.materialize)
        self.reseal(suffix=b"unrecorded trailing data")
        self.reject(self.materialize)

    def test_engine_missing_tools_or_shaders_refuse_even_with_stock_cache(self):
        stock = self.sdk / "bin/cache/artifacts/engine/linux-x64"
        stock.mkdir(parents=True, mode=0o700)
        shader_roles = frozenset(("shader_lib/flutter/runtime_effect.glsl",
                                  "shader_lib/impeller/types.glsl"))
        self.assertTrue(shader_roles.issubset(app.ENGINE_SHADERS))
        for name in sorted(app.ENGINE_ELFS | shader_roles):
            path = stock / name
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            write(path, ELF if name in app.ENGINE_ELFS else b"stock shader include\n")
            data = self.payloads.pop(name)
            self.reseal()
            self.reject(self.materialize)
            self.payloads[name] = data
        self.payloads["unrecorded"] = b"extra role"
        self.reseal()
        self.reject(self.materialize)

    def test_engine_sdk_drift_shadow_and_non_elf_refuse(self):
        path = self.sdk / "bin/cache/pkg/sky_engine/pubspec.yaml"
        original = path.read_bytes()
        path.unlink()
        write(path, b"name: different\n")
        self.reject(self.materialize)
        path.unlink()
        write(path, original)
        shadow = directory(self.sdk / "packages/sky_engine")
        self.reject(self.materialize)
        shadow.rmdir()
        self.payloads["gen_snapshot"] = b"not an ELF"
        self.reseal()
        self.reject(self.materialize)

    def test_engine_second_projection_and_locked_parent_preserve_state(self):
        descriptor = os.open(self.execution, os.O_RDONLY | os.O_DIRECTORY)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.reject(self.materialize)
        finally:
            os.close(descriptor)
        source = self.materialize()
        original = identity(source), (source / "out/host_release/gen_snapshot").read_bytes()
        self.reject(self.materialize, empty=False)
        self.assertEqual((identity(source), (source / "out/host_release/gen_snapshot").read_bytes()), original)
        self.assertEqual([path.name for path in self.execution.iterdir()], [app.ENGINE_MATERIALIZED])

    def test_engine_dart_identity_replacement_during_projection_refuses(self):
        original = app._verify_engine_sdk_roles
        calls = 0
        def replace(*arguments):
            nonlocal calls
            calls += 1
            if calls == 2:
                dart = self.sdk / "bin/cache/dart-sdk"
                dart.rename(self.case / "retained-dart")
                (dart / "bin/snapshots").mkdir(parents=True, mode=0o700)
                write(dart / "bin/snapshots/frontend_server_aot.dart.snapshot", ELF)
            return original(*arguments)
        app._verify_engine_sdk_roles = replace
        try:
            self.reject(self.materialize, empty=False)
        finally:
            app._verify_engine_sdk_roles = original
        self.assertEqual(calls, 2)
        self.assertTrue((self.execution / app.ENGINE_MATERIALIZED).is_dir())
        self.reject(self.materialize, empty=False)

    def test_complete_toolkit_owned_descriptors_are_not_inherited_authority(self):
        prefix = "bin/cache/pkg/sky_engine/"
        sky_files = sum(relative.startswith(prefix) for relative in self.values)
        for index in range(sky_files, 289):
            relative = prefix + f"lib/descriptor_case_{index}.dart"
            data = f"// owned SDK role {index}\n".encode()
            write(self.sdk / relative, data)
            self.values[relative] = data
            self.payloads[relative.replace(prefix, "gen/dart-pkg/sky_engine/")] = data
        self.reseal()
        original = app._verify_engine_sdk_roles
        inherited = set(os.listdir("/proc/self/fd"))
        calls = []
        def old_reentry(*arguments):
            calls.append(len(os.listdir("/proc/self/fd")))
            app.require_descriptor_capacity()
            return original(*arguments)
        old_parent = directory(self.case / "old-reentry-execution")
        app._verify_engine_sdk_roles = old_reentry
        try:
            with self.assertRaisesRegex(app.publication.PublicationError,
                                        "inherited descriptor inventory exceeds its reserve"):
                self.materialize(parent_path=str(old_parent), parent_identity=identity(old_parent))
        finally:
            app._verify_engine_sdk_roles = original
        self.assertEqual(len(calls), 2)
        self.assertLessEqual(calls[0], 64)
        self.assertGreater(calls[1], 64)
        self.assertEqual(set(os.listdir("/proc/self/fd")), inherited)
        source = self.materialize()
        host = source / "out/host_release"
        self.assertEqual(len(list((host / "gen/dart-pkg/sky_engine").rglob("*.dart"))),
                         sum(relative.startswith(prefix) and relative.endswith(".dart") for relative in self.values))
        self.assertEqual({relative: (host / relative).read_bytes() for relative in self.payloads}, self.payloads)
        self.assertEqual(os.readlink(host / "dart-sdk"), str(self.sdk / "bin/cache/dart-sdk"))
        self.assertEqual(set(os.listdir("/proc/self/fd")), inherited)
        print(f"FLUTTER_ENGINE_OWNED_FD_NATIVE_AB=pass sky_files=289 old=refused new=pass "
              f"entry_fds={calls[0]} owned_fds={calls[1]} entry_limit=64 cleanup=joined", file=sys.stderr)


def main():
    successful = False
    try:
        result = unittest.TextTestRunner(verbosity=2).run(
            unittest.defaultTestLoader.loadTestsFromTestCase(LinuxFlutterArtifactTests))
        successful = result.wasSuccessful() and result.testsRun == 23 and not result.skipped
        sdk_result = unittest.TextTestRunner(verbosity=2).run(
            unittest.defaultTestLoader.loadTestsFromTestCase(EngineSdkRoleTests))
        successful = successful and sdk_result.wasSuccessful() and sdk_result.testsRun == 6 and not sdk_result.skipped
        engine_result = unittest.TextTestRunner(verbosity=2).run(
            unittest.defaultTestLoader.loadTestsFromTestCase(EngineMaterializationTests))
        successful = successful and engine_result.wasSuccessful() and engine_result.testsRun == 9 and not engine_result.skipped
    finally:
        subprocess.run([
            "/usr/bin/python3", "-I", "-S", str(SCRIPT_DIR / "verify-private-tree-closure.py"),
            "--remove-private-root", str(WORKSPACE), "--expected-identity", ":".join(map(str, WORKSPACE_ID)),
        ], check=True)
    if not successful:
        raise SystemExit(1)
    print("FLUTTER_ENGINE_SDK_ROLES=pass cases=6 fixture=manifest-and-filesystem "
          "sky=exact frontend=exact mutation=refused links=refused writes=none cleanup=joined", file=sys.stderr)
    print("FLUTTER_ENGINE_MATERIALIZATION=pass cases=9 fixture=system-elf-and-toolkit "
          "inventory=closed sdk=reused mutation=refused fallback=refused cleanup=joined", file=sys.stderr)
    print("LINUX_FLUTTER_ARTIFACT=pass fixture=system-elf-and-assets cases=23 publication=noclobber admission=exact execution=guest-only cleanup=joined")


if __name__ == "__main__":
    main()
