#!/usr/bin/env python3
"""Focused metadata-selection regressions; execute only inside the verifier VM."""

import copy
import json
from pathlib import Path
import runpy
import unittest


selector = runpy.run_path(str(Path(__file__).with_name("select-hbb-common-test-artifact.py")))
select_artifact = selector["select_artifact"]
EXECUTABLE = "/cargo-target/debug/deps/hbb_common-0123456789abcdef"
ARTIFACT = {
    "reason": "compiler-artifact",
    "manifest_path": "/source/libs/hbb_common/Cargo.toml",
    "target": {"name": "hbb_common", "kind": ["lib"],
               "src_path": "/source/libs/hbb_common/src/lib.rs"},
    "profile": {"test": True},
    "executable": EXECUTABLE,
}
FINISHED = {"reason": "build-finished", "success": True}


def encode(*messages):
    return b"\n".join(json.dumps(message).encode() for message in messages)


class ArtifactSelectionTests(unittest.TestCase):
    def test_prs_derivation_selects_the_shared_library_integration_target(self):
        artifact = copy.deepcopy(ARTIFACT)
        artifact["target"] = {"name": "prs_derivation", "kind": ["test"],
                              "src_path": "/source/libs/hbb_common/tests/prs_derivation.rs"}
        artifact["executable"] = "/cargo-target/debug/deps/prs_derivation-0123456789abcdef"
        self.assertEqual(select_artifact(encode(artifact, FINISHED), "prs_derivation"),
                         artifact["executable"])
        for field in ("manifest_path", "target", "profile", "executable"):
            value = "/source/libs/pake/Cargo.toml" if field == "manifest_path" else (
                {"test": False} if field == "profile" else ARTIFACT[field])
            with self.subTest(field=field), self.assertRaises(ValueError):
                select_artifact(encode(dict(artifact, **{field: value}), FINISHED), "prs_derivation")

    def test_nfc_conformance_uses_the_exact_pake_integration_target(self):
        artifact = copy.deepcopy(ARTIFACT)
        artifact["manifest_path"] = "/source/libs/pake/Cargo.toml"
        artifact["target"] = {"name": "nfc_conformance", "kind": ["test"],
                              "src_path": "/source/libs/pake/tests/nfc_conformance.rs"}
        artifact["executable"] = "/cargo-target/debug/deps/nfc_conformance-0123456789abcdef"
        self.assertEqual(select_artifact(encode(artifact, FINISHED), "nfc_conformance"),
                         artifact["executable"])
        for field in ("manifest_path", "target", "profile", "executable"):
            value = {"test": False} if field == "profile" else ARTIFACT[field]
            with self.subTest(field=field), self.assertRaises(ValueError):
                select_artifact(encode(dict(artifact, **{field: value}), FINISHED), "nfc_conformance")

    def test_optimized_artifact_requires_compiler_reported_settings(self):
        profile = {"test": True, "opt_level": "3", "debug_assertions": False,
                   "overflow_checks": False}
        artifact = dict(ARTIFACT, profile=profile)
        self.assertEqual(select_artifact(encode(artifact, FINISHED), optimized=True), EXECUTABLE)
        for field, values in [("opt_level", [None, "0", "2", 3]),
                              ("debug_assertions", [None, True, 0, "false"]),
                              ("overflow_checks", [None, True, 0, "false"])]:
            for value in values:
                candidate = dict(profile, **{field: value})
                if value is None:
                    del candidate[field]
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    select_artifact(encode(dict(artifact, profile=candidate), FINISHED),
                                    optimized=True)
        self.assertEqual(select_artifact(encode(ARTIFACT, FINISHED)), EXECUTABLE)

    def test_key_transition_target_is_separate_from_handshake(self):
        artifact = copy.deepcopy(ARTIFACT)
        artifact["manifest_path"] = "/source/libs/cpace_it/Cargo.toml"
        artifact["target"] = {"name": "key_transition", "kind": ["test"],
                              "src_path": "/source/libs/cpace_it/tests/key_transition.rs"}
        artifact["executable"] = "/cargo-target/debug/deps/key_transition-0123456789abcdef"
        self.assertEqual(select_artifact(encode(artifact, FINISHED), "key_transition"),
                         artifact["executable"])
        for field, value in [
                ("manifest_path", "/source/libs/hbb_common/Cargo.toml"),
                ("target", dict(artifact["target"], name="handshake")),
                ("target", dict(artifact["target"], src_path="/source/libs/cpace_it/tests/handshake.rs")),
                ("target", dict(artifact["target"], kind=["lib"])),
                ("profile", {"test": False}), ("executable", EXECUTABLE)]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                select_artifact(encode(dict(artifact, **{field: value}), FINISHED), "key_transition")
        with self.assertRaises(ValueError):
            select_artifact(encode(artifact, FINISHED), "cpace_it")

    def test_protobuf_parser_package_is_exact(self):
        for package in ("protobuf_it", "protobuf"):
            artifact = copy.deepcopy(ARTIFACT)
            artifact["manifest_path"] = f"/source/libs/{package}/Cargo.toml"
            artifact["target"] = {"name": package, "kind": ["lib"],
                                  "src_path": f"/source/libs/{package}/src/lib.rs"}
            artifact["executable"] = f"/cargo-target/debug/deps/{package}-0123456789abcdef"
            self.assertEqual(select_artifact(encode(artifact, FINISHED), package),
                             artifact["executable"])
            for field in ("manifest_path", "target", "profile", "executable"):
                value = {"test": False} if field == "profile" else ARTIFACT[field]
                with self.subTest(package=package, field=field), self.assertRaises(ValueError):
                    select_artifact(encode(dict(artifact, **{field: value}), FINISHED), package)
            for source in ("/cargo-target/fuse-test-source", "/vendor"):
                with self.subTest(package=package, source=source), self.assertRaises(ValueError):
                    select_artifact(encode(artifact, FINISHED), package, source)
            with self.assertRaises(ValueError):
                select_artifact(encode(dict(artifact,
                    manifest_path="/vendor/protobuf-3.7.2/Cargo.toml"), FINISHED), package)

    def test_exact_artifact_with_unrelated_output(self):
        dependency = dict(ARTIFACT, manifest_path="/vendor/other/Cargo.toml")
        output = b"procedural macro diagnostic\n" + encode(dependency, ARTIFACT, FINISHED)
        self.assertEqual(select_artifact(output), EXECUTABLE)

    def test_missing_or_duplicate_artifact(self):
        for messages in [(FINISHED,), (ARTIFACT, ARTIFACT, FINISHED)]:
            with self.subTest(messages=messages), self.assertRaises(ValueError):
                select_artifact(encode(*messages))

    def test_exact_package_target_and_test_profile_are_required(self):
        for field, value in [("manifest_path", "/source/other/Cargo.toml"),
                             ("target", dict(ARTIFACT["target"], kind=["bin"])),
                             ("target", dict(ARTIFACT["target"], name="other")),
                             ("target", dict(ARTIFACT["target"], src_path="/source/other.rs")),
                             ("profile", {"test": False}), ("profile", {"test": 1})]:
            candidate = copy.deepcopy(ARTIFACT)
            candidate[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                select_artifact(encode(candidate, FINISHED))

    def test_no_filename_or_path_fallback(self):
        for path in [None, "/tmp/hbb_common-0123456789abcdef",
                     "/cargo-target/debug/deps/../hbb_common-0123456789abcdef",
                     "/cargo-target/debug/deps/other-0123456789abcdef"]:
            candidate = dict(ARTIFACT, executable=path, filenames=[EXECUTABLE])
            with self.subTest(path=path), self.assertRaises(ValueError):
                select_artifact(encode(candidate, FINISHED))

    def test_successful_completion_is_required_exactly_once(self):
        for tail in [(), ({"reason": "build-finished", "success": False},),
                     (FINISHED, FINISHED)]:
            with self.subTest(tail=tail), self.assertRaises(ValueError):
                select_artifact(encode(ARTIFACT, *tail))

    def test_malformed_and_oversized_output(self):
        for output in [b"{malformed", b"x" * (selector["MAX_OUTPUT"] + 1)]:
            with self.subTest(size=len(output)), self.assertRaises(ValueError):
                select_artifact(output)

    def test_clipboard_package_and_private_source_are_exact(self):
        root = "/cargo-target/fuse-test-source"
        artifact = copy.deepcopy(ARTIFACT)
        artifact["manifest_path"] = root + "/libs/clipboard/Cargo.toml"
        artifact["target"]["name"] = "clipboard"
        artifact["target"]["src_path"] = root + "/libs/clipboard/src/lib.rs"
        artifact["executable"] = "/cargo-target/debug/deps/clipboard-0123456789abcdef"
        self.assertEqual(select_artifact(encode(artifact, FINISHED), "clipboard", root),
                         artifact["executable"])
        for output, package, source in [
                (encode(ARTIFACT, FINISHED), "clipboard", root),
                (encode(artifact, FINISHED), "hbb_common", root),
                (encode(artifact, FINISHED), "clipboard", "/source"),
                (encode(artifact, FINISHED), "other", root),
                (encode(artifact, FINISHED), "clipboard", "/tmp/source")]:
            with self.subTest(package=package, source=source), self.assertRaises(ValueError):
                select_artifact(output, package, source)

    def test_cpace_handshake_target_is_exact(self):
        artifact = copy.deepcopy(ARTIFACT)
        artifact["manifest_path"] = "/source/libs/cpace_it/Cargo.toml"
        artifact["target"] = {"name": "handshake", "kind": ["test"],
                              "src_path": "/source/libs/cpace_it/tests/handshake.rs"}
        artifact["executable"] = "/cargo-target/debug/deps/handshake-0123456789abcdef"
        self.assertEqual(select_artifact(encode(artifact, FINISHED), "cpace_it"),
                         artifact["executable"])
        for field, value in [
                ("manifest_path", "/source/libs/hbb_common/Cargo.toml"),
                ("target", dict(artifact["target"], kind=["lib"])),
                ("target", dict(artifact["target"], name="other")),
                ("target", dict(artifact["target"], src_path="/source/other.rs")),
                ("profile", {"test": False}), ("profile", {"test": 1}),
                ("executable", EXECUTABLE), ("executable", "/tmp/handshake-0123456789abcdef")]:
            candidate = dict(artifact, **{field: value})
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                select_artifact(encode(candidate, FINISHED), "cpace_it")
        for output in (encode(FINISHED), encode(artifact, artifact, FINISHED),
                       encode(artifact), encode(artifact, FINISHED, FINISHED)):
            with self.assertRaises(ValueError):
                select_artifact(output, "cpace_it")
        with self.assertRaises(ValueError):
            select_artifact(encode(artifact, FINISHED), "cpace_it", "/cargo-target/fuse-test-source")

    def test_descriptor_lifetime_target_is_exact(self):
        artifact = copy.deepcopy(ARTIFACT)
        artifact["target"] = {"name": "descriptor_lifetime", "kind": ["test"],
                              "src_path": "/source/libs/hbb_common/tests/descriptor_lifetime.rs"}
        artifact["executable"] = "/cargo-target/debug/deps/descriptor_lifetime-0123456789abcdef"
        self.assertEqual(select_artifact(encode(artifact, FINISHED), "descriptor_lifetime"),
                         artifact["executable"])
        for field, value in [("manifest_path", "/source/Cargo.toml"),
                             ("target", dict(artifact["target"], kind=["lib"])),
                             ("target", dict(artifact["target"], src_path="/source/other.rs")),
                             ("profile", {"test": False}), ("profile", {"test": 1}),
                             ("executable", EXECUTABLE)]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                select_artifact(encode(dict(artifact, **{field: value}), FINISHED), "descriptor_lifetime")
        for output in (encode(FINISHED), encode(artifact, artifact, FINISHED),
                       encode(artifact), encode(artifact, FINISHED, FINISHED)):
            with self.assertRaises(ValueError):
                select_artifact(output, "descriptor_lifetime")

    def test_surface_policy_target_is_exact(self):
        artifact = copy.deepcopy(ARTIFACT)
        artifact["manifest_path"] = "/source/libs/surface_it/Cargo.toml"
        artifact["target"] = {"name": "surface", "kind": ["test"],
                              "src_path": "/source/libs/surface_it/tests/surface.rs"}
        artifact["executable"] = "/cargo-target/debug/deps/surface-0123456789abcdef"
        self.assertEqual(select_artifact(encode(artifact, FINISHED), "surface_it"),
                         artifact["executable"])
        for field in ("manifest_path", "target", "profile", "executable"):
            value = {"test": False} if field == "profile" else ARTIFACT[field]
            candidate = dict(artifact, **{field: value})
            with self.subTest(field=field), self.assertRaises(ValueError):
                select_artifact(encode(candidate, FINISHED), "surface_it")
        for output in (encode(FINISHED), encode(artifact, artifact, FINISHED),
                       encode(artifact), encode(artifact, FINISHED, FINISHED)):
            with self.assertRaises(ValueError):
                select_artifact(output, "surface_it")
        with self.assertRaises(ValueError):
            select_artifact(encode(artifact, FINISHED), "surface_it", "/cargo-target/fuse-test-source")

    def test_probe_example_target_is_exact(self):
        artifact = copy.deepcopy(ARTIFACT)
        artifact["target"] = {"name": "probe_client", "kind": ["example"],
                              "src_path": "/source/examples/probe_client.rs"}
        artifact["executable"] = "/cargo-target/debug/examples/probe_client-0123456789abcdef"
        for source in ("/source/examples/probe_client.rs",
                       "/source/libs/hbb_common/../../examples/probe_client.rs"):
            artifact["target"]["src_path"] = source
            self.assertEqual(select_artifact(encode(artifact, FINISHED), "probe_client"),
                             artifact["executable"])
        for field, value in [
                ("manifest_path", "/source/Cargo.toml"),
                ("target", dict(artifact["target"], kind=["bin"])),
                ("target", dict(artifact["target"], name="other")),
                ("target", dict(artifact["target"], src_path="/source/other.rs")),
                ("profile", {"test": False}), ("profile", {"test": 1}),
                ("executable", EXECUTABLE),
                ("executable", "/cargo-target/debug/examples/probe_client")]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                select_artifact(encode(dict(artifact, **{field: value}), FINISHED), "probe_client")
        for output in (encode(FINISHED), encode(artifact, artifact, FINISHED),
                       encode(artifact), encode(artifact, FINISHED, FINISHED)):
            with self.assertRaises(ValueError):
                select_artifact(output, "probe_client")
        with self.assertRaises(ValueError):
            select_artifact(encode(artifact, FINISHED), "probe_client", "/cargo-target/fuse-test-source")


if __name__ == "__main__":
    unittest.main()
