#!/usr/bin/env python3
"""Exercise the result parser's inventory and finality, not product behavior."""

import copy
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest


sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location(
    "flutter_result", Path(__file__).with_name("verify-flutter-model-test-result.py")
)
result = importlib.util.module_from_spec(spec)
spec.loader.exec_module(result)


class ResultTests(unittest.TestCase):
    def events(self, profile):
        if profile == "models":
            suites = sorted(result.EXPECTED_SUITES)
            names = ["model {}".format(i) for i in range(result.model_test_count())]
        elif profile == "frame-queue":
            suites = ["latest_frame_queue_test.dart"]
            names = sorted(result.FRAME_QUEUE_TESTS)
        else:
            suites = ["address_validator_test.dart"]
            names = sorted(result.DIRECT_ADDRESS_TESTS)
        events = [{"type": "start"}]
        for suite_id, name in enumerate(suites):
            events.append({
                "type": "suite",
                "suite": {"id": suite_id, "path": "/test/" + name},
            })
        for test_id, name in enumerate(names):
            events.append({
                "type": "testStart",
                "test": {"id": test_id, "suiteID": test_id % len(suites), "name": name},
            })
            events.append({
                "type": "testDone", "testID": test_id,
                "result": "success", "skipped": False, "hidden": False,
            })
        events.append({"type": "done", "success": True})
        return events

    def parse(self, events, profile):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "test.json"
            path.write_text(
                "".join(json.dumps(event) + "\n" for event in events), encoding="utf-8"
            )
            return result.parse_result(path, profile)

    def test_complete_profiles(self):
        self.assertEqual(
            self.parse(self.events("models"), "models"),
            (len(result.EXPECTED_SUITES), result.model_test_count()),
        )
        self.assertEqual(self.parse(self.events("frame-queue"), "frame-queue"), (1, 24))
        self.assertEqual(self.parse(self.events("direct-address"), "direct-address"), (1, 12))
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "count"
            path.write_bytes(b"7\n")
            self.assertEqual(result.model_test_count(path), 7)
            for value in (
                b"", b"0\n", b"07\n", b"+7\n", b"-7\n", b"7\r\n", b"7",
                b"7\n8\n", b"word\n", b"10000\n", b"4097\n",
            ):
                with self.subTest(count=value):
                    path.write_bytes(value)
                    with self.assertRaises(result.ResultError):
                        result.model_test_count(path)
            path.unlink()
            target = Path(root) / "target"
            target.write_bytes(b"7\n")
            for kind in ("missing", "directory", "symlink", "hardlink", "fifo"):
                with self.subTest(count_file=kind):
                    if kind == "directory":
                        path.mkdir()
                    elif kind == "symlink":
                        path.symlink_to(target)
                    elif kind == "hardlink":
                        os.link(target, path)
                    elif kind == "fifo":
                        os.mkfifo(path)
                    with self.assertRaises((OSError, result.ResultError)):
                        result.model_test_count(path)
                    if kind == "directory":
                        path.rmdir()
                    elif kind != "missing":
                        path.unlink()

    def test_focused_inventory_is_exact(self):
        for profile in ("frame-queue", "direct-address"):
            events = self.events(profile)
            for edit in ("rename", "duplicate", "suite", "missing"):
                with self.subTest(profile=profile, edit=edit):
                    changed = copy.deepcopy(events)
                    if edit == "rename":
                        changed[2]["test"]["name"] = "unrelated passing test"
                    elif edit == "duplicate":
                        changed[4]["test"]["name"] = changed[2]["test"]["name"]
                    elif edit == "suite":
                        changed[1]["suite"]["path"] = "/test/unrelated_test.dart"
                    else:
                        del changed[-3:-1]
                    with self.assertRaises(result.ResultError):
                        self.parse(changed, profile)

    def test_failure_skip_and_incomplete_are_rejected(self):
        for profile in ("models", "frame-queue", "direct-address"):
            events = self.events(profile)
            done_index = next(
                i for i, event in enumerate(events) if event["type"] == "testDone"
            )
            for edit in ("failed", "skipped", "unfinished", "lost-test", "no-final", "late-event"):
                with self.subTest(profile=profile, edit=edit):
                    changed = copy.deepcopy(events)
                    if edit == "failed":
                        changed[done_index]["result"] = "failure"
                    elif edit == "skipped":
                        changed[done_index]["skipped"] = True
                    elif edit == "unfinished":
                        del changed[done_index]
                    elif edit == "lost-test":
                        del changed[-3:-1]
                    elif edit == "no-final":
                        changed.pop()
                    else:
                        changed.append({"type": "print", "message": "late"})
                    with self.assertRaises(result.ResultError):
                        self.parse(changed, profile)


if __name__ == "__main__":
    unittest.main()
