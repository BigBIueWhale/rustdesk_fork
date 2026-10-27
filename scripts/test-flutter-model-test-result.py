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
        elif profile == "file-metadata":
            suites = ["file_metadata_probe_test.dart"]
            names = sorted(result.FILE_METADATA_TESTS)
        elif profile == "menu-button":
            suites = ["menu_button_test.dart"]
            names = sorted(result.MENU_BUTTON_TESTS)
        elif profile == "draggable-divider":
            suites = ["draggable_divider_test.dart"]
            names = sorted(result.DRAGGABLE_DIVIDER_TESTS)
        elif profile == "list-search":
            suites = ["list_search_action_listener_test.dart"]
            names = sorted(result.LIST_SEARCH_TESTS)
        elif profile == "peer-search":
            suites = ["peer_search_probe_test.dart"]
            names = sorted(result.PEER_SEARCH_TESTS)
        elif profile == "tab-selection":
            suites = sorted(result.TAB_SELECTION_SUITES)
            names = sorted(set().union(*result.TAB_SELECTION_SUITES.values()))
        elif profile == "status-refresh":
            suites = sorted(result.STATUS_REFRESH_SUITES)
            names = sorted(set().union(*result.STATUS_REFRESH_SUITES.values()))
        elif profile == "share-rdp":
            suites = ["share_rdp_change_lifecycle_test.dart"]
            names = sorted(result.SHARE_RDP_TESTS)
        elif profile == "password-fields":
            suites = ["password_text_field_test.dart"]
            names = sorted(result.PASSWORD_FIELD_TESTS)
        elif profile == "window-dispatch":
            suites = ["desktop_window_dispatch_test.dart"]
            names = sorted(result.WINDOW_DISPATCH_TESTS)
        elif profile == "audio-input":
            suites = sorted(result.AUDIO_INPUT_SUITES)
            names = sorted(set().union(*result.AUDIO_INPUT_SUITES.values()))
        elif profile == "custom-scale":
            suites = ["custom_scale_controls_test.dart"]
            names = sorted(result.CUSTOM_SCALE_TESTS)
        elif profile == "file-progress":
            suites = ["file_progress_test.dart"]
            names = sorted(result.FILE_PROGRESS_TESTS)
        elif profile == "peer-data":
            suites = sorted(result.PEER_DATA_SUITES)
            names = sorted(set().union(*result.PEER_DATA_SUITES.values()))
        elif profile == "file-navigation":
            suites = sorted(result.FILE_NAVIGATION_SUITES)
            names = sorted(set().union(*result.FILE_NAVIGATION_SUITES.values()))
        elif profile == "settings-navigation":
            suites = ["settings_navigation_probe_test.dart"]
            names = sorted(result.SETTINGS_NAVIGATION_TESTS)
        elif profile == "terminal-output":
            suites = sorted(result.TERMINAL_OUTPUT_TESTS)
            names = sorted(set().union(*result.TERMINAL_OUTPUT_TESTS.values()))
        elif profile == "connect-password":
            suites = ["connect_password_dialog_lifecycle_test.dart"]
            names = sorted(result.CREDENTIAL_DIALOG_TESTS[suites[0]])
        elif profile == "credential-dialog":
            suites = sorted(result.CREDENTIAL_DIALOG_TESTS)
            names = sorted(set().union(*result.CREDENTIAL_DIALOG_TESTS.values()))
        elif profile == "modifier-release":
            inventory = {
                "input_modifier_release_test.dart": result.MODIFIER_RELEASE_TESTS,
                "input_mouse_buttons_test.dart": result.PHYSICAL_MOUSE_TESTS,
                "trackpad_fling_test.dart": result.TRACKPAD_INPUT_TESTS,
                "input_side_buttons_test.dart": result.SIDE_BUTTON_TESTS,
                "relative_mouse_enable_probe_test.dart": result.RELATIVE_MOUSE_ENABLE_TESTS,
            }
            suites = sorted(inventory)
            names = sorted(set().union(*inventory.values()))
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
            suite_id = test_id % len(suites)
            if profile in ("credential-dialog", "terminal-output", "file-navigation", "modifier-release", "peer-data", "tab-selection", "status-refresh", "audio-input"):
                inventory = (result.AUDIO_INPUT_SUITES if profile == "audio-input"
                             else result.CREDENTIAL_DIALOG_TESTS if profile == "credential-dialog"
                             else result.STATUS_REFRESH_SUITES if profile == "status-refresh"
                             else result.TAB_SELECTION_SUITES if profile == "tab-selection"
                             else result.PEER_DATA_SUITES if profile == "peer-data"
                             else result.TERMINAL_OUTPUT_TESTS if profile == "terminal-output"
                             else inventory if profile == "modifier-release"
                             else result.FILE_NAVIGATION_SUITES)
                suite_id = next(i for i, suite in enumerate(suites)
                                if name in inventory[suite])
            events.append({
                "type": "testStart",
                "test": {"id": test_id, "suiteID": suite_id, "name": name},
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
        self.assertEqual(
            self.parse(self.events("frame-queue"), "frame-queue"),
            (1, len(result.FRAME_QUEUE_TESTS)),
        )
        self.assertEqual(self.parse(self.events("direct-address"), "direct-address"), (1, 19))
        self.assertEqual(self.parse(self.events("password-fields"), "password-fields"), (1, 4))
        self.assertEqual(self.parse(self.events("menu-button"), "menu-button"), (1, 6))
        self.assertEqual(self.parse(self.events("draggable-divider"), "draggable-divider"), (1, 14))
        self.assertEqual(self.parse(self.events("list-search"), "list-search"), (1, 6))
        self.assertEqual(self.parse(self.events("peer-search"), "peer-search"), (1, 6))
        self.assertEqual(self.parse(self.events("tab-selection"), "tab-selection"), (2, 31))
        self.assertEqual(self.parse(self.events("status-refresh"), "status-refresh"), (2, 16))
        self.assertEqual(self.parse(self.events("share-rdp"), "share-rdp"), (1, 4))
        self.assertEqual(self.parse(self.events("window-dispatch"), "window-dispatch"), (1, 8))
        self.assertEqual(self.parse(self.events("peer-data"), "peer-data"), (4, 82))
        self.assertEqual(self.parse(self.events("file-progress"), "file-progress"), (1, 43))
        self.assertEqual(self.parse(self.events("audio-input"), "audio-input"), (2, 17))
        self.assertEqual(self.parse(self.events("custom-scale"), "custom-scale"), (1, 35))
        self.assertEqual(self.parse(self.events("file-navigation"), "file-navigation"), (7, 125))
        self.assertEqual(self.parse(self.events("terminal-output"), "terminal-output"), (2, 37))
        self.assertEqual(self.parse(self.events("settings-navigation"), "settings-navigation"), (1, 40))
        self.assertEqual(self.parse(self.events("modifier-release"), "modifier-release"), (5, 112))
        self.assertEqual(self.parse(self.events("connect-password"), "connect-password"), (1, 7))
        self.assertEqual(self.parse(self.events("credential-dialog"), "credential-dialog"), (9, 98))
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
        for profile in ("frame-queue", "direct-address", "file-metadata", "password-fields", "share-rdp", "connect-password", "credential-dialog", "terminal-output", "settings-navigation", "window-dispatch", "menu-button", "draggable-divider", "list-search", "peer-search", "tab-selection", "status-refresh", "peer-data", "file-progress", "custom-scale", "audio-input", "file-navigation", "modifier-release"):
            events = self.events(profile)
            for edit in ("rename", "duplicate", "suite", "missing", "wrong-suite"):
                with self.subTest(profile=profile, edit=edit):
                    changed = copy.deepcopy(events)
                    started = [e["test"] for e in changed if e["type"] == "testStart"]
                    if edit == "rename":
                        started[0]["name"] = "unrelated passing test"
                    elif edit == "duplicate":
                        started[1]["name"] = started[0]["name"]
                    elif edit == "suite":
                        changed[1]["suite"]["path"] = "/test/unrelated_test.dart"
                    elif edit == "wrong-suite":
                        suite_count = sum(e["type"] == "suite" for e in changed)
                        started[0]["suiteID"] = (
                            (started[0]["suiteID"] + 1) % suite_count
                            if suite_count > 1 else 1
                        )
                    else:
                        del changed[-3:-1]
                    with self.assertRaises(result.ResultError):
                        self.parse(changed, profile)

    def test_failure_skip_and_incomplete_are_rejected(self):
        for profile in ("models", "frame-queue", "direct-address", "file-metadata", "password-fields", "share-rdp", "connect-password", "credential-dialog", "terminal-output", "settings-navigation", "window-dispatch", "menu-button", "draggable-divider", "list-search", "peer-search", "tab-selection", "status-refresh", "peer-data", "file-progress", "custom-scale", "audio-input", "file-navigation", "modifier-release"):
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
