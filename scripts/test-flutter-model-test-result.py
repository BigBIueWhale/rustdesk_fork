#!/usr/bin/env python3
"""Exercise the result parser's inventory and finality, not product behavior."""

import copy
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import tracemalloc
import unittest
from unittest import mock


sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location(
    "flutter_result", Path(__file__).with_name("verify-flutter-model-test-result.py")
)
result = importlib.util.module_from_spec(spec)
spec.loader.exec_module(result)


SINGLE_PROFILE = None
if len(sys.argv) > 1 and sys.argv[1] in ("--screenshot-save", "--locales", "--draggable-divider", "--file-columns", "--trackpad-speed", "--menu-button", "--help-button", "--password-fields", "--file-progress", "--peer-search", "--audio-input", "--peer-data", "--combo-box", "--image-quality", "--desktop-theme", "--status-refresh", "--custom-scale"):
    SINGLE_PROFILE = sys.argv.pop(1)[2:]


class ResultTests(unittest.TestCase):
    def events(self, profile):
        if profile == "models":
            suites = sorted(result.MODEL_TESTS)
            model_cases = [(suite, name) for suite in suites
                           for name in sorted(result.MODEL_TESTS[suite])]
            names = [name for _, name in model_cases]
        elif profile == "frame-queue":
            suites = ["latest_frame_queue_test.dart"]
            names = sorted(result.FRAME_QUEUE_TESTS)
        elif profile == "file-metadata":
            suites = ["file_metadata_probe_test.dart"]
            names = sorted(result.FILE_METADATA_TESTS)
        elif profile == "hold-drag":
            suites = ["hold_tap_move_test.dart"]
            names = sorted(result.HOLD_DRAG_TESTS)
        elif profile == "locales":
            suites = ["locales_test.dart"]
            names = sorted(result.LOCALE_TESTS)
        elif profile == "path-labels":
            suites = ["start_ellipsis_text_test.dart"]
            names = sorted(result.PATH_LABEL_TESTS)
        elif profile == "setting-checkbox":
            suites = ["setting_checkbox_test.dart"]
            names = sorted(result.SETTING_CHECKBOX_TESTS)
        elif profile == "help-button":
            suites = sorted(result.HELP_BUTTON_SUITES)
            names = sorted(set().union(*result.HELP_BUTTON_SUITES.values()))
        elif profile == "menu-button":
            suites = sorted(result.MENU_BUTTON_SUITES)
            names = sorted(set().union(*result.MENU_BUTTON_SUITES.values()))
        elif profile == "draggable-divider":
            suites = ["draggable_divider_test.dart"]
            names = sorted(result.DRAGGABLE_DIVIDER_TESTS)
        elif profile == "list-search":
            suites = ["list_search_action_listener_test.dart"]
            names = sorted(result.LIST_SEARCH_TESTS)
        elif profile == "credential-badge":
            suites = sorted(result.CREDENTIAL_BADGE_SUITES)
            names = sorted(set().union(*result.CREDENTIAL_BADGE_SUITES.values()))
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
            suites = sorted(result.PASSWORD_FIELD_SUITES)
            names = sorted(set().union(*result.PASSWORD_FIELD_SUITES.values()))
        elif profile == "window-dispatch":
            suites = ["desktop_window_dispatch_test.dart"]
            names = sorted(result.WINDOW_DISPATCH_TESTS)
        elif profile == "audio-input":
            suites = sorted(result.AUDIO_INPUT_SUITES)
            names = sorted(set().union(*result.AUDIO_INPUT_SUITES.values()))
        elif profile == "reconnect":
            suites = sorted(result.RECONNECT_SUITES)
            names = sorted(set().union(*result.RECONNECT_SUITES.values()))
        elif profile == "combo-box":
            suites = sorted(result.COMBO_BOX_SUITES)
            names = sorted(set().union(*result.COMBO_BOX_SUITES.values()))
        elif profile == "image-quality":
            suites = sorted(result.IMAGE_QUALITY_SUITES)
            names = sorted(set().union(*result.IMAGE_QUALITY_SUITES.values()))
        elif profile == "custom-scale":
            suites = ["custom_scale_controls_test.dart"]
            names = sorted(result.CUSTOM_SCALE_TESTS)
        elif profile == "trackpad-speed":
            suites = sorted(result.TRACKPAD_SPEED_SUITES)
            names = sorted(set().union(*result.TRACKPAD_SPEED_SUITES.values()))
        elif profile == "virtual-mouse-buttons":
            suites = ["virtual_mouse_button_probe_test.dart"]
            names = sorted(result.VIRTUAL_MOUSE_BUTTONS_TESTS)
        elif profile == "virtual-joystick":
            suites = ["virtual_joystick_test.dart"]
            names = sorted(result.VIRTUAL_JOYSTICK_TESTS)
        elif profile == "floating-position":
            suites = ["draggable_position_test.dart"]
            names = sorted(result.FLOATING_POSITION_TESTS)
        elif profile == "screenshot-save":
            suites = ["screenshot_save_probe_test.dart"]
            names = sorted(result.SCREENSHOT_SAVE_TESTS)
        elif profile == "clipboard-keystrokes":
            suites = ["clipboard_keystrokes_probe_test.dart"]
            names = sorted(result.CLIPBOARD_KEYSTROKES_TESTS)
        elif profile == "file-columns":
            suites = ["file_columns_probe_test.dart"]
            names = sorted(result.FILE_COLUMNS_TESTS)
        elif profile == "file-search":
            suites = ["file_search_probe_test.dart"]
            names = sorted(result.FILE_SEARCH_TESTS)
        elif profile == "file-progress":
            suites = ["file_progress_test.dart"]
            names = sorted(result.FILE_PROGRESS_TESTS)
        elif profile == "peer-data":
            suites = sorted(result.PEER_DATA_SUITES)
            names = sorted(set().union(*result.PEER_DATA_SUITES.values()))
        elif profile == "file-navigation":
            suites = sorted(result.FILE_NAVIGATION_SUITES)
            names = sorted(set().union(*result.FILE_NAVIGATION_SUITES.values()))
        elif profile in {"settings-navigation", "desktop-theme"}:
            suites = ["settings_navigation_probe_test.dart"]
            names = sorted(result.SETTINGS_NAVIGATION_TESTS)
            if profile == "desktop-theme":
                names = [name for name in names
                         if name.startswith(("desktop home", "desktop theme", "recording directory", "settings "))]
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
            if profile == "models":
                suite_id = suites.index(model_cases[test_id][0])
            if profile in ("credential-dialog", "terminal-output", "file-navigation", "modifier-release", "peer-data", "tab-selection", "status-refresh", "audio-input", "trackpad-speed", "reconnect", "credential-badge", "menu-button", "help-button", "password-fields", "combo-box", "image-quality"):
                inventory = (result.AUDIO_INPUT_SUITES if profile == "audio-input"
                             else result.COMBO_BOX_SUITES if profile == "combo-box"
                             else result.IMAGE_QUALITY_SUITES if profile == "image-quality"
                             else result.TRACKPAD_SPEED_SUITES if profile == "trackpad-speed"
                             else result.CREDENTIAL_BADGE_SUITES if profile == "credential-badge"
                             else result.HELP_BUTTON_SUITES if profile == "help-button"
                             else result.MENU_BUTTON_SUITES if profile == "menu-button"
                             else result.PASSWORD_FIELD_SUITES if profile == "password-fields"
                             else result.RECONNECT_SUITES if profile == "reconnect"
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
        if SINGLE_PROFILE == "help-button":
            self.assertEqual(self.parse(self.events(SINGLE_PROFILE), SINGLE_PROFILE), (2, 14))
            return
        if SINGLE_PROFILE == "combo-box":
            self.assertEqual(self.parse(self.events(SINGLE_PROFILE), SINGLE_PROFILE), (2, 12))
            return
        if SINGLE_PROFILE == "image-quality":
            self.assertEqual(self.parse(self.events(SINGLE_PROFILE), SINGLE_PROFILE), (2, 33))
            return
        if SINGLE_PROFILE == "status-refresh":
            self.assertEqual(self.parse(self.events(SINGLE_PROFILE), SINGLE_PROFILE), (2, 23))
            return
        if SINGLE_PROFILE == "peer-data":
            self.assertEqual(self.parse(self.events(SINGLE_PROFILE), SINGLE_PROFILE), (7, 113))
            return
        if SINGLE_PROFILE == "audio-input":
            self.assertEqual(self.parse(self.events(SINGLE_PROFILE), SINGLE_PROFILE), (3, 40))
            return
        if SINGLE_PROFILE == "password-fields":
            self.assertEqual(self.parse(self.events(SINGLE_PROFILE), SINGLE_PROFILE), (3, 25))
            return
        if SINGLE_PROFILE == "menu-button":
            self.assertEqual(self.parse(self.events(SINGLE_PROFILE), SINGLE_PROFILE), (6, 53))
            return
        if SINGLE_PROFILE == "trackpad-speed":
            self.assertEqual(self.parse(self.events(SINGLE_PROFILE), SINGLE_PROFILE), (2, 16))
            return
        if SINGLE_PROFILE is not None:
            self.assertEqual(self.parse(self.events(SINGLE_PROFILE), SINGLE_PROFILE),
                             (1, {"locales": 10, "screenshot-save": 12,
                                  "draggable-divider": 22, "file-columns": 13,
                                  "file-progress": 43, "peer-search": 36,
                                  "desktop-theme": 30, "custom-scale": 42}[SINGLE_PROFILE]))
            return
        self.assertEqual(
            self.parse(self.events("models"), "models"),
            (len(result.MODEL_TESTS), result.model_test_count()),
        )
        self.assertEqual(
            self.parse(self.events("frame-queue"), "frame-queue"),
            (1, len(result.FRAME_QUEUE_TESTS)),
        )
        self.assertEqual(self.parse(self.events("direct-address"), "direct-address"), (1, 33))
        self.assertEqual(self.parse(self.events("password-fields"), "password-fields"), (3, 25))
        self.assertEqual(self.parse(self.events("menu-button"), "menu-button"), (6, 53))
        self.assertEqual(self.parse(self.events("hold-drag"), "hold-drag"), (1, 17))
        self.assertEqual(self.parse(self.events("locales"), "locales"), (1, 10))
        self.assertEqual(self.parse(self.events("path-labels"), "path-labels"), (1, 16))
        self.assertEqual(self.parse(self.events("setting-checkbox"), "setting-checkbox"), (1, 8))
        self.assertEqual(self.parse(self.events("draggable-divider"), "draggable-divider"), (1, 22))
        self.assertEqual(self.parse(self.events("list-search"), "list-search"), (1, 11))
        self.assertEqual(self.parse(self.events("credential-badge"), "credential-badge"), (2, 14))
        self.assertEqual(self.parse(self.events("peer-search"), "peer-search"), (1, 36))
        self.assertEqual(self.parse(self.events("tab-selection"), "tab-selection"), (2, 31))
        self.assertEqual(self.parse(self.events("status-refresh"), "status-refresh"), (2, 23))
        self.assertEqual(self.parse(self.events("share-rdp"), "share-rdp"), (1, 4))
        self.assertEqual(self.parse(self.events("window-dispatch"), "window-dispatch"), (1, 8))
        self.assertEqual(self.parse(self.events("peer-data"), "peer-data"), (7, 113))
        self.assertEqual(self.parse(self.events("file-progress"), "file-progress"), (1, 43))
        self.assertEqual(self.parse(self.events("audio-input"), "audio-input"), (3, 40))
        self.assertEqual(self.parse(self.events("reconnect"), "reconnect"), (2, 11))
        self.assertEqual(self.parse(self.events("custom-scale"), "custom-scale"), (1, 42))
        self.assertEqual(self.parse(self.events("trackpad-speed"), "trackpad-speed"), (2, 16))
        self.assertEqual(self.parse(self.events("virtual-mouse-buttons"), "virtual-mouse-buttons"), (1, 17))
        self.assertEqual(self.parse(self.events("virtual-joystick"), "virtual-joystick"), (1, 8))
        self.assertEqual(self.parse(self.events("floating-position"), "floating-position"), (1, 16))
        self.assertEqual(self.parse(self.events("clipboard-keystrokes"), "clipboard-keystrokes"), (1, 12))
        self.assertEqual(self.parse(self.events("file-search"), "file-search"), (1, 12))
        self.assertEqual(self.parse(self.events("file-navigation"), "file-navigation"), (7, 125))
        self.assertEqual(self.parse(self.events("terminal-output"), "terminal-output"), (2, 37))
        self.assertEqual(self.parse(self.events("settings-navigation"), "settings-navigation"), (1, 60))
        self.assertEqual(self.parse(self.events("desktop-theme"), "desktop-theme"), (1, 30))
        self.assertEqual(self.parse(self.events("modifier-release"), "modifier-release"), (5, 112))
        self.assertEqual(self.parse(self.events("connect-password"), "connect-password"), (1, 14))
        self.assertEqual(self.parse(self.events("credential-dialog"), "credential-dialog"), (10, 117))
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

    def test_inventory_is_exact(self):
        for profile in ((SINGLE_PROFILE,) if SINGLE_PROFILE is not None else ("models", "frame-queue", "direct-address", "file-metadata", "password-fields", "share-rdp", "connect-password", "credential-dialog", "terminal-output", "settings-navigation", "desktop-theme", "window-dispatch", "menu-button", "help-button", "hold-drag", "locales", "path-labels", "setting-checkbox", "draggable-divider", "list-search", "credential-badge", "peer-search", "tab-selection", "status-refresh", "peer-data", "file-progress", "custom-scale", "trackpad-speed", "floating-position", "virtual-joystick", "virtual-mouse-buttons", "clipboard-keystrokes", "file-search", "audio-input", "reconnect", "file-navigation", "modifier-release", "combo-box", "image-quality")):
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

    def test_failure_skip_incomplete_and_changed_inputs_are_rejected(self):
        for profile in ((SINGLE_PROFILE,) if SINGLE_PROFILE is not None else ("models", "frame-queue", "direct-address", "file-metadata", "password-fields", "share-rdp", "connect-password", "credential-dialog", "terminal-output", "settings-navigation", "desktop-theme", "window-dispatch", "menu-button", "help-button", "hold-drag", "locales", "path-labels", "setting-checkbox", "draggable-divider", "list-search", "credential-badge", "peer-search", "tab-selection", "status-refresh", "peer-data", "file-progress", "custom-scale", "trackpad-speed", "floating-position", "virtual-joystick", "virtual-mouse-buttons", "clipboard-keystrokes", "file-search", "audio-input", "reconnect", "file-navigation", "modifier-release", "combo-box", "image-quality")):
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

        valid = "".join(json.dumps(event) + "\n"
                        for event in self.events("direct-address")).encode()
        for kind in ("missing", "directory", "symlink", "hardlink", "fifo", "oversized"):
            with self.subTest(result_file=kind), tempfile.TemporaryDirectory() as root:
                path = Path(root) / "test.json"
                target = Path(root) / "target.json"
                target.write_bytes(valid)
                if kind == "directory":
                    path.mkdir()
                elif kind == "symlink":
                    path.symlink_to(target)
                elif kind == "hardlink":
                    os.link(target, path)
                elif kind == "fifo":
                    os.mkfifo(path)
                elif kind == "oversized":
                    with path.open("wb") as stream:
                        stream.truncate(result.MAXIMUM_BYTES + 1)
                with self.assertRaises((OSError, result.ResultError)):
                    result.parse_result(path, "direct-address")
                self.assertEqual(target.read_bytes(), valid)

        for change in ("replacement", "growth", "truncation", "hardlink", "rewrite"):
            with self.subTest(result_change=change), tempfile.TemporaryDirectory() as root:
                path = Path(root) / "test.json"
                original = valid + b"invalid trailing event\n" if change == "replacement" else valid
                path.write_bytes(original)
                initial = path.stat()
                target = Path(root) / "replacement.json"
                target.write_bytes(valid)
                observed = []

                def after_metadata(read_metadata):
                    def read(*args, **kwargs):
                        metadata = read_metadata(*args, **kwargs)
                        if not observed and (metadata.st_dev, metadata.st_ino) == (
                                initial.st_dev, initial.st_ino):
                            observed.append(True)
                            if change == "replacement":
                                path.rename(Path(root) / "original.json")
                                path.symlink_to(target)
                            elif change == "growth":
                                path.write_bytes(b'{"type":"print","message":"added"}\n' + valid)
                            elif change == "truncation":
                                path.write_bytes(valid[:-1])
                            elif change == "hardlink":
                                os.link(path, Path(root) / "second-link.json")
                            else:
                                path.write_bytes(valid)
                                os.utime(path, ns=(initial.st_atime_ns,
                                                  initial.st_mtime_ns + 1_000_000_000))
                        return metadata
                    return read

                with mock.patch.object(result.os, "lstat", side_effect=after_metadata(os.lstat)), \
                        mock.patch.object(result.os, "fstat", side_effect=after_metadata(os.fstat)):
                    with self.assertRaises((OSError, result.ResultError)):
                        result.parse_result(path, "direct-address")
                self.assertEqual(observed, [True])
                self.assertEqual(target.read_bytes(), valid)
                if change == "replacement":
                    self.assertEqual((Path(root) / "original.json").read_bytes(), original)

        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "test.json"
            path.write_bytes(b" " * (6 * result.MAXIMUM_LINE_BYTES) + b"\n")
            tracemalloc.start()
            try:
                with self.assertRaises(result.ResultError):
                    result.parse_result(path, "direct-address")
                _, peak = tracemalloc.get_traced_memory()
            finally:
                tracemalloc.stop()
            self.assertLess(peak, 4 * result.MAXIMUM_LINE_BYTES,
                            "an oversized line was allocated before refusal")


if __name__ == "__main__":
    unittest.main()
