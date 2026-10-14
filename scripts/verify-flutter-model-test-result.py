#!/usr/bin/env python3
"""Validate bounded Flutter JSON results for the model checkpoint or focused shards."""

import argparse
import json
import os
import re
import stat
import sys


EXPECTED_SUITES = {
    "android_permission_request_coordinator_test.dart",
    "blockable_overlay_test.dart",
    "custom_cursor_registry_test.dart",
    "desktop_tab_retirement_test.dart",
    "desktop_texture_lifecycle_test.dart",
    "display_selection_queue_test.dart",
    "file_command_session_ownership_test.dart",
    "file_dialog_event_loop_test.dart",
    "global_event_dispatcher_test.dart",
    "latest_frame_queue_test.dart",
    "mobile_file_session_lifecycle_test.dart",
    "mobile_session_start_queue_test.dart",
    "owned_image_paint_test.dart",
    "permanent_password_dialog_lifecycle_test.dart",
    "presentation_recovery_test.dart",
    "reconnect_schedule_authority_test.dart",
    "remote_key_routing_test.dart",
    "rgba_publication_order_test.dart",
    "server_status_refresh_loop_test.dart",
    "server_model_test.dart",
    "session_event_queue_test.dart",
    "session_stream_finality_test.dart",
    "start_ellipsis_text_test.dart",
    "terminal_output_decoder_test.dart",
    "terminal_model_lifecycle_test.dart",
}
FRAME_QUEUE_TESTS = {
    "retains one running frame and only the latest successor per display",
    "different displays drain independently",
    "nonwaiting pool bounds independent displays across replacement",
    "nonwaiting pool retains the same-display latest successor",
    "bounded parallel lane overtakes one stalled presentation",
    "parallel recovery remains inside the total drain bound",
    "parallel limit cannot exceed the total drain bound",
    "shared drain pool survives queue replacement without minting capacity",
    "shared drain pool retains only the latest waiting frame",
    "shared drain pool starts live waiting lanes in FIFO order",
    "shared drain pool refuses excess waiting lanes visibly",
    "pool-waiting displays remain inside the queue-wide key bound",
    "running and waiting displays share one distinct-key budget",
    "detached and waiting displays share one distinct-key budget",
    "parallel failure retires its peer and retained successor",
    "observed submissions retain only running and latest without futures",
    "observed failure is visible and retires its exact queue",
    "a failed frame retires its retained successor",
    "owner mismatch and display overflow refuse frames before invocation",
    "exact retirement releases retained frames and cannot block replacement",
    "recovery bypasses a detached asynchronous presentation",
    "a detached failure cannot retire its recovered generation",
    "recovery fails visibly at the per-display drain bound",
    "detached displays remain inside the queue-wide key bound",
}
DIRECT_ADDRESS_TESTS = {
    "direct-address normalization (R-G2/R-SV5) trims only surrounding whitespace",
    "direct-address normalization (R-G2/R-SV5) preserves malformed interior whitespace for fail-closed validation",
    "direct-address normalization (R-G2/R-SV5) controller exposes address semantics without rewriting the target",
    "initial address restoration restores untouched text after a selection-only change",
    "initial address restoration a typed target wins over a delayed saved address",
    "initial address restoration cleared text stays empty when the saved address arrives",
    "initial address restoration existing text or an earlier edit prevents the lookup",
    "initial address restoration one controller admits only one initial lookup",
    "initial address restoration disposal retires a pending lookup and prevents another read",
    "initial address restoration lookup errors propagate and retire the initial attempt",
    "isDirectAddress (R-G2/R-SV10 bare-ID rejection) rejects a bare numeric RustDesk ID",
    "isDirectAddress (R-G2/R-SV10 bare-ID rejection) rejects inherited relay-route syntax on otherwise direct targets",
    "isDirectAddress (R-G2/R-SV10 bare-ID rejection) accepts an IPv4, with or without a port",
    "isDirectAddress (R-G2/R-SV10 bare-ID rejection) accepts domain:port, rejects a bare hostname",
    "isDirectAddress (R-G2/R-SV10 bare-ID rejection) rejects IPv6 direct targets",
    "isDirectAddress (R-G2/R-SV10 bare-ID rejection) requires supplied ports in the nonzero 16-bit range",
    "isDirectAddress (R-G2/R-SV10 bare-ID rejection) rejects empty / whitespace / junk",
    "shared Rust/Dart direct-address vectors",
    "hostname label and complete name bounds",
}
MAXIMUM_BYTES = 8 * 1024 * 1024
PASSWORD_FIELD_TESTS = {
    "password keyboard policy survives reveal on android",
    "password keyboard policy survives reveal on iOS",
    "ordinary obscured field is a keyboard learning control",
    "password field retains focused obscured semantics",
}
TERMINAL_OUTPUT_TESTS = {
    "terminal UTF-8 survives every two-packet split",
    "terminal UTF-8 emits complete text while retaining only a partial tail",
    "terminal invalid UTF-8 has the same replacement policy across packets",
    "terminal end of stream flushes an incomplete character exactly once",
    "terminal decoders keep concurrent terminal byte streams separate",
    "replacement terminal stream cannot complete its predecessor tail",
}
CREDENTIAL_DIALOG_TESTS = {
    "connect_password_dialog_lifecycle_test.dart": {
        "connect prompt is present before its saved preference resolves",
        "retired connect preference cannot change its replacement",
        "explicit remember choice wins over delayed saved preference",
        "connect submit admits one accepted replacement attempt",
        "rejected connect submission retains its prompt for retry",
        "cancel retires a pending connect preference and callbacks",
        "failed saved preference needs an explicit remember decision",
    },
    "permanent_password_dialog_lifecycle_test.dart": {
        "one submit owns every action until durable completion",
        "failed mutation reopens the same dialog owner",
        "retired dialog ignores its outstanding completion",
        "replacement dialog takes over the same pending mutation",
    },
    "password_text_field_test.dart": PASSWORD_FIELD_TESTS,
    "password_field_semantics_test.dart": {
        "obscured dialog field exposes enabled focused semantics",
    },
    "dialog_close_ownership_test.dart": {
        "screenshot choice retires only its entry and dispatches once",
        "superseded screenshot callbacks cannot act before unmount",
        "dismissed screenshot callbacks preserve a later dialog",
        "unbound message cannot close the active desktop tab",
        "image wait cancel retires its entry and dispatches once",
        "superseded image wait cancel cannot act before unmount",
        "dismissed image wait cancel cannot act before unmount",
        "message submit retires only its entry and dispatches once",
        "retired message submit cannot act before unmount",
        "retired message cancel and close cannot dismiss a replacement",
        "message reconnect countdown never submits an action",
        "retired message reconnect cannot act before unmount",
        "message reconnect retires its entry and dispatches once",
        "dialog close grants only its exact current entry",
        "loading cancel retires only its own entry and dispatches once",
        "superseded loading cancel has no authority before unmount",
        "superseded connect callbacks cannot act before unmount",
    },
    "blockable_overlay_test.dart": {
        "mobile close precedes a held system UI reply",
        "failed system UI reply cannot close a replacement route",
        "blockable overlay keeps one mounted owner and rebuilds its underlying route",
        "middle blocker owns the tap before revealing the route",
        "one explicit dialog tag owns one disposable overlay entry",
    },
    "file_command_session_ownership_test.dart": {
        "native file-job allocation failures cannot dispatch fallback IDs",
        "retired send continuation cannot target replacement session",
        "send operation snapshots entries and directory arguments at admission",
        "rename snapshots directory policy before the dialog await",
        "create waits for its exact result and exposes an exact error",
        "remote empty-directory deletion uses a fresh exact result owner",
        "directory-link deletion is one leaf command",
        "deleted-subtree matching is component exact for both path styles",
        "job result requires exact session action and file before completion",
        "retirement completes an exact pending job result with an error",
        "exact job error is caller-visible instead of successful completion",
        "delete state changes only after exact result and dispatch finality",
        "invalid or unowned cancel IDs never reach the native request surface",
        "dispatch failure wins over an early matching success response",
        "timed-out late result remains owned until dispatch settles",
        "load-last-job cannot resume after its session is replaced",
    },
}
MAXIMUM_EVENTS = 16_384
MAXIMUM_LINE_BYTES = 1024 * 1024


class ResultError(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise ResultError(message)


def model_test_count(path=None):
    if path is None:
        path = os.path.join(os.path.dirname(__file__), "flutter-model-test-count.txt")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        require(stat.S_ISREG(metadata.st_mode), "model test count is not one regular file")
        require(metadata.st_nlink == 1, "model test count has multiple links")
        require(metadata.st_size <= 5, "model test count exceeds its byte bound")
        value = stream.read(6)
    require(re.fullmatch(rb"[1-9][0-9]{0,3}\n", value), "model test count is malformed")
    count = int(value)
    require(count <= 4096, "model test count exceeds its bound")
    return count


def parse_result(path, profile="models"):
    require(profile in {"models", "frame-queue", "direct-address", "password-fields", "credential-dialog", "terminal-output"}, "test profile is unknown")
    expected_suites = EXPECTED_SUITES
    expected_by_suite = None
    if profile == "frame-queue":
        expected_suites = {"latest_frame_queue_test.dart"}
        expected_tests = len(FRAME_QUEUE_TESTS)
        expected_names = FRAME_QUEUE_TESTS
    elif profile == "direct-address":
        expected_suites = {"address_validator_test.dart"}
        expected_tests = len(DIRECT_ADDRESS_TESTS)
        expected_names = DIRECT_ADDRESS_TESTS
    elif profile == "password-fields":
        expected_suites = {"password_text_field_test.dart"}
        expected_tests = len(PASSWORD_FIELD_TESTS)
        expected_names = PASSWORD_FIELD_TESTS
    elif profile == "terminal-output":
        expected_suites = {"terminal_output_decoder_test.dart"}
        expected_tests = len(TERMINAL_OUTPUT_TESTS)
        expected_names = TERMINAL_OUTPUT_TESTS
    elif profile == "credential-dialog":
        expected_by_suite = CREDENTIAL_DIALOG_TESTS
        expected_suites = set(expected_by_suite)
        expected_names = set().union(*expected_by_suite.values())
        expected_tests = len(expected_names)
    else:
        expected_tests = model_test_count()
    metadata = os.lstat(path)
    require(stat.S_ISREG(metadata.st_mode), "result is not one regular file")
    require(metadata.st_nlink == 1, "result has multiple links")
    require(metadata.st_size <= MAXIMUM_BYTES, "result exceeds its byte bound")

    suites = {}
    tests = {}
    completed = set()
    starts = 0
    done_events = 0
    events = 0
    visible_successes = 0
    visible_names = set()
    with open(path, "rb") as stream:
        for raw_line in stream:
            events += 1
            require(events <= MAXIMUM_EVENTS, "result exceeds its event bound")
            require(len(raw_line) <= MAXIMUM_LINE_BYTES, "result line exceeds its byte bound")
            require(raw_line.endswith(b"\n"), "result has an unterminated event")
            try:
                event = json.loads(raw_line.decode("utf-8"))
            except (UnicodeDecodeError, ValueError) as error:
                raise ResultError("result contains malformed JSON: {}".format(error))
            require(isinstance(event, dict), "result event is not an object")
            event_type = event.get("type")
            require(isinstance(event_type, str), "result event type is absent")
            require(done_events == 0, "result contains an event after final completion")
            if event_type == "start":
                starts += 1
            elif event_type == "suite":
                suite = event.get("suite")
                require(isinstance(suite, dict), "suite event is malformed")
                suite_id = suite.get("id")
                path_value = suite.get("path")
                require(isinstance(suite_id, int) and suite_id >= 0, "suite ID is malformed")
                require(isinstance(path_value, str), "suite path is malformed")
                require(suite_id not in suites, "suite ID is duplicated")
                suites[suite_id] = os.path.basename(path_value)
            elif event_type == "testStart":
                test = event.get("test")
                require(isinstance(test, dict), "test-start event is malformed")
                test_id = test.get("id")
                suite_id = test.get("suiteID")
                require(isinstance(test_id, int) and test_id >= 0, "test ID is malformed")
                require(isinstance(suite_id, int) and suite_id in suites, "test suite is unknown")
                require(test_id not in tests, "test ID is duplicated")
                name = test.get("name")
                require(isinstance(name, str), "test name is malformed")
                tests[test_id] = (suite_id, name)
            elif event_type == "error":
                raise ResultError("Flutter reported a test error event")
            elif event_type == "testDone":
                test_id = event.get("testID")
                require(isinstance(test_id, int) and test_id in tests, "completed test is unknown")
                require(test_id not in completed, "test completion is duplicated")
                require(event.get("result") == "success", "test result is not successful")
                require(event.get("skipped") is False, "test was skipped")
                hidden = event.get("hidden")
                require(isinstance(hidden, bool), "completed-test hidden state is malformed")
                completed.add(test_id)
                if not hidden:
                    visible_successes += 1
                    name = tests[test_id][1]
                    if expected_by_suite is not None:
                        suite_name = suites[tests[test_id][0]]
                        require(name in expected_by_suite.get(suite_name, set()),
                                "test name does not belong to its suite")
                    if profile != "models":
                        require(name not in visible_names, "visible test name is duplicated")
                        visible_names.add(name)
            elif event_type == "done":
                done_events += 1
                require(event.get("success") is True, "final test result is not successful")

    require(events > 0, "result is empty")
    require(starts == 1, "start event is absent or duplicated")
    require(done_events == 1, "done event is absent or duplicated")
    require(set(suites.values()) == expected_suites, "executed suite inventory differs")
    require(len(suites) == len(expected_suites), "suite path is duplicated")
    require(completed == set(tests), "one or more started tests never completed")
    require(visible_successes == expected_tests, "executed test count differs")
    if profile != "models":
        require(visible_names == expected_names, "executed focused test names differ")
    return len(suites), visible_successes


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("result")
    parser.add_argument(
        "--profile", choices=("models", "frame-queue", "direct-address", "password-fields", "credential-dialog", "terminal-output"), default="models"
    )
    arguments = parser.parse_args()
    try:
        suites, tests = parse_result(arguments.result, arguments.profile)
    except (OSError, ResultError) as error:
        print("FLUTTER MODEL TEST RESULT: FAILED — {}".format(error), file=sys.stderr)
        return 1
    prefix = {
        "models": "FLUTTER_MODEL_TEST_JSON",
        "frame-queue": "FLUTTER_FRAME_QUEUE_TEST_JSON",
        "direct-address": "FLUTTER_DIRECT_ADDRESS_TEST_JSON",
        "password-fields": "FLUTTER_PASSWORD_FIELD_TEST_JSON",
        "terminal-output": "FLUTTER_TERMINAL_OUTPUT_TEST_JSON",
        "credential-dialog": "FLUTTER_CREDENTIAL_DIALOG_TEST_JSON",
    }[arguments.profile]
    print("{}=pass suites={} tests={}".format(prefix, suites, tests))
    return 0


if __name__ == "__main__":
    sys.exit(main())
