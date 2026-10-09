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
    require(profile in {"models", "frame-queue", "direct-address"}, "test profile is unknown")
    expected_suites = EXPECTED_SUITES
    if profile == "frame-queue":
        expected_suites = {"latest_frame_queue_test.dart"}
        expected_tests = len(FRAME_QUEUE_TESTS)
        expected_names = FRAME_QUEUE_TESTS
    elif profile == "direct-address":
        expected_suites = {"address_validator_test.dart"}
        expected_tests = len(DIRECT_ADDRESS_TESTS)
        expected_names = DIRECT_ADDRESS_TESTS
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
        "--profile", choices=("models", "frame-queue", "direct-address"), default="models"
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
    }[arguments.profile]
    print("{}=pass suites={} tests={}".format(prefix, suites, tests))
    return 0


if __name__ == "__main__":
    sys.exit(main())
