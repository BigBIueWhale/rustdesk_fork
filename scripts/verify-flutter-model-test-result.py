#!/usr/bin/env python3
"""Validate the bounded JSON result stream from the focused Flutter model tests."""

import argparse
import json
import os
import stat
import sys


EXPECTED_SUITES = {
    "blockable_overlay_test.dart",
    "custom_cursor_registry_test.dart",
    "desktop_tab_retirement_test.dart",
    "desktop_texture_lifecycle_test.dart",
    "display_selection_queue_test.dart",
    "global_event_dispatcher_test.dart",
    "latest_frame_queue_test.dart",
    "mobile_session_start_queue_test.dart",
    "owned_image_paint_test.dart",
    "presentation_recovery_test.dart",
    "rgba_publication_order_test.dart",
    "server_status_refresh_loop_test.dart",
    "session_event_queue_test.dart",
    "session_stream_finality_test.dart",
    "start_ellipsis_text_test.dart",
}
EXPECTED_TESTS = 112
MAXIMUM_BYTES = 8 * 1024 * 1024
MAXIMUM_EVENTS = 16_384
MAXIMUM_LINE_BYTES = 1024 * 1024


class ResultError(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise ResultError(message)


def parse_result(path):
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
                tests[test_id] = suite_id
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
            elif event_type == "done":
                done_events += 1
                require(event.get("success") is True, "final test result is not successful")

    require(events > 0, "result is empty")
    require(starts == 1, "start event is absent or duplicated")
    require(done_events == 1, "done event is absent or duplicated")
    require(set(suites.values()) == EXPECTED_SUITES, "executed suite inventory differs")
    require(len(suites) == len(EXPECTED_SUITES), "suite path is duplicated")
    require(completed == set(tests), "one or more started tests never completed")
    require(visible_successes == EXPECTED_TESTS, "executed test count differs")
    return len(suites), visible_successes


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("result")
    arguments = parser.parse_args()
    try:
        suites, tests = parse_result(arguments.result)
    except (OSError, ResultError) as error:
        print("FLUTTER MODEL TEST RESULT: FAILED — {}".format(error), file=sys.stderr)
        return 1
    print("FLUTTER_MODEL_TEST_JSON=pass suites={} tests={}".format(suites, tests))
    return 0


if __name__ == "__main__":
    sys.exit(main())
