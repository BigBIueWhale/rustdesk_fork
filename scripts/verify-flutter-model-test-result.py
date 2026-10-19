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
    "desktop_window_dispatch_test.dart",
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
WINDOW_DISPATCH_TESTS = {
    "window dispatch preserves valid payload and sender",
    "window dispatch preserves null and successful event replies",
    "window dispatch removes its registered handler",
    "window dispatch redacts synchronous handler failure",
    "window dispatch redacts asynchronous JSON failure",
    "window dispatch redacts platform error fields",
    "window dispatch refuses a malformed sender envelope",
    "window dispatch joins event failure before replying",
}
PASSWORD_FIELD_TESTS = {
    "password keyboard policy survives reveal on android",
    "password keyboard policy survives reveal on iOS",
    "ordinary obscured field is a keyboard learning control",
    "password field retains focused obscured semantics",
}
KEYBOARD_LAYOUT_TESTS = {
    "keyboard chooser waits and blocks repeated choices",
    "keyboard chooser displays save errors and retries the same choice",
    "keyboard chooser exposes mismatched readback and permits retry",
    "keyboard chooser retains its admitted save through parent rebuild",
    "keyboard chooser disposal retires callbacks while the save settles",
    "keyboard layout callback publishes only confirmed native readback",
    "keyboard layout callback preserves its model after native failure",
}
SCROLL_PREFERENCE_TESTS = {
    "edge thickness owns a bounded draft without initial writes",
    "edge thickness rebuild retains its draft and latest writer",
    "edge thickness serializes writes and keeps only latest intent",
    "edge thickness refusal mismatch and null results retain retry",
    "edge thickness removal cancels queued and captured edits",
    "edge thickness removed admitted work retires feedback",
    "edge thickness disable and reenable retire old callbacks",
    "edge thickness replacement owner cannot receive old completion",
    "edge thickness external values do not replace pending edits",
    "scroll style selection joins the checked canvas operation",
    "scroll style refusal mismatch and invalid choices remain explicit",
    "scroll style retirement blocks admission and late feedback",
    "canvas scrolling saves share admission through publication",
    "canvas scrolling failed saves preserve state and permit retry",
    "canvas retired scroll owner suppresses viewport effects",
    "canvas clear keeps admitted scrolling work owned until completion",
    "canvas disposal joins accepted scroll save without notification",
    "canvas scroll commit retires older style initialization",
    "canvas thickness commit retires older thickness initialization",
    "canvas ready scroll initializers remain useful without commits",
    "canvas scroll reads reject invalid values and retired snapshots",
    "canvas scroll snapshot is retired by a committed thickness change",
}

CUSTOM_SCALE_TESTS = {
    "custom scale removal cancels its deferred read subscription",
    "custom scale initializes percentage and normalized position together",
    "custom scale initial read cannot replace a newer saved draft",
    "custom scale rebuild preserves its draft and uses current callbacks",
    "custom scale serializes saves and retains only the latest draft",
    "custom scale failed save preserves canvas and retries the same draft",
    "custom scale mismatched result remains visible and retryable",
    "custom scale failed loading retries a read without saving defaults",
    "custom scale removal cancels queued and captured edit callbacks",
    "custom scale removed widget retires feedback while admitted canvas work settles",
    "custom scale retargeting invalidates old reads and captured handlers",
    "custom scale retired save error cannot replace a new session draft",
    "custom scale slider preserves limits and its hundred percent detent",
    "replacement custom scale controls wait for admission and retain retry",
    "canvas custom scale admission is shared through publication",
    "canvas scale owner retirement preserves state while accepted work settles",
    "canvas clear retains accepted scale admission until completion",
    "canvas scale read failure preserves geometry and permits retry",
    "canvas scale getter refuses invalid values and unavailable owners",
    "canvas scale commit retires an older pending preference update",
    "canvas style change retires an older custom scale read",
    "canvas ready initializers remain useful without a preference commit",
    "canvas scale mutation failure releases admission for retry",
    "canvas scale getter reports a superseded pre-commit read",
}

SETTING_OPTION_TESTS = {
    "view style choice joins persistence before canvas publication",
    "view style refusal and mismatch leave the canvas and preserve retry",
    "view style canvas refusal and failure remain visible and retryable",
    "view style owner retirement blocks writes and late canvas effects",
    "view style retired canvas completion cannot publish failure feedback",
    "view style selection admits only the three named styles",
    "image preset choice awaits the effective native acknowledgement",
    "image Custom choice stages its editor without a preset write",
    "image preset errors and mismatched replies preserve retry",
    "image choice retirement blocks admission and late feedback",
    "image Custom errors and retirement never write a marker",
    "image preset selection admits only the three named presets",
    "quality editor Close waits for an admitted hidden FPS save",
    "quality dialog editing initializes its counterpart without losing a draft",
    "quality editor Close flushes latest edits and waits for both fields",
    "quality editor Close failure stays open for explicit retry",
    "quality editor retired Close cannot close a replacement",
    "quality editor refuses nonfinite and out of range effective values",
    "quality editor retains drafts and current writers across rebuild",
    "quality editor removal retires timers and captured edits",
    "quality editor serializes a field and preserves independent FPS",
    "quality editor failures stay visible and permit identical retry",
    "quality editor uses confirmed effective quality and FPS",
    "quality editor fixed quality disables its More control",
    "quality editor hiding FPS cancels its queued save",
    "quality editor replacement ignores retired callbacks and errors",
    "quality editor clean values follow external refresh",
    "quality editor leaving More saves its bounded current value",
    "quality editor preserves narrow mobile layout and hidden FPS",
    "trackpad disabling retires queued work without bypassing a pending save",
    "trackpad retired save errors cannot affect a replacement",
    "trackpad draft survives rebuild and uses the current save callback",
    "trackpad removal cancels debounce and disposes its controller",
    "trackpad retired edit callbacks cannot dispatch work",
    "trackpad serializes saves and retains only the latest newer draft",
    "trackpad failed saves retain the draft and permit identical retry",
    "trackpad success publishes its confirmed effective value",
    "trackpad clean refresh preserves unsubmitted text on rebuild",
    "trackpad replacement retires old edits and pending completion",
    "trackpad dialog staging keeps bounded local values without saves",
    "default option save waits and returns the effective native value",
    "default option failure is visible and the identical retry stays usable",
    "default option empty effective value is distinct from failure",
    "audio load failure stays visible and retries in a narrow view",
    "audio parent rebuild retains its pending read and later refreshes",
    "audio stale retry cannot start duplicate pending reads",
    "audio role replacement ignores old data and error completion",
    "audio retired retry cannot read after replacement or disposal",
    "audio empty default and absent devices remain valid load outcomes",
    "audio admitted write drains while retired callbacks cannot dispatch",
    "audio live write waits then publishes confirmed readback",
    "Flutter UI preference save waits and returns effective readback",
    "Flutter UI preference failure preserves readback and permits retry",
    "Flutter UI preference readback failure reports uncertainty and permits retry",
    "local option save waits before publishing dependent effects",
    "local option failures report feedback and stop dependent effects",
    "local option failure permits the identical retry",
    "favorite save owns its submitted IDs and waits for completion",
    "failed favorite membership change reports failure and permits retry",
    "option save waits for its native completion",
    "native option failure reports feedback without success",
    "synchronous option dispatch failure is reported",
    "failed option save permits the identical retry",
}
AUTO_DISCONNECT_FIELD_TESTS = {
    "inline timeout keeps one save while a newer draft is edited",
    "inline timeout retains its controller and draft across rebuilds",
    "inline timeout refreshes an unedited effective value",
    "inline timeout reports failure and permits the identical retry",
    "inline timeout refuses a mismatched effective value",
    "retired inline timeout cannot update its replacement",
    "disabled inline timeout cannot save or bypass a pending write",
    "inline timeout preserves valid input and the empty default",
}
AUTO_DISCONNECT_TESTS = {
    "cancel and escape preserve the stored timeout",
    "successful save waits for readback",
    "unchanged readback keeps the dialog open for retry",
    "pending save admits only one submission",
    "dismissed dialog ignores its pending completion",
    "save and read errors leave an editable dialog",
    "timeout field preserves its numeric limits and empty default",
}
KEYBOARD_MODE_REFRESH_TESTS = {
    "keyboard refresh keeps the newest completed request",
    "keyboard refresh retires changed owners and refuses late admission",
    "keyboard Flutter source choice retires an older native read",
    "keyboard refresh rejects an input source changed during its read",
    "keyboard refresh observes failed reads without publishing stale state",
    "keyboard refresh preserves compatibility choices and null fallback",
    "keyboard retirement rejects an old reply and permits a fresh read",
    "keyboard refresh adapter rejects a retired exact owner before native access",
}
TRACKPAD_DIALOG_TESTS = {
    "trackpad dialog stages raw text until committed Close",
    "trackpad dialog retains failed saves for identical retry",
    "trackpad dialog admits one save and blocks pending Escape",
    "trackpad dialog retirement cannot close a replacement",
    "trackpad dialog Escape and unchanged Close perform no save",
    "trackpad dialog bounds raw Close and rejects empty input",
    "trackpad dialog rebuild retains draft and uses current writer",
    "trackpad dialog fits narrow layout and stages slider input",
    "trackpad model admits one writer across dialogs and allows retry",
    "trackpad model retires failed writes and stale refreshes",
}
MODIFIER_RELEASE_TESTS = {
    "right Alt retains its own release identity",
    "modern modifier release preserves the other held side",
    "modern focus cleanup emits every held modifier once",
    "modern reset removes pending modifier releases",
    "raw tracking uses the changed key without aggregate state",
    "raw chord retains every changed modifier",
    "raw key up retires its key after aggregate state is clear",
    "raw key up preserves a different held modifier",
    "raw focus cleanup retires each exact pending release",
    "ordinary raw keys and reset cannot retain modifier ownership",
}
DIRECTORY_ORDERING_TESTS = {
    "new destination survives an older navigation response",
    "pending destination rejects an older navigation result",
    "failed destination does not restore an older request",
    "old refresh cannot replace a newer destination",
    "background refresh cannot cancel pending navigation",
    "duplicate destination does not retire its pending read",
    "reset retires a pending read within the same session",
    "initial home cannot replace a pending destination",
    "initial home cannot replace an established destination",
    "resolved home reply completes its directory request",
}
FILE_NAVIGATION_TESTS = {
    "peer compatibility failure prevents transfer dispatch",
    "refresh retires the preceding directory selection",
    "navigation retires the preceding directory selection",
    "initial home listing retires the preceding selection",
    "failed navigation retains the displayed directory and selection",
    "sorting a displayed directory retains its selection",
    "retired listing preserves the replacement selection",
    "retired selection cannot dispatch a transfer after refresh",
    "current directory selection still dispatches a transfer",
    "published listing does not cancel an admitted transfer snapshot",
    "refresh retains descending name order",
    "refresh retains descending type order",
    "refresh retains descending modified order",
    "refresh retains descending size order",
    "refresh retains ascending name order",
    "folder navigation retains the selected sort direction",
    "pending listing uses the latest selected sort and direction",
    "retired listing cannot replace the current directory",
    "initial home listing retains the selected sort direction",
    "local listing methods share capacity before native dispatch",
    "remote listing owner also bounds local listing admission",
    "cancelled local request retains capacity until native completion",
    "timed out local request retains capacity through late native error",
    "local error and malformed JSON release exact capacity slots",
    "retired local session refuses dispatch and late native success",
    "cancelled remote dispatches retain shared capacity until settlement",
    "late remote dispatch errors release only their retired owner",
    "stale remote sessions refuse every dispatch family",
    "timed out remote dispatches stay bounded across cancellation",
    "early remote responses retain cancelled dispatch capacity",
    "synchronous listing completions cannot resurrect capacity owners",
    "retired local listing completions never consult their session owner",
    "timed-out local listing completions never consult their session owner",
    "local listing owner lookup failures reach the caller and release capacity",
    "new remote listing owners share retained dispatch admission",
    "new local listing owners share retained dispatch admission",
}
FILE_COMMAND_TESTS = {
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
    "cleared file jobs retain dispatch capacity until actual completion",
    "cleared file jobs retain capacity after early success and error",
    "timed out file jobs retain dispatch capacity across clear",
    "retired file job failure cannot release replacement ownership",
    "settled file dispatches release cancelled response waiters",
    "inline file job completion and reentrant clear cannot retain slots",
    "new file job owners share admission with listing owners",
}
FILE_NAVIGATION_SUITES = {
    "file_navigation_sort_test.dart": FILE_NAVIGATION_TESTS,
    "file_command_session_ownership_test.dart": FILE_COMMAND_TESTS,
}
PEER_DATA_TESTS = {
    "peer decode redacts malformed JSON exception content",
    "peer decode redacts invalid shapes and field values",
    "peer decode preserves valid metadata and recovers after refusal",
    "peer decode accepts empty input without a diagnostic",
    "cached peer decode refuses data without payload diagnostics",
    "cached peer decode preserves snapshots and recovers after refusal",
    "platform metadata refuses input without payload diagnostics",
    "platform metadata preserves snapshots and quiet empty input",
    "resolution metadata refuses partial and private input",
    "resolution metadata preserves both formats and recovery",
}
TERMINAL_OUTPUT_TESTS = {
    "terminal_output_decoder_test.dart": {
        "terminal UTF-8 survives every two-packet split",
        "terminal UTF-8 emits complete text while retaining only a partial tail",
        "terminal invalid UTF-8 has the same replacement policy across packets",
        "terminal end of stream flushes an incomplete character exactly once",
        "terminal decoders keep concurrent terminal byte streams separate",
        "replacement terminal stream cannot complete its predecessor tail",
    },
    "terminal_model_lifecycle_test.dart": {
        "terminal CSI parser resets across reopen ready=false",
        "terminal CSI parser resets across reopen ready=true",
        "terminal OSC parser resets across reopen ready=false",
        "terminal OSC parser resets across reopen ready=true",
        "terminal parser preserves current splits and presented state",
        "terminal pool retains one owner until its last release",
        "terminal pool refuses an unowned retain or release",
        "terminal pool replacement survives old page releases",
        "terminal pool authority uses identity rather than equality",
        "terminal pool retires its slot before external cleanup",
        "terminal pool cannot reset a live owner reference count",
        "current terminal open completion notifies once",
        "disposed terminal ignores delayed open completion",
        "replacement terminal retires predecessor open notification",
        "terminal close retires its pending open notification",
        "terminal reopen retires the previous open completion",
        "reopened terminal cannot answer a queued predecessor query",
        "closed terminal cannot buffer an old query reply for reopen",
        "queued terminal queries retain their exact open owner",
        "current terminal query replies preserve replay suppression",
    },
}
GLOBAL_EVENT_TESTS = {
    "runs admitted events in FIFO order without handler overlap",
    "replacement retires old pending work without migrating its event",
    "active old work settles before replacement work and never overlaps",
    "fallback overflow fails once, retires pending work, and recovers",
    "byte and message bounds fail the exact fallback visibly",
    "registered handler inventory is finite and reusable after retirement",
    "registered handlers are captured and retired by exact registration",
    "registered-only routing never falls through to session fallback",
    "configured latest-state events hand off synchronously outside FIFO",
    "configured synchronous handoff fails closed on an async callback",
    "handler and malformed-input failures remain visible and drainable",
}
CREDENTIAL_DIALOG_TESTS = {
    "global_event_dispatcher_test.dart": GLOBAL_EVENT_TESTS,
    "peer_model_test.dart": {
        "direct peers retain their address and local display metadata",
        "retired account metadata cannot prevent a direct peer from loading",
        "direct peers expose no retired credential or group fields",
        "disposing owned peers releases their registration",
        "disposed duplicate peers cannot retire the incumbent",
    },
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
        "mobile terminal close owns one route and completes once",
        "retired mobile terminal callback cannot close a replacement route",
        "hidden mobile terminal callback cannot pop a different route",
        "mobile terminal session replacement revokes captured close",
        "mobile terminal route rejects foreign and unbound callbacks",
        "mobile terminal close drains local route history only",
        "blockable overlay keeps one mounted owner and rebuilds its underlying route",
        "middle blocker owns the tap before revealing the route",
        "one explicit dialog tag owns one disposable overlay entry",
    },
    "file_command_session_ownership_test.dart": FILE_COMMAND_TESTS,
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
    require(profile in {"models", "frame-queue", "direct-address", "password-fields", "credential-dialog", "terminal-output", "window-dispatch", "peer-data", "file-navigation", "directory-ordering", "modifier-release", "auto-disconnect"}, "test profile is unknown")
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
    elif profile == "window-dispatch":
        expected_suites = {"desktop_window_dispatch_test.dart"}
        expected_tests = len(WINDOW_DISPATCH_TESTS)
        expected_names = WINDOW_DISPATCH_TESTS
    elif profile == "auto-disconnect":
        expected_by_suite = {
            "auto_disconnect_timeout_dialog_test.dart": AUTO_DISCONNECT_TESTS,
            "auto_disconnect_timeout_field_test.dart": AUTO_DISCONNECT_FIELD_TESTS,
            "setting_option_mutation_test.dart": SETTING_OPTION_TESTS,
            "keyboard_layout_type_chooser_test.dart": KEYBOARD_LAYOUT_TESTS,
            "trackpad_speed_dialog_test.dart": TRACKPAD_DIALOG_TESTS,
            "input_keyboard_mode_test.dart": KEYBOARD_MODE_REFRESH_TESTS,
            "custom_scale_controls_test.dart": CUSTOM_SCALE_TESTS,
            "scroll_preferences_test.dart": SCROLL_PREFERENCE_TESTS,
        }
        expected_suites = set(expected_by_suite)
        expected_names = set().union(*expected_by_suite.values())
        expected_tests = len(expected_names)
    elif profile == "modifier-release":
        expected_suites = {"input_modifier_release_test.dart"}
        expected_tests = len(MODIFIER_RELEASE_TESTS)
        expected_names = MODIFIER_RELEASE_TESTS
    elif profile == "directory-ordering":
        expected_suites = {"file_navigation_ordering_test.dart"}
        expected_tests = len(DIRECTORY_ORDERING_TESTS)
        expected_names = DIRECTORY_ORDERING_TESTS
    elif profile == "file-navigation":
        expected_by_suite = FILE_NAVIGATION_SUITES
        expected_suites = set(expected_by_suite)
        expected_names = set().union(*expected_by_suite.values())
        expected_tests = len(expected_names)
    elif profile == "peer-data":
        expected_suites = {"peer_decode_test.dart"}
        expected_tests = len(PEER_DATA_TESTS)
        expected_names = PEER_DATA_TESTS
    elif profile == "terminal-output":
        expected_by_suite = TERMINAL_OUTPUT_TESTS
        expected_suites = set(expected_by_suite)
        expected_names = set().union(*expected_by_suite.values())
        expected_tests = len(expected_names)
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
        "--profile", choices=("models", "frame-queue", "direct-address", "password-fields", "credential-dialog", "terminal-output", "window-dispatch", "peer-data", "file-navigation", "directory-ordering", "modifier-release", "auto-disconnect"), default="models"
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
        "window-dispatch": "FLUTTER_WINDOW_DISPATCH_TEST_JSON",
        "modifier-release": "FLUTTER_MODIFIER_RELEASE_TEST_JSON",
        "auto-disconnect": "FLUTTER_AUTO_DISCONNECT_TEST_JSON",
        "directory-ordering": "FLUTTER_DIRECTORY_ORDERING_TEST_JSON",
        "file-navigation": "FLUTTER_FILE_NAVIGATION_TEST_JSON",
        "peer-data": "FLUTTER_PEER_DATA_TEST_JSON",
        "terminal-output": "FLUTTER_TERMINAL_OUTPUT_TEST_JSON",
        "credential-dialog": "FLUTTER_CREDENTIAL_DIALOG_TEST_JSON",
    }[arguments.profile]
    print("{}=pass suites={} tests={}".format(prefix, suites, tests))
    return 0


if __name__ == "__main__":
    sys.exit(main())
