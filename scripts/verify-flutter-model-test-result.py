#!/usr/bin/env python3
"""Validate bounded Flutter JSON results for the model checkpoint or focused shards."""

import argparse
import json
import os
import re
import stat
import sys


REVERSE_WHEEL_TESTS = {
    "reverse wheel reads and writes capture both owner identifiers",
    "reverse wheel bounds admission before native dispatch",
    "reverse wheel write failure and mismatch preserve the confirmed value",
    "reverse wheel retired read cannot publish into replacement owner",
    "reverse wheel admitted write remains owned after owner retirement",
    "reverse wheel disposal retains pending capacity without late notification",
    "reverse wheel initial read is singular through rebuilds",
    "reverse wheel failed read stays unknown and retries explicitly",
    "reverse wheel visual value waits for acknowledged write",
    "reverse wheel failed write retries requested true",
    "reverse wheel failed write retries requested false",
    "reverse wheel mismatched acknowledgement is visible and retryable",
    "reverse wheel shared controls observe one write and confirmed value",
    "reverse wheel retarget rejects captured callbacks and old completion",
    "reverse wheel disable and reenable retire old callbacks",
    "reverse wheel replacement reads while old control read is pending",
    "reverse wheel disposed deferred listener cannot start another read",
    "reverse wheel stale retry cannot target replacement session",
    "reverse wheel mobile control uses the same confirmed state",
}

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
    "observed failure retires before reentrant recovery and admission",
    "pending capacity failure retires before reentrant recovery",
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
SHARE_RDP_TESTS = {
    "r_s11ir an unmounted owner refuses admission",
    "r_s11ir duplicate UI actions share one synchronous request latch",
    "r_s11ir failure is visible before the mounted latch is released",
    "r_s11ir an unmounted owner receives no late UI callback",
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
    "scroll menu owns and cancels its deferred preference read",
    "scroll menu reloads an initial read after presentation retirement",
    "scroll menu view style visibility keeps the owned thickness draft",
    "scroll menu rebuild preserves pending thickness draft and admission",
    "scroll menu initial read is singular and retires on retarget",
    "scroll menu read failure retries without writing defaults",
    "scroll menu retired callbacks cannot mutate a replacement session",
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
    "canvas changed scroll mode retires a pending view style read",
    "canvas scroll mode change cancels and joins its queued timer",
    "canvas asynchronous view read leaves event handling available",
    "canvas view read errors and invalid styles preserve geometry and retry",
    "canvas retired first view read cannot start its scale query",
    "canvas delayed original read cannot replace applied adaptive style",
    "canvas retirement during final style read prevents publication",
    "canvas pending scale uses current geometry after its reads",
    "canvas scrolling read failure and retired style cannot reset geometry",
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

CANVAS_IMAGE_TESTS = {
    "cursor startup grace does not revive after wall clock rollback",
    "cursor startup grace survives wall clock advance",
    "cursor peer protection does not revive after wall clock rollback",
    "cursor peer protection survives wall clock advance",
    "cursor control timers expire at their exact elapsed boundaries",
    "cursor clear retires protection and starts a fresh grace period",
    "cursor models retain independent control timers",
    "edge fallback replacement and clear release provider tickers",
    "canvas disposal releases ticker and both scroll controllers",
    "held edge reply refuses cancel owner",
    "held edge reply refuses disable owner",
    "held edge reply refuses presentation owner",
    "held edge reply refuses topology owner",
    "held edge reply refuses replacement owner",
    "held edge reply refuses clear owner",
    "held edge reply refuses dispose owner",
    "edge motion holds one request and only the latest waiting motion",
    "active fallback stops at presentation and fresh motion is useful",
    "active fallback stops at topology and fresh motion is useful",
    "edge retirement joins a held reply without reviving scrolling",
    "failed old edge request preserves the latest useful motion",
    "fallback keeps progressing while current edge motion changes",
    "current edge transport failure refuses fallback and permits retry",
    "edge scroll listener retirement stops remaining canvas effects",
    "bump-generated interior motion does not cancel its canvas pair",
    "waiting edge motion rechecks bounds after the accepted scroll",
    "fallback becomes idle at horizontal bounds and can restart",
    "fallback becomes idle at vertical bounds and can restart",
    "fallback becomes idle at both bounds and can restart",
    "zero-time fallback frame stays useful without notifying",
    "mobile canvas clear removes both pending timers",
    "mobile canvas dispose removes both pending timers",
    "mobile focus presentation preserves current geometry",
    "mobile focus topology preserves current geometry",
    "mobile focus clear preserves current geometry",
    "mobile focus dispose preserves current geometry",
    "mobile restore presentation preserves current geometry",
    "mobile restore topology preserves current geometry",
    "mobile restore clear preserves current geometry",
    "mobile restore dispose preserves current geometry",
    "saved mobile snapshot presentation refuses a later restore",
    "saved mobile snapshot topology refuses a later restore",
    "mobile keyboard cycles focus and restore useful geometry",
    "mobile snapshot replacement and duplicate restore keep one timer",
    "superseded canvas view read preserves successor state",
    "superseded canvas scroll read preserves successor state",
    "superseded canvas edge read preserves successor state",
    "retired presentation canvas view read has no effects",
    "retired presentation canvas scroll read has no effects",
    "retired presentation canvas edge read has no effects",
    "retired clear canvas view read has no effects",
    "retired clear canvas scroll read has no effects",
    "retired clear canvas edge read has no effects",
    "delayed canvas scroll update joins and refuses a retired owner",
    "deferred canvas scroll clear cancels and joins its timer",
    "deferred canvas scroll dispose cancels and joins its timer",
    "deferred canvas scroll replacement cancels and joins its timer",
    "disposed canvas refuses pending reads and new update owners",
    "retired cursor initialization preserves current geometry",
    "superseded cursor initialization cannot reset successor geometry",
    "a ready first image is not superseded by pending geometry",
    "a lower late image cannot replace a ready higher image",
    "presentation retirement rejects images awaiting geometry",
    "first-image view failure releases its image",
    "first-image scroll failure releases its image",
    "first-image edge failure releases its image",
    "first-image cursor failure releases its image",
    "rejected updates cannot dispose the current image",
    "notification retirement cannot dispose an adopted image twice",
    "owned image paint fills loose stack bounds and retains pixels",
    "native image ownership survives conversion faults and paint retirement",
}

TWO_FINGER_TAP_TESTS = {
    "two finger tap accepts one complete overlapping pair",
    "two finger tap supports repeated completed sequences",
    "two finger tap completes rapid pairs without waiting for timeout",
    "two finger tap cancellation retires the old deadline before retry",
    "two finger tap arena rejection cancels the complete sequence",
    "two finger tap single pointer timeout releases arena sweep",
    "two finger tap disposal releases both exact arena holds",
    "two finger tap refuses a third held pointer",
    "two finger tap refuses nonoverlapping single taps",
    "two finger tap movement refusal permits a fresh complete pair",
}

CUSTOM_TOUCH_TESTS = {
    "custom touch one finger starts before updates and ends once",
    "custom touch rapid successive pans each own a start",
    "custom touch replacement scale pointers start a fresh phase",
    "custom touch scale to pan survives continuous movement",
    "custom touch three to two survives continuous movement",
    "custom touch fourth pointer pauses recognized updates",
    "custom touch disposal cannot publish a deferred start",
    "custom touch cancellation permits an immediate fresh pan",
    "custom touch rejected extra pointer leaves a balanced usable pan",
    "custom touch three finger start retains transformed coordinates",
}

HOLD_DRAG_TESTS = {
    "hold drag accepts tap hold movement and release",
    "hold drag quick second release cannot end or start a drag",
    "hold drag movement admission resolves both exact arenas",
    "hold drag repeated completion leaves no earlier arena owners",
    "hold drag active movement can return inside initial tolerance",
    "hold drag active cancellation ends once and permits retry",
    "hold drag active disposal ends once without late start",
    "hold drag pending cancellation releases the first tap hold",
    "hold drag state retires when the end callback is absent",
    "hold drag refuses a first tap that moved beyond tolerance",
    "hold drag preserves the real quick double tap recognizer",
    "hold drag extra pointer retires the pending sequence",
    "hold drag start retains device and transformed coordinates",
    "hold drag first tap timeout releases fallback and permits retry",
}

SETTING_OPTION_TESTS = {
    "mobile default switch Android owns pending save through rebuild",
    "mobile default switch Android refusal and mismatch keep identical retry",
    "mobile default switch Android catches writer errors for retry",
    "mobile default switch Android disabled and retired callbacks refuse",
    "mobile default switch Android replacement retires old option owner",
    "mobile default switch Android keeps empty and explicit false encodings",
    "mobile default switch iOS owns pending save through rebuild",
    "mobile default switch iOS refusal and mismatch keep identical retry",
    "mobile default switch iOS catches writer errors for retry",
    "mobile default switch iOS disabled and retired callbacks refuse",
    "mobile default switch iOS replacement retires old option owner",
    "mobile default switch iOS keeps empty and explicit false encodings",
    "default checkbox owns one pending save through parent rebuild",
    "default checkbox refusal and mismatch preserve identical retry",
    "default checkbox catches save errors and keeps the choice retryable",
    "default checkbox disabled and retired callbacks cannot save",
    "default checkbox replacement retires the old option owner",
    "default checkbox preserves empty and explicit false encodings",
    "setting checkbox pending commit survives parent rebuild",
    "setting checkbox serializes captured callbacks through rebuild",
    "setting checkbox rejected readback retries the identical choice",
    "setting checkbox thrown save stays visible and retryable",
    "setting checkbox disabled and retired callbacks cannot write",
    "setting checkbox replacement ignores admitted completion",
    "setting checkbox clean parent refresh replaces confirmed display",
    "setting checkbox row taps publish confirmed values and icons",
    "combo uses keys independently of display labels",
    "combo duplicate labels preserve distinct selection identities",
    "combo pending and failed changes retain the confirmed selection",
    "combo refreshed confirmed value replaces the displayed selection",
    "combo empty options disable selection without inventing a value",
    "combo unavailable selection stays visible without choosing another key",
    "combo disabled and unchanged choices dispatch nothing",
    "combo label refresh preserves its selected identity",
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
    "audio pending write refuses duplicate and rebuilt selections",
    "audio replacement retains admission until the old write settles",
    "audio failed write releases admission for an identical retry",
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
PHYSICAL_MOUSE_TESTS = {
    "physical mouse single primary press and release remain paired",
    "physical mouse right to left releases right before pressing left",
    "physical mouse left to right releases left before pressing right",
    "physical mouse mixed replacement releases every previous button",
    "physical mouse first down decomposes the five supported buttons",
    "physical mouse coalesced presses keep individual peer identities",
    "physical mouse partial chord release preserves the held primary",
    "physical mouse final up retires stale chord button flags",
    "physical mouse unchanged chord emits movement without button repeats",
    "physical mouse hover retires missing releases before a fresh press",
    "physical mouse unsupported bits cannot become empty peer buttons",
    "physical mouse secondary release preserves a held primary",
    "physical mouse independent models retain separate button history",
    "physical mouse nonmouse movement cannot replace mouse button history",
    "physical mouse outside release preserves left",
    "physical mouse outside release preserves right",
    "physical mouse outside release preserves wheel",
    "physical mouse outside release preserves back",
    "physical mouse outside release preserves forward",
    "physical mouse outside chord release retires every button once",
    "physical mouse outside presses and movement remain rejected",
    "physical mouse bounds retain snapping tolerance and mobile clamping",
    "physical mouse widget cancellation releases the primary button",
    "physical mouse widget outside cancellation releases a chord",
    "physical mouse widget cancellation permits a fresh matching press",
    "physical mouse widget repeated cancellation releases once",
    "physical mouse widget touch cancellation preserves a mouse press",
    "physical mouse widget cancellation without a press emits nothing",
    "physical mouse widget ordinary up retains caller callbacks",
    "physical mouse widget mouse cancellation survives a touch pointer",
    "physical mouse widget mouse up survives a touch pointer",
}

TRACKPAD_INPUT_TESTS = {
    "trackpad gesture orphan update and end emit nothing",
    "trackpad gesture changed session cannot inherit pan or fling",
    "trackpad gesture changed client cannot inherit pan or fling",
    "trackpad gesture wrong pointer preserves the active sequence",
    "trackpad gesture wrong device preserves the active sequence",
    "trackpad gesture wrong view preserves the active sequence",
    "trackpad gesture late end preserves a replacement pointer",
    "trackpad gesture duplicate end preserves its running coast",
    "trackpad gesture matching pan and scale retain their target",
    "trackpad gesture same owner retains fractional scrolling",
    "trackpad gesture fractional remainder belongs to its exact owner",
    "trackpad gesture reset refuses late update and end",
    "trackpad gesture Android matching sequence retains all phases",
    "trackpad gesture Android orphan callbacks emit no phases",
    "trackpad gesture Android replacement cannot inherit old phases",
    "trackpad fling retains Linux scaling decay and finite completion",
    "trackpad fling new pan cancels the pending timer immediately",
    "trackpad fling pointer down cancels the pending timer immediately",
    "trackpad fling hover cancels the pending timer immediately",
    "trackpad fling window blur cancels the pending timer immediately",
    "trackpad fling disposal retires pending coast work",
    "trackpad fling disposed model refuses later pan callbacks",
    "trackpad fling reset retires old work and permits a fresh coast",
    "trackpad fling changed session retires the captured coast",
    "trackpad fling changed client retires the captured coast",
    "trackpad fling models retain independent timer ownership",
    "trackpad fling waits for its admitted send before another timer",
    "trackpad fling late send completion cannot restart disposed work",
    "trackpad fling reentrant stop cannot create another timer",
    "trackpad fling reentrant replacement retains one timer",
    "trackpad fling dispatch failure retires its own timer",
}

SIDE_BUTTON_TESTS = {
    "side button duplicate down preserves one accepted press",
    "side button duplicate down cannot transfer a press to another model",
    "side button up retains the session selected by down",
    "side button stale disposal preserves a newer press and active model",
    "side button separate buttons retain independent models",
    "side button view only refuses presses with either cursor setting",
    "side button unknown names cannot release a held button",
    "side button malformed messages preserve the held press",
    "side button retired owner cannot admit a new press",
    "side button release survives permission and camera changes",
    "side button disposal releases each accepted press once",
    "side button pending and failed sends do not block the channel",
}

MODIFIER_RELEASE_TESTS = {
    "right Alt retains its own release identity",
    "modern modifier release preserves the other held side",
    "modern modifier cache retains key-up identity through cleanup",
    "modern reset removes pending modifier releases",
    "raw tracking uses the changed key without aggregate state",
    "raw chord retains every changed modifier",
    "raw key up retires its key after aggregate state is clear",
    "raw key up preserves a different held modifier",
    "ordinary raw keys and reset cannot retain modifier ownership",
    "owned modifier dispatch focus leave releases the captured owner in one batch",
    "owned modifier dispatch modern key up bypasses changed input source and keyboard mode",
    "owned modifier dispatch raw key up bypasses changed input source and clears its slot",
    "owned modifier dispatch permission revocation retires modifiers before blocking new input",
    "owned modifier dispatch view only retires modifiers and refuses later new input",
    "owned modifier dispatch focus cleanup fences a down whose bridge completion is pending",
    "owned modifier dispatch modifier repeats share a sequence and a later press gets a new one",
    "owned modifier dispatch connection suspension refuses input until a new round is installed",
    "owned modifier dispatch retired owner cannot install a late keyboard round",
    "owned modifier dispatch changing the owner during a round read refuses later dispatch",
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
    "peer_credential_badge_test.dart": {
        "confirmed forget clears matching badges without another read",
        "failed forget preserves the badge and the same peer can retry",
        "confirmed forget retires an older credential read",
        "confirmed forget retires an older error and retry callback",
        "peer credential badge renders only saved PRS and reads once",
        "peer credential badge reports errors and admits one retry",
        "peer credential badge retires old reads and old display data",
        "peer credential badge rejects a retired retry callback",
        "peer credential badge drains a failed read after disposal",
    },
    "peer_removal_test.dart": {
        "peer option workflow waits for write and refresh with exact arguments",
        "peer option workflow reports write or refresh failure and retries",
        "peer rename owns one pending save until success",
        "retired peer rename callbacks cannot save a replacement",
        "peer rename failure stays visible and permits a changed retry",
        "admitted peer rename drains without closing its replacement",
        "peer rename disposes its editor while admitted failure drains",
        "peer credential removal waits for the exact submitted operation",
        "peer credential removal reports failure and retries the same peer",
        "peer credential removal preserves a synchronous bridge failure",
        "peer deletion owns its IDs and waits for each deletion and refresh",
        "peer deletion reports a single failure and permits an identical retry",
        "peer deletion completes the submitted batch after a partial failure",
        "peer deletion reports a refresh failure after completed deletion",
        "peer deletion preserves a synchronous native failure as a failed result",
        "peer delete confirmation admits one pending submission",
        "retired peer delete callback cannot submit into a replacement",
        "admitted peer deletion drains without closing a replacement",
        "peer delete submission failure stays visible and retries",
        "peer deletion captures immutable IDs without exposing mutable selection",
        "peer deletion cannot clear a replaced selection or tab round trip",
        "peer deletion retires its unchanged selection exactly once",
        "peer deletion cannot notify a disposed selection owner",
    },
    "file_rename_dialog_test.dart": {
        "rename admits one request until its exact result settles",
        "retired rename callbacks cannot admit a file operation",
        "rename failure after dismissal leaves the retired widget alone",
        "rename failure stays visible and permits an explicit retry",
    },
    "file_navigation_sort_test.dart": FILE_NAVIGATION_TESTS,
    "file_command_session_ownership_test.dart": FILE_COMMAND_TESTS,
    "file_dialog_event_loop_test.dart": {
        "bounded event loop consumes admitted work in FIFO order",
        "capacity counts running and pending events",
        "close retires pending work and rejects admission while closed",
        "retired callback cannot consume replacement-generation work",
        "callback failure is terminal and clears successors",
        "file confirmation parser owns one exact bounded typed payload",
        "file confirmation parser rejects malformed scalar authority",
        "file confirmation parser rejects unowned path storage",
    },
    "file_conflict_dialog_test.dart": {
        "overwrite dialog does not claim content identity",
        "overwrite dialog preserves cancel skip overwrite and escape",
        "overwrite dialog remembers a choice only for its opening",
        "overwrite dialog omits unavailable remember control",
    },
}
PEER_DATA_TESTS = {
    "chat draft survives missing client at both send inputs",
    "chat draft survives reused id at both send inputs",
    "chat draft survives invalid generation at both send inputs",
    "chat draft survives disconnected client at both send inputs",
    "chat draft clears accepted incoming sends at both inputs",
    "chat draft clears accepted outgoing sends at both inputs",
    "chat send refuses missing client before bridge dispatch",
    "chat send refuses reused id before bridge dispatch",
    "chat send refuses invalid generation before bridge dispatch",
    "chat send refuses disconnected client before bridge dispatch",
    "chat panel completes repeated open and close transitions",
    "chat panel preserves closed state and retries show failure",
    "chat panel preserves closed state and retries resize failure",
    "chat panel preserves closed state and retries position failure",
    "chat panel preserves open state and retries show failure",
    "chat panel preserves open state and retries resize failure",
    "chat panel preserves open state and retries position failure",
    "chat panel serializes closed transition until native completion",
    "chat panel serializes open transition until native completion",
    "chat delivery keeps a live outgoing owner",
    "chat delivery refuses outgoing close after page wait",
    "chat delivery refuses outgoing session after page wait",
    "chat delivery refuses outgoing ui after page wait",
    "chat delivery refuses retired outgoing owner after window wait",
    "chat delivery keeps a live incoming generation",
    "chat delivery refuses replaced incoming generation after page wait",
    "chat delivery refuses replaced incoming generation after CM wait",
    "chat reset clears outgoing bodies and preserves incoming history",
    "chat reset supports empty repeated and reused session histories",
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


FILE_METADATA_TESTS = {
    *(f"ordinary timestamp {value} keeps its date" for value in
      (0, 1, -1, 1700000000, -2147483648, 2147483647, 8640000000000, -8640000000000)),
    *(f"unsupported timestamp {value} is unavailable without data loss" for value in
      (8640000000001, -8640000000001, 2305843009213693952, -2305843009213693952)),
    "drive row retains its blank timestamp",
    "timestamp rendering preserves the remaining entry fields",
    "modified ordering uses raw seconds ascending=false",
    "modified ordering uses raw seconds ascending=true",
}


def parse_result(path, profile="models"):
    require(profile in {"models", "frame-queue", "direct-address", "file-metadata", "password-fields", "share-rdp", "credential-dialog", "terminal-output", "window-dispatch", "peer-data", "file-navigation", "directory-ordering", "modifier-release", "auto-disconnect"}, "test profile is unknown")
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
    elif profile == "file-metadata":
        expected_suites = {"file_metadata_probe_test.dart"}
        expected_tests = len(FILE_METADATA_TESTS)
        expected_names = FILE_METADATA_TESTS
    elif profile == "share-rdp":
        expected_suites = {"share_rdp_change_lifecycle_test.dart"}
        expected_tests = len(SHARE_RDP_TESTS)
        expected_names = SHARE_RDP_TESTS
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
            "owned_image_paint_test.dart": CANVAS_IMAGE_TESTS,
            "reverse_mouse_wheel_test.dart": REVERSE_WHEEL_TESTS,
            "two_finger_tap_test.dart": TWO_FINGER_TAP_TESTS,
            "custom_touch_gestures_test.dart": CUSTOM_TOUCH_TESTS,
            "hold_tap_move_test.dart": HOLD_DRAG_TESTS,
        }
        expected_suites = set(expected_by_suite)
        expected_names = set().union(*expected_by_suite.values())
        expected_tests = len(expected_names)
    elif profile == "modifier-release":
        expected_by_suite = {
            "input_modifier_release_test.dart": MODIFIER_RELEASE_TESTS,
            "input_mouse_buttons_test.dart": PHYSICAL_MOUSE_TESTS,
            "trackpad_fling_test.dart": TRACKPAD_INPUT_TESTS,
            "input_side_buttons_test.dart": SIDE_BUTTON_TESTS,
        }
        expected_suites = set(expected_by_suite)
        expected_names = set().union(*expected_by_suite.values())
        expected_tests = len(expected_names)
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
        "--profile", choices=("models", "frame-queue", "direct-address", "file-metadata", "password-fields", "share-rdp", "credential-dialog", "terminal-output", "window-dispatch", "peer-data", "file-navigation", "directory-ordering", "modifier-release", "auto-disconnect"), default="models"
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
        "file-metadata": "FLUTTER_FILE_METADATA_TEST_JSON",
        "password-fields": "FLUTTER_PASSWORD_FIELD_TEST_JSON",
        "share-rdp": "FLUTTER_SHARE_RDP_TEST_JSON",
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
