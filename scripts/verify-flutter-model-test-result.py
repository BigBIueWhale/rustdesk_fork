#!/usr/bin/env python3
"""Validate bounded Flutter JSON results for the model checkpoint or focused shards."""

import argparse
import json
import os
import re
import stat
import sys


RELATIVE_MOUSE_ENABLE_TESTS = {
    "relative mouse current geometry enables once and disables",
    "relative mouse disable retires a delayed enable",
    "relative mouse old geometry cannot warp a replacement mode",
    "relative mouse disposal closes pending and future admission",
    "relative mouse invalid geometry stays disabled and permits retry",
    "relative mouse missing window and failed geometry do not enable",
    "relative mouse session reset retires the old geometry request",
    "relative mouse enable rechecks permission and camera admission",
    "relative mouse stale geometry error preserves the current mode",
}


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

LOCALE_TESTS = {
    "framework locale resolves Kazakh language",
    "framework locale resolves Kazakh region",
    "framework locale resolves Vietnamese language",
    "framework locale resolves Vietnamese region",
    "framework locale resolves English",
    "framework locale resolves French",
    "framework locale resolves unsupported language",
    "framework locale preserves Hebrew direction",
    "framework locale selects a supported later preference",
    "framework locale follows live system changes",
}

PATH_LABEL_TESTS = {
    "leaves fitting text unchanged",
    "retains the longest fitting suffix",
    "never cuts a grapheme cluster",
    "exposes the complete text to assistive technology",
    *{
        f"keeps filename end after {separator} in {layout} width"
        for separator in ("LF", "CRLF", "line separator", "paragraph separator")
        for layout in ("bounded", "unbounded")
    },
    *{
        f"bold accessibility preserves {size} filename end with {style} style"
        for size in ("fitting", "truncated")
        for style in ("inherited", "explicit")
    },
}
SETTING_CHECKBOX_TESTS = {
    *{
        f"checkbox label exposes checked={checked} enabled={enabled}"
        for checked in ("false", "true")
        for enabled in ("false", "true")
    },
    "checkbox semantic action waits for one acknowledged write",
    "checkbox failed semantic write stays unchecked and can retry",
    "checkbox and label pointer actions each write exactly once",
    "checkbox keyboard focus retains one toggle per Space",
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
    "RDP port editing shows the saved port without publishing an edit",
    "RDP port editing can clear the saved port and enter a replacement",
    "RDP port editing invalid edits retain the selected port and do not publish",
    "RDP port editing accepts canonical ports with their editing selection",
    "RDP port editing rebuild retains the current draft and controller",
    "RDP port editing pending save disables editing without losing the draft",
    "RDP port editing removal disposes its text controller",
    "RDP port editing replacement owns a fresh editor and retires the old one",
    "tunnel port editing accepts empty and canonical 16-bit numeric drafts",
    "tunnel port editing rejects the whole invalid edit without changing the draft",
    "tunnel port editing preserves selection and composition of accepted text",
    "tunnel port editing an out-of-range digit preserves the visible port",
    "tunnel port editing invalid paste preserves the selected port and cursor",
    "tunnel port editing clearing and replacing a port still works",
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
KEYBOARD_LAYOUT_TESTS = {
    "keyboard choice exposes one labelled radio per option",
    "keyboard choice tabs once per option and activates with Space",
    "keyboard choice semantics waits for confirmed save",
    "keyboard choice semantic failure preserves selection and retries",
    "keyboard choice keeps both diagram pointer targets",
    "keyboard choice label and radio each submit once",
    "keyboard choice removal refuses captured actions during save",
}

MENU_BUTTON_TESTS = {
    "menu button exposes its enabled role and action",
    "menu button exposes disabled state without an action",
    "menu button paints keyboard focus above its background",
    "menu button retains pointer hover and exit painting",
    "menu button activates once per keyboard or pointer action",
    "menu button disabled rebuild refuses activation and can recover",
}
MENU_BUTTON_SUITES = {
    "toolbar_button_probe_test.dart": {
        f"toolbar {variant} {case}"
        for variant in ("action", "submenu")
        for case in (
            "paints and retires keyboard focus",
            "retains pointer hover and exit",
            "activates by keyboard and pointer",
            "disabling clears focus and permits reuse",
        )
        if variant == "action" or case in (
            "paints and retires keyboard focus", "retains pointer hover and exit")
    },
    "menu_button_test.dart": MENU_BUTTON_TESTS,
    "popup_menu_position_test.dart": {
        f"popup position {variant} {direction} {layout}"
        for variant in ("custom", "material")
        for direction in ("ltr", "rtl")
        for layout in ("root", "offset", "scaled")
    },
    "fixed_width_button_probe_test.dart": {
        f"help button {variant} {case}"
        for variant in ("filled", "outline")
        for case in (
            "exposes its role and action",
            "paints keyboard focus",
            "activates once per keyboard or pointer action",
            "preserves geometry and retires cancelled presses",
        )
    },
}
DRAGGABLE_DIVIDER_TESTS = {
    "divider keyboard horizontal rtl resizes by distance",
    "divider keyboard horizontal ltr resizes by distance",
    "divider keyboard vertical rtl resizes by distance",
    "divider keyboard vertical ltr resizes by distance",
    "divider keyboard ignores modified unrelated and unfocused keys",
    "divider keyboard disabling retires focus and supports fresh traversal",
    "divider keyboard uses the current axis and direction after rebuilding",
    "divider paints keyboard focus and restores its original color",
    "divider RTL mouse drag follows the pointer",
    "divider RTL touch drag follows the pointer",
    "divider horizontal RTL drag keeps vertical distance",
    "divider change to ltr retires the active drag",
    "divider change to rtl retires the active drag",
    "divider primary mouse drag resizes columns by exact distance",
    "divider secondary and middle drags leave columns unchanged",
    "divider touch drag preserves axis distance",
    "divider hover chooses axis cursor without resizing",
    "divider disabled state neither resizes nor advertises resizing",
    "divider disabling an active drag requires a fresh pointer",
    "divider cancelled drag releases input for the next drag",
    "divider trackpad scrolling leaves columns unchanged",
    "divider axis change retires an active drag",
}
LIST_SEARCH_TESTS = {
    "list search ignores Control Left shortcuts",
    "list search ignores Control Right shortcuts",
    "list search ignores Meta Left shortcuts",
    "list search ignores Meta Right shortcuts",
    "list search preserves shifted Option and AltGr characters",
    "list search accumulates and cycles while focus stays inside",
    "list search starts fresh after focus returns from another control",
    "list search keeps pane histories separate after switching back",
    "list search preserves a prefix when a descendant takes focus",
    "list search preserves a prefix across a parent rebuild",
    "list search resets repeated character cycling after focus leaves",
}
TAB_SELECTION_SUITES = {
    "tab_selection_probe_test.dart": {
        "tab selection after closing background last",
        "tab selection after closing background middle right",
        "tab selection after closing background left",
        "tab selection after closing active middle",
        "tab selection after closing active first",
        "tab selection after closing active last",
        "tab selection resets after closing the only tab",
        "tab selection follows the user during delayed close",
        "tab selection survives failed retirement",
        "tab selection refuses indices outside the current list",
        "tab selection presents the selected page after layout",
        "tab selection supersedes an older deferred switch",
        "tab selection retires a removed deferred page index",
        "tab selection applies on mounting after unmounted requests",
        "tab selection cannot replay a retired view switch",
        "tab selection replaces same-count pages between frames",
        "tab selection gives a same-key replacement fresh page state",
        "tab selection preserves surviving page state across list changes",
        "tab notification follows new page initialization",
        "tab notification selects an existing tab without replacement",
        "tab notification coalesces superseded selections before layout",
        "tab notification waits for an unmounted selection to mount",
        "tab notification reapplies the selected tab after remount",
        "tab notification is not repeated for a parent rebuild",
        "tab notification retires a same-key replacement before dispatch",
        "tab notification permits a reentrant selection without duplicates",
        "tab notification retires selection cleared before layout",
    },
    "desktop_tab_retirement_test.dart": {
        "tab removal waits for exact resource retirement",
        "failed retirement keeps the exact tab and reports failure",
        "window close retires every snapshotted tab before clearing",
        "delayed close cannot remove a replacement with the same key",
    },
}

PEER_SEARCH_TESTS = {
    "bulk favorite pending save admits once and retires its selection",
    *{f"bulk favorite {replacement} completion preserves replacement"
      for replacement in ("new-selection", "tab-round-trip")},
    *{f"bulk favorite {failure} failure preserves selection and retries"
      for failure in ("sync", "async")},
    *{f"bulk favorite {retirement}-retired callback refuses dispatch"
      for retirement in ("page", "selection")},
    *{f"bulk favorite {outcome} after page retirement has no feedback"
      for outcome in ("success", "failure")},
    *{f"peer {tab} {case}"
      for tab in ("recent", "fav")
      for case in ("initial filtering renders without a waiting frame",
                   "query changes retire old row actions in one frame",
                   "list updates retire replaced row actions in one frame",
                   "search matches all local fields and clears")},
    "peer layout selection owns one save through rebuild",
    "peer layout save cannot close a later dialog",
    "peer layout retired menu cannot start a save",
    "peer layout retired save drains without late error feedback",
    *{f"peer layout {failure} failure reports and permits retry"
      for failure in ("write", "readback", "invalid", "mismatch")},
    "peer layout cancellation and newly fixed policy refuse writes",
    "peer layout loads all supported saved choices",
    "peer layout rejects invalid saved choices without throwing",
    "peer layout reload replaces a previous choice and recovers",
    "peer layout preserves storage errors and current state",
    "peer search opens focused and publishes typed text",
    "peer search keeps focus and caret through parent rebuilds",
    "peer search does not change selection when focus leaves",
    "peer search selects the query when focus returns",
    "peer search close clears the query and reopening accepts input",
    "peer search disposes its focus node when removed",
}
STATUS_REFRESH_TESTS = {
    "close waits for readiness without admitting a refresh",
    "reentrant close drains the accepted readiness turn",
    "reentrant close drains the accepted refresh turn",
    "never overlaps a slow refresh and waits a full interval",
    "initial readiness is checked once before periodic refresh",
    "a failed turn is visible and does not wedge later turns",
    "close drains the active turn and prevents rearming",
    "close cancels the deferred first turn before it begins",
    "refuses duplicate start and restart after close",
}
STATUS_REFRESH_SUITES = {
    "server_status_refresh_loop_test.dart": STATUS_REFRESH_TESTS,
    "listener_status_probe_test.dart": {
        "reachable listener publishes without a password read",
        "unreachable listener reports configured password false",
        "unreachable listener reports configured password true",
        "listener polling never overlaps either pending read",
        "retired listener refuses a follow-up password read",
        "retired password read cannot update a replacement listener",
        "a stopped listener reads a fresh password explanation",
    },
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
PASSWORD_FIELD_SUITES = {
    "password_text_field_test.dart": PASSWORD_FIELD_TESTS,
    "password_focus_probe_test.dart": {
        "password prompt autofocus opens the editor",
        "password prompt preserves immediate keyboard traversal",
        "password prompt preserves immediate pointer focus",
        "password prompt respects an already focused editor",
        "password prompt rebuild preserves user focus",
        "password prompt reveal preserves text and selection",
        "password prompt removal retires its focus node",
    },
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
    "scroll menu restores thickness after an unconfirmed backend effect",
    "scroll menu read failure retries without writing defaults",
    "scroll menu retired callbacks cannot mutate a replacement session",
    "edge thickness owns a bounded draft without initial writes",
    "edge thickness rebuild retains its draft and latest writer",
    "edge thickness serializes writes and keeps only latest intent",
    "edge thickness refusal mismatch and null results retain retry",
    "edge thickness removal cancels queued and captured edits",
    "edge thickness rebuild preserves an unconfirmed restore",
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
    "custom scale keyboard moves through the hundred percent detent",
    "custom scale accessibility actions move away from the detent",
    "custom scale accessibility reports zoom across the full range",
    "custom scale buttons preserve precise steps and clamp at both ends",
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
    "custom scale retired read completion preserves current loading",
    "custom scale retired save completion preserves current admission",
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
    "hold drag movement uses scaled receiver coordinates",
    "hold drag movement uses rotated receiver coordinates",
    "hold drag movement uses reflected receiver coordinates",
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
    "quality and FPS restore earlier values after unconfirmed saves",
    "quality and FPS rebuilds preserve unconfirmed saves",
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
    "trackpad restores earlier values after unconfirmed saves",
    "trackpad rebuilds preserve unconfirmed saves",
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
    "audio write failure survives rebuild and clears when retry starts",
    "audio retired write failure drains without replacement feedback",
    "audio replacement clears an already reported write failure",
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
    "trackpad dialog confirms retries after unconfirmed saves",
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
    "wheel ordinary directions retain session and dominant axis",
    "wheel inactive owner refuses dispatch and permits fresh input",
    "wheel disposed model refuses retained callbacks",
    "wheel permission refusal permits an authorized retry",
    "wheel view-only and camera refusals retain normal control",
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
    "trackpad slow pinch in retains cumulative zoom",
    "trackpad slow pinch out retains cumulative zoom",
    "trackpad pinch total is independent of event subdivision",
    "trackpad pinch reversal preserves zoom within one wire unit",
    "trackpad pinch remainder retires with its gesture",
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
    "numeric modified sorting has bounded metadata work",
    "numeric size sorting has bounded metadata work",
    "every sort preserves drives directories files and selection",
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
    "confirmed remote file leaves the listing before a later failure",
    "confirmed remote directory leaves the listing before a later failure",
    "confirmed local file leaves the listing before a later failure",
    "confirmed local directory leaves the listing before a later failure",
    "delete result preserves replacement listings and changed entry paths",
    "recursive deletion keeps its row until directory cleanup settles",
    "failed recursive cleanup preserves the directory row and selection",
    "skipping a deletion preserves its row through a later failure",
    "delete remote file failure is visible and stops the batch",
    "delete remote directory failure is visible and stops the batch",
    "delete local file failure is visible and stops the batch",
    "delete local directory failure is visible and stops the batch",
    "delete listing failure stops before the next selected entry",
    "delete allocation failure is visible and permits a fresh retry",
    "delete retired failure cannot replace the current dialog",
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
FILE_PROGRESS_TESTS = {
    "folder summary accepts native whole-number totals",
    "folder summary accepts exact integer totals without rounding",
    "folder summary refuses malformed shapes and oversized input",
    "folder summary refuses invalid action and count fields",
    "folder summary refuses invalid totals without partial mutation",
    "folder summary preserves stale unknown and nontransfer owners",
    "folder summary renders recovery without disclosing payloads",
    "mobile action sheet keeps long ltr text and actions inside a narrow screen",
    "mobile action sheet keeps long rtl text and actions inside a narrow screen",
    "mobile action sheet grows for accessibility text without overflow",
    "mobile action sheet preserves supplied actions across rebuilds",
    "mobile action sheet accepts immutable action lists",
    "mobile action sheet child rebuild keeps one disabled cancel",
    "mobile cancel preserves other jobs and result waiters",
    "mobile late cancel cannot remove replacement or cleared jobs",
    "mobile stale status callback cannot act on replacement jobs",
    "mobile completed status dismisses only displayed job",
    "mobile cancel failure preserves jobs and permits retry",
    "mobile cancel obeys session ownership before and after dispatch",
    "mobile status hides after its only job is cancelled",
    "resume reply preserves earlier done event",
    "resume reply preserves earlier error event",
    "resume reply preserves earlier skipped event",
    "resume reply cannot mutate a removed or replacement job",
    "resume accepts current paused jobs and refuses stale sessions",
    "resume bridge failure preserves the job and permits retry",
    "resume admits one pending request per exact job",
    "resume pending ownership permits independent jobs and failure retry",
    "retired resume cannot release replacement job admission",
    "resume failure cannot publish to retired or replacement jobs",
    "resume failure preserves an earlier terminal event",
    "synchronous resume failure publishes status and releases retry",
    "paused transfer status includes its resume failure",
    "resume refuses nonpaused and nontransfer jobs before dispatch",
    "first file upload progress renders before file completion",
    "first file download progress renders before file completion",
    "before-first progress index cannot complete a file command",
    'file progress accepts zero fractional speed and large byte counts',
    'file progress refuses invalid speeds without partial mutation',
    'file progress refuses invalid byte counts without partial mutation',
    'file progress refuses invalid action and file identities',
    'file progress preserves current jobs on stale or unknown events',
    'file progress diagnostics do not disclose rejected event contents',
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
CHAT_HISTORY_TESTS = {
    "chat history retains the newest 256 messages",
    "chat history bounds retained text independently of message count",
    "chat oversized history copy preserves submitted text and Unicode",
    "chat conversation retention protects selection and newest histories",
    "chat recently updated history survives conversation eviction",
    "chat empty selected conversations share the retention ceiling",
    "chat retained collection views cannot bypass admission",
    "chat clearing history releases its text capacity for reuse",
}
PEER_DATA_TESTS = {
    "chat delayed focus preserves current and disabled node behavior",
    "chat delayed focus retires on overlay unblock and allows reopening",
    "chat delayed focus retires on overlay replacement and allows reopening",
    "chat delayed focus retires on window hide and allows reopening",
    "chat delayed focus retires on overlay hide and allows reopening",
    "chat delayed focus retires on session close and allows reopening",
    "chat delayed focus keeps only the latest request",
    "chat delayed focus disposal retires and refuses later requests",
    "chat panel closing retires focus before a held window reply",
    "chat overlay keeps one listener and current focus behavior",
    "chat overlay replacement retires the previous focus listener",
    "chat overlay replacement during delivery revokes the old callback",
    "chat disposal during overlay delivery retires and refuses bindings",
    "chat Shift Enter preserves the draft with left Shift",
    "chat Shift Enter preserves the draft with right Shift",
    "chat releasing Shift while Enter is held cannot send",
    "chat held Enter cannot submit a later draft",
    "CM voice callback retains its exact owner across client mutation",
    "CM voice identity changes update retained native client state",
    "CM close batch retains rows after accepted submissions",
    "CM close batch refuses a false native result",
    "CM close batch waits for all mixed results",
    "CM close batch joins requests after a bridge error",
    "CM close batch captures owners before replacement",
    "CM close batch accepts empty and disconnected snapshots",
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
    "peer snapshot refuses malformed envelopes without partial publication",
    "peer snapshot refuses a malformed final row atomically",
    "peer snapshot admits native address separators and complete clearing",
    "cached peer decode refuses data without payload diagnostics",
    "cached peer decode preserves snapshots and recovers after refusal",
    "platform metadata refuses input without payload diagnostics",
    "platform metadata preserves snapshots and quiet empty input",
    "resolution metadata refuses partial and private input",
    "resolution metadata preserves both formats and recovery",
}
PEER_CACHE_TESTS = {
    "peer cache publishes current rows and preserves select all",
    "peer cache owns its submitted list and refuses external mutation",
    "peer cache clears immediately when the current tab changes",
    "peer cache retires queued rows across a tab round trip",
    "peer cache coalesces pending updates to the latest list",
    "peer cache disposal cancels pending and refuses later publication",
}
AUTOCOMPLETE_PEER_TESTS = {
    "autocomplete aliased long address fits 220 pixels",
    "autocomplete plain long address fits 220 pixels",
    "autocomplete aliased long address fits 320 pixels",
    "autocomplete plain long address fits 320 pixels",
    "autocomplete short alias and address remain fully visible",
}
PEER_LOADER_TESTS = {
    "peer loader ignores refused snapshots before and after valid data",
    "peer loader waits for data beyond the request receipt",
    "peer loader accepts an empty published result",
    "peer loader retains cached metadata and unique remaining addresses",
    "peer loader does not dispatch overlapping requests",
    "peer loader request failure remains retryable and not loaded",
    "peer loader clear refuses later loading and model publication",
    "peer loader clear retires a pending request and its failure",
}
PEER_DATA_SUITES = {
    "chat_history_test.dart": CHAT_HISTORY_TESTS,
    "peer_decode_test.dart": PEER_DATA_TESTS,
    "peer_tab_cache_test.dart": PEER_CACHE_TESTS,
    "autocomplete_peer_tile_test.dart": AUTOCOMPLETE_PEER_TESTS,
    "all_peers_loader_test.dart": PEER_LOADER_TESTS,
}
SETTINGS_NAVIGATION_TESTS = {
    "desktop theme owns one save across clicks rebuilds and tab changes",
    "desktop theme write failure remains visible and permits retry",
    "desktop theme notification failure stays local and permits retry",
    "desktop theme close drains admitted save and retires callbacks",
    "desktop theme fixed preference rejects retained callbacks",
    "desktop theme publishes effective preference and follow system",
    *{f"mobile boolean {key} {case}"
      for key in ("enable-abr", "allow-auto-disconnect", "allow-auto-record-incoming",
                  "allow-auto-record-outgoing", "enable-show-terminal-extra-keys")
      for case in (
          "owns one save across rebuild and scroll",
          "refusal and mismatch preserve retry",
          "readback error stays local and retries",
          "admitted write drains after close")},
    "mobile boolean fixed options cannot dispatch a save",
    "mobile boolean unrelated options retain independent admission",
    *{f"mobile keep awake {skin} {case}"
      for skin in ("android", "iOS")
      for case in (
          "owns save through rebuild and scrolling",
          "failure and mismatch permit identical retry",
          "readback errors stay local and retry",
          "close drains admitted save and retires callbacks")},
    "recording directory change admits one picker and one save",
    "recording directory closed page cannot apply a picker result",
    "recording directory cancellation and picker failure allow retry",
    "recording directory save failure retries and retires after close",
    "settings sidebar and external requests select the current page",
    "settings close and reopen retire the exact navigation owner",
    *{f"settings {tab} scrolling survives rebuilds and retires on close"
      for tab in ("general", "safety", "display", "about")},
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
        "terminal disposal releases only its owned selection controller",
        "terminal view borrows its controller until model retirement",
        "terminal live input follows the complete pre-open buffer",
        "terminal live input has one ordered sender",
        "terminal pending input retires on close",
        "terminal pending input retires on reopen",
        "terminal pending input retires on replace",
        "terminal pending input retires on dispose",
        "terminal input recovers after send failure sync=false",
        "terminal input recovers after send failure sync=true",
        "terminal input stalls only its own model",
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
    "windows_session_dialog_test.dart": {
        "Windows chooser connects the first advertised session",
        "Windows chooser connects the changed selection",
        "Windows chooser submits only once before unmount",
        "Windows chooser dismissed callbacks have no selection authority",
        "Windows chooser replacement retires the prior submit",
        "Windows chooser retires before reentrant selection dispatch",
        "Windows chooser Enter submits its current selection",
        "Windows chooser numpad Enter submits its current selection",
        "Windows chooser retired dropdown cannot update disposed state",
    },
    "global_event_dispatcher_test.dart": GLOBAL_EVENT_TESTS,
    "peer_model_test.dart": {
        "direct peers retain their address and local display metadata",
        "retired account metadata cannot prevent a direct peer from loading",
        "direct peers expose no retired credential or group fields",
        "disposing owned peers releases their registration",
        "disposed duplicate peers cannot retire the incumbent",
    },
    "connect_password_dialog_lifecycle_test.dart": {
        *(f"connect keyboard action submits once on {platform}" for platform in
          ("android", "iOS", "linux", "windows", "macOS")),
        "connect keyboard action waits for preference and permits retry",
        "connect keyboard action refuses a stale owner",
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
PASSWORD_FIELD_SUITES["connect_password_dialog_lifecycle_test.dart"] = (
    CREDENTIAL_DIALOG_TESTS["connect_password_dialog_lifecycle_test.dart"]
)
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


TRACKPAD_SPEED_SUITES = {
    "trackpad_speed_dialog_test.dart": TRACKPAD_DIALOG_TESTS,
    "trackpad_speed_accessibility_test.dart": {
        "trackpad announces speed across its enabled and disabled range",
        "trackpad accessibility predictions match adjusted and saved speed",
        "trackpad keyboard changes retain confirmed backend values",
        "trackpad disabled accessibility cannot adjust or save speed",
        "trackpad submitted integer speed survives rebuild and reload",
        "trackpad accessibility clamps one point adjustments at both bounds",
    },
}


AUDIO_INPUT_SUITES = {
    "setting_option_mutation_test.dart": {
        name for name in SETTING_OPTION_TESTS if name.startswith("audio ")
    },
    "audio_input_selection_test.dart": {
        'audio choices retain distinct identifiers for duplicate labels',
        'audio choices separate translated system sound from device identity',
        'audio choices preserve current identity across labels and ordering',
        'audio dropdown selects each duplicate device by identifier',
        'audio dropdown retains unavailable selection without a default write',
        'audio dropdown sends the empty system identifier and preserves named devices',
    },
}


RECONNECT_SUITES = {
    'reconnect_backoff_test.dart': {
        'reconnect timer backoff stays bounded through repeated failures',
        'reconnect countdown agrees with the capped timer',
        'reconnect nonretry message cancels and resets the delay',
        'reconnect model reset retires callbacks and resets the delay',
        'reconnect replacement rejects an already queued callback',
        'reconnect retired session refuses scheduling and timer actions',
        'reconnect keyed event cancels and resets the delay',
    },
    'reconnect_schedule_authority_test.dart': {
        'a replaced reconnect callback can never claim the session',
        'credential recovery retires and suppresses generic retries',
        'only native connection admission ends credential recovery',
        'owner reset invalidates every callback from the old owner',
    },
}


VIRTUAL_MOUSE_BUTTONS_TESTS = {
    f'virtual {button} button {case}'
    for button in ('left', 'right')
    for case in (
        'quick tap releases once',
        'early cancellation emits nothing',
        'release retires pending cursor sync',
        'cancel retires pending cursor sync',
        'removal retires pending cursor sync',
        'replacement retires pending cursor sync',
        'release waits for admitted down',
        'removal releases an admitted hold',
    )
} | {'virtual buttons release their own simultaneous holds'}


VIRTUAL_JOYSTICK_TESTS = {
    f'virtual joystick {mode} {case}'
    for mode in ('absolute', 'relative')
    for case in (
        'drag and cancellation stop movement',
        'early cancellation prevents movement',
        'removal stops queued movement',
        'removal before hold prevents movement',
    )
}


FLOATING_POSITION_TESTS = {
    *(f'floating {kind} panel {case}'
      for kind in ('standard', 'ios')
      for case in (
          'avoids the first keyboard inset and restores',
          'opens above an already visible keyboard',
          'keeps its top reachable in a short viewport',
          'preserves an unobscured position',
      )),
    'floating position preserves finite saved coordinates',
    'floating position treats absent or wrong arity as unset',
    'floating position rejects malformed coordinates without throwing',
    'floating position rejects nonfinite coordinates',
    'floating position reload discards an invalid saved checkpoint',
    'floating position invalid data leaves other positions loadable',
    'floating position places the actual draggable at saved coordinates',
    'floating position preserves storage read errors',
}


FILE_COLUMNS_TESTS = {
    f'file columns {direction} {side} uses visible Size width'
    for direction in ('ltr', 'rtl') for side in ('local', 'remote')
} | {
    f'file columns {direction} {behavior}'
    for direction in ('ltr', 'rtl') for behavior in (
        'first divider clamps both adjacent widths',
        'last divider clamps rendered Size width',
        'keyboard reaches the visible width limit',
        'header and row boundaries agree',
    )
} | {'file columns resizing the window uses the current rendered capacity'}


FILE_SEARCH_TESTS = {
    'file search selects only visible entries in both panes',
    'file search uses the filtered row index for scrolling',
    'file search follows directory replacement without parent rebuild',
    'file search cycles current visible rows and wraps',
    'file search restarts after its selected row disappears',
    'file search reflects a new visible row order',
    'file search repeats Unicode graphemes',
    'file search repeats after multi-selection',
    'file search retired callbacks do not alter current selection',
    'file search retired sessions ignore both callbacks',
    'file search missing matches and empty listings clear selection',
    'file search preserves unfiltered prefix and repeat behavior',
}


SCREENSHOT_SAVE_TESTS = {
    'screenshot save preserves selected path and exact request',
    'screenshot picker cancellation discards its exact request',
    'screenshot save returned error is visible',
    'screenshot picker synchronous exception is visible',
    'screenshot picker asynchronous exception is visible',
    'screenshot save synchronous exception is visible',
    'screenshot save asynchronous exception is visible',
    'screenshot retired before deferred picker cannot start it',
    'screenshot retired picker completion cannot save',
    'screenshot retired picker exception stays silent',
    'screenshot retired save exception stays silent',
    'screenshot retired save returned error stays silent',
}


CLIPBOARD_KEYSTROKES_TESTS = {
    'clipboard keystrokes send current Unicode text unchanged',
    'clipboard keystrokes ignore an unavailable clipboard',
    'clipboard keystrokes are absent in view only mode',
    'clipboard keystrokes preserve role and keyboard restrictions',
    'clipboard keystrokes stale callback refuses clipboard access',
    'clipboard keystrokes replaced owner refuses clipboard access',
    'clipboard keystrokes close during read prevents input',
    'clipboard keystrokes session replacement during read prevents input',
    'clipboard keystrokes owner replacement during read prevents input',
    'clipboard keystrokes permission loss during read prevents input',
    'clipboard keystrokes view only change during read prevents input',
    'clipboard keystrokes unrelated metadata change preserves input',
}


CREDENTIAL_BADGE_SUITES = {
    "peer_credential_badge_test.dart": FILE_NAVIGATION_SUITES["peer_credential_badge_test.dart"],
    "peer_credential_badge_accessibility_test.dart": {
        "credential retry exposes a labelled enabled button action",
        "credential retry activates once with Enter",
        "credential retry activates once with Space",
        "credential retry paints keyboard focus",
        "credential retry pointer activation admits one pending read",
    },
}


MODEL_TESTS = {
    "android_permission_request_coordinator_test.dart": {
        "immediate grant completes the already-owned request",
        "denial completes instead of leaving the request pending",
        "stale type or identity cannot retire the current request",
        "overlap cannot displace the in-flight request",
        "a predecessor callback cannot complete its successor",
    },
    "blockable_overlay_test.dart": CREDENTIAL_DIALOG_TESTS["blockable_overlay_test.dart"],
    "custom_cursor_registry_test.dart": {
        "activation queue preserves issue order across asynchronous turns",
        "replacement owns display before old lease deletion",
        "Flutter manager replacement presents before predecessor release",
        "device removal revokes a pending activation before presentation",
        "Flutter pointer route retires only the removed device",
        "stale device retirement cannot revoke its replacement",
        "unactivated replacement chain inherits predecessor retirement",
        "owner retirement revokes every owned device and waits for fallback",
        "in-flight presentation retains its lease through fallback",
        "slow obsolete registration cannot block a newer activation",
        "failed desired registration falls back before old lease deletion",
        "failed fallback retains the possibly displayed lease",
        "partial presentation failure retains both possible displays",
        "bounds count and bytes with deterministic inactive LRU eviction",
        "entry and byte limits are global across UI owners",
        "never evicts an active platform cursor and refuses excess capacity",
        "pending registration remains globally accounted until finality",
        "retirement waits for registration and the final exact lease",
        "failed registration releases capacity without invoking delete",
        "uncertain registration attempts exact cleanup and fails closed",
        "replacement registration waits for exact eviction deletion",
        "uncertain deletion fails closed for all later registrations",
        "throwing presentation diagnostics cannot interrupt fallback finality",
        "throwing registry diagnostics cannot strand registration finality",
    },
    "desktop_tab_retirement_test.dart": {
        "tab removal waits for exact resource retirement",
        "failed retirement keeps the exact tab and reports failure",
        "window close retires every snapshotted tab before clearing",
        "delayed close cannot remove a replacement with the same key",
    },
    "desktop_texture_lifecycle_test.dart": {
        "retirement before initialization completes prevents late publication",
        "published texture is unpublished before one exact release",
        "initialization failure is reported and the allocation is released",
        "rejected initialization is reported and the allocation is released",
        "failed publication is unpublished and released immediately",
        "unpublication failure retains native allocation and fails retirement",
        "release refusal and exception remain visible through exact retirement",
        "failed slot creation is bounded and a later demand can retry",
        "failed asynchronous activation is retired and retry is bounded",
        "new demand during failed activation receives a fresh exact attempt",
        "failed retirement blocks replacement and remains terminal",
        "withdrawal during successful activation retires before replacement",
        "replacement waits for exact predecessor retirement",
    },
    "desktop_window_dispatch_test.dart": WINDOW_DISPATCH_TESTS,
    "display_selection_queue_test.dart": {
        "keeps one running display selection and only the latest successor",
        "a refused display selection does not wedge its bounded successor",
        "a failed display selection does not wedge its bounded successor",
        "a stale owner cannot enter the display selection sequencer",
        "a retired session cannot block its replacement session",
    },
    "file_command_session_ownership_test.dart": FILE_COMMAND_TESTS | {"failed recursive cleanup preserves the directory row and selection"},
    "file_dialog_event_loop_test.dart": FILE_NAVIGATION_SUITES["file_dialog_event_loop_test.dart"],
    "global_event_dispatcher_test.dart": GLOBAL_EVENT_TESTS,
    "latest_frame_queue_test.dart": FRAME_QUEUE_TESTS,
    "mobile_file_session_lifecycle_test.dart": {
        "directory response owner exists before bridge dispatch settles",
        "empty and recursive response owners exist before dispatch settles",
        "recursive requests require a positive signed-32-bit action ID",
        "recursive errors require an exact canonical event owner",
        "response must match session, locality, operation, and key",
        "retirement cancels an in-flight dispatch and permits replacement",
        "dispatch failure removes its exact reservation",
        "one total capacity bounds all response maps",
        "timeout quarantines its key until the late response is consumed",
        "timed-out directory retains capacity until dispatch settles",
        "timed-out empty-directory retains capacity until dispatch settles",
        "timed-out recursive-response retains capacity until dispatch settles",
        "timed-out recursive-error retains capacity until dispatch settles",
    },
    "mobile_session_start_queue_test.dart": {
        "retains one running request and only the latest pending request",
        "cancels the exact pending request without interrupting finality",
        "closing the running request waits while a newer request is pending",
        "a failed running request does not wedge the bounded successor",
    },
    "owned_image_paint_test.dart": CANVAS_IMAGE_TESTS,
    "permanent_password_dialog_lifecycle_test.dart": CREDENTIAL_DIALOG_TESTS["permanent_password_dialog_lifecycle_test.dart"],
    "presentation_recovery_test.dart": {
        "presentation readiness invokes only its exact session owner",
        "stale cleanup cannot clear a replacement readiness registration",
        "clearing readiness invalidates every retained registration",
        "initial and duplicate resume notifications do not request a refresh",
        "one suspended presentation produces one refresh",
        "a hidden desktop tab retains recovery until it is selected",
        "a failed refresh is rearmed for a later resume transition",
        "exact readiness retries a failed visible recovery",
        "readiness alone never creates a refresh demand",
        "readiness during a failing request preserves one exact retry",
        "readiness while suspended waits for the visible owner",
        "suspend and resume during a request preserve one follow-up refresh",
        "retirement cancels pending and in-flight follow-up recovery",
        "retirement still reports an in-flight refresh failure",
    },
    "reconnect_schedule_authority_test.dart": RECONNECT_SUITES["reconnect_schedule_authority_test.dart"],
    "remote_key_routing_test.dart": {
        "Android navigation Back never enters the remote handler",
        "Flutter key-state synchronization also preserves local Back ownership",
        "physical Back with the Android logical key still forwards both edges",
        "physical browser Back keeps its distinct remote logical identity",
        "a physical-ID collision alone cannot suppress another logical key",
        "non-Android routing preserves the exact event and handler result",
        "focused Android Back reaches ancestors without remote input",
        "focused physical Android Back remains remote input",
    },
    "rgba_publication_order_test.dart": {
        "a newer admission does not suppress an earlier useful completion",
        "a higher completion permanently rejects a lower late result",
        "a higher conversion failure does not starve a lower completion",
        "completion order remains global across displays",
        "an exact new session invalidates predecessor work and may restart",
        "retirement invalidates admitted work and resets publication order",
        "nonpositive and duplicate native publications are rejected",
    },
    "server_model_test.dart": {
        "controlled clients ignore retired role-swap state",
        "full CM snapshot repairs same-count owner and state changes",
        "CM snapshot validates owners before mutating live client state",
        "incremental CM admission retires every disconnected same-peer row",
        "Android service command owns preflight through final dispatch",
        "Android service command failure releases only the command latch",
        "Android running service without capture requests MediaProjection",
    },
    "server_status_refresh_loop_test.dart": STATUS_REFRESH_TESTS,
    "session_event_queue_test.dart": {
        "runs bounded session-state work in native stream order",
        "media checkpoints neither consume capacity nor survive later state",
        "capacity failure retires running and queued session-state work",
        "task failure is terminal and does not run retained successors",
        "mismatched owners are refused before invocation",
        "exact retirement cannot block a replacement session",
    },
    "session_stream_finality_test.dart": {
        "an exact normal-close event suppresses later stream termination",
        "unexpected stream termination is admitted exactly once",
        "replacement invalidates the predecessor with the same owner",
        "owner retirement cannot retire a different current owner",
    },
    "start_ellipsis_text_test.dart": PATH_LABEL_TESTS,
    "terminal_model_lifecycle_test.dart": TERMINAL_OUTPUT_TESTS["terminal_model_lifecycle_test.dart"],
    "terminal_output_decoder_test.dart": TERMINAL_OUTPUT_TESTS["terminal_output_decoder_test.dart"],
}


def parse_result(path, profile="models"):
    require(profile in {"models", "frame-queue", "direct-address", "file-metadata", "password-fields", "share-rdp", "connect-password", "credential-dialog", "terminal-output", "settings-navigation", "desktop-theme", "window-dispatch", "menu-button", "keyboard-layout", "hold-drag", "locales", "path-labels", "setting-checkbox", "draggable-divider", "list-search", "credential-badge", "peer-search", "tab-selection", "status-refresh", "peer-data", "file-progress", "custom-scale", "trackpad-speed", "floating-position", "virtual-joystick", "virtual-mouse-buttons", "screenshot-save", "clipboard-keystrokes", "file-search", "file-columns", "audio-input", "reconnect", "file-navigation", "directory-ordering", "modifier-release", "auto-disconnect"}, "test profile is unknown")
    expected_suites = set(MODEL_TESTS)
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
    elif profile == "hold-drag":
        expected_suites = {"hold_tap_move_test.dart"}
        expected_tests = len(HOLD_DRAG_TESTS)
        expected_names = HOLD_DRAG_TESTS
    elif profile == "locales":
        expected_suites = {"locales_test.dart"}
        expected_tests = len(LOCALE_TESTS)
        expected_names = LOCALE_TESTS
    elif profile == "path-labels":
        expected_suites = {"start_ellipsis_text_test.dart"}
        expected_tests = len(PATH_LABEL_TESTS)
        expected_names = PATH_LABEL_TESTS
    elif profile == "setting-checkbox":
        expected_suites = {"setting_checkbox_test.dart"}
        expected_tests = len(SETTING_CHECKBOX_TESTS)
        expected_names = SETTING_CHECKBOX_TESTS
    elif profile == "keyboard-layout":
        expected_suites = {"keyboard_layout_probe_test.dart"}
        expected_names = KEYBOARD_LAYOUT_TESTS
        expected_tests = len(expected_names)
    elif profile == "menu-button":
        expected_by_suite = MENU_BUTTON_SUITES
        expected_suites = set(expected_by_suite)
        expected_names = set().union(*expected_by_suite.values())
        expected_tests = len(expected_names)
    elif profile == "draggable-divider":
        expected_suites = {"draggable_divider_test.dart"}
        expected_tests = len(DRAGGABLE_DIVIDER_TESTS)
        expected_names = DRAGGABLE_DIVIDER_TESTS
    elif profile == "list-search":
        expected_suites = {"list_search_action_listener_test.dart"}
        expected_tests = len(LIST_SEARCH_TESTS)
        expected_names = LIST_SEARCH_TESTS
    elif profile == "credential-badge":
        expected_by_suite = CREDENTIAL_BADGE_SUITES
        expected_suites = set(expected_by_suite)
        expected_tests = sum(map(len, expected_by_suite.values()))
        expected_names = set().union(*expected_by_suite.values())
    elif profile == "peer-search":
        expected_suites = {"peer_search_probe_test.dart"}
        expected_tests = len(PEER_SEARCH_TESTS)
        expected_names = PEER_SEARCH_TESTS
    elif profile == "tab-selection":
        expected_by_suite = TAB_SELECTION_SUITES
        expected_suites = set(expected_by_suite)
        expected_names = set().union(*expected_by_suite.values())
        expected_tests = len(expected_names)
    elif profile == "status-refresh":
        expected_by_suite = STATUS_REFRESH_SUITES
        expected_suites = set(expected_by_suite)
        expected_names = set().union(*expected_by_suite.values())
        expected_tests = len(expected_names)
    elif profile == "share-rdp":
        expected_suites = {"share_rdp_change_lifecycle_test.dart"}
        expected_tests = len(SHARE_RDP_TESTS)
        expected_names = SHARE_RDP_TESTS
    elif profile == "password-fields":
        expected_by_suite = PASSWORD_FIELD_SUITES
        expected_suites = set(expected_by_suite)
        expected_names = set().union(*expected_by_suite.values())
        expected_tests = len(expected_names)
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
            "relative_mouse_enable_probe_test.dart": RELATIVE_MOUSE_ENABLE_TESTS,
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
    elif profile == "audio-input":
        expected_by_suite = AUDIO_INPUT_SUITES
        expected_suites = set(expected_by_suite)
        expected_names = set().union(*expected_by_suite.values())
        expected_tests = len(expected_names)
    elif profile == "reconnect":
        expected_by_suite = RECONNECT_SUITES
        expected_suites = set(expected_by_suite)
        expected_names = set().union(*expected_by_suite.values())
        expected_tests = len(expected_names)
    elif profile == "trackpad-speed":
        expected_by_suite = TRACKPAD_SPEED_SUITES
        expected_suites = set(expected_by_suite)
        expected_names = set().union(*expected_by_suite.values())
        expected_tests = len(expected_names)
    elif profile == "custom-scale":
        expected_suites = {"custom_scale_controls_test.dart"}
        expected_tests = len(CUSTOM_SCALE_TESTS)
        expected_names = CUSTOM_SCALE_TESTS
    elif profile == "virtual-mouse-buttons":
        expected_suites = {"virtual_mouse_button_probe_test.dart"}
        expected_tests = len(VIRTUAL_MOUSE_BUTTONS_TESTS)
        expected_names = VIRTUAL_MOUSE_BUTTONS_TESTS
    elif profile == "virtual-joystick":
        expected_suites = {"virtual_joystick_test.dart"}
        expected_tests = len(VIRTUAL_JOYSTICK_TESTS)
        expected_names = VIRTUAL_JOYSTICK_TESTS
    elif profile == "floating-position":
        expected_suites = {"draggable_position_test.dart"}
        expected_tests = len(FLOATING_POSITION_TESTS)
        expected_names = FLOATING_POSITION_TESTS
    elif profile == "screenshot-save":
        expected_suites = {"screenshot_save_probe_test.dart"}
        expected_tests = len(SCREENSHOT_SAVE_TESTS)
        expected_names = SCREENSHOT_SAVE_TESTS
    elif profile == "clipboard-keystrokes":
        expected_suites = {"clipboard_keystrokes_probe_test.dart"}
        expected_tests = len(CLIPBOARD_KEYSTROKES_TESTS)
        expected_names = CLIPBOARD_KEYSTROKES_TESTS
    elif profile == "file-columns":
        expected_suites = {"file_columns_probe_test.dart"}
        expected_tests = len(FILE_COLUMNS_TESTS)
        expected_names = FILE_COLUMNS_TESTS
    elif profile == "file-search":
        expected_suites = {"file_search_probe_test.dart"}
        expected_tests = len(FILE_SEARCH_TESTS)
        expected_names = FILE_SEARCH_TESTS
    elif profile == "file-progress":
        expected_suites = {"file_progress_test.dart"}
        expected_tests = len(FILE_PROGRESS_TESTS)
        expected_names = FILE_PROGRESS_TESTS
    elif profile == "peer-data":
        expected_by_suite = PEER_DATA_SUITES
        expected_suites = set(expected_by_suite)
        expected_names = set().union(*expected_by_suite.values())
        expected_tests = len(expected_names)
    elif profile in {"settings-navigation", "desktop-theme"}:
        expected_suites = {"settings_navigation_probe_test.dart"}
        expected_names = SETTINGS_NAVIGATION_TESTS
        if profile == "desktop-theme":
            expected_names = {name for name in expected_names
                              if name.startswith(("desktop theme", "recording directory", "settings "))}
        expected_tests = len(expected_names)
    elif profile == "terminal-output":
        expected_by_suite = TERMINAL_OUTPUT_TESTS
        expected_suites = set(expected_by_suite)
        expected_names = set().union(*expected_by_suite.values())
        expected_tests = len(expected_names)
    elif profile == "connect-password":
        expected_suites = {"connect_password_dialog_lifecycle_test.dart"}
        expected_names = CREDENTIAL_DIALOG_TESTS["connect_password_dialog_lifecycle_test.dart"]
        expected_tests = len(expected_names)
    elif profile == "credential-dialog":
        expected_by_suite = CREDENTIAL_DIALOG_TESTS
        expected_suites = set(expected_by_suite)
        expected_names = set().union(*expected_by_suite.values())
        expected_tests = len(expected_names)
    else:
        expected_tests = model_test_count()
    suites = {}
    tests = {}
    completed = set()
    starts = 0
    done_events = 0
    events = 0
    visible_successes = 0
    visible_names = set()
    with open(path, "rb", opener=lambda name, flags: os.open(
            name, flags | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)) as stream:
        metadata = os.fstat(stream.fileno())
        require(stat.S_ISREG(metadata.st_mode), "result is not one regular file")
        require(metadata.st_nlink == 1, "result has multiple links")
        require(metadata.st_size <= MAXIMUM_BYTES, "result exceeds its byte bound")
        bytes_read = 0
        while True:
            raw_line = stream.readline(min(
                MAXIMUM_LINE_BYTES, metadata.st_size - bytes_read) + 1)
            if not raw_line:
                break
            bytes_read += len(raw_line)
            require(bytes_read <= metadata.st_size, "result grew while reading")
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
        after = os.fstat(stream.fileno())
        require(bytes_read == metadata.st_size, "result length changed while reading")
        require(after.st_nlink == 1 and
                (after.st_size, after.st_mtime_ns, after.st_ctime_ns) ==
                (metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns),
                "result changed while reading")

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
        "--profile", choices=("models", "frame-queue", "direct-address", "file-metadata", "password-fields", "share-rdp", "connect-password", "credential-dialog", "terminal-output", "settings-navigation", "desktop-theme", "window-dispatch", "menu-button", "keyboard-layout", "hold-drag", "locales", "path-labels", "setting-checkbox", "draggable-divider", "list-search", "credential-badge", "peer-search", "tab-selection", "status-refresh", "peer-data", "file-progress", "custom-scale", "trackpad-speed", "floating-position", "virtual-joystick", "virtual-mouse-buttons", "screenshot-save", "clipboard-keystrokes", "file-search", "file-columns", "audio-input", "reconnect", "file-navigation", "directory-ordering", "modifier-release", "auto-disconnect"), default="models"
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
        "menu-button": "FLUTTER_MENU_BUTTON_TEST_JSON",
        "hold-drag": "FLUTTER_HOLD_DRAG_TEST_JSON",
        "locales": "FLUTTER_LOCALE_TEST_JSON",
        "path-labels": "FLUTTER_PATH_LABEL_TEST_JSON",
        "setting-checkbox": "FLUTTER_SETTING_CHECKBOX_TEST_JSON",
        "draggable-divider": "FLUTTER_DRAGGABLE_DIVIDER_TEST_JSON",
        "list-search": "FLUTTER_LIST_SEARCH_TEST_JSON",
        "credential-badge": "FLUTTER_CREDENTIAL_BADGE_TEST_JSON",
        "peer-search": "FLUTTER_PEER_SEARCH_TEST_JSON",
        "tab-selection": "FLUTTER_TAB_SELECTION_TEST_JSON",
        "status-refresh": "FLUTTER_STATUS_REFRESH_TEST_JSON",
        "share-rdp": "FLUTTER_SHARE_RDP_TEST_JSON",
        "window-dispatch": "FLUTTER_WINDOW_DISPATCH_TEST_JSON",
        "modifier-release": "FLUTTER_MODIFIER_RELEASE_TEST_JSON",
        "auto-disconnect": "FLUTTER_AUTO_DISCONNECT_TEST_JSON",
        "keyboard-layout": "FLUTTER_KEYBOARD_LAYOUT_TEST_JSON",
        "directory-ordering": "FLUTTER_DIRECTORY_ORDERING_TEST_JSON",
        "file-navigation": "FLUTTER_FILE_NAVIGATION_TEST_JSON",
        "custom-scale": "FLUTTER_CUSTOM_SCALE_TEST_JSON",
        "trackpad-speed": "FLUTTER_TRACKPAD_SPEED_TEST_JSON",
        "virtual-mouse-buttons": "FLUTTER_VIRTUAL_MOUSE_BUTTONS_TEST_JSON",
        "virtual-joystick": "FLUTTER_VIRTUAL_JOYSTICK_TEST_JSON",
        "floating-position": "FLUTTER_FLOATING_POSITION_TEST_JSON",
        "screenshot-save": "FLUTTER_SCREENSHOT_SAVE_TEST_JSON",
        "clipboard-keystrokes": "FLUTTER_CLIPBOARD_KEYSTROKES_TEST_JSON",
        "file-search": "FLUTTER_FILE_SEARCH_TEST_JSON",
        "file-columns": "FLUTTER_FILE_COLUMNS_TEST_JSON",
        "audio-input": "FLUTTER_AUDIO_INPUT_TEST_JSON",
        "reconnect": "FLUTTER_RECONNECT_TEST_JSON",
        "file-progress": "FLUTTER_FILE_PROGRESS_TEST_JSON",
        "peer-data": "FLUTTER_PEER_DATA_TEST_JSON",
        "settings-navigation": "FLUTTER_SETTINGS_NAVIGATION_TEST_JSON",
        "desktop-theme": "FLUTTER_SETTINGS_NAVIGATION_TEST_JSON",
        "terminal-output": "FLUTTER_TERMINAL_OUTPUT_TEST_JSON",
        "connect-password": "FLUTTER_CONNECT_PASSWORD_TEST_JSON",
        "credential-dialog": "FLUTTER_CREDENTIAL_DIALOG_TEST_JSON",
    }[arguments.profile]
    print("{}=pass suites={} tests={}".format(prefix, suites, tests))
    return 0


if __name__ == "__main__":
    sys.exit(main())
