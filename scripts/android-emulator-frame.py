#!/usr/bin/env python3
"""Validate and classify one externally observed Android emulator display frame."""

from __future__ import annotations

import collections
import os
import re
import stat
import struct
import sys
import tempfile
import time
from pathlib import Path


MAGIC = b"RUSTDESK_ANDROID_FRAME_V1\n"
MAX_RECORD_BYTES = 256 * 1024
ALLOWED_DIMENSIONS = {(120, 200), (200, 120)}
PALETTE = (
    (232, 36, 36),
    (36, 224, 48),
    (36, 64, 232),
    (232, 220, 36),
    (224, 36, 220),
    (36, 220, 220),
    (240, 120, 24),
    (128, 40, 232),
    (24, 132, 232),
    (232, 40, 128),
    (132, 232, 24),
    (24, 232, 132),
    (196, 92, 44),
    (44, 196, 92),
    (92, 44, 196),
    (196, 196, 196),
)
STATE_CODE_BARS = 24
STATE_CODE_ROWS = 4
MAX_SOURCE_BYTES = 2 * 1024 * 1024
FRESHNESS_LIMIT_MS = 2000
STATE_CODE_MIN_BAR_WIDTH = 3
STATE_CODE_MIN_CONTRAST = 8
STATE_CODE_MIN_SEPARATION = 5
METADATA = re.compile(
    rb"seq=([0-9]+) timestamp_us=([0-9]+) observed_epoch_us=([0-9]+) "
    rb"observed_monotonic_ns=([0-9]+) width=([0-9]+) height=([0-9]+) "
    rb"format=rgb888 orientation=bottom-up bytes=([0-9]+)\n"
)


class InvalidFrame(ValueError):
    pass


def parse_record(data: bytes, now_monotonic_ns: int | None = None) -> dict[str, object]:
    if len(data) > MAX_RECORD_BYTES:
        raise InvalidFrame("record exceeds its byte bound")
    if not data.startswith(MAGIC):
        raise InvalidFrame("record magic differs")
    try:
        header, pixels = data[len(MAGIC) :].split(b"\n", 1)
    except ValueError as error:
        raise InvalidFrame("record has no metadata terminator") from error
    match = METADATA.fullmatch(header + b"\n")
    if match is None:
        raise InvalidFrame("record metadata differs")
    (
        sequence,
        timestamp_us,
        observed_epoch_us,
        observed_monotonic_ns,
        width,
        height,
        declared_bytes,
    ) = map(int, match.groups())
    if sequence > 0xFFFFFFFF:
        raise InvalidFrame("sequence exceeds uint32")
    if timestamp_us == 0 or observed_epoch_us == 0 or observed_monotonic_ns == 0:
        raise InvalidFrame("frame timestamps must be nonzero")
    if (width, height) not in ALLOWED_DIMENSIONS:
        raise InvalidFrame("frame dimensions differ")
    expected_bytes = width * height * 3
    if declared_bytes != expected_bytes or len(pixels) != expected_bytes:
        raise InvalidFrame("pixel length differs")
    transport_us = observed_epoch_us - timestamp_us
    if transport_us < -5_000 or transport_us > 60_000_000:
        raise InvalidFrame("emulator timestamp is outside the admitted clock window")
    if now_monotonic_ns is None:
        now_monotonic_ns = time.monotonic_ns()
    queue_ns = now_monotonic_ns - observed_monotonic_ns
    if queue_ns < 0 or queue_ns > 60_000_000_000:
        raise InvalidFrame("observer publication timestamp is outside the admitted window")
    observation_us = max(0, transport_us) + (queue_ns + 999) // 1_000
    observation_ms = (observation_us + 999) // 1_000
    return {
        "sequence": sequence,
        "timestamp_us": timestamp_us,
        "observed_epoch_us": observed_epoch_us,
        "observed_monotonic_ns": observed_monotonic_ns,
        "observation_ms": observation_ms,
        "width": width,
        "height": height,
        "pixels": pixels,
    }


def state_code_bars(state: int, row: int) -> tuple[int, ...]:
    if not 0 <= state <= 0xFFFFFFFF or not 0 <= row < STATE_CODE_ROWS:
        raise InvalidFrame("frame identity or band ordinal differs")
    value = (row << 8) | ((state >> (24 - row * 8)) & 255)
    bars = [0, 1]
    for shift in range(9, -1, -1):
        bit = (value >> shift) & 1
        bars.extend((bit, bit ^ 1))
    bars.extend((1, 0))
    return tuple(bars)


def pixel_luma(
    pixels: memoryview, width: int, height: int, logical_y: int, x: int
) -> int:
    storage_y = height - logical_y - 1
    offset = (storage_y * width + x) * 3
    return (
        54 * pixels[offset]
        + 183 * pixels[offset + 1]
        + 19 * pixels[offset + 2]
    ) // 256


def decode_state_code_row(
    pixels: memoryview,
    width: int,
    height: int,
    logical_y: int,
    left: int,
    span: int,
) -> tuple[int, int] | None:
    values = tuple(
        pixel_luma(
            pixels,
            width,
            height,
            logical_y,
            left + ((2 * bar + 1) * span) // (2 * STATE_CODE_BARS),
        )
        for bar in range(STATE_CODE_BARS)
    )
    contrasts = [values[1] - values[0], values[-2] - values[-1]]
    if min(contrasts) < STATE_CODE_MIN_CONTRAST:
        return None
    state = 0
    for bar in range(2, STATE_CODE_BARS - 2, 2):
        difference = values[bar] - values[bar + 1]
        contrast = abs(difference)
        if contrast < STATE_CODE_MIN_CONTRAST:
            return None
        state = (state << 1) | int(difference > 0)
        contrasts.append(contrast)
    ordinal = state >> 8
    expected = state_code_bars((state & 255) << (24 - ordinal * 8), ordinal)
    dark = [value for value, white in zip(values, expected) if not white]
    light = [value for value, white in zip(values, expected) if white]
    separation = min(light) - max(dark)
    if separation < STATE_CODE_MIN_SEPARATION:
        return None
    return state, min(contrasts + [separation])


def source_history(path: Path, now_monotonic_ns: int | None = None) -> dict[int, int]:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        metadata = os.fstat(descriptor)
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
                or metadata.st_uid != os.getuid() or metadata.st_gid != os.getgid()
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or not 0 < metadata.st_size <= MAX_SOURCE_BYTES):
            raise InvalidFrame("source publication file authority differs")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            data = stream.read(metadata.st_size)
        if len(data) != metadata.st_size:
            raise InvalidFrame("source publication prefix was truncated")
    finally:
        os.close(descriptor)
    if now_monotonic_ns is None:
        now_monotonic_ns = time.monotonic_ns()
    # The sole writer appends flushed records. Ignore only an unfinished final line.
    lines = data[:data.rfind(b"\n") + 1].splitlines()
    if not lines or re.fullmatch(
        rb"FLUTTER_PEER_SOURCE_READY display=:[0-9]+ dimensions=640x480 interval_ms=250 "
        rb"identity=counter32 rows=4 bars=24 wrap=refused", lines[0]
    ) is None:
        raise InvalidFrame("source frame identity format differs")
    history = {}
    previous_us = 0
    complete = False
    for line in lines[1:]:
        match = re.fullmatch(
            rb"RUSTDESK_PRESENTATION_TRACE stage=source-publish monotonic_us=([0-9]+) "
            rb"state=([0-9]+) low=([0-9]+) high=([0-9]+)", line
        )
        if match is None:
            if (not complete and line == f"FLUTTER_PEER_SOURCE_COMPLETE frames={len(history)}".encode()):
                complete = True
                continue
            raise InvalidFrame("source publication record differs")
        publication_us, identity, low, high = map(int, match.groups())
        if (complete or identity != len(history) or identity > 0xFFFFFFFF
                or identity >= 32768 or not previous_us < publication_us <= now_monotonic_ns // 1000
                or low != identity & 15 or high != (identity >> 4) & 15):
            raise InvalidFrame("source publication identity or clock is incoherent")
        history[identity] = publication_us
        previous_us = publication_us
    if not history:
        raise InvalidFrame("source has no complete publication evidence")
    return history


def analyze(record: dict[str, object], history: dict[int, int],
            now_monotonic_ns: int | None = None) -> dict[str, object]:
    width = int(record["width"])
    height = int(record["height"])
    pixels = memoryview(record["pixels"])
    sampled_colors: collections.Counter[tuple[int, int, int]] = collections.Counter()
    for storage_y in range(height):
        row_offset = storage_y * width * 3
        for x in range(width):
            offset = row_offset + x * 3
            rgb = (pixels[offset], pixels[offset + 1], pixels[offset + 2])
            sampled_colors[rgb] += 1

    minimum_span = max(STATE_CODE_BARS * STATE_CODE_MIN_BAR_WIDTH, width * 3 // 5)
    spans = list(range(minimum_span, width + 1, 2))
    if not spans or spans[-1] != width:
        spans.append(width)
    best_by_state: dict[int, dict[str, object]] = {}
    decoded_rows = 0
    geometries = 0

    for span in spans:
        centered_left = (width - span) // 2
        lefts = sorted(
            {
                centered_left + delta
                for delta in range(-3, 4)
                if 0 <= centered_left + delta <= width - span
            }
        )
        for left in lefts:
            geometries += 1
            run_state = None
            run_top = 0
            run_rows = 0
            run_contrast = 0
            runs = []
            for logical_y in range(height):
                decoded = decode_state_code_row(
                    pixels, width, height, logical_y, left, span
                )
                if decoded is None:
                    if run_state is not None:
                        runs.append((run_state, run_rows, run_top, run_contrast))
                    run_state = None
                    run_rows = 0
                    run_contrast = 0
                    continue
                decoded_rows += 1
                state, contrast = decoded
                if state == run_state:
                    run_rows += 1
                    run_contrast = min(run_contrast, contrast)
                else:
                    if run_state is not None:
                        runs.append((run_state, run_rows, run_top, run_contrast))
                    run_state = state
                    run_top = logical_y
                    run_rows = 1
                    run_contrast = contrast
            if run_state is not None:
                runs.append((run_state, run_rows, run_top, run_contrast))
            for start in range(len(runs) - STATE_CODE_ROWS + 1):
                bands = runs[start:start + STATE_CODE_ROWS]
                if [value >> 8 for value, _, _, _ in bands] != list(range(STATE_CODE_ROWS)):
                    continue
                lengths = [rows for _, rows, _, _ in bands]
                if min(lengths) < 3 or max(lengths) - min(lengths) > 2:
                    continue
                if any(not 0 <= bands[row + 1][2] - bands[row][2] - bands[row][1] <= 2
                       for row in range(STATE_CODE_ROWS - 1)):
                    continue
                state = 0
                for value, _, _, _ in bands:
                    state = (state << 8) | (value & 255)
                candidate = {
                    "score": sum(lengths), "state": state, "layout": "left-right",
                    "matched": sum(lengths) * STATE_CODE_BARS, "left": left,
                    "span": span, "top": bands[0][2],
                    "contrast": min(band[3] for band in bands), "minimum": 12,
                }
                previous = best_by_state.get(state)
                ranking = (candidate["score"], candidate["contrast"], span)
                if previous is None or ranking > (previous["score"], previous["contrast"], previous["span"]):
                    best_by_state[state] = candidate

    # Include all decoding time. Observation time describes the capture, not the content age.
    if now_monotonic_ns is None:
        now_monotonic_ns = time.monotonic_ns()
    for state, candidate in best_by_state.items():
        publication_us = history.get(state)
        known = publication_us is not None and 0 < publication_us * 1000 <= int(record["observed_monotonic_ns"])
        age = ((now_monotonic_ns - publication_us * 1000 + 999999) // 1000000
               if known else -1)
        candidate["age"] = age
        candidate["fresh"] = known and 0 <= age <= FRESHNESS_LIMIT_MS

    candidates = sorted(
        best_by_state.values(),
        key=lambda entry: (
            int(entry["score"]),
            int(entry["contrast"]),
            int(entry["span"]),
        ),
        reverse=True,
    )
    chosen = None
    valid = [
        candidate
        for candidate in candidates
        if candidate["fresh"]
        and int(candidate["score"]) >= int(candidate["minimum"])
    ]
    if valid:
        chosen = max(
            valid,
            key=lambda entry: (
                int(entry["score"]),
                int(entry["contrast"]),
                -int(entry["age"]),
                int(entry["span"]),
            ),
        )
    return {
        "chosen": chosen,
        "decoded_rows": decoded_rows,
        "geometries": geometries,
        "top_colors": sampled_colors.most_common(8),
        "candidates": candidates[:8],
    }


def classify(record: dict[str, object], history: dict[int, int],
             now_monotonic_ns: int | None = None) -> dict[str, object] | None:
    return analyze(record, history, now_monotonic_ns)["chosen"]


def decode(path: Path, source_log: Path, diagnose: bool) -> int:
    with path.open("rb") as stream:
        data = stream.read(MAX_RECORD_BYTES + 1)
    record = parse_record(data)
    history = source_history(source_log)
    analysis = analyze(record, history)
    candidate = analysis["chosen"]
    if diagnose:
        top_colors = ",".join(
            f"{red:02x}{green:02x}{blue:02x}:{count}"
            for (red, green, blue), count in analysis["top_colors"]
        ) or "none"
        candidates = ",".join(
            f"{entry['layout']}:state-{entry['state']}:age-{entry['age']}:"
            f"score-{entry['score']}:matched-{entry['matched']}:"
            f"left-{entry['left']}:span-{entry['span']}:top-{entry['top']}:"
            f"contrast-{entry['contrast']}:minimum-{entry['minimum']}"
            for entry in analysis["candidates"]
        ) or "none"
        print(
            "ANDROID_PEER_FRAMEBUFFER_DIAGNOSTIC "
            f"width={record['width']} height={record['height']} format=rgb888 "
            f"orientation=bottom-up seq={record['sequence']} "
            f"timestamp_us={record['timestamp_us']} "
            f"observer_age_ms={record['observation_ms']} source_state={max(history)} "
            f"barcode_decoded_rows={analysis['decoded_rows']} "
            f"barcode_geometries={analysis['geometries']} "
            f"top_colors={top_colors} candidates={candidates}"
        )
        return 0
    if candidate is None:
        print(
            f"unavailable rgb888 bottom-up {record['width']} {record['height']} "
            f"{record['sequence']} {record['timestamp_us']} {record['observation_ms']}"
        )
        return 0
    print(
        f"{candidate['state']} {candidate['age']} {candidate['score']} "
        f"{candidate['matched']} {candidate['layout']} rgb888 bottom-up "
        f"{record['width']} {record['height']} {record['sequence']} "
        f"{record['timestamp_us']} {record['observation_ms']}"
    )
    return 0


def fixture_record(
    width: int,
    height: int,
    state: int,
    remote_left: int,
    remote_top: int,
    remote_width: int,
    remote_height: int,
    sequence: int,
    now_epoch_us: int,
    now_monotonic_ns: int,
    include_code: bool = True,
    code_dark: tuple[int, int, int] = (0, 0, 0),
    code_light: tuple[int, int, int] = (255, 255, 255),
    code_row_order: tuple[int, ...] = (0, 1, 2, 3),
) -> bytes:
    low = PALETTE[state & 15]
    high = PALETTE[(state >> 4) & 15]
    background = (197, 190, 184)
    codes = [state_code_bars(state, row) for row in range(STATE_CODE_ROWS)]
    pixels = bytearray()
    for storage_y in range(height):
        logical_y = height - storage_y - 1
        for x in range(width):
            if not (
                remote_left <= x < remote_left + remote_width
                and remote_top <= logical_y < remote_top + remote_height
            ):
                pixels.extend(background)
                continue
            remote_x = x - remote_left
            remote_y = logical_y - remote_top
            if include_code and remote_y * 5 < remote_height * 2:
                bar = min(STATE_CODE_BARS - 1, remote_x * STATE_CODE_BARS // remote_width)
                row = remote_y * 10 // remote_height
                pixels.extend(code_light if codes[code_row_order[row]][bar] else code_dark)
            else:
                pixels.extend(low if remote_x * 2 < remote_width else high)
    metadata = (
        f"seq={sequence} timestamp_us={now_epoch_us - 1_000} "
        f"observed_epoch_us={now_epoch_us} "
        f"observed_monotonic_ns={now_monotonic_ns - 1_000_000} "
        f"width={width} height={height} format=rgb888 orientation=bottom-up "
        f"bytes={len(pixels)}\n"
    ).encode("ascii")
    return MAGIC + metadata + bytes(pixels)


def self_test() -> int:
    now_epoch_us = time.time_ns() // 1_000
    now_monotonic_ns = 100_000_000_000
    scenarios = 0
    for dimensions, remote, state, age, code_levels in (
        (
            (120, 200),
            (0, 55, 120, 90),
            0x1234ABAA,
            250,
            ((182, 182, 182), (195, 195, 195)),
        ),
        ((200, 120), (32, 9, 136, 102), 0xABCD123C, 1750, ((0, 0, 0), (255, 255, 255))),
    ):
        data = fixture_record(
            *dimensions,
            state,
            *remote,
            17 + scenarios,
            now_epoch_us,
            now_monotonic_ns,
            code_dark=code_levels[0],
            code_light=code_levels[1],
        )
        record = parse_record(data, now_monotonic_ns)
        candidate = classify(record, {state: (now_monotonic_ns - age * 1_000_000) // 1000}, now_monotonic_ns)
        if candidate is None or candidate["state"] != state or candidate["age"] != age:
            raise AssertionError("valid fixture was not classified exactly")
        if candidate["layout"] != "left-right" or record["observation_ms"] != 2:
            raise AssertionError("fixture orientation or timing differs")
        scenarios += 1

    valid = fixture_record(
        120, 200, 0x42, 0, 55, 120, 90, 9, now_epoch_us, now_monotonic_ns
    )
    invalid = [
        b"wrong" + valid[len(b"wrong") :],
        valid[:-1],
        valid.replace(b"width=120", b"width=121", 1),
        valid.replace(b"format=rgb888", b"format=rgba8888", 1),
        valid.replace(b"orientation=bottom-up", b"orientation=top-down", 1),
        valid.replace(b"seq=9", b"seq=4294967296", 1),
        valid.replace(
            f"timestamp_us={now_epoch_us - 1_000}".encode(),
            f"timestamp_us={now_epoch_us + 10_000}".encode(),
            1,
        ),
        valid.replace(
            f"observed_monotonic_ns={now_monotonic_ns - 1_000_000}".encode(),
            f"observed_monotonic_ns={now_monotonic_ns + 1_000_000}".encode(),
            1,
        ),
    ]
    for data in invalid:
        try:
            parse_record(data, now_monotonic_ns)
        except InvalidFrame:
            scenarios += 1
        else:
            raise AssertionError("invalid fixture was accepted")
    with tempfile.TemporaryDirectory(prefix="android-frame-fixture-") as root:
        path = Path(root, "frame")
        path.write_bytes(valid)
        record = parse_record(path.read_bytes(), now_monotonic_ns)
        for history in (
            {0x42: (now_monotonic_ns - 64_000_000_000) // 1000,
             0x142: (now_monotonic_ns - 1_000_000) // 1000},
            {0x42: (now_monotonic_ns - 4_000_000_000) // 1000},
            {0x142: (now_monotonic_ns - 1_000_000) // 1000},
            {0x42: (now_monotonic_ns + 1_000_000) // 1000},
            {},
        ):
            if classify(record, history, now_monotonic_ns) is not None:
                raise AssertionError("stale, aliased, unknown or future identity was accepted")
        no_code = fixture_record(
            120,
            200,
            0x42,
            0,
            55,
            120,
            90,
            10,
            now_epoch_us,
            now_monotonic_ns,
            include_code=False,
        )
        if classify(parse_record(no_code, now_monotonic_ns),
                    {0x42: (now_monotonic_ns - 1_000_000) // 1000}, now_monotonic_ns) is not None:
            raise AssertionError("letterbox and palette pixels were accepted without a code")
        scenarios += 1
        for order in ((3, 2, 1, 0), (0, 1, 1, 3)):
            malformed = fixture_record(
                120, 200, 0x42, 0, 55, 120, 90, 10, now_epoch_us, now_monotonic_ns,
                code_row_order=order,
            )
            if classify(parse_record(malformed, now_monotonic_ns),
                        {0x42: (now_monotonic_ns - 1_000_000) // 1000}, now_monotonic_ns) is not None:
                raise AssertionError("reordered or missing identity band was accepted")
        maximum = fixture_record(
            120, 200, 0xFFFFFFFF, 0, 55, 120, 90, 10, now_epoch_us, now_monotonic_ns,
        )
        candidate = classify(parse_record(maximum, now_monotonic_ns),
                             {0xFFFFFFFF: (now_monotonic_ns - 1_000_000) // 1000}, now_monotonic_ns)
        if candidate is None or candidate["state"] != 0xFFFFFFFF:
            raise AssertionError("full uint32 identity was truncated")
        ready = (b"FLUTTER_PEER_SOURCE_READY display=:99 dimensions=640x480 interval_ms=250 "
                 b"identity=counter32 rows=4 bars=24 wrap=refused\n")
        trace = b"RUSTDESK_PRESENTATION_TRACE stage=source-publish monotonic_us=99000000 state=0 low=0 high=0\n"
        source = Path(root, "source")
        source.write_bytes(ready + trace + b"unfinished")
        source.chmod(0o600)
        if source_history(source, now_monotonic_ns) != {0: 99000000}:
            raise AssertionError("complete source prefix was not admitted")
        for content in (ready, ready + trace + trace, ready + trace.replace(b"state=0", b"state=1"),
                        ready + trace.replace(b"99000000", b"101000000"),
                        ready.replace(b"counter32", b"counter8") + trace):
            source.write_bytes(content)
            try:
                source_history(source, now_monotonic_ns)
            except InvalidFrame:
                pass
            else:
                raise AssertionError("incoherent publication evidence was accepted")
        source.unlink()
        os.mkfifo(source, 0o600)
        try:
            source_history(source, now_monotonic_ns)
        except InvalidFrame:
            pass
        else:
            raise AssertionError("special publication object was accepted")
    print("ANDROID_EMULATOR_FRAME_PARSER_SELF_TEST=pass format=counter32 source=monotonic-publication alias=refused")
    return 0


def main(arguments: list[str]) -> int:
    if arguments == ["self-test"]:
        return self_test()
    if len(arguments) not in (3, 4) or arguments[0] != "decode":
        raise SystemExit(
            "usage: android-emulator-frame.py self-test | "
            "decode FRAME SOURCE_LOG [diagnose]"
        )
    diagnose = len(arguments) == 4 and arguments[3] == "diagnose"
    if len(arguments) == 4 and not diagnose:
        raise SystemExit("unknown decode mode")
    return decode(Path(arguments[1]), Path(arguments[2]), diagnose)


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except (InvalidFrame, OSError, ValueError) as error:
        print(f"android-emulator-frame: {error}", file=sys.stderr)
        raise SystemExit(1)
