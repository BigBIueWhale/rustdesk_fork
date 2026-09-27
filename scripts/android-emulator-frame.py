#!/usr/bin/env python3
"""Validate and classify one externally observed Android emulator display frame."""

from __future__ import annotations

import collections
import re
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
STATE_CODE_BARS = 20
STATE_CODE_MIN_BAR_WIDTH = 3
STATE_CODE_MIN_CONTRAST = 48
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


def state_code_bars(state: int) -> tuple[int, ...]:
    bars = [0, 1]
    for shift in range(7, -1, -1):
        bit = (state >> shift) & 1
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
    return state, min(contrasts)


def analyze(record: dict[str, object], source_state: int) -> dict[str, object]:
    if not 0 <= source_state <= 255:
        raise InvalidFrame("source state is outside uint8")
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

    def record_run(
        state: int | None,
        rows: int,
        top: int,
        contrast: int,
        left: int,
        span: int,
    ) -> None:
        if state is None or rows == 0:
            return
        minimum_rows = max(6, (span * 3 + 39) // 40)
        candidate = {
            "fresh": (source_state - state) % 256 <= 8,
            "score": rows,
            "state": state,
            "age": (source_state - state) % 256,
            "layout": "left-right",
            "matched": rows * STATE_CODE_BARS,
            "left": left,
            "span": span,
            "top": top,
            "contrast": contrast,
            "minimum": minimum_rows,
        }
        previous = best_by_state.get(state)
        ranking = (rows, contrast, span)
        if previous is None or ranking > (
            int(previous["score"]),
            int(previous["contrast"]),
            int(previous["span"]),
        ):
            best_by_state[state] = candidate

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
            for logical_y in range(height):
                decoded = decode_state_code_row(
                    pixels, width, height, logical_y, left, span
                )
                if decoded is None:
                    record_run(
                        run_state,
                        run_rows,
                        run_top,
                        run_contrast,
                        left,
                        span,
                    )
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
                    record_run(
                        run_state,
                        run_rows,
                        run_top,
                        run_contrast,
                        left,
                        span,
                    )
                    run_state = state
                    run_top = logical_y
                    run_rows = 1
                    run_contrast = contrast
            record_run(
                run_state,
                run_rows,
                run_top,
                run_contrast,
                left,
                span,
            )

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


def classify(record: dict[str, object], source_state: int) -> dict[str, object] | None:
    return analyze(record, source_state)["chosen"]


def decode(path: Path, source_state: int, diagnose: bool) -> int:
    with path.open("rb") as stream:
        data = stream.read(MAX_RECORD_BYTES + 1)
    record = parse_record(data)
    analysis = analyze(record, source_state)
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
            f"observer_age_ms={record['observation_ms']} source_state={source_state} "
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
) -> bytes:
    low = PALETTE[state & 15]
    high = PALETTE[(state >> 4) & 15]
    background = (197, 190, 184)
    code = state_code_bars(state)
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
            if include_code and remote_y * 5 < remote_height:
                bar = min(STATE_CODE_BARS - 1, remote_x * STATE_CODE_BARS // remote_width)
                pixels.extend((255, 255, 255) if code[bar] else (0, 0, 0))
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
    now_monotonic_ns = time.monotonic_ns()
    scenarios = 0
    for dimensions, remote, state, age in (
        ((120, 200), (0, 55, 120, 90), 0xAA, 0),
        ((200, 120), (32, 9, 136, 102), 0x3C, 1),
    ):
        data = fixture_record(
            *dimensions,
            state,
            *remote,
            17 + scenarios,
            now_epoch_us,
            now_monotonic_ns,
        )
        record = parse_record(data, now_monotonic_ns)
        candidate = classify(record, (state + age) & 0xFF)
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
        if classify(record, 0x80) is not None:
            raise AssertionError("stale barcode state was accepted")
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
        if classify(parse_record(no_code, now_monotonic_ns), 0x42) is not None:
            raise AssertionError("letterbox and palette pixels were accepted without a code")
        scenarios += 1
    print(f"ANDROID_EMULATOR_FRAME_PARSER_SELF_TEST=pass scenarios={scenarios}")
    return 0


def main(arguments: list[str]) -> int:
    if arguments == ["self-test"]:
        return self_test()
    if len(arguments) not in (3, 4) or arguments[0] != "decode":
        raise SystemExit(
            "usage: android-emulator-frame.py self-test | "
            "decode FRAME SOURCE_STATE [diagnose]"
        )
    source_state = int(arguments[2])
    diagnose = len(arguments) == 4 and arguments[3] == "diagnose"
    if len(arguments) == 4 and not diagnose:
        raise SystemExit("unknown decode mode")
    return decode(Path(arguments[1]), source_state, diagnose)


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except (InvalidFrame, OSError, ValueError) as error:
        print(f"android-emulator-frame: {error}", file=sys.stderr)
        raise SystemExit(1)
