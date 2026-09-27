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


def analyze(record: dict[str, object], source_state: int) -> dict[str, object]:
    if not 0 <= source_state <= 255:
        raise InvalidFrame("source state is outside uint8")
    width = int(record["width"])
    height = int(record["height"])
    pixels = memoryview(record["pixels"])
    regions = {
        "left-right": (collections.Counter(), collections.Counter()),
        "top-bottom": (collections.Counter(), collections.Counter()),
    }
    sampled_colors: collections.Counter[tuple[int, int, int]] = collections.Counter()
    palette_samples = 0
    for storage_y in range(height):
        logical_y = height - storage_y - 1
        row_offset = storage_y * width * 3
        for x in range(width):
            offset = row_offset + x * 3
            rgb = (pixels[offset], pixels[offset + 1], pixels[offset + 2])
            sampled_colors[rgb] += 1
            distances = [
                sum((rgb[channel] - color[channel]) ** 2 for channel in range(3))
                for color in PALETTE
            ]
            nearest = min(range(len(PALETTE)), key=distances.__getitem__)
            if distances[nearest] > 55 * 55:
                continue
            regions["left-right"][0 if x < width // 2 else 1][nearest] += 1
            regions["top-bottom"][0 if logical_y < height // 2 else 1][nearest] += 1
            palette_samples += 1

    candidates = []
    for layout, (first, second) in regions.items():
        if not first or not second:
            continue
        low, low_count = first.most_common(1)[0]
        high, high_count = second.most_common(1)[0]
        state = high * 16 + low
        age = (source_state - state) % 256
        score = min(low_count, high_count)
        candidates.append(
            {
                "fresh": age <= 8,
                "score": score,
                "state": state,
                "age": age,
                "layout": layout,
                "matched": low_count + high_count,
            }
        )
    chosen = None
    valid = [candidate for candidate in candidates if candidate["fresh"]]
    if valid:
        candidate = max(
            valid,
            key=lambda entry: (
                int(entry["score"]),
                -int(entry["age"]),
                str(entry["layout"]),
            ),
        )
        minimum = max(20, width * height // 40)
        if (
            int(candidate["score"]) >= minimum
            and int(candidate["matched"]) >= minimum * 2
        ):
            chosen = candidate
    return {
        "chosen": chosen,
        "palette_samples": palette_samples,
        "top_colors": sampled_colors.most_common(8),
        "candidates": candidates,
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
            f"score-{entry['score']}:matched-{entry['matched']}"
            for entry in analysis["candidates"]
        ) or "none"
        print(
            "ANDROID_PEER_FRAMEBUFFER_DIAGNOSTIC "
            f"width={record['width']} height={record['height']} format=rgb888 "
            f"orientation=bottom-up seq={record['sequence']} "
            f"timestamp_us={record['timestamp_us']} "
            f"observer_age_ms={record['observation_ms']} source_state={source_state} "
            f"palette_samples={analysis['palette_samples']} "
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
    layout: str,
    sequence: int,
    now_epoch_us: int,
    now_monotonic_ns: int,
) -> bytes:
    low = PALETTE[state & 15]
    high = PALETTE[(state >> 4) & 15]
    pixels = bytearray()
    for storage_y in range(height):
        logical_y = height - storage_y - 1
        for x in range(width):
            if layout == "left-right":
                pixels.extend(low if x < width // 2 else high)
            elif layout == "top-bottom":
                pixels.extend(low if logical_y < height // 2 else high)
            else:
                raise ValueError(layout)
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
    for dimensions, layout, state, age in (
        ((120, 200), "left-right", 0xA5, 0),
        ((200, 120), "top-bottom", 0x3C, 1),
    ):
        data = fixture_record(
            *dimensions,
            state,
            layout,
            17 + scenarios,
            now_epoch_us,
            now_monotonic_ns,
        )
        record = parse_record(data, now_monotonic_ns)
        candidate = classify(record, (state + age) & 0xFF)
        if candidate is None or candidate["state"] != state or candidate["age"] != age:
            raise AssertionError("valid fixture was not classified exactly")
        if candidate["layout"] != layout or record["observation_ms"] != 2:
            raise AssertionError("fixture orientation or timing differs")
        scenarios += 1

    valid = fixture_record(
        120, 200, 0x42, "left-right", 9, now_epoch_us, now_monotonic_ns
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
            raise AssertionError("stale palette state was accepted")
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
