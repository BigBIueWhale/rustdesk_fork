#!/usr/bin/env python3
"""Count complete UTF-8 ledger bytes with pinned, offline cl100k_base in the VM."""
import argparse
import base64
import hashlib
import io
import json
import os
import platform
from pathlib import Path, PurePosixPath
import stat
import sys
import tarfile
import tempfile
import zipfile


def digest(data):
    return hashlib.sha256(data).hexdigest()


def read_bounded(path, limit, expected):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= limit:
            raise ValueError("Input is not a bounded regular file")
        data = stream.read(limit + 1)
    if len(data) != info.st_size or digest(data) != expected:
        raise ValueError("Input bytes differ from the admitted digest")
    return data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("archive", "input", "archive-sha256", "input-sha256",
                 "wheel-sha256", "ranks-sha256"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    if (os.getuid(), os.getgid()) != (4000, 4000) or sys.version_info[:2] != (3, 11):
        raise ValueError("This recipe requires the admitted Debian VM principal and CPython 3.11")
    status = Path("/proc/self/status").read_text()
    if "CapEff:\t0000000000000000\n" not in status or "NoNewPrivs:\t1\n" not in status:
        raise ValueError("Tokenizer execution lacks the confined principal")
    data = read_bounded(args.input, 8 * 1024 * 1024, args.input_sha256)
    text = data.decode("utf-8", errors="strict")
    archive = read_bounded(args.archive, 8 * 1024 * 1024, args.archive_sha256)
    wheel_name = "tiktoken-0.12.0-cp311-cp311-manylinux_2_28_x86_64.whl"
    expected = {wheel_name: args.wheel_sha256, "cl100k_base.tiktoken": args.ranks_sha256}
    files = {}
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as bundle:
        for member in bundle:
            if member.name not in expected or member.name in files or not member.isfile():
                raise ValueError("Tokenizer archive inventory differs")
            if not 0 < member.size <= 4 * 1024 * 1024:
                raise ValueError("Tokenizer archive member exceeds its bound")
            stream = bundle.extractfile(member)
            if stream is None:
                raise ValueError("Tokenizer archive member is unreadable")
            with stream:
                content = stream.read(member.size + 1)
            if len(content) != member.size or digest(content) != expected[member.name]:
                raise ValueError("Tokenizer member differs from its publisher pin")
            files[member.name] = content
    if files.keys() != expected.keys():
        raise ValueError("Tokenizer archive is incomplete")
    ranks = {}
    for line in files["cl100k_base.tiktoken"].splitlines():
        token, rank = line.split()
        key = base64.b64decode(token, validate=True)
        if key in ranks:
            raise ValueError("Duplicate mergeable token")
        ranks[key] = int(rank)
    if len(ranks) != 100256 or set(ranks.values()) != set(range(100256)):
        raise ValueError("Encoding vocabulary differs")
    pattern = r"""'(?i:[sdmt]|ll|ve|re)|[^\r\n\p{L}\p{N}]?+\p{L}++|\p{N}{1,3}+| ?[^\s\p{L}\p{N}]++[\r\n]*+|\s++$|\s*[\r\n]|\s+(?!\S)|\s"""
    special = {"<|endoftext|>": 100257, "<|fim_prefix|>": 100258,
               "<|fim_middle|>": 100259, "<|fim_suffix|>": 100260,
               "<|endofprompt|>": 100276}
    with tempfile.TemporaryDirectory(prefix="ledger-tokenizer-") as work:
        with zipfile.ZipFile(io.BytesIO(files[wheel_name])) as wheel:
            members = wheel.infolist()
            if len(members) > 64 or sum(m.file_size for m in members) > 16 * 1024 * 1024:
                raise ValueError("Wheel extraction exceeds its bound")
            seen = set()
            for member in members:
                path = PurePosixPath(member.filename)
                if path.is_absolute() or ".." in path.parts or member.filename in seen:
                    raise ValueError("Wheel extraction path differs")
                if stat.S_ISLNK(member.external_attr >> 16):
                    raise ValueError("Wheel contains a symlink")
                seen.add(member.filename)
            wheel.extractall(work)
        sys.path.insert(0, work)
        import tiktoken
        if tiktoken.__version__ != "0.12.0":
            raise ValueError("Tokenizer version differs")
        encoding = tiktoken.Encoding(name="cl100k_base", pat_str=pattern,
                                     mergeable_ranks=ranks, special_tokens=special)
        if encoding.encode_ordinary("hello world") != [15339, 1917]:
            raise ValueError("Known encoding result differs")
        if len(encoding.encode_ordinary("1\n" * 1000)) != 2000:
            raise ValueError("Actual token/byte counterexample differs")
        for spelling, token in special.items():
            ordinary = encoding.encode_ordinary(spelling)
            if token in ordinary or encoding.decode_bytes(ordinary) != spelling.encode():
                raise ValueError("Special-token spelling was not counted literally")
        tokens = encoding.encode_ordinary(text)
        if encoding.decode_bytes(tokens) != data:
            raise ValueError("Whole-input tokenization does not round trip")
        native_sha = digest(Path(tiktoken._tiktoken.__file__).read_bytes())
    result = {"method": "tiktoken-0.12.0/cl100k_base/encode_ordinary",
              "text_handling": "whole-file-strict-UTF8-no-normalization-literal-specials",
              "input_sha256": digest(data), "input_bytes": len(data), "tokens": len(tokens),
              "archive_sha256": digest(archive), "wheel_sha256": args.wheel_sha256,
              "ranks_sha256": args.ranks_sha256, "native_sha256": native_sha,
              "recipe_sha256": digest(Path(__file__).read_bytes()),
              "python": platform.python_version(), "libc": platform.libc_ver(),
              "round_trip": True, "known_controls": 7}
    print("LEDGER_TOKEN_COUNT=" + json.dumps(result, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
