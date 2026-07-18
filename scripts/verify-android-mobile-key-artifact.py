#!/usr/bin/env python3
"""Verify the mobile at-rest key bootstrap in the final Android APK."""

import argparse
import pathlib
import re
import resource
import stat
import subprocess
import sys
import tempfile
import zipfile


MAIN_APPLICATION = "Lcom/carriez/flutter_hbb/MainApplication;"
STORAGE_KEY_CLASS = "Lcom/carriez/flutter_hbb/MobileAtRestStorageKey;"
RUSTDESK_LIBRARY = "lib/arm64-v8a/librustdesk.so"
JNI_SETTER = "Java_ffi_FFI_setMobileAtRestStorageKey"
MAX_DEX_BYTES = 64 * 1024 * 1024
MAX_DEXDUMP_OUTPUT_BYTES = 512 * 1024 * 1024
MAX_NATIVE_LIBRARY_BYTES = 256 * 1024 * 1024
MAX_READELF_OUTPUT_BYTES = 4 * 1024 * 1024
TOOL_TIMEOUT_SECONDS = 120


class ArtifactError(Exception):
    pass


def run_tool(command, output_limit):
    def bound_output_files():
        _, hard_limit = resource.getrlimit(resource.RLIMIT_FSIZE)
        limit = output_limit if hard_limit == resource.RLIM_INFINITY else min(output_limit, hard_limit)
        resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))

    with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
        try:
            proc = subprocess.run(
                [str(part) for part in command],
                check=False,
                stdout=stdout_file,
                stderr=stderr_file,
                timeout=TOOL_TIMEOUT_SECONDS,
                preexec_fn=bound_output_files,
            )
        except subprocess.TimeoutExpired as exc:
            raise ArtifactError(
                f"{pathlib.Path(command[0]).name} exceeded {TOOL_TIMEOUT_SECONDS} seconds"
            ) from exc
        stdout_file.seek(0)
        stderr_file.seek(0)
        stdout_bytes = stdout_file.read(output_limit + 1)
        stderr_bytes = stderr_file.read(output_limit + 1)
    if len(stdout_bytes) > output_limit or len(stderr_bytes) > output_limit:
        raise ArtifactError(f"{pathlib.Path(command[0]).name} output exceeds its bound")
    stdout = stdout_bytes.decode("utf-8", errors="replace")
    stderr = stderr_bytes.decode("utf-8", errors="replace")
    if proc.returncode != 0:
        detail = stderr.strip() or stdout.strip() or "no diagnostic"
        raise ArtifactError(f"{pathlib.Path(command[0]).name} failed: {detail}")
    return stdout


def zip_member_bytes(archive, name, size_limit):
    matches = [info for info in archive.infolist() if info.filename == name]
    if len(matches) != 1:
        raise ArtifactError(f"APK must contain exactly one {name}, found {len(matches)}")
    info = matches[0]
    file_type = stat.S_IFMT(info.external_attr >> 16)
    if file_type == stat.S_IFLNK:
        raise ArtifactError(f"APK member must not be a symlink: {name}")
    if info.flag_bits & 0x1:
        raise ArtifactError(f"APK member must not be encrypted: {name}")
    if info.file_size <= 0 or info.file_size > size_limit:
        raise ArtifactError(f"APK member has invalid uncompressed size: {name}")
    data = archive.read(info)
    if len(data) != info.file_size:
        raise ArtifactError(f"APK member read was incomplete: {name}")
    return data


def dex_member_names(archive):
    names = []
    numbers = []
    for info in archive.infolist():
        match = re.fullmatch(r"classes(?:(\d+))?\.dex", info.filename)
        if not match:
            continue
        number = 1 if match.group(1) is None else int(match.group(1))
        if number < 1 or (number == 1 and match.group(1) is not None):
            raise ArtifactError(f"invalid DEX member name: {info.filename}")
        names.append(info.filename)
        numbers.append(number)
    if not names:
        raise ArtifactError("APK contains no classes*.dex")
    if len(names) != len(set(names)):
        raise ArtifactError("APK contains a duplicate DEX member name")
    if sorted(numbers) != list(range(1, len(numbers) + 1)):
        raise ArtifactError("APK DEX members are not a contiguous classes.dex sequence")
    return [name for _, name in sorted(zip(numbers, names))]


def class_blocks(dexdump_outputs, descriptor):
    blocks = []
    header = re.compile(r"(?m)^\s*Class descriptor\s+:\s+'([^']+)'\s*$")
    for dex_name, text in dexdump_outputs:
        matches = list(header.finditer(text))
        for index, match in enumerate(matches):
            if match.group(1) != descriptor:
                continue
            end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
            blocks.append((dex_name, text[match.start():end]))
    return blocks


def one_class_block(dexdump_outputs, descriptor):
    matches = class_blocks(dexdump_outputs, descriptor)
    if len(matches) != 1:
        raise ArtifactError(f"final APK must contain exactly one {descriptor}, found {len(matches)}")
    return matches[0][1]


def method_body(class_block, name, descriptor):
    entry_header = re.compile(r"(?m)^\s+#\d+\s+:\s+\(in [^)]+\)\s*$")
    headers = list(entry_header.finditer(class_block))
    matching_entries = []
    for index, header in enumerate(headers):
        end = headers[index + 1].start() if index + 1 < len(headers) else len(class_block)
        entry = class_block[header.start():end]
        entry_name = re.search(r"(?m)^\s+name\s+:\s+'([^']+)'\s*$", entry)
        entry_type = re.search(r"(?m)^\s+type\s+:\s+'([^']+)'\s*$", entry)
        if (
            entry_name is not None
            and entry_type is not None
            and entry_name.group(1) == name
            and entry_type.group(1) == descriptor
        ):
            matching_entries.append(entry)
    if len(matching_entries) != 1:
        raise ArtifactError(
            f"{name}{descriptor} must have exactly one DEX method entry, found {len(matching_entries)}"
        )
    body = re.search(
        r"(?ms)^\s+code\s+-\s*$\n(?P<body>.*?)(?=^\s+catches\s+:)",
        matching_entries[0],
    )
    if body is None:
        raise ArtifactError(f"{name}{descriptor} must have a concrete DEX body")
    return body.group("body")


def require_in_order(where, text, needles):
    offset = 0
    for needle in needles:
        found = text.find(needle, offset)
        if found < 0:
            raise ArtifactError(f"{where}: missing or reordered DEX reference {needle}")
        offset = found + len(needle)


def require_references(where, text, needles):
    for needle in needles:
        if needle not in text:
            raise ArtifactError(f"{where}: missing DEX reference {needle}")


def validate_dex(dexdump_outputs):
    main = one_class_block(dexdump_outputs, MAIN_APPLICATION)
    storage = one_class_block(dexdump_outputs, STORAGE_KEY_CLASS)

    on_create = method_body(main, "onCreate", "()V")
    require_in_order(
        "MainApplication.onCreate",
        on_create,
        [
            "Landroid/app/Application;.onCreate:()V",
            (
                "Lcom/carriez/flutter_hbb/MobileAtRestStorageKey;."
                "getOrCreate:(Landroid/content/Context;)[B"
            ),
            "Lffi/FFI;.setMobileAtRestStorageKey:([B)Z",
            "Lffi/FFI;.onAppStart:(Landroid/content/Context;)V",
        ],
    )

    get_or_create = method_body(storage, "getOrCreate", "(Landroid/content/Context;)[B")
    require_references(
        "MobileAtRestStorageKey.getOrCreate",
        get_or_create,
        [
            "Landroid/content/Context;.getSharedPreferences:",
            "getOrCreateWrappingKey:()Ljavax/crypto/SecretKey;",
            "Ljava/security/SecureRandom;.nextBytes:([B)V",
            "wrapStorageKey:(Ljavax/crypto/SecretKey;[B)Lkotlin/Pair;",
            "Landroid/content/SharedPreferences$Editor;.commit:()Z",
            "unwrapStorageKey:(Ljavax/crypto/SecretKey;Ljava/lang/String;Ljava/lang/String;)[B",
            "Ljava/util/Arrays;.equals:([B[B)Z",
        ],
    )
    commit = get_or_create.find("Landroid/content/SharedPreferences$Editor;.commit:()Z")
    reread = get_or_create.find("Landroid/content/SharedPreferences;.getString:", commit)
    round_trip = get_or_create.find("unwrapStorageKey:", reread)
    compare = get_or_create.find("Ljava/util/Arrays;.equals:([B[B)Z", round_trip)
    if min(commit, reread, round_trip, compare) < 0:
        raise ArtifactError(
            "MobileAtRestStorageKey.getOrCreate: durable commit is not followed by reread, unwrap, and equality check"
        )
    if get_or_create.count("Landroid/content/SharedPreferences;.getString:") < 4:
        raise ArtifactError(
            "MobileAtRestStorageKey.getOrCreate: stored and post-commit envelope reads are incomplete"
        )

    get_wrapping_key = method_body(storage, "getOrCreateWrappingKey", "()Ljavax/crypto/SecretKey;")
    require_references(
        "MobileAtRestStorageKey.getOrCreateWrappingKey",
        get_wrapping_key,
        [
            "Ljava/security/KeyStore;.getInstance:",
            "Ljava/security/KeyStore;.load:",
            "Ljava/security/KeyStore;.getKey:",
            "Ljava/security/KeyStore;.deleteEntry:",
        ],
    )
    if get_wrapping_key.count("generateWrappingKey:(Z)Ljavax/crypto/SecretKey;") != 2:
        raise ArtifactError(
            "MobileAtRestStorageKey.getOrCreateWrappingKey: expected StrongBox attempt and ordinary AndroidKeyStore fallback"
        )

    generate = method_body(storage, "generateWrappingKey", "(Z)Ljavax/crypto/SecretKey;")
    require_references(
        "MobileAtRestStorageKey.generateWrappingKey",
        generate,
        [
            "Ljavax/crypto/KeyGenerator;.getInstance:",
            "Landroid/security/keystore/KeyGenParameterSpec$Builder;.setKeySize:",
            "Landroid/security/keystore/KeyGenParameterSpec$Builder;.setBlockModes:",
            "Landroid/security/keystore/KeyGenParameterSpec$Builder;.setEncryptionPaddings:",
            "Landroid/security/keystore/KeyGenParameterSpec$Builder;.setRandomizedEncryptionRequired:",
            "Landroid/security/keystore/KeyGenParameterSpec$Builder;.setUserAuthenticationRequired:",
            "Landroid/security/keystore/KeyGenParameterSpec$Builder;.setUnlockedDeviceRequired:",
            "Landroid/security/keystore/KeyGenParameterSpec$Builder;.setIsStrongBoxBacked:",
            "Ljavax/crypto/KeyGenerator;.generateKey:()Ljavax/crypto/SecretKey;",
        ],
    )

    wrap = method_body(
        storage,
        "wrapStorageKey",
        "(Ljavax/crypto/SecretKey;[B)Lkotlin/Pair;",
    )
    require_references(
        "MobileAtRestStorageKey.wrapStorageKey",
        wrap,
        [
            "Ljavax/crypto/Cipher;.getInstance:",
            "Ljavax/crypto/Cipher;.init:(ILjava/security/Key;)V",
            "Ljavax/crypto/Cipher;.doFinal:([B)[B",
            "Ljavax/crypto/Cipher;.getIV:()[B",
        ],
    )

    unwrap = method_body(
        storage,
        "unwrapStorageKey",
        "(Ljavax/crypto/SecretKey;Ljava/lang/String;Ljava/lang/String;)[B",
    )
    require_references(
        "MobileAtRestStorageKey.unwrapStorageKey",
        unwrap,
        [
            "Ljavax/crypto/Cipher;.getInstance:",
            "Ljavax/crypto/spec/GCMParameterSpec;.<init>:(I[B)V",
            "Ljavax/crypto/Cipher;.init:(ILjava/security/Key;Ljava/security/spec/AlgorithmParameterSpec;)V",
            "Ljavax/crypto/Cipher;.doFinal:([B)[B",
        ],
    )

    require_references(
        "MobileAtRestStorageKey",
        storage,
        [
            '"AndroidKeyStore"',
            '"AES/GCM/NoPadding"',
            '"rustdesk_mobile_at_rest_wrapping_v1"',
            '"rustdesk_mobile_at_rest_storage"',
            '"storage_key_ciphertext_v1"',
            '"storage_key_iv_v1"',
        ],
    )


def validate_native_symbols(readelf_output):
    if not re.search(r"(?m)^\s*Machine:\s+AArch64\s*$", readelf_output):
        raise ArtifactError("librustdesk.so is not an AArch64 ELF")
    symbols = re.findall(r"(?m)^.*\s([A-Za-z_][A-Za-z0-9_]*)\s*$", readelf_output)
    if symbols.count(JNI_SETTER) != 1:
        raise ArtifactError(
            f"librustdesk.so must define exactly one dynamic {JNI_SETTER} symbol, found {symbols.count(JNI_SETTER)}"
        )


def verify_apk(apk, dexdump, readelf):
    try:
        archive = zipfile.ZipFile(apk)
    except (OSError, zipfile.BadZipFile) as exc:
        raise ArtifactError(f"cannot open APK: {exc}") from exc
    with archive:
        names = [info.filename for info in archive.infolist()]
        if len(names) != len(set(names)):
            raise ArtifactError("APK contains duplicate member names")
        dex_names = dex_member_names(archive)
        with tempfile.TemporaryDirectory(prefix="rustdesk-apk-key-proof-") as temporary:
            temporary_path = pathlib.Path(temporary)
            outputs = []
            total_dex_bytes = 0
            remaining_dexdump_output = MAX_DEXDUMP_OUTPUT_BYTES
            for dex_name in dex_names:
                data = zip_member_bytes(archive, dex_name, MAX_DEX_BYTES)
                total_dex_bytes += len(data)
                if total_dex_bytes > MAX_DEX_BYTES:
                    raise ArtifactError("APK DEX payload exceeds the verification bound")
                dex_path = temporary_path / dex_name
                dex_path.write_bytes(data)
                if remaining_dexdump_output <= 0:
                    raise ArtifactError("APK dexdump output exceeds the verification bound")
                output = run_tool([dexdump, "-d", dex_path], remaining_dexdump_output)
                rendered_size = len(output.encode("utf-8"))
                if rendered_size > remaining_dexdump_output:
                    raise ArtifactError("APK dexdump output exceeds the verification bound")
                remaining_dexdump_output -= rendered_size
                outputs.append((dex_name, output))

            native_data = zip_member_bytes(
                archive,
                RUSTDESK_LIBRARY,
                MAX_NATIVE_LIBRARY_BYTES,
            )
            native_path = temporary_path / "librustdesk.so"
            native_path.write_bytes(native_data)
            readelf_output = run_tool(
                [readelf, "--wide", "--file-header", "--dyn-syms", native_path],
                MAX_READELF_OUTPUT_BYTES,
            )

    validate_dex(outputs)
    validate_native_symbols(readelf_output)


def synthetic_method(owner, name, descriptor, body):
    return (
        f"    #0              : (in {owner})\n"
        f"      name          : '{name}'\n"
        f"      type          : '{descriptor}'\n"
        "      access        : 0x0001 (PUBLIC)\n"
        "      code          -\n"
        f"{body}\n"
        "      catches       : (none)\n"
    )


def self_test():
    if run_tool(["/bin/sh", "-c", "printf bounded"], 16) != "bounded":
        raise ArtifactError("self-test: bounded tool output was not captured")
    try:
        run_tool(["/bin/sh", "-c", "printf output-exceeds-bound"], 8)
    except ArtifactError:
        pass
    else:
        raise ArtifactError("self-test: oversized tool output was accepted")

    method = synthetic_method("Ltest/Test;", "run", "()V", "first second third")
    if method_body(method, "run", "()V").strip() != "first second third":
        raise ArtifactError("self-test: method parser failed")
    no_code = (
        "    #0              : (in Ltest/Test;)\n"
        "      name          : 'run'\n"
        "      type          : '()V'\n"
        "      access        : 0x0101 (PUBLIC NATIVE)\n"
        + synthetic_method("Ltest/Test;", "other", "()V", "borrowed body")
    )
    try:
        method_body(no_code, "run", "()V")
    except ArtifactError:
        pass
    else:
        raise ArtifactError("self-test: code-less method borrowed the following method body")
    require_in_order("self-test", "first second third", ["first", "second", "third"])
    try:
        require_in_order("self-test", "first third second", ["first", "second", "third"])
    except ArtifactError:
        pass
    else:
        raise ArtifactError("self-test: reordered call sequence was accepted")

    native = "  Machine:                           AArch64\n     1: 0 0 FUNC GLOBAL DEFAULT 1 " + JNI_SETTER + "\n"
    validate_native_symbols(native)
    for bad in (native.replace("AArch64", "X86-64"), native.replace(JNI_SETTER, "other"), native + native):
        try:
            validate_native_symbols(bad)
        except ArtifactError:
            pass
        else:
            raise ArtifactError("self-test: invalid native symbol evidence was accepted")
    print("ok Android mobile at-rest APK artifact verifier self-test")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--apk", type=pathlib.Path)
    parser.add_argument("--dexdump", type=pathlib.Path)
    parser.add_argument("--readelf", type=pathlib.Path)
    args = parser.parse_args()

    if args.self_test:
        if any((args.apk, args.dexdump, args.readelf)):
            parser.error("--self-test does not accept artifact arguments")
        self_test()
        return 0

    if not all((args.apk, args.dexdump, args.readelf)):
        parser.error("--apk, --dexdump, and --readelf are required")
    for label, path in (("APK", args.apk), ("dexdump", args.dexdump), ("readelf", args.readelf)):
        if not path.is_file():
            raise ArtifactError(f"{label} not found: {path}")

    verify_apk(args.apk, args.dexdump, args.readelf)
    print(f"ok Android mobile at-rest key bootstrap artifact: {args.apk}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except ArtifactError as exc:
        print(exc, file=sys.stderr)
        sys.exit(1)
