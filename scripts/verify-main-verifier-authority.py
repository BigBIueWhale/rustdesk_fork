#!/usr/bin/env python3
"""Mutation-bind verify.sh's immutable, confined build/test container authority."""

import argparse
from pathlib import Path
import re
import sys


class ContractError(RuntimeError):
    pass


class Mutation:
    def __init__(self, source, old, new, label):
        self.source = source
        self.old = old
        self.new = new
        self.label = label


def require(condition, message):
    if not condition:
        raise ContractError(message)


def require_all(source, tokens, label):
    for token in tokens:
        require(token in source, "{}: missing {!r}".format(label, token))


def extract(source, start, end, label):
    require(source.count(start) == 1, "{} start cardinality differs".format(label))
    begin = source.index(start)
    finish = source.index(end, begin) + len(end)
    return source[begin:finish]


def forbid_docker_authority(block, label, allow_capabilities=False):
    forbidden = (
        "docker.sock",
        "--privileged",
        "--pid=host",
        "--pid host",
        "--ipc=host",
        "--ipc host",
        "--uts=host",
        "--uts host",
        "--network=host",
        "--network host",
        "--net=host",
        "--net host",
        "--publish",
        "--expose",
        "--volume",
        "-v ",
        "--pull=always",
    )
    for token in forbidden:
        require(token not in block, "{} retained forbidden authority {!r}".format(label, token))
    if not allow_capabilities:
        require("--cap-add" not in block, "{} adds a capability".format(label))
    require(re.search(r"(?:^|\s)-p(?:\s|=)", block) is None, "{} publishes a port".format(label))


def validate_contract(sources):
    shell = sources["shell"]
    wrapper = sources["wrapper"]
    helper = sources["helper"]
    filesystem = sources["filesystem"]
    pins = sources["pins"]
    provenance = sources["provenance"]
    metadata = sources["metadata"]
    dockerfile = sources["dockerfile"]
    verify = sources["verify"]
    requirements = sources["requirements"]
    hardening = sources["hardening"]
    validator = sources["validator"]

    require(shell.count('"$DOCKER_BIN" run ') == 3, "verify.sh must have exactly three Docker run definitions")
    require(shell.count('RUN=("$DOCKER_BIN" run ') == 1, "verify.sh must have exactly one ordinary run definition")
    require_all(
        shell,
        (
            "readonly DOCKER_BIN=/usr/bin/docker",
            '[ "$(id -u)" -ne 0 ] || { echo "verify: refuses host or container-root execution"',
            '[ "$(id -g)" -ne 0 ] || { echo "verify: refuses a root primary group"',
            '[[ "$DEV_CHECK_IMAGE_ID" =~ ^sha256:[0-9a-f]{64}$ ]]',
            'IMAGE_ID="$($DOCKER_BIN image inspect --format \'{{.Id}}\' "$DEV_CHECK_IMAGE_ID")"',
            '[ "$IMAGE_ID" = "$DEV_CHECK_IMAGE_ID" ]',
            'archive_current_source >"$VERIFY_SOURCE_ARCHIVE"',
            'install -d -m 0700 "$VERIFY_SOURCE" "$VERIFY_TARGET"',
            'SOURCE_DIGEST="$(sha256sum "$VERIFY_SOURCE_ARCHIVE"',
            'chmod -R a-w "$VERIFY_SOURCE"',
            "snapshot-subtree-create",
            '--expected "$SHA256_CARGO_VENDOR_CLOSURE_V1"',
            "sed 's#directory = .*#directory = \"/vendor\"#' online/cargo-vendor-config.toml",
            'chmod 0400 "$VERIFY_CARGO_CONFIG"',
            'SOURCE_DIGEST_AFTER="$(archive_current_source | sha256sum',
            '[ "$SOURCE_DIGEST_AFTER" = "$SOURCE_DIGEST" ]',
            'FINAL_IMAGE_ID="$($DOCKER_BIN image inspect --format \'{{.Id}}\' "$IMAGE_ID"',
            'VERIFY_SUCCESS_MESSAGE="VERIFY: all required source, behavior, compile, policy, inventory, and excision gates green"',
        ),
        "main verifier transaction",
    )
    require(
        shell.index('archive_current_source >"$VERIFY_SOURCE_ARCHIVE"')
        < shell.index("snapshot-subtree-create")
        < shell.index('RUN=("$DOCKER_BIN" run '),
        "private source/vendor setup does not precede ordinary execution",
    )
    require(
        shell.count('--expected "$SHA256_CARGO_VENDOR_CLOSURE_V1"') == 2,
        "vendor closure must be pinned at snapshot creation and final verification",
    )
    require(
        shell.rindex("verify-subtree")
        < shell.index('SOURCE_DIGEST_AFTER="$(archive_current_source')
        < shell.index('FINAL_IMAGE_ID="$($DOCKER_BIN image inspect'),
        "verifier postconditions are not ordered",
    )
    for forbidden in (
        'docker build -q -t "$IMG" -f scripts/Dockerfile.devcheck scripts',
        "docker build -t rd-devcheck .",
        "docker volume create rd-cargo-cache",
        "docker volume create rd-git-cache",
        "docker volume create rd-verify-target",
        "\nIMG=rd-devcheck\n",
    ):
        require(forbidden not in shell, "main verifier retained legacy authority {!r}".format(forbidden))

    preflight = extract(
        shell,
        '"$DOCKER_BIN" run --rm --pull=never --network=none --read-only \\\n  --user "$(id -u):$(id -g)"',
        'IMAGE_PREFLIGHT_STATUS=$?',
        "devcheck preflight",
    )
    require_all(
        preflight,
        (
            "--rm",
            "--pull=never",
            "--network=none",
            "--read-only",
            '--user "$(id -u):$(id -g)"',
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--pids-limit=32",
            "--memory=256m",
            "--memory-swap=256m",
            "--cpus=1",
            "--tmpfs /tmp:rw,noexec,nosuid,nodev,mode=1777,size=16m",
            '"$IMAGE_ID"',
        ),
        "devcheck preflight",
    )
    require("--mount " not in preflight, "devcheck preflight has a bind mount")
    forbid_docker_authority(preflight, "devcheck preflight")

    ordinary = extract(
        shell,
        'RUN=("$DOCKER_BIN" run --rm --pull=never --network=none --read-only',
        "/work/scripts/verify-container-command.sh)",
        "ordinary verifier container",
    )
    require_all(
        ordinary,
        (
            '--user "$(id -u):$(id -g)"',
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--pids-limit=512",
            "--memory=12g",
            "--memory-swap=12g",
            "--cpus=4",
            "--tmpfs /tmp:rw,exec,nosuid,nodev,mode=1777,size=2g",
            '--mount "type=bind,source=$VERIFY_SOURCE,target=/work,readonly"',
            '--mount "type=bind,source=$VERIFY_VENDOR,target=/vendor,readonly"',
            '--mount "type=bind,source=$VERIFY_TARGET,target=/build"',
            '--mount "type=bind,source=$VERIFY_CARGO_CONFIG,target=/tmp/cargo-config.toml,readonly"',
            "--env CARGO_HOME=/tmp/cargo-home",
            "--env CARGO_INCREMENTAL=0",
            "--env CARGO_NET_OFFLINE=true",
            "--env RUSTUP_TOOLCHAIN=1.75.0",
            '--workdir /work "$IMAGE_ID"',
        ),
        "ordinary verifier container",
    )
    require(ordinary.count("--mount ") == 4, "ordinary verifier mount inventory differs")
    forbid_docker_authority(ordinary, "ordinary verifier container")

    root = extract(
        shell,
        '"$DOCKER_BIN" run --rm --pull=never --network=none --read-only \\\n    --user 0:0',
        '>"$output" 2>"$error"',
        "root IPC container",
    )
    require_all(
        root,
        (
            "--user 0:0",
            "--cap-drop=ALL --cap-add=CHOWN --cap-add=FOWNER",
            "--security-opt=no-new-privileges",
            "--pids-limit=64",
            "--memory=1g",
            "--memory-swap=1g",
            "--cpus=1",
            "--tmpfs /tmp:rw,exec,nosuid,nodev,mode=1777,size=128m",
            '--mount "type=bind,source=$ROOT_IPC_ARTIFACT,target=/root-ipc-test,readonly"',
            "--env RUSTDESK_ROOT_IPC_FS_HARNESS=1",
            '"$IMAGE_ID" /root-ipc-test "$test_name" --exact --nocapture --test-threads=1',
        ),
        "root IPC container",
    )
    require(root.count("--mount ") == 1, "root IPC container mount inventory differs")
    require(root.count("--cap-add=") == 2, "root IPC capability inventory differs")
    for token in ("$VERIFY_SOURCE", "$VERIFY_VENDOR", "$VERIFY_TARGET", "$VERIFY_CARGO_CONFIG", "/work", "/vendor", "/build"):
        require(token not in root, "root IPC container received forbidden input {!r}".format(token))
    forbid_docker_authority(root, "root IPC container", allow_capabilities=True)
    require(shell.count("run_root_ipc_test \\\n  ipc::ipc_fs::tests::") == 2, "root IPC test call inventory differs")
    require_all(
        shell,
        (
            '"${RUN[@]}" cargo test --lib --features linux-pkg-config --no-run --message-format=json',
            "/usr/bin/python3 -I -S scripts/prepare-root-ipc-test.py",
            '--target-root "$VERIFY_TARGET"',
            '--output "$ROOT_IPC_ARTIFACT"',
            "! grep -qi 'skip' \"$output\" \"$error\"",
            'grep -cF "test $test_name ... ok"',
            "test_ensure_secure_ipc_parent_dir_recreates_foreign_service_dir recreate",
            "test_ensure_secure_ipc_parent_dir_foreign_nonempty_fails_closed nonempty",
        ),
        "root IPC result finality",
    )

    require_all(
        wrapper,
        (
            '[ "$(id -u)" -ne 0 ] && [ "$(id -g)" -ne 0 ]',
            'install -d -m 0700 -- "$HOME" "$CARGO_HOME"',
            "case \"$1\" in",
            "cargo)",
            '[ "$#" -eq 3 ] && [ "$2" = -p ] && [ "$3" = rustdesk ]',
            'install -m 0400 -- /tmp/cargo-config.toml "$CARGO_HOME/config.toml"',
            "exec cargo clean -p rustdesk",
            'exec cargo --config /tmp/cargo-config.toml --offline --locked "$@"',
            "bash)",
            '[ "$#" -eq 2 ] && [ "$2" = scripts/version-metadata-check.sh ]',
            "unexpected command",
        ),
        "ordinary command wrapper",
    )
    require_all(
        metadata,
        (
            '[ "${CARGO_HOME:-}" = /tmp/cargo-home ]',
            '[ -f /tmp/cargo-config.toml ] && [ ! -L /tmp/cargo-config.toml ]',
            "cargo --config /tmp/cargo-config.toml --offline --locked metadata",
        ),
        "version metadata command",
    )
    require_all(
        helper,
        (
            "MAX_MESSAGES_BYTES = 64 * 1024 * 1024",
            "MAX_ARTIFACT_BYTES = 1024 * 1024 * 1024",
            'target.get("name") == "librustdesk"',
            'target.get("kind") == ["cdylib", "staticlib", "rlib"]',
            'target.get("crate_types") == ["cdylib", "staticlib", "rlib"]',
            'target.get("src_path") == "/work/src/lib.rs"',
            'profile.get("test") is True',
            "ARTIFACT_RE.fullmatch(values[0])",
            'metadata.st_nlink == 1',
            'metadata.st_mode & 0o022 == 0',
            "os.O_EXCL",
            "os.fchmod(output_fd, 0o555)",
            'require(checks == 10',
        ),
        "root artifact preparation helper",
    )
    require_all(
        filesystem,
        (
            'std::env::var_os("RUSTDESK_ROOT_IPC_FS_HARNESS")',
            '"RUSTDESK_ROOT_IPC_FS_HARNESS requires effective UID 0"',
            '"root IPC filesystem harness requires POSIX ACL support: {}"',
        ),
        "root IPC source behavior",
    )
    require(filesystem.count("RUSTDESK_ROOT_IPC_FS_HARNESS requires effective UID 0") == 2, "both root tests must reject a non-root required harness")
    require_all(
        provenance,
        (
            "def create_subtree_snapshot(",
            'snapshot_tree = destination / "subtree"',
            "source_after = verify_subtree(source, expected)",
            "snapshot = verify_subtree(snapshot_tree, expected)",
            "make_read_only(snapshot_tree)",
            'subparsers.add_parser("snapshot-subtree-create")',
            'elif args.command == "snapshot-subtree-create":',
        ),
        "vendor snapshot provenance",
    )
    require_all(
        pins,
        (
            'DEV_CHECK_IMAGE_ID="sha256:2f0406ee5b7dcd5683d900fb8b45668abd69934e6b4bdbf4737165fc01e72398"',
            'SHA256_DEV_CHECK_DOCKERFILE="a2c6a501a8799e4c396cdc29cc9d37d30fcc8dfad9ac3dea4816f0d8a956345f"',
            'SHA256_DEV_CHECK_CARGO="0b2f6c8f85a3d02fde2efc0ced4657869d73fccfce59defb4e8d29233116e6db"',
            'SHA256_DEV_CHECK_RUSTC="7cd1c64771117a00efd8eb5113e2aed512545441c23436f6923e5deb8c97016c"',
            'SHA256_DEV_CHECK_DPKG_MANIFEST="6aef89cdf99e9f69ae645354c4ca3f7229d0a5adfa3f97f6d9fa47e3d2317c5b"',
        ),
        "devcheck image pins",
    )
    require("FROM rust:1.75-slim" in dockerfile, "devcheck recipe toolchain base differs")
    require_all(
        verify,
        (
            "/usr/bin/python3 -I -S scripts/prepare-root-ipc-test.py --self-test",
            "/usr/bin/python3 -I -S scripts/verify-main-verifier-authority.py --repo . --self-test",
        ),
        "shared verifier wiring",
    )
    require('<span class="id">R-S11bg</span>' in requirements, "requirements are missing R-S11bg")
    require("<tr><td>184</td>" in requirements, "requirements are missing Appendix C #184")
    require(
        "R-S11bg/R-S11e-73 — main verifier container and root-test authority" in hardening,
        "hardening ledger is missing the main verifier authority closure",
    )
    require("independently archived" in hardening, "hardening ledger hides image acquisition debt")

    mutation_text = validator[validator.index("\nMUTATIONS = (") : validator.index("\n)\n\n\ndef mutate_once")]
    require_all(
        mutation_text,
        (
            'Mutation("shell", "--network=none", "--network=bridge"',
            'Mutation("shell", \'--user "$(id -u):$(id -g)"\'',
            'Mutation("shell", "--cap-drop=ALL --cap-add=CHOWN --cap-add=FOWNER"',
            'Mutation("wrapper", "exec cargo --config /tmp/cargo-config.toml --offline --locked"',
            'Mutation("helper", \'metadata.st_nlink == 1\'',
            'Mutation("helper", \'target.get("name") == "librustdesk"\'',
            'Mutation("helper", \'target.get("kind") == ["cdylib", "staticlib", "rlib"]\'',
            'Mutation("helper", "os.fchmod(output_fd, 0o555)"',
            'Mutation("filesystem", \'"root IPC filesystem harness requires POSIX ACL support: {}"\'',
            'Mutation("provenance", "def create_subtree_snapshot("',
            'Mutation("requirements", \'<span class="id">R-S11bg</span>\'',
            'Mutation("hardening", "R-S11bg/R-S11e-73 — main verifier container and root-test authority"',
        ),
        "main verifier mutation coverage",
    )


MUTATIONS = (
    Mutation("shell", '[ "$(id -u)" -ne 0 ]', '[ "$(id -u)" -ge 0 ]', "host UID-root refusal"),
    Mutation("shell", '[ "$(id -g)" -ne 0 ]', '[ "$(id -g)" -ge 0 ]', "host GID-root refusal"),
    Mutation("shell", 'IMAGE_ID="$($DOCKER_BIN image inspect', 'IMAGE_ID="rd-devcheck-$( $DOCKER_BIN image inspect', "immutable image lookup"),
    Mutation("shell", '[ "$IMAGE_ID" = "$DEV_CHECK_IMAGE_ID" ]', '[ -n "$IMAGE_ID" ]', "image identity equality"),
    Mutation("shell", 'archive_current_source >"$VERIFY_SOURCE_ARCHIVE"', 'cp -a . "$VERIFY_SOURCE"', "normalized source snapshot"),
    Mutation("shell", 'chmod -R a-w "$VERIFY_SOURCE"', 'chmod -R u+w "$VERIFY_SOURCE"', "read-only private source"),
    Mutation("shell", "snapshot-subtree-create", "verify-subtree", "private vendor snapshot"),
    Mutation("shell", '--expected "$SHA256_CARGO_VENDOR_CLOSURE_V1"', '--expected 0000000000000000', "vendor closure pin"),
    Mutation("shell", 'chmod 0400 "$VERIFY_CARGO_CONFIG"', 'chmod 0600 "$VERIFY_CARGO_CONFIG"', "read-only Cargo config"),
    Mutation("shell", '[ "$SOURCE_DIGEST_AFTER" = "$SOURCE_DIGEST" ]', '[ -n "$SOURCE_DIGEST_AFTER" ]', "real-source postcondition"),
    Mutation("shell", 'FINAL_IMAGE_ID="$($DOCKER_BIN image inspect', 'FINAL_IMAGE_ID="$IMAGE_ID" # $DOCKER_BIN image inspect', "final image postcondition"),
    Mutation("shell", "--pull=never", "--pull=always", "pull refusal"),
    Mutation("shell", "--network=none", "--network=bridge", "network isolation"),
    Mutation("shell", "--read-only", "--hostname=verify", "read-only root"),
    Mutation("shell", '--user "$(id -u):$(id -g)"', '--user 0:0', "ordinary nonroot user"),
    Mutation("shell", "--cap-drop=ALL", "--cap-add=SYS_ADMIN", "ordinary capability drop"),
    Mutation("shell", "--security-opt=no-new-privileges", "--security-opt=label=disable", "no-new-privileges"),
    Mutation("shell", "--pids-limit=512", "--pids-limit=-1", "ordinary PID bound"),
    Mutation("shell", "--memory=12g", "--memory=0", "ordinary memory bound"),
    Mutation("shell", "--memory-swap=12g", "--memory-swap=-1", "ordinary swap bound"),
    Mutation("shell", "--cpus=4", "--cpuset-cpus=0-255", "ordinary CPU bound"),
    Mutation("shell", "size=2g", "size=20g", "ordinary temporary-storage bound"),
    Mutation("shell", 'source=$VERIFY_SOURCE,target=/work,readonly', 'source=$PWD,target=/work', "private source mount"),
    Mutation("shell", 'source=$VERIFY_VENDOR,target=/vendor,readonly', 'source=$PWD/online,target=/vendor', "private vendor mount"),
    Mutation("shell", 'source=$VERIFY_TARGET,target=/build', 'source=$PWD,target=/build', "private target mount"),
    Mutation("shell", 'source=$VERIFY_CARGO_CONFIG,target=/tmp/cargo-config.toml,readonly', 'source=$PWD/.cargo/config.toml,target=/tmp/cargo-config.toml', "exact Cargo config mount"),
    Mutation("shell", 'target=/tmp/cargo-config.toml,readonly', 'target=/cargo-config.toml,readonly', "Cargo 1.75-safe config path"),
    Mutation("shell", "--env CARGO_INCREMENTAL=0", "--env CARGO_INCREMENTAL=1", "nonincremental build"),
    Mutation("shell", "--env CARGO_NET_OFFLINE=true", "--env CARGO_NET_OFFLINE=false", "Cargo offline environment"),
    Mutation("shell", "--user 0:0", '--user "$(id -u):$(id -g)"', "root test euid"),
    Mutation("shell", "--cap-drop=ALL --cap-add=CHOWN --cap-add=FOWNER", "--cap-add=SYS_ADMIN", "minimal root capabilities"),
    Mutation("shell", "--pids-limit=64", "--pids-limit=-1", "root PID bound"),
    Mutation("shell", "--memory=1g", "--memory=0", "root memory bound"),
    Mutation("shell", 'source=$ROOT_IPC_ARTIFACT,target=/root-ipc-test,readonly', 'source=$VERIFY_SOURCE,target=/work', "root mount inventory"),
    Mutation("shell", "--env RUSTDESK_ROOT_IPC_FS_HARNESS=1", "--env RUSTDESK_ROOT_IPC_FS_HARNESS=0", "root required-harness flag"),
    Mutation("shell", "! grep -qi 'skip'", "grep -qi 'skip'", "root skip refusal"),
    Mutation("shell", 'grep -cF "test $test_name ... ok"', 'grep -cF "test result: ok"', "exact root test identity"),
    Mutation("shell", "test_ensure_secure_ipc_parent_dir_recreates_foreign_service_dir recreate", "test_ensure_secure_ipc_parent_dir_creates_parent_with_expected_mode recreate", "root recreate case"),
    Mutation("shell", 'RUN=("$DOCKER_BIN" run', 'docker build -t rd-devcheck .\nRUN=("$DOCKER_BIN" run', "image build absence"),
    Mutation("wrapper", "exec cargo --config /tmp/cargo-config.toml --offline --locked", "exec cargo", "locked offline Cargo wrapper"),
    Mutation("wrapper", '[ "$#" -eq 3 ] && [ "$2" = -p ] && [ "$3" = rustdesk ]', "true", "exact Cargo clean"),
    Mutation("wrapper", 'install -m 0400 -- /tmp/cargo-config.toml "$CARGO_HOME/config.toml"', "true # private clean config removed", "Cargo clean source map"),
    Mutation("wrapper", '[ "$(id -u)" -ne 0 ] && [ "$(id -g)" -ne 0 ]', "true", "wrapper nonroot assertion"),
    Mutation("wrapper", '[ "$#" -eq 2 ] && [ "$2" = scripts/version-metadata-check.sh ]', "true", "wrapper shell allowlist"),
    Mutation("metadata", "cargo --config /tmp/cargo-config.toml --offline --locked metadata", "cargo metadata", "metadata Cargo authority"),
    Mutation("helper", 'metadata.st_nlink == 1', 'metadata.st_nlink >= 1', "artifact hardlink refusal"),
    Mutation("helper", 'metadata.st_mode & 0o022 == 0', "True", "artifact writability refusal"),
    Mutation("helper", 'profile.get("test") is True', 'profile.get("test") is not None', "test-profile selection"),
    Mutation("helper", 'target.get("name") == "librustdesk"', 'target.get("name") == "rustdesk"', "exact library target selection"),
    Mutation("helper", 'target.get("kind") == ["cdylib", "staticlib", "rlib"]', 'target.get("kind") == ["lib"]', "exact library kind selection"),
    Mutation("helper", "ARTIFACT_RE.fullmatch(values[0])", "values[0].startswith('/build')", "artifact path grammar"),
    Mutation("helper", "os.O_EXCL", "0", "exclusive artifact output"),
    Mutation("helper", "os.fchmod(output_fd, 0o555)", "os.fchmod(output_fd, 0o500)", "capability-minimal artifact execution mode"),
    Mutation("helper", 'require(checks == 10', 'require(checks >= 0', "artifact helper self-test count"),
    Mutation("filesystem", '"RUSTDESK_ROOT_IPC_FS_HARNESS requires effective UID 0"', '"root check disabled"', "root-required behavior"),
    Mutation("filesystem", '"root IPC filesystem harness requires POSIX ACL support: {}"', '"optional POSIX ACL: {}"', "required ACL behavior"),
    Mutation("provenance", "def create_subtree_snapshot(", "def ignored_subtree_snapshot(", "subtree snapshot implementation"),
    Mutation("provenance", "source_after = verify_subtree(source, expected)", "source_after = before", "subtree source stability"),
    Mutation("pins", 'DEV_CHECK_IMAGE_ID="sha256:2f0406ee', 'DEV_CHECK_IMAGE_ID="rd-devcheck-', "image content pin"),
    Mutation("verify", "/usr/bin/python3 -I -S scripts/verify-main-verifier-authority.py --repo . --self-test", "/usr/bin/python3 -I -S scripts/verify-main-verifier-authority.py --repo .", "shared mutation gate"),
    Mutation("requirements", '<span class="id">R-S11bg</span>', '<span class="id">R-S11bg-disabled</span>', "normative requirement"),
    Mutation("requirements", "<tr><td>184</td>", "<tr><td>184-disabled</td>", "Appendix disposition"),
    Mutation("hardening", "R-S11bg/R-S11e-73 — main verifier container and root-test authority", "R-S11bg/R-S11e-73 — verifier authority deferred", "hardening ledger"),
)


def mutate_once(sources, mutation):
    source = sources[mutation.source]
    require(mutation.old in source, "self-test mutation {!r} matched zero times".format(mutation.label))
    changed = dict(sources)
    changed[mutation.source] = source.replace(mutation.old, mutation.new, 1)
    return changed


def load_sources(repo):
    return {
        "shell": (repo / "scripts/verify.sh").read_text(encoding="utf-8"),
        "wrapper": (repo / "scripts/verify-container-command.sh").read_text(encoding="utf-8"),
        "helper": (repo / "scripts/prepare-root-ipc-test.py").read_text(encoding="utf-8"),
        "filesystem": (repo / "src/ipc/fs.rs").read_text(encoding="utf-8"),
        "pins": (repo / "scripts/pins.env").read_text(encoding="utf-8"),
        "provenance": (repo / "scripts/online-input-provenance.py").read_text(encoding="utf-8"),
        "metadata": (repo / "scripts/version-metadata-check.sh").read_text(encoding="utf-8"),
        "dockerfile": (repo / "scripts/Dockerfile.devcheck").read_text(encoding="utf-8"),
        "verify": (repo / "scripts/verify.sh").read_text(encoding="utf-8"),
        "requirements": (repo / "requirements.html").read_text(encoding="utf-8"),
        "hardening": (repo / "HARDENING_STATUS.md").read_text(encoding="utf-8"),
        "validator": (repo / "scripts/verify-main-verifier-authority.py").read_text(encoding="utf-8"),
    }


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, default=Path("."))
    parser.add_argument("--self-test", action="store_true")
    arguments = parser.parse_args(argv)
    try:
        sources = load_sources(arguments.repo.resolve())
        validate_contract(sources)
        if arguments.self_test:
            for mutation in MUTATIONS:
                try:
                    validate_contract(mutate_once(sources, mutation))
                except ContractError:
                    continue
                raise ContractError("self-test mutation was accepted: {}".format(mutation.label))
            print(
                "verify-main-verifier-authority: ok ({} deliberate mutations rejected)".format(
                    len(MUTATIONS)
                )
            )
        else:
            print("verify-main-verifier-authority: ok")
        return 0
    except (ContractError, OSError, UnicodeError, ValueError) as error:
        print("verify-main-verifier-authority: {}".format(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
