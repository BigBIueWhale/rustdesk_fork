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


def forbid_docker_authority(block, label):
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
    require("--cap-add" not in block, "{} adds a capability".format(label))
    require(re.search(r"(?:^|\s)-p(?:\s|=)", block) is None, "{} publishes a port".format(label))


def validate_contract(sources):
    shell = sources["shell"]
    lib = sources["lib"]
    wrapper = sources["wrapper"]
    helper = sources["helper"]
    fixture_helper = sources["fixture_helper"]
    filesystem = sources["filesystem"]
    pins = sources["pins"]
    provenance = sources["provenance"]
    metadata = sources["metadata"]
    dockerfile = sources["dockerfile"]
    image_provenance = sources["image_provenance"]
    online_fetch = sources["online_fetch"]
    verify = sources["verify"]
    requirements = sources["requirements"]
    hardening = sources["hardening"]
    validator = sources["validator"]

    docker_run_definitions = re.findall(
        r"(?m)^(?:local_docker run |RUN=\(local_docker run |  local_docker run )",
        shell,
    )
    require(
        len(docker_run_definitions) == 3,
        "verify.sh must have exactly three fixed Docker run definitions",
    )
    require(shell.count("RUN=(local_docker run ") == 1, "verify.sh must have exactly one ordinary run definition")
    require('"$DOCKER_BIN" run ' not in shell, "verify.sh retained a direct ambient Docker launch")
    require(
        re.search(r"(?m)^readonly DOCKER_BIN=/usr/bin/docker$", shell) is None,
        "verify.sh retained its obsolete direct Docker client",
    )
    require(
        shell.count("local_docker image inspect --format") == 2,
        "verify.sh must have exactly two fixed Docker image inspections",
    )
    require_all(
        shell,
        (
            'readonly VERIFY_UID="$(/usr/bin/id -u)"',
            'readonly VERIFY_GID="$(/usr/bin/id -g)"',
            '[ "$VERIFY_UID" -ne 0 ] || { echo "verify: refuses host or container-root execution"',
            '[ "$VERIFY_GID" -ne 0 ] || { echo "verify: refuses a root primary group"',
            'initialize_local_docker_authority "$VERIFY_TMP/docker-config" "main-verifier"',
            'if [ "$LOCAL_DOCKER_AUTHORITY_INITIALIZED" -eq 1 ]',
            "&& ! remove_local_docker_authority; then",
            "verify: preserving changed private Docker authority",
            '[[ "$DEV_CHECK_IMAGE_ID" =~ ^sha256:[0-9a-f]{64}$ ]]',
            'IMAGE_ID="$(local_docker image inspect --format \'{{.Id}}\' "$DEV_CHECK_IMAGE_ID")"',
            '[ "$IMAGE_ID" = "$DEV_CHECK_IMAGE_ID" ]',
            'archive_current_source >"$VERIFY_SOURCE_ARCHIVE"',
            'install -d -m 0700 "$VERIFY_SOURCE" "$VERIFY_TARGET"',
            'SOURCE_DIGEST="$(sha256sum "$VERIFY_SOURCE_ARCHIVE"',
            'for generated_bridge_mountpoint in src/bridge_generated.rs src/bridge_generated.io.rs; do',
            '[ ! -e "$VERIFY_SOURCE/$generated_bridge_mountpoint" ]',
            '[ ! -L "$VERIFY_SOURCE/$generated_bridge_mountpoint" ]',
            'install -m 0444 /dev/null "$VERIFY_SOURCE/$generated_bridge_mountpoint"',
            '"$VERIFY_UID:$VERIFY_GID:444:1:0"',
            'chmod -R a-w "$VERIFY_SOURCE"',
            "snapshot-subtree-create",
            '--expected "$SHA256_CARGO_VENDOR_CLOSURE_V1"',
            "sed 's#directory = .*#directory = \"/vendor\"#' online/cargo-vendor-config.toml",
            'chmod 0400 "$VERIFY_CARGO_CONFIG"',
            'create_private_online_snapshot "$VERIFY_FRB_ONLINE_PARENT"',
            'ONLINE_DIR="$VERIFY_FRB_ONLINE_PARENT/online" FRB_IMAGE_ID="$DEB_BUILDER_IMAGE_ID"',
            '/usr/bin/bash "$VERIFY_SOURCE/scripts/frb-codegen.sh"',
            '--source-root "$VERIFY_SOURCE"',
            '--online-root "$VERIFY_FRB_ONLINE_PARENT/online"',
            '--output-root "$VERIFY_FRB_OUTPUT"',
            'verify_private_online_snapshot "$VERIFY_FRB_ONLINE_PARENT"',
            'sha256sum --check .frb-manifest.sha256',
            '"$VERIFY_UID:$VERIFY_GID:644:1"',
            'SOURCE_DIGEST_AFTER="$(archive_current_source | sha256sum',
            '[ "$SOURCE_DIGEST_AFTER" = "$SOURCE_DIGEST" ]',
            'FINAL_IMAGE_ID="$(local_docker image inspect --format \'{{.Id}}\' "$IMAGE_ID"',
            'VERIFY_SUCCESS_MESSAGE="VERIFY: all required source, behavior, compile, policy, inventory, and excision gates green"',
        ),
        "main verifier transaction",
    )
    require(
        shell.index('[ "$VERIFY_UID" -ne 0 ]')
        < shell.index('[ "$VERIFY_GID" -ne 0 ]')
        < shell.index("source scripts/lib.sh")
        < shell.index("load_pins")
        < shell.index("VERIFY_TMP=$(umask 077")
        < shell.index('initialize_local_docker_authority "$VERIFY_TMP/docker-config" "main-verifier"')
        < shell.index("verify_scan_self_test")
        < shell.index("local_docker image inspect"),
        "fixed Docker authority is not established before verdict preparation and Docker use",
    )
    cleanup = extract(
        shell,
        "cleanup_verify_tmp() {",
        '\n}\ntrap cleanup_verify_tmp EXIT',
        "main verifier cleanup",
    )
    require(
        cleanup.index("remove_local_docker_authority")
        < cleanup.index("verify-private-tree-closure.py"),
        "fixed Docker authority is not removed before recursive workspace cleanup",
    )
    require(
        "preserving changed private Docker authority" in cleanup
        and "elif [ -z \"$VERIFY_TMP_ID\" ]" in cleanup,
        "changed Docker authority does not stop recursive workspace cleanup",
    )
    require(
        shell.index('archive_current_source >"$VERIFY_SOURCE_ARCHIVE"')
        < shell.index("snapshot-subtree-create")
        < shell.index('create_private_online_snapshot "$VERIFY_FRB_ONLINE_PARENT"')
        < shell.index('/usr/bin/bash "$VERIFY_SOURCE/scripts/frb-codegen.sh"')
        < shell.index("RUN=(local_docker run "),
        "private source/vendor/bridge setup does not precede ordinary execution",
    )
    require(
        shell.count('--expected "$SHA256_CARGO_VENDOR_CLOSURE_V1"') == 2,
        "vendor closure must be pinned at snapshot creation and final verification",
    )
    require(
        shell.count('verify_private_online_snapshot "$VERIFY_FRB_ONLINE_PARENT"') == 2,
        "fresh-bridge online snapshot must be verified before and after generation",
    )
    require(
        shell.rindex("verify-subtree")
        < shell.index('SOURCE_DIGEST_AFTER="$(archive_current_source')
        < shell.index('FINAL_IMAGE_ID="$(local_docker image inspect'),
        "verifier postconditions are not ordered",
    )

    require_all(
        lib,
        (
            "LOCAL_DOCKER_AUTHORITY_INITIALIZED=0\nLOCAL_DOCKER_AUTHORITY_LABEL=",
            "initialize_local_docker_authority() {",
            '[ "$(/usr/bin/id -u)" -ne 0 ] || die "$2 refuses host or container-root Docker authority"',
            '[ "$(/usr/bin/id -g)" -ne 0 ] || die "$2 refuses a root primary group for Docker authority"',
            "[ -f /usr/bin/docker ] && [ ! -L /usr/bin/docker ] && [ -x /usr/bin/docker ]",
            "[ -S /var/run/docker.sock ] && [ ! -L /var/run/docker.sock ]",
            "DOCKER_HOST DOCKER_CONTEXT DOCKER_CONFIG DOCKER_CERT_PATH DOCKER_TLS_VERIFY DOCKER_TLS",
            "DOCKER_API_VERSION DOCKER_DEFAULT_PLATFORM DOCKER_CONTENT_TRUST",
            "DOCKER_CONTENT_TRUST_SERVER DOCKER_CUSTOM_HEADERS",
            "(umask 077 && set -o noclobber && printf '{}\\n' >\"$config/config.json\")",
            "assert_local_docker_authority() {",
            "local_docker() {",
            "/usr/bin/env -i",
            "DOCKER_HOST=unix:///var/run/docker.sock",
            'DOCKER_CONFIG="$LOCAL_DOCKER_AUTHORITY_CONFIG"',
            "/usr/bin/docker",
            "--host unix:///var/run/docker.sock",
            '--config "$LOCAL_DOCKER_AUTHORITY_CONFIG"',
            "remove_local_docker_authority() {",
            '/usr/bin/rm -- "$LOCAL_DOCKER_AUTHORITY_CONFIG/config.json"',
            '/usr/bin/rmdir -- "$LOCAL_DOCKER_AUTHORITY_CONFIG"',
        ),
        "shared fixed local Docker authority",
    )
    local_docker = extract(
        lib,
        "local_docker() {",
        "\n}\n\nlocal_docker_image_provenance() {",
        "shared fixed Docker launcher",
    )
    require(
        local_docker.count("assert_local_docker_authority") == 2,
        "shared Docker launcher does not prove authority before and after each operation",
    )
    require(
        "/usr/bin/env -i" in local_docker
        and "/usr/bin/docker" in local_docker
        and "--host unix:///var/run/docker.sock" in local_docker
        and '--config "$LOCAL_DOCKER_AUTHORITY_CONFIG"' in local_docker,
        "shared Docker launcher is not bound to its empty environment, client, endpoint, and configuration",
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
        'local_docker run --rm --pull=never --network=none --read-only \\\n  --user "$VERIFY_UID:$VERIFY_GID"',
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
            '--user "$VERIFY_UID:$VERIFY_GID"',
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
        "RUN=(local_docker run --rm --pull=never --network=none --read-only",
        "/work/scripts/verify-container-command.sh)",
        "ordinary verifier container",
    )
    require_all(
        ordinary,
        (
            '--user "$VERIFY_UID:$VERIFY_GID"',
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
            '--mount "type=bind,source=$VERIFY_FRB_OUTPUT/src/bridge_generated.rs,target=/work/src/bridge_generated.rs,readonly"',
            '--mount "type=bind,source=$VERIFY_FRB_OUTPUT/src/bridge_generated.io.rs,target=/work/src/bridge_generated.io.rs,readonly"',
            "--env CARGO_HOME=/tmp/cargo-home",
            "--env CARGO_INCREMENTAL=0",
            "--env CARGO_NET_OFFLINE=true",
            "--env RUSTUP_TOOLCHAIN=1.75.0",
            '--workdir /work "$IMAGE_ID"',
        ),
        "ordinary verifier container",
    )
    require(ordinary.count("--mount ") == 6, "ordinary verifier mount inventory differs")
    forbid_docker_authority(ordinary, "ordinary verifier container")

    fixture = extract(
        shell,
        "run_nonroot_ipc_command() {",
        "\n}\n\ncleanup_nonroot_ipc_fixture() {",
        "two-principal IPC fixture container",
    )
    require_all(
        fixture,
        (
            '--user "$run_uid:$run_gid"',
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--pids-limit=64",
            "--memory=1g",
            "--memory-swap=1g",
            "--cpus=1",
            "--tmpfs /tmp:rw,noexec,nosuid,nodev,mode=1777,size=32m",
            '--mount "type=bind,source=$IPC_TEST_ARTIFACT,target=/ipc-test-artifact,readonly"',
            '--mount "type=bind,source=$VERIFY_SOURCE/scripts/prepare-foreign-ipc-fixture.py,target=/prepare-foreign-ipc-fixture.py,readonly"',
            '--mount "type=bind,source=$IPC_FIXTURE_ROOT,target=/fixture"',
            "--env RUSTDESK_NONROOT_IPC_FS_FIXTURE=/fixture",
            '--env RUSTDESK_FOREIGN_IPC_UID="$IPC_FOREIGN_UID"',
            '"$IMAGE_ID" "$@"',
        ),
        "two-principal IPC fixture container",
    )
    require(fixture.count("--mount ") == 3, "two-principal IPC fixture mount inventory differs")
    for token in ("$VERIFY_VENDOR", "$VERIFY_TARGET", "$VERIFY_CARGO_CONFIG", "/work", "/vendor", "/build"):
        require(token not in fixture, "IPC fixture container received forbidden input {!r}".format(token))
    forbid_docker_authority(fixture, "two-principal IPC fixture container")
    require("--user 0:0" not in shell, "main verifier retained a UID-0 container")
    require(shell.count("run_nonroot_ipc_test \\\n  ipc::ipc_fs::tests::") == 2, "non-root IPC test call inventory differs")
    require_all(
        shell,
        (
            '"${RUN[@]}" cargo test --lib --features linux-pkg-config --no-run --message-format=json',
            "/usr/bin/python3 -I -S scripts/prepare-ipc-test-artifact.py",
            '--target-root "$VERIFY_TARGET"',
            '--output "$IPC_TEST_ARTIFACT"',
            "IPC_FOREIGN_UID=65534",
            "IPC_FOREIGN_UID=65533",
            "IPC_FOREIGN_GID=65534",
            "IPC_FOREIGN_GID=65533",
            '[ "$IPC_FOREIGN_UID" -ne 0 ] && [ "$IPC_FOREIGN_GID" -ne 0 ]',
            'install -d -m 0733 "$IPC_FIXTURE_ROOT"',
            'run_nonroot_ipc_command "$IPC_FOREIGN_UID" "$IPC_FOREIGN_GID" prepare',
            "/usr/bin/python3 -I -S /prepare-foreign-ipc-fixture.py",
            '--root /fixture --actor-uid "$VERIFY_UID" --actor-gid "$VERIFY_GID"',
            "dirs=2 acl=required",
            "/ipc-test-artifact \"$test_name\" --ignored --exact --nocapture --test-threads=1",
            "! grep -qi 'skip' \"$output\" \"$error\"",
            'grep -cF "test $test_name ... ok"',
            "test_recreate_foreign_service_ipc_parent_dir_drops_foreign_acl_nonroot recreate",
            "test_recreate_foreign_service_ipc_parent_dir_nonempty_fails_closed_nonroot nonempty",
            '[ -n "$IPC_FIXTURE_ROOT" ] && [ "$IPC_FIXTURE_CLEANED" -eq 0 ]',
            "&& ! cleanup_nonroot_ipc_fixture; then",
            'run_nonroot_ipc_command "$VERIFY_UID" "$VERIFY_GID" cleanup',
            "--cleanup --root /fixture",
            '--foreign-uid "$IPC_FOREIGN_UID" --foreign-gid "$IPC_FOREIGN_GID"',
            "dirs=2 root=0700",
            "IPC_FIXTURE_CLEANED=1",
        ),
        "two-principal IPC result finality",
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
            "os.fchmod(output_fd, 0o500)",
            'require(checks == 10',
        ),
        "IPC artifact preparation helper",
    )
    require_all(
        fixture_helper,
        (
            'root == Path("/fixture")',
            'require(metadata.st_nlink == 2, "fixture root must begin without child directories")',
            'require(metadata.st_uid == actor_uid, "fixture root owner differs")',
            'stat.S_IMODE(metadata.st_mode) == 0o733',
            'flags = os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC',
            'root_fd = open_directory(root, path_only=True)',
            'require(foreign_uid != 0 and foreign_gid != 0, "fixture preparer must be non-root")',
            'require(foreign_uid != actor_uid, "fixture preparer and actor UIDs must differ")',
            'acl = foreign_access_acl(foreign_uid, actor_uid)',
            'sorted((foreign_uid, actor_uid))',
            'os.O_EXCL',
            'create_regular_at(child_fd, "attacker-junk", b"x", mode=0o644)',
            'os.setxattr(child_fd, ACL_XATTR, acl, 0)',
            'raise FixtureError(\n                "required non-root POSIX ACL fixture is unavailable: {}"',
            'require(os.getxattr(child_fd, ACL_XATTR) == acl',
            'require(os.geteuid() == actor_uid, "fixture cleanup must run as the actor UID")',
            'require(stat.S_IMODE(metadata.st_mode) == 0o775, "foreign cleanup fixture mode differs")',
            'require(read_acl_or_none(child_fd) == acl, "foreign cleanup fixture ACL differs")',
            'require(entries.issubset(allowed), "fixture cleanup found an unknown entry")',
            "os.unlink(entry_name, dir_fd=child_fd)",
            "os.rmdir(name, dir_fd=root_fd)",
            "os.fchmod(root_fd, 0o700)",
            'require(checks == 7',
        ),
        "foreign IPC fixture helper",
    )
    require(
        fixture_helper.count("os.getxattr(child_fd, ACL_XATTR) == acl") == 2,
        "foreign IPC fixture ACL readback inventory differs",
    )
    require(
        fixture_helper.count("acl = foreign_access_acl(foreign_uid, actor_uid)") == 2,
        "foreign IPC fixture ACL construction inventory differs",
    )
    recreation_predicate = extract(
        filesystem,
        "fn should_recreate_foreign_service_ipc_parent(",
        "\n}\n\n// Purpose:",
        "foreign service-parent recreation predicate",
    )
    require_all(
        recreation_predicate,
        (
            "owner_uid != expected_uid",
            "expected_uid == 0",
            "config::is_service_ipc_postfix(postfix)",
        ),
        "foreign service-parent recreation predicate",
    )
    require_all(
        filesystem,
        (
            "if should_recreate_foreign_service_ipc_parent(owner_uid, expected_uid, postfix)",
            'std::env::var_os("RUSTDESK_NONROOT_IPC_FS_FIXTURE")',
            '"non-root IPC filesystem fixture forbids effective UID 0"',
            '"required foreign POSIX ACL fixture is absent"',
            "super::recreate_foreign_service_ipc_parent_dir(&parent_dir, \"_service\")",
            '"reject-and-recreate must drop the pre-set foreign POSIX ACL; inode adoption would preserve it"',
        ),
        "non-root IPC source behavior",
    )
    require("RUSTDESK_ROOT_IPC_FS_HARNESS" not in filesystem, "obsolete root IPC harness remains")
    require("libc::chown" not in filesystem[filesystem.index("mod tests {") :], "IPC tests retain chown")
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
            'DEV_CHECK_IMAGE_ID="sha256:da876c1ffa017736b2f63d56f8b106956d6b4d730ebbf3e99feffda42ac0b91c"',
            'DEV_CHECK_BASE_IMAGE_ID="sha256:70c2a016184099262fd7cee46f3d35fec3568c45c62f87e37f7f665f766b1f74"',
            'DEV_CHECK_IMAGE_CONFIG_ID="sha256:0d2606df948de4484771f2b2204cca50d9b2af9b1945f9c76f4d2f70945b6da3"',
            'DEV_CHECK_IMAGE_MANIFEST_ID="sha256:93864e168e6c5f4e6b3afc9be219f7bb688701a460e13855dd793834b2a8c3a5"',
            'DEV_CHECK_SOURCE_COMMIT="02320c1a05dd7646e2c3f8b67a891cbbbe681b92"',
            'DEV_CHECK_SOURCE_REPOSITORY="https://github.com/BigBIueWhale/rustdesk_fork.git"',
            'SHA256_DEV_CHECK_IMAGE_ARCHIVE="234f17f9355c7bfc8228ff2536bcd5ffbac351f0736e377d5ba46750922af352"',
            'SIZE_DEV_CHECK_IMAGE_ARCHIVE="822395974"',
            'SHA256_DEV_CHECK_DOCKERFILE="a2c6a501a8799e4c396cdc29cc9d37d30fcc8dfad9ac3dea4816f0d8a956345f"',
            'SHA256_DEV_CHECK_CARGO="0b2f6c8f85a3d02fde2efc0ced4657869d73fccfce59defb4e8d29233116e6db"',
            'SHA256_DEV_CHECK_RUSTC="7cd1c64771117a00efd8eb5113e2aed512545441c23436f6923e5deb8c97016c"',
            'SHA256_DEV_CHECK_DPKG_MANIFEST="6aef89cdf99e9f69ae645354c4ca3f7229d0a5adfa3f97f6d9fa47e3d2317c5b"',
        ),
        "devcheck image pins",
    )
    require("FROM rust:1.75-slim" in dockerfile, "devcheck recipe toolchain base differs")
    require_all(
        image_provenance,
        (
            "class VerifierSpec:",
            "def validate_verifier_attestation(",
            '"resolvedDependencies"',
            '"vcs:revision"',
            '"digest": {"sha256": spec.base.rsplit("sha256:", 1)[1]}',
            'root_args.get("vcs:revision") != spec.source_commit',
            "spec.source_repository",
            "spec.config_id",
            "spec.manifest_id",
            "expected_tags = spec.archive_tags",
            'if item.get("RepoTags") != expected_tags:',
            'fail(f"{spec.role} image archive must be mode 0400")',
            'fail(f"{spec.role} image archive requires a positive exact size")',
            "save_ref = spec.image_id",
            "RENAME_NOREPLACE = 1",
            "def rename_noreplace(",
            "verify_archive(temporary, archive_sha, spec, count)",
            "verify_local(spec.image_id, spec)",
            "if verifier_checks != 16:",
        ),
        "devcheck image archive provenance",
    )
    require_all(
        online_fetch,
        (
            "devcheck_image_spec_args()",
            "require_devcheck_image_pins()",
            "verify_or_load_devcheck_image()",
            "maintenance_capture_devcheck_image()",
            'online_source_git merge-base --is-ancestor "$DEV_CHECK_SOURCE_COMMIT" HEAD',
            'online_source_git show "$DEV_CHECK_SOURCE_COMMIT:scripts/Dockerfile.devcheck"',
            '--archive "$ONLINE_DIR/verifier-images/devcheck.docker.tar.gz"',
            '--archive-sha "$SHA256_DEV_CHECK_IMAGE_ARCHIVE"',
            '--archive-size "$SIZE_DEV_CHECK_IMAGE_ARCHIVE"',
            "--maintenance-capture-devcheck-image",
            "--devcheck-image",
        ),
        "devcheck image archive orchestration",
    )
    load_block = extract(
        online_fetch,
        "verify_or_load_devcheck_image() {",
        "\n}\n\nmaintenance_capture_devcheck_image() {",
        "devcheck image recovery orchestration",
    )
    require(
        "online_image_provenance verify-load" in load_block,
        "devcheck recovery does not use the verified load boundary",
    )
    require(
        online_fetch.count("verify_or_load_devcheck_image") == 5,
        "devcheck image preparation is not wired to the Apple candidate, "
        "explicit, offline-input, and default paths",
    )
    capture_block = extract(
        online_fetch,
        "maintenance_capture_devcheck_image() {",
        "\n}\n\n# Explicit maintenance candidate builds.",
        "devcheck image capture orchestration",
    )
    for forbidden in ("online_docker build", "online_docker pull", "docker tag", "--network=bridge"):
        require(
            forbidden not in capture_block,
            "devcheck image capture retained forbidden authority {!r}".format(forbidden),
        )
    require_all(
        verify,
        (
            "/usr/bin/python3 -I -S scripts/prepare-ipc-test-artifact.py --self-test",
            "/usr/bin/python3 -I -S scripts/prepare-foreign-ipc-fixture.py --self-test",
            "/usr/bin/python3 -I -S scripts/offline-image-provenance.py --self-test",
            "/usr/bin/python3 -I -S scripts/verify-main-verifier-authority.py --repo . --self-test",
        ),
        "shared verifier wiring",
    )
    require('<span class="id">R-S11bg</span>' in requirements, "requirements are missing R-S11bg")
    main_requirement = extract(
        requirements,
        '<div class="req"><span class="id">R-S11bg</span>',
        "</div></div>",
        "main verifier authority requirement",
    )
    require_all(
        main_requirement,
        (
            "immutable, all-non-root build and fixture authority",
            "two distinct numeric non-root principals",
            "<code>unlinkat(AT_REMOVEDIR)</code>",
            "mode 0500",
            "exactly three mounts",
            "not installed root-service runtime evidence",
        ),
        "main verifier authority requirement",
    )
    require("<tr><td>184</td>" in requirements, "requirements are missing Appendix C #184")
    require(
        "R-S11bg/R-S11e-73 — main verifier all-nonroot container and recoverable image authority" in hardening,
        "hardening ledger is missing the main verifier authority closure",
    )
    require("recoverable archive distribution" in hardening, "hardening ledger hides image archive closure")
    require("fresh independent rebuild" in hardening, "hardening ledger hides remaining rebuild debt")
    docker_requirement_start = '<div class="req"><span class="id">R-S11dh</span>'
    require(docker_requirement_start in requirements, "requirements are missing R-S11dh")
    docker_requirement = extract(
        requirements,
        docker_requirement_start,
        "</div></div>",
        "main verifier Docker authority requirement",
    )
    require_all(
        docker_requirement,
        (
            "Both image inspections and all three launch definitions",
            "fixed local Unix socket",
            "canonical <code>{}</code> <code>config.json</code>",
            "Appendix C #261",
            "R-S11e-126",
        ),
        "main verifier Docker authority requirement",
    )
    require("<tr><td>261</td>" in requirements, "requirements are missing Appendix C #261")
    require(
        "R-S11dh/R-S11e-126 — main verifier Docker client, daemon, and configuration authority"
        in hardening,
        "hardening ledger is missing the main verifier Docker authority closure",
    )

    mutation_text = validator[validator.index("\nMUTATIONS = (") : validator.index("\n)\n\n\ndef mutate_once")]
    require_all(
        mutation_text,
        (
            'Mutation("shell", "--network=none", "--network=bridge"',
            'Mutation("shell", \'--user "$VERIFY_UID:$VERIFY_GID"\'',
            'Mutation("shell", \'--user "$run_uid:$run_gid"\'',
            'Mutation("shell", \'--mount "type=bind,source=$IPC_FIXTURE_ROOT,target=/fixture"\'',
            'Mutation("wrapper", "exec cargo --config /tmp/cargo-config.toml --offline --locked"',
            'Mutation("helper", \'metadata.st_nlink == 1\'',
            'Mutation("helper", \'target.get("name") == "librustdesk"\'',
            'Mutation("helper", \'target.get("kind") == ["cdylib", "staticlib", "rlib"]\'',
            'Mutation("helper", "os.fchmod(output_fd, 0o500)"',
            'Mutation("fixture_helper", "os.setxattr(child_fd, ACL_XATTR, acl, 0)"',
            'Mutation("filesystem", "expected_uid == 0"',
            'Mutation("provenance", "def create_subtree_snapshot("',
            'Mutation("image_provenance", "expected_tags = spec.archive_tags"',
            'Mutation("image_provenance", "save_ref = spec.image_id"',
            'Mutation("image_provenance", "RENAME_NOREPLACE = 1"',
            'Mutation("online_fetch", \'--archive-size "$SIZE_DEV_CHECK_IMAGE_ARCHIVE"\'',
            'Mutation("online_fetch", \'online_image_provenance verify-load \\\\\\n        --archive "$ONLINE_DIR/verifier-images/devcheck.docker.tar.gz"\'',
            'Mutation("online_fetch", "verify_or_load_devcheck_image\\n            return 0"',
            'Mutation("pins", \'SHA256_DEV_CHECK_IMAGE_ARCHIVE="234f17f9355c7bfc',
            'Mutation(\n        "shell",\n        \'initialize_local_docker_authority "$VERIFY_TMP/docker-config" "main-verifier"\'',
            'Mutation("shell", "local_docker run --rm"',
            'Mutation(\n        "lib",\n        "DOCKER_HOST DOCKER_CONTEXT DOCKER_CONFIG DOCKER_CERT_PATH DOCKER_TLS_VERIFY DOCKER_TLS"',
            'Mutation("requirements", \'<span class="id">R-S11bg</span>\'',
            'Mutation("requirements", \'<span class="id">R-S11dh</span>\'',
            'Mutation("hardening", "R-S11bg/R-S11e-73 — main verifier all-nonroot container and recoverable image authority"',
            'Mutation(\n        "hardening",\n        "R-S11dh/R-S11e-126 — main verifier Docker client, daemon, and configuration authority"',
        ),
        "main verifier mutation coverage",
    )


MUTATIONS = (
    Mutation("shell", 'readonly VERIFY_UID="$(/usr/bin/id -u)"', 'readonly VERIFY_UID="$(id -u)"', "absolute host UID source"),
    Mutation("shell", 'readonly VERIFY_GID="$(/usr/bin/id -g)"', 'readonly VERIFY_GID="$(id -g)"', "absolute host GID source"),
    Mutation("shell", '[ "$VERIFY_UID" -ne 0 ]', '[ "$VERIFY_UID" -ge 0 ]', "host UID-root refusal"),
    Mutation("shell", '[ "$VERIFY_GID" -ne 0 ]', '[ "$VERIFY_GID" -ge 0 ]', "host GID-root refusal"),
    Mutation(
        "shell",
        'initialize_local_docker_authority "$VERIFY_TMP/docker-config" "main-verifier"',
        "true # fixed Docker authority initialization disabled",
        "fixed Docker authority initialization",
    ),
    Mutation(
        "shell",
        'if [ "$LOCAL_DOCKER_AUTHORITY_INITIALIZED" -eq 1 ] \\\n      && ! remove_local_docker_authority; then',
        'if false; then',
        "fixed Docker authority cleanup",
    ),
    Mutation("shell", 'IMAGE_ID="$(local_docker image inspect', 'IMAGE_ID="rd-devcheck-$( local_docker image inspect', "immutable image lookup"),
    Mutation("shell", 'IMAGE_ID="$(local_docker image inspect', 'IMAGE_ID="$(/usr/bin/docker image inspect', "fixed initial image inspection"),
    Mutation("shell", '[ "$IMAGE_ID" = "$DEV_CHECK_IMAGE_ID" ]', '[ -n "$IMAGE_ID" ]', "image identity equality"),
    Mutation("shell", 'archive_current_source >"$VERIFY_SOURCE_ARCHIVE"', 'cp -a . "$VERIFY_SOURCE"', "normalized source snapshot"),
    Mutation("shell", 'for generated_bridge_mountpoint in src/bridge_generated.rs src/bridge_generated.io.rs; do', 'for generated_bridge_mountpoint in src/bridge_generated.rs; do', "complete generated bridge mountpoint inventory"),
    Mutation("shell", '[ ! -e "$VERIFY_SOURCE/$generated_bridge_mountpoint" ]', 'true # generated bridge mountpoint absence ignored', "generated bridge mountpoint absence"),
    Mutation("shell", 'install -m 0444 /dev/null "$VERIFY_SOURCE/$generated_bridge_mountpoint"', 'touch "$VERIFY_SOURCE/$generated_bridge_mountpoint"', "read-only generated bridge mountpoint creation"),
    Mutation("shell", '"$VERIFY_UID:$VERIFY_GID:444:1:0"', '"$VERIFY_UID:$VERIFY_GID:644:1:0"', "generated bridge mountpoint metadata"),
    Mutation("shell", 'chmod -R a-w "$VERIFY_SOURCE"', 'chmod -R u+w "$VERIFY_SOURCE"', "read-only private source"),
    Mutation("shell", "snapshot-subtree-create", "verify-subtree", "private vendor snapshot"),
    Mutation("shell", '--expected "$SHA256_CARGO_VENDOR_CLOSURE_V1"', '--expected 0000000000000000', "vendor closure pin"),
    Mutation("shell", 'chmod 0400 "$VERIFY_CARGO_CONFIG"', 'chmod 0600 "$VERIFY_CARGO_CONFIG"', "read-only Cargo config"),
    Mutation("shell", '[ "$SOURCE_DIGEST_AFTER" = "$SOURCE_DIGEST" ]', '[ -n "$SOURCE_DIGEST_AFTER" ]', "real-source postcondition"),
    Mutation("shell", 'FINAL_IMAGE_ID="$(local_docker image inspect', 'FINAL_IMAGE_ID="$IMAGE_ID" # local_docker image inspect', "final image postcondition"),
    Mutation("shell", 'FINAL_IMAGE_ID="$(local_docker image inspect', 'FINAL_IMAGE_ID="$(/usr/bin/docker image inspect', "fixed final image inspection"),
    Mutation("shell", "local_docker run --rm", "/usr/bin/docker run --rm", "fixed Docker launcher"),
    Mutation("shell", "--pull=never", "--pull=always", "pull refusal"),
    Mutation("shell", "--network=none", "--network=bridge", "network isolation"),
    Mutation("shell", "--read-only", "--hostname=verify", "read-only root"),
    Mutation("shell", '--user "$VERIFY_UID:$VERIFY_GID"', '--user 0:0', "ordinary nonroot user"),
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
    Mutation("shell", 'source=$VERIFY_FRB_OUTPUT/src/bridge_generated.rs,target=/work/src/bridge_generated.rs,readonly', 'source=$PWD/src/bridge_generated.rs,target=/work/src/bridge_generated.rs', "fresh generated Rust bridge mount"),
    Mutation("shell", 'source=$VERIFY_FRB_OUTPUT/src/bridge_generated.io.rs,target=/work/src/bridge_generated.io.rs,readonly', 'source=$PWD/src/bridge_generated.io.rs,target=/work/src/bridge_generated.io.rs', "fresh generated Rust IO bridge mount"),
    Mutation("shell", 'create_private_online_snapshot "$VERIFY_FRB_ONLINE_PARENT"', 'cp -a online "$VERIFY_FRB_ONLINE_PARENT"', "fresh bridge private online snapshot"),
    Mutation("shell", '/usr/bin/bash "$VERIFY_SOURCE/scripts/frb-codegen.sh"', '/usr/bin/bash scripts/frb-codegen.sh', "exact-snapshot bridge generator"),
    Mutation("shell", 'verify_private_online_snapshot "$VERIFY_FRB_ONLINE_PARENT"', 'true # fresh bridge online verification removed', "fresh bridge online postcondition"),
    Mutation("shell", 'sha256sum --check .frb-manifest.sha256', 'true # fresh bridge manifest verification removed', "fresh bridge manifest verification"),
    Mutation("shell", 'target=/tmp/cargo-config.toml,readonly', 'target=/cargo-config.toml,readonly', "Cargo 1.75-safe config path"),
    Mutation("shell", "--env CARGO_INCREMENTAL=0", "--env CARGO_INCREMENTAL=1", "nonincremental build"),
    Mutation("shell", "--env CARGO_NET_OFFLINE=true", "--env CARGO_NET_OFFLINE=false", "Cargo offline environment"),
    Mutation("shell", '--user "$run_uid:$run_gid"', '--user 0:0', "IPC fixture nonroot user"),
    Mutation("shell", "--pids-limit=64", "--pids-limit=-1", "IPC fixture PID bound"),
    Mutation("shell", "--memory=1g", "--memory=0", "IPC fixture memory bound"),
    Mutation("shell", 'source=$IPC_TEST_ARTIFACT,target=/ipc-test-artifact,readonly', 'source=$VERIFY_SOURCE,target=/work', "IPC fixture artifact mount"),
    Mutation("shell", '--mount "type=bind,source=$IPC_FIXTURE_ROOT,target=/fixture"', '--mount "type=bind,source=$VERIFY_SOURCE,target=/fixture"', "IPC writable fixture mount"),
    Mutation("shell", "--env RUSTDESK_NONROOT_IPC_FS_FIXTURE=/fixture", "--env RUSTDESK_NONROOT_IPC_FS_FIXTURE=/tmp", "IPC exact fixture root"),
    Mutation("shell", "IPC_FOREIGN_UID=65534", "IPC_FOREIGN_UID=0", "foreign nonroot UID"),
    Mutation("shell", 'install -d -m 0733 "$IPC_FIXTURE_ROOT"', 'install -d -m 0777 "$IPC_FIXTURE_ROOT"', "fixture root mode"),
    Mutation("shell", "! grep -qi 'skip'", "grep -qi 'skip'", "IPC skip refusal"),
    Mutation("shell", 'grep -cF "test $test_name ... ok"', 'grep -cF "test result: ok"', "exact IPC test identity"),
    Mutation("shell", "test_recreate_foreign_service_ipc_parent_dir_drops_foreign_acl_nonroot recreate", "test_ensure_secure_ipc_parent_dir_creates_parent_with_expected_mode recreate", "foreign ACL recreation case"),
    Mutation("shell", "&& ! cleanup_nonroot_ipc_fixture; then", "&& false; then", "failure-path IPC fixture cleanup"),
    Mutation("shell", 'run_nonroot_ipc_command "$VERIFY_UID" "$VERIFY_GID" cleanup', 'run_nonroot_ipc_command "$IPC_FOREIGN_UID" "$IPC_FOREIGN_GID" cleanup', "actor-owned IPC fixture cleanup"),
    Mutation("shell", '--foreign-uid "$IPC_FOREIGN_UID" --foreign-gid "$IPC_FOREIGN_GID"', '--foreign-uid "$VERIFY_UID" --foreign-gid "$VERIFY_GID"', "distinct cleanup principal"),
    Mutation("shell", "RUN=(local_docker run", "docker build -t rd-devcheck .\nRUN=(local_docker run", "image build absence"),
    Mutation(
        "lib",
        "DOCKER_HOST DOCKER_CONTEXT DOCKER_CONFIG DOCKER_CERT_PATH DOCKER_TLS_VERIFY DOCKER_TLS",
        "DOCKER_HOST DOCKER_CONFIG DOCKER_CERT_PATH DOCKER_TLS_VERIFY DOCKER_TLS",
        "ambient local Docker authority state",
    ),
    Mutation(
        "lib",
        "(umask 077 && set -o noclobber && printf '{}\\n' >\"$config/config.json\")",
        "(umask 077 && printf '{}\\n' >\"$config/config.json\")",
        "private Docker config no-clobber creation",
    ),
    Mutation(
        "lib",
        "local_docker() {\n    local status=0\n    assert_local_docker_authority || return 1\n    /usr/bin/env -i",
        "local_docker() {\n    local status=0\n    assert_local_docker_authority || return 1\n    /usr/bin/env",
        "empty Docker client environment",
    ),
    Mutation(
        "lib",
        "--host unix:///var/run/docker.sock",
        "--host tcp://127.0.0.1:2375",
        "fixed local Docker endpoint",
    ),
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
    Mutation("helper", "os.fchmod(output_fd, 0o500)", "os.fchmod(output_fd, 0o555)", "owner-only artifact execution mode"),
    Mutation("helper", 'require(checks == 10', 'require(checks >= 0', "artifact helper self-test count"),
    Mutation("fixture_helper", 'require(metadata.st_nlink == 2, "fixture root must begin without child directories")', 'require(metadata.st_nlink >= 2, "fixture root must begin without child directories")', "empty fixture root"),
    Mutation("fixture_helper", 'require(metadata.st_uid == actor_uid, "fixture root owner differs")', 'require(metadata.st_uid >= 0, "fixture root owner differs")', "fixture actor ownership"),
    Mutation("fixture_helper", 'require(foreign_uid != 0 and foreign_gid != 0, "fixture preparer must be non-root")', 'require(foreign_uid >= 0 and foreign_gid >= 0, "fixture preparer must be non-root")', "foreign principal nonroot"),
    Mutation("fixture_helper", 'require(foreign_uid != actor_uid, "fixture preparer and actor UIDs must differ")', 'require(foreign_uid == actor_uid, "fixture preparer and actor UIDs must differ")', "distinct fixture principals"),
    Mutation("fixture_helper", "root_fd = open_directory(root, path_only=True)", "root_fd = open_directory(root)", "non-reading fixture-root descriptor"),
    Mutation("fixture_helper", "acl = foreign_access_acl(foreign_uid, actor_uid)", "acl = foreign_access_acl(foreign_uid, foreign_uid)", "actor directory-write surrogate"),
    Mutation("fixture_helper", "os.O_EXCL", "0", "exclusive fixture entries"),
    Mutation("fixture_helper", 'create_regular_at(child_fd, "attacker-junk", b"x", mode=0o644)', 'create_regular_at(child_fd, "attacker-junk", b"x")', "readable preservation marker"),
    Mutation("fixture_helper", "os.setxattr(child_fd, ACL_XATTR, acl, 0)", "True # POSIX ACL omitted", "required ACL fixture"),
    Mutation("fixture_helper", 'require(os.getxattr(child_fd, ACL_XATTR) == acl', 'require(True', "exact ACL bytes"),
    Mutation("fixture_helper", 'require(os.geteuid() == actor_uid, "fixture cleanup must run as the actor UID")', 'require(os.geteuid() >= 0, "fixture cleanup must run as the actor UID")', "actor cleanup identity"),
    Mutation("fixture_helper", 'require(entries.issubset(allowed), "fixture cleanup found an unknown entry")', 'require(True, "fixture cleanup found an unknown entry")', "cleanup entry allowlist"),
    Mutation("fixture_helper", "os.unlink(entry_name, dir_fd=child_fd)", "os.unlink(entry_name)", "descriptor-relative fixture unlink"),
    Mutation("fixture_helper", "os.rmdir(name, dir_fd=root_fd)", "os.rmdir(name)", "descriptor-relative fixture removal"),
    Mutation("fixture_helper", "os.fchmod(root_fd, 0o700)", "os.chmod('/fixture', 0o700)", "descriptor-bound fixture-root restoration"),
    Mutation("fixture_helper", 'require(checks == 7', 'require(checks >= 0', "fixture helper self-test count"),
    Mutation("filesystem", "owner_uid != expected_uid", "owner_uid == expected_uid", "foreign-owner predicate"),
    Mutation("filesystem", "expected_uid == 0", "expected_uid >= 0", "root-service predicate"),
    Mutation(
        "filesystem",
        "owner_uid != expected_uid && expected_uid == 0 && config::is_service_ipc_postfix(postfix)",
        "owner_uid != expected_uid && expected_uid == 0 && true",
        "service-postfix predicate",
    ),
    Mutation("filesystem", '"required foreign POSIX ACL fixture is absent"', '"optional foreign POSIX ACL fixture"', "required ACL behavior"),
    Mutation("provenance", "def create_subtree_snapshot(", "def ignored_subtree_snapshot(", "subtree snapshot implementation"),
    Mutation("provenance", "source_after = verify_subtree(source, expected)", "source_after = before", "subtree source stability"),
    Mutation("pins", 'DEV_CHECK_IMAGE_ID="sha256:da876c1f', 'DEV_CHECK_IMAGE_ID="rd-devcheck-', "image content pin"),
    Mutation("pins", 'SHA256_DEV_CHECK_IMAGE_ARCHIVE="234f17f9355c7bfc', 'SHA256_DEV_CHECK_IMAGE_ARCHIVE="0000000000000000', "image archive pin"),
    Mutation("pins", 'SIZE_DEV_CHECK_IMAGE_ARCHIVE="822395974"', 'SIZE_DEV_CHECK_IMAGE_ARCHIVE="0"', "image archive size pin"),
    Mutation("image_provenance", "expected_tags = spec.archive_tags", "expected_tags = [\"rd-devcheck:latest\"]", "untagged image archive"),
    Mutation("image_provenance", "save_ref = spec.image_id", "save_ref = \"rd-devcheck:latest\"", "content-ID-only image capture"),
    Mutation("image_provenance", "RENAME_NOREPLACE = 1", "RENAME_NOREPLACE = 0", "image archive no-clobber publication"),
    Mutation("image_provenance", 'root_args.get("vcs:revision") != spec.source_commit', 'root_args.get("vcs:revision") is not None', "attested source revision"),
    Mutation("image_provenance", '"digest": {"sha256": spec.base.rsplit("sha256:", 1)[1]}', '"digest": {"sha256": "0" * 64}', "attested base identity"),
    Mutation("online_fetch", '--archive-size "$SIZE_DEV_CHECK_IMAGE_ARCHIVE"', '--archive-size 0', "archive exact-size verification"),
    Mutation("online_fetch", 'online_image_provenance verify-load \\\n        --archive "$ONLINE_DIR/verifier-images/devcheck.docker.tar.gz"', 'online_image_provenance verify-archive \\\n        --archive "$ONLINE_DIR/verifier-images/devcheck.docker.tar.gz"', "separate archive recovery load"),
    Mutation("online_fetch", "verify_or_load_devcheck_image\n            return 0", "true # devcheck image preparation removed\n            return 0", "explicit archive recovery entry point"),
    Mutation("verify", "/usr/bin/python3 -I -S scripts/offline-image-provenance.py --self-test", "true # image archive self-test removed", "image archive behavioral gate"),
    Mutation("verify", "/usr/bin/python3 -I -S scripts/verify-main-verifier-authority.py --repo . --self-test", "/usr/bin/python3 -I -S scripts/verify-main-verifier-authority.py --repo .", "shared mutation gate"),
    Mutation("requirements", '<span class="id">R-S11bg</span>', '<span class="id">R-S11bg-disabled</span>', "normative requirement"),
    Mutation("requirements", "<tr><td>184</td>", "<tr><td>184-disabled</td>", "Appendix disposition"),
    Mutation("hardening", "R-S11bg/R-S11e-73 — main verifier all-nonroot container and recoverable image authority", "R-S11bg/R-S11e-73 — verifier authority deferred", "hardening ledger"),
    Mutation("requirements", '<span class="id">R-S11dh</span>', '<span class="id">R-S11dh-disabled</span>', "Docker authority normative requirement"),
    Mutation("requirements", "<tr><td>261</td>", "<tr><td>261-disabled</td>", "Docker authority Appendix disposition"),
    Mutation(
        "hardening",
        "R-S11dh/R-S11e-126 — main verifier Docker client, daemon, and configuration authority",
        "R-S11dh/R-S11e-XXX — main verifier Docker authority deferred",
        "Docker authority hardening ledger",
    ),
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
        "lib": (repo / "scripts/lib.sh").read_text(encoding="utf-8"),
        "wrapper": (repo / "scripts/verify-container-command.sh").read_text(encoding="utf-8"),
        "helper": (repo / "scripts/prepare-ipc-test-artifact.py").read_text(encoding="utf-8"),
        "fixture_helper": (repo / "scripts/prepare-foreign-ipc-fixture.py").read_text(encoding="utf-8"),
        "filesystem": (repo / "src/ipc/fs.rs").read_text(encoding="utf-8"),
        "pins": (repo / "scripts/pins.env").read_text(encoding="utf-8"),
        "provenance": (repo / "scripts/online-input-provenance.py").read_text(encoding="utf-8"),
        "metadata": (repo / "scripts/version-metadata-check.sh").read_text(encoding="utf-8"),
        "dockerfile": (repo / "scripts/Dockerfile.devcheck").read_text(encoding="utf-8"),
        "image_provenance": (repo / "scripts/offline-image-provenance.py").read_text(encoding="utf-8"),
        "online_fetch": (repo / "scripts/online-fetch.sh").read_text(encoding="utf-8"),
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
