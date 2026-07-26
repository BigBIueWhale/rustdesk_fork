#!/usr/bin/env python3
"""Validate Windows helper container, image, mount, and KVM authority."""

import argparse
import pathlib
from typing import Dict, NamedTuple, Tuple


class AuthorityError(Exception):
    pass


class Mutation(NamedTuple):
    source: str
    old: str
    new: str
    label: str


def require(source: str, token: str, label: str) -> None:
    if token not in source:
        raise AuthorityError("missing {}".format(label))


def require_count(source: str, token: str, count: int, label: str) -> None:
    observed = source.count(token)
    if observed != count:
        raise AuthorityError("{} count is {}, expected {}".format(label, observed, count))


def forbid(source: str, token: str, label: str) -> None:
    if token in source:
        raise AuthorityError("forbidden {}".format(label))


def require_order(source: str, tokens: Tuple[str, ...], label: str) -> None:
    try:
        positions = tuple(source.index(token) for token in tokens)
    except ValueError:
        raise AuthorityError("{} is incomplete or misordered".format(label))
    if positions != tuple(sorted(positions)) or len(set(positions)) != len(positions):
        raise AuthorityError("{} is incomplete or misordered".format(label))


def validate(sources: Dict[str, str]) -> None:
    runtime = sources["runtime"]
    build = sources["build"]
    provision = sources["provision"]
    golden_verify = sources["golden_verify"]
    extractor = sources["extractor"]
    inspector = sources["inspector"]
    provenance = sources["provenance"]
    library = sources["library"]

    for token, label in (
        ("export PATH=/usr/bin:/bin", "closed host command path"),
        ('WINDOWS_HELPER_RUNTIME_ROOT_ID=""', "runtime-root identity state"),
        ("WINDOWS_HELPER_DOCKER_AUTHORITY_OPEN=0",
         "runtime-owned Docker-authority state"),
        ('[ "$WINDOWS_HELPER_DOCKER_AUTHORITY_OPEN" -eq 0 ] \\\n'
         '        || die "Windows helper Docker authority state is already open"',
         "authority-open state precondition"),
        ('[ "$LOCAL_DOCKER_AUTHORITY_INITIALIZED" -eq 0 ] \\\n'
         '        || die "Windows helper refuses an existing process-local Docker authority"',
         "foreign process-local authority refusal"),
        ('[ "$WINDOWS_HELPER_DOCKER_AUTHORITY_OPEN" -eq 0 ] \\\n'
         '            && [ "$LOCAL_DOCKER_AUTHORITY_INITIALIZED" -eq 0 ] \\\n'
         '            || { echo "Windows helper empty runtime has live Docker authority state"',
         "empty-runtime authority-state refusal"),
        ('"${WINDOWS_HELPER_BUILD_UID:-}" = "$(/usr/bin/id -u)"',
         "captured UID revalidation"),
        ('"${WINDOWS_HELPER_BUILD_GID:-}" = "$(/usr/bin/id -g)"',
         "captured GID revalidation"),
        ('[ "$WINDOWS_HELPER_BUILD_UID" -ne 0 ]',
         "runtime host-UID root refusal"),
        ('[ "$WINDOWS_HELPER_BUILD_GID" -ne 0 ]',
         "runtime primary-GID root refusal"),
        ("refuse host or container-root execution", "root execution refusal"),
        ("refuse a root primary group", "root primary-group refusal"),
        ("/usr/bin/mktemp -d /tmp/rustdesk-windows-helper.XXXXXXXXXX",
         "private random runtime root"),
        ("WINDOWS_HELPER_RUNTIME_ROOT_ID=\"$(\n"
         "        /usr/bin/stat -c '%d:%i' -- \"$WINDOWS_HELPER_RUNTIME_ROOT\"",
         "recorded runtime-root identity"),
        ('initialize_local_docker_authority \\\n'
         '        "$WINDOWS_HELPER_RUNTIME_ROOT/docker-config" \\\n'
         '        "Windows helper runtime"',
         "shared fixed local-Docker authority initialization"),
        ("WINDOWS_HELPER_DOCKER_AUTHORITY_OPEN=1",
         "successful authority-open commit"),
        ('if [ "$WINDOWS_HELPER_DOCKER_AUTHORITY_OPEN" -eq 1 ]; then',
         "runtime-owned Docker cleanup selection"),
        ('[ "$LOCAL_DOCKER_AUTHORITY_INITIALIZED" -eq 1 ] \\\n'
         '            || { echo "Windows helper preserving runtime after premature Docker authority loss"',
         "premature Docker-authority loss refusal"),
        ("assert_local_docker_authority || die \"Windows helper local-Docker authority changed\"",
         "shared local-Docker authority proof"),
        ("remove_local_docker_authority || return 1",
         "Docker-first terminal authority retirement"),
        ('/usr/bin/python3 -I -S "$LIB_DIR/verify-private-tree-closure.py" \\\n'
         '            --remove-private-root "$WINDOWS_HELPER_RUNTIME_ROOT" \\\n'
         '            --expected-identity "$WINDOWS_HELPER_RUNTIME_ROOT_ID"',
         "descriptor-safe exact runtime-root removal"),
        ('require_pinned_builder_image win-helper "$WIN_HELPER_IMAGE_ID"',
         "immutable helper image provenance"),
        ('windows_helper_verify_archive "$archive"',
         "structural helper archive verification"),
        ("windows_helper_verify_archive() {",
         "structural helper archive verifier"),
        ('--archive-size "$WIN_HELPER_IMAGE_ARCHIVE_SIZE"',
         "helper archive size authority"),
        ('--dockerfile-sha "$SHA256_WIN_HELPER_CERTIFICATION_DOCKERFILE"',
         "helper certification recipe authority"),
        ('--bootstrap-image-id "$WIN_HELPER_BOOTSTRAP_IMAGE_ID"',
         "helper bootstrap identity authority"),
        ('--config-id "$WIN_HELPER_CONFIG_ID"',
         "helper config identity authority"),
        ('--manifest-id "$WIN_HELPER_MANIFEST_ID"',
         "helper runtime-manifest authority"),
        ("windows_helper_snapshot_program \"$extractor_source\"",
         "private kernel-extractor snapshot"),
        ("windows_helper_snapshot_program \"$inspector_source\"",
         "private golden-inspector snapshot"),
        ('--kernel-version "$WIN_HELPER_KERNEL_VERSION"',
         "pinned helper-kernel version"),
        ('--kernel-sha256 "$SHA256_WIN_HELPER_KERNEL"',
         "independent helper-kernel byte pin"),
        ('"$WIN_HELPER_IMAGE_ID" "${WINDOWS_HELPER_COMMAND[@]}"',
         "exact image-ID execution"),
        ("run --rm --pull=never --network=none --read-only",
         "no-pull networkless read-only-root launch"),
        ('--user "$WINDOWS_HELPER_BUILD_UID:$WINDOWS_HELPER_BUILD_GID"',
         "numeric nonroot identity"),
        ("--cap-drop=ALL --security-opt=no-new-privileges",
         "capability and privilege confinement"),
        ("--pids-limit=64 --memory=1g --memory-swap=1g --cpus=1",
         "small-operation resource ceiling"),
        ("--pids-limit=64 --memory=2g --memory-swap=2g --cpus=2",
         "media-operation resource ceiling"),
        ("--pids-limit=256 --memory=4g --memory-swap=4g --cpus=2",
         "libguestfs resource ceiling"),
        ("--tmpfs /tmp:rw,noexec,nosuid,nodev,mode=1777,size=64m",
         "small-operation scratch ceiling"),
        ("--tmpfs /tmp:rw,noexec,nosuid,nodev,mode=1777,size=128m",
         "media-operation scratch ceiling"),
        ("--tmpfs /tmp:rw,exec,nosuid,nodev,mode=1777,size=2g",
         "libguestfs executable scratch ceiling"),
        ("--tmpfs /var/tmp:rw,exec,nosuid,nodev,mode=1777,size=512m",
         "QEMU temporary-file ceiling"),
        ("SUPERMIN_KERNEL=/authority/kernel/vmlinuz",
         "explicit nonroot supermin kernel"),
        ("source=$WINDOWS_HELPER_RUNTIME_ROOT/kernel/vmlinuz,target=/authority/kernel/vmlinuz,readonly,bind-recursive=disabled",
         "read-only derived-kernel mount"),
        ("source=$WINDOWS_HELPER_RUNTIME_ROOT/authority/windows-golden-inspect.sh,target=/authority/windows-golden-inspect.sh,readonly,bind-recursive=disabled",
         "read-only inspector mount"),
        ("Windows helper containers accept only explicit bind mounts",
         "bind-only caller mount grammar"),
        ("Windows helper bind target must be lexically canonical",
         "canonical container target"),
        ("Windows helper bind source must be a regular file or directory",
         "special-file mount refusal"),
        ("/authority/windows-golden-inspect.sh)",
         "fixed inspector target protection"),
        ("writable Windows helper bind source must be current-UID owned",
         "writable mount ownership"),
        ("writable Windows helper bind source must not be group/world writable",
         "writable mount mode"),
        ("writable Windows helper file must be single-link",
         "writable hard-link refusal"),
        ('WINDOWS_HELPER_VALIDATED_MOUNT_VALUE="$value,bind-recursive=disabled"',
         "central recursive-bind exclusion"),
        ('WINDOWS_HELPER_MOUNTS+=(--mount "$WINDOWS_HELPER_VALIDATED_MOUNT_VALUE")',
         "normalized caller-mount launch"),
        ("--group-add \"$WINDOWS_HELPER_KVM_GID\"", "narrow KVM group authorization"),
        ("--device /dev/kvm:/dev/kvm:rw", "read/write-only KVM device authorization"),
        ('\'\'|*[!0-9]*|0) die "/dev/kvm must have one non-root numeric group"',
         "root KVM-group refusal"),
        ("local_docker run --rm --pull=never --network=none --read-only",
         "shared exact-authority container launch"),
        ("--ulimit core=0:0 --ulimit nofile=4096:4096",
         "core and descriptor ceilings"),
        ("--ulimit fsize=137438953472:137438953472",
         "finite Windows-helper file-size ceiling"),
    ):
        require(runtime, token, label)

    require_count(
        runtime,
        'windows_helper_verify_archive "$archive"',
        2,
        "archive pre/post verification",
    )
    require_count(runtime, "--device /dev/kvm:/dev/kvm:rw", 1, "single exact device grant")
    require_count(runtime, "--network=none", 1, "single common network policy")
    require_count(runtime, "--pull=never", 1, "single common pull policy")
    require_count(runtime, "--cap-drop=ALL", 1, "single common capability policy")
    require_count(
        runtime,
        "initialize_local_docker_authority \\\n"
        '        "$WINDOWS_HELPER_RUNTIME_ROOT/docker-config" \\\n'
        '        "Windows helper runtime"',
        1,
        "single shared Docker-authority initialization",
    )
    require_count(
        runtime,
        "remove_local_docker_authority || return 1",
        1,
        "single exact Docker-authority retirement",
    )
    require_count(
        runtime,
        '--remove-private-root "$WINDOWS_HELPER_RUNTIME_ROOT"',
        1,
        "single exact runtime-root closer",
    )

    for token, label in (
        ("WINDOWS_HELPER_DOCKER_BIN=", "bespoke Docker client"),
        ("WINDOWS_HELPER_DOCKER_HOST=", "bespoke Docker daemon routing"),
        ("/usr/bin/docker", "direct Docker client execution"),
        ("windows_helper_docker_command", "bespoke Docker wrapper"),
        ("windows_helper_assert_docker_config", "bespoke Docker configuration proof"),
        ("export DOCKER_HOST", "caller-exported Docker host"),
        ("export DOCKER_CONFIG", "caller-exported Docker configuration"),
        ("--device /dev/kvm:/dev/kvm:rwm", "KVM device-node creation permission"),
        ("chmod -R u+rwX \"$WINDOWS_HELPER_RUNTIME_ROOT\"", "recursive cleanup permission repair"),
        ("rm -rf -- \"$WINDOWS_HELPER_RUNTIME_ROOT\"", "pathname-recursive runtime cleanup"),
        ("--privileged", "privileged launch"),
        ("--cap-add", "added capability"),
        ("--network=host", "host network namespace"),
        ("--pid=host", "host PID namespace"),
        ("--ipc=host", "host IPC namespace"),
        ("--uts=host", "host UTS namespace"),
        ("--publish", "port publication"),
        ("-p ", "short port publication"),
        ("--user 0:0", "container-root identity"),
        ("docker build", "image-build fallback"),
        ("docker pull", "image-pull fallback"),
        ("source=/var/run/docker.sock", "Docker socket mount"),
        ("/var/run/docker.sock:/var/run/docker.sock", "Docker socket volume"),
        ('verify_sha256 "$archive" "$SHA256_WIN_HELPER_IMAGE_ARCHIVE"',
         "digest-only helper archive verdict"),
    ):
        forbid(runtime, token, label)

    for token, label in (
        ("initialize_local_docker_authority() {", "shared authority initializer"),
        ("assert_local_docker_authority() {", "shared authority prover"),
        ("local_docker() {", "shared exact-environment Docker wrapper"),
        ("local_docker_image_provenance() {", "shared exact-environment provenance wrapper"),
        ("remove_local_docker_authority() {", "shared exact authority retirement"),
        ("DOCKER_HOST DOCKER_CONTEXT DOCKER_CONFIG DOCKER_CERT_PATH DOCKER_TLS_VERIFY DOCKER_TLS",
         "complete inherited Docker-input refusal"),
        ('DOCKER_HOST=unix:///var/run/docker.sock', "fixed local Docker socket routing"),
        ('--host unix:///var/run/docker.sock', "redundant fixed Docker host argument"),
    ):
        require(library, token, label)

    require_order(
        runtime,
        (
            'WINDOWS_HELPER_RUNTIME_ROOT_ID="$(\n'
            "        /usr/bin/stat -c '%d:%i' -- \"$WINDOWS_HELPER_RUNTIME_ROOT\"",
            "/usr/bin/install -d -m 0700",
            "initialize_local_docker_authority \\\n"
            '        "$WINDOWS_HELPER_RUNTIME_ROOT/docker-config" \\\n'
            '        "Windows helper runtime"',
            "WINDOWS_HELPER_DOCKER_AUTHORITY_OPEN=1",
        ),
        "runtime-root identity before population and Docker-authority commit",
    )
    require_order(
        runtime,
        (
            "remove_local_docker_authority || return 1",
            "        WINDOWS_HELPER_DOCKER_AUTHORITY_OPEN=0\n"
            "    elif",
            "/usr/bin/env -i PATH=/usr/bin:/bin",
            '--remove-private-root "$WINDOWS_HELPER_RUNTIME_ROOT"',
            '    WINDOWS_HELPER_RUNTIME_ROOT=""\n'
            '    WINDOWS_HELPER_RUNTIME_ROOT_ID=""',
        ),
        "Docker-first cleanup before runtime-root retirement",
    )

    for source, label in (
        (build, "Windows build"),
        (provision, "Windows provision"),
        (golden_verify, "Windows golden verification"),
    ):
        require_order(
            source,
            (
                "set -euo pipefail",
                "umask 077",
                "export PATH=/usr/bin:/bin",
                'readonly WINDOWS_HELPER_BUILD_UID="$(/usr/bin/id -u)"',
                'readonly WINDOWS_HELPER_BUILD_GID="$(/usr/bin/id -g)"',
                '[ "$WINDOWS_HELPER_BUILD_UID" -ne 0 ]',
                "refuses host or container-root execution",
                '[ "$WINDOWS_HELPER_BUILD_GID" -ne 0 ]',
                "refuses a root primary group",
                'SCRIPT_DIR="$(cd "$(/usr/bin/dirname -- "${BASH_SOURCE[0]}")" && /usr/bin/pwd -P)"',
                'source "$SCRIPT_DIR/lib.sh"',
                "load_pins",
                'source "$SCRIPT_DIR/windows-helper-runtime.sh"',
            ),
            label + " pre-source nonroot authority",
        )
        require(
            source,
            '[ "$WINDOWS_HELPER_BUILD_UID" -ne 0 ]',
            label + " exact host-UID root refusal",
        )
        require(
            source,
            '[ "$WINDOWS_HELPER_BUILD_GID" -ne 0 ]',
            label + " exact primary-GID root refusal",
        )
        if any(
            line.strip().startswith("require_cmd ")
            and "docker" in line.strip().split()[1:]
            for line in source.splitlines()
        ):
            raise AuthorityError(
                "forbidden {} ambient Docker preflight".format(label)
            )

    for token, label in (
        ("source \"$SCRIPT_DIR/windows-helper-runtime.sh\"", "shared authority runtime"),
        ("windows_helper_authority_open", "authority opening"),
        ('windows_helper_runtime_resolve "$ONLINE_DIR/build-images/win-helper.docker.tar.gz"',
         "exact captured archive resolution"),
        ('require_pinned_builder_image deb-builder "$DEB_BUILDER_IMAGE_ID"',
         "exact FRB helper provenance"),
        ("windows_helper_authority_close", "terminal authority cleanup"),
        ('/wix-nuget-packages=/online/wix-nuget-packages',
         "exact read-only WiX local-package source mapping"),
        ('source=$manifest,target=/authority/offline-input-manifest.json,readonly',
         "exact offline manifest input"),
        ('source=$media_output,target=/out"', "private ISO output"),
        ('source=$CURRENT_PASS_ROOT/output.img,target=/authority/output.img"',
         "exact writable output-disk mount"),
        ("qemu-img create -f qcow2 -F qcow2 -b ../golden.qcow2 overlay.qcow2",
         "portable relative overlay backing path"),
        ('source=$CURRENT_PASS_ROOT/overlay.qcow2,target=/authority/pass/overlay.qcow2"',
         "exact writable overlay mount"),
        ('source=$PRIVATE_GOLDEN,target=/authority/golden.qcow2,readonly',
         "exact read-only private golden mount"),
        ('source=$CURRENT_PASS_ROOT/output.img,target=/authority/output.img,readonly',
         "exact read-only artifact-disk extraction"),
        ('source=$msi_input,target=/authority/input.msi,readonly',
         "exact read-only MSI input"),
        ('source=$SOURCE_SNAPSHOT/scripts/canonicalize-msi.py,target=/authority/canonicalize-msi.py,readonly',
         "exact read-only MSI canonicalizer"),
        ('source=$msi_stage,target=/out"', "private MSI output"),
    ):
        require(build, token, label)
    require_count(build, "windows_helper_small_run", 1, "one small helper operation")
    require_count(build, "windows_helper_media_run", 1, "one media helper operation")
    require_count(build, "windows_helper_guestfish_run", 3, "three libguestfs operations")
    main = build[build.index("\nmain() {") :]
    require_order(
        main,
        (
            "windows_helper_authority_open",
            "preflight",
            "snapshot_golden",
            "build_offline_media",
            "run_pass A",
            "verify_private_golden",
            "publish_result",
        ),
        "Windows build authority, immutable inputs, execution, and publication",
    )
    for token, label in (
        ("docker run", "direct helper launch outside the runtime"),
        ("docker image inspect", "mutable image-name inspection"),
        ("source=$RUN_ROOT,target=/run", "whole-run-root writable mount"),
        ("source=$CURRENT_PASS_ROOT,target=/pass", "whole-pass-root writable mount"),
        ("source=$SOURCE_SNAPSHOT/scripts,target=/scripts", "whole-script-tree mount"),
        ("--env HOST_UID=", "container-root output chown"),
        ("chown -R", "container-root output ownership repair"),
        ("wix-nuget.tar.gz", "obsolete expanded WiX archive"),
        ("WIX_NUGET_ROOT", "host-extracted WiX cache"),
    ):
        forbid(build, token, label)

    for source, label in ((provision, "provision"), (golden_verify, "golden verification")):
        require(
            source,
            'source "$SCRIPT_DIR/windows-helper-runtime.sh"',
            label + " shared immutable-image runtime",
        )
        require(
            source,
            'windows_helper_runtime_resolve "$ONLINE_DIR/build-images/win-helper.docker.tar.gz"',
            label + " exact archive resolution",
        )
        require(source, "windows_helper_kvm_guestfish_run", label + " KVM wrapper")
        require(
            source,
            'source=$GOLDEN,target=/authority/golden.qcow2,readonly',
            label + " exact read-only golden mount",
        )
        require(
            source,
            "/authority/windows-golden-inspect.sh",
            label + " fixed inspector",
        )
        forbid(source, "docker run", label + " direct Docker launch")
        forbid(source, "docker image inspect", label + " mutable image inspection")
        forbid(source, "source=$STATE_DIR,target=/state", label + " whole-state mount")
        forbid(source, "-v \"$STATE_DIR", label + " short whole-state volume")
    require_count(provision, "windows_helper_kvm_guestfish_run", 1, "one provision inspector")
    require_count(golden_verify, "windows_helper_kvm_guestfish_run", 1, "one golden verifier")
    existing_golden = provision[
        provision.index('    if [ -f "$GOLDEN" ]; then') : provision.index("    build_media")
    ]
    require_order(
        existing_golden,
        (
            'verify_sha256 "$GOLDEN" "${SHA256_WIN11_GOLDEN_QCOW2}"',
            "if golden_has_done_marker; then",
        ),
        "existing golden hash-before-marker inspection",
    )
    provision_loop = provision[provision.index("    while true; do") :]
    require_order(
        provision_loop,
        (
            "if golden_has_done_marker; then",
            'verify_sha256 "$GOLDEN" "${SHA256_WIN11_GOLDEN_QCOW2}"',
            "golden Win11 template built:",
        ),
        "provision marker, final hash, and acceptance",
    )
    require_order(
        golden_verify,
        (
            'verify_sha256 "$GOLDEN" "${SHA256_WIN11_GOLDEN_QCOW2}"',
            "windows_helper_authority_open",
            "windows_helper_kvm_guestfish_run",
        ),
        "diagnostic golden hash-before-inspection",
    )

    for token, label in (
        ("outer image archive contains duplicate member names", "outer-member uniqueness"),
        ("Docker image manifest must describe exactly one image", "single-image archive"),
        ("len(layers) != len(set(layers))", "unique image layers"),
        ('target = f"boot/vmlinuz-{args.kernel_version}"', "exact kernel path"),
        ('whiteout = f"boot/.wh.vmlinuz-{args.kernel_version}"', "kernel-whiteout refusal"),
        ('opaque_whiteout = "boot/.wh..wh..opq"', "opaque boot-whiteout refusal"),
        ('boot_whiteout = ".wh.boot"', "whole boot-directory whiteout refusal"),
        ("if found != 1:", "single kernel member"),
        ("digest.hexdigest() != expected_sha256", "kernel SHA-256 verification"),
        ("os.O_EXCL", "no-clobber kernel extraction"),
        ("os.fsync(descriptor)", "kernel data durability"),
        ("os.fsync(parent_descriptor)", "kernel directory durability"),
    ):
        require(extractor, token, label)

    for token, label in (
        ("readonly GOLDEN=/authority/golden.qcow2", "fixed golden path"),
        ("marker)", "fixed marker operation"),
        ("inventory)", "fixed inventory operation"),
        ("/usr/bin/virt-cat", "fixed virt-cat executable"),
        ("/usr/bin/virt-ls", "fixed virt-ls executable"),
    ):
        require(inspector, token, label)
    for token, label in (
        ('DOCKER = "/usr/bin/docker"', "fixed provenance Docker client"),
        ("local image provenance verification refuses root execution",
         "provenance root refusal"),
        (
            '"--rm",\n'
            '            "--pull=never",\n'
            '            "--network=none",\n'
            '            "--read-only",\n'
            '            "--user",\n'
            '            f"{os.getuid()}:{os.getgid()}",\n'
            '            "--cap-drop=ALL",\n'
            '            "--security-opt=no-new-privileges",\n'
            '            "--pids-limit=64",',
            "provenance no-pull launch",
        ),
        ('"--network=none"', "provenance networkless launch"),
        ('"--read-only"', "provenance read-only root"),
        ('f"{os.getuid()}:{os.getgid()}"', "provenance numeric nonroot identity"),
        ('"--cap-drop=ALL"', "provenance capability drop"),
        ('"--security-opt=no-new-privileges"', "provenance no-new-privileges"),
        ('"--pids-limit=64"', "provenance process ceiling"),
        ('"--memory-swap=512m"', "provenance no-swap expansion"),
    ):
        require(provenance, token, label)

    require(sources["pins"], 'WIN_HELPER_IMAGE_ID="sha256:', "immutable helper image pin")
    require(
        sources["pins"],
        'WIN_HELPER_KERNEL_VERSION="6.8.0-134-generic"',
        "helper kernel version pin",
    )
    require(
        sources["pins"],
        'SHA256_WIN_HELPER_KERNEL="72526aac4c8c3f63d30fe0741f0c3b1923e700585750cb135815d5c2f831b691"',
        "helper kernel SHA-256 pin",
    )
    require(
        sources["verify"],
        "python3 scripts/verify-windows-helper-authority.py --repo . --self-test",
        "shared focused-verifier wiring",
    )
    require(sources["requirements"], '<span class="id">R-S11ch</span>', "R-S11ch requirement")
    require(sources["requirements"], '<span class="id">R-S11do</span>', "R-S11do requirement")
    require(
        sources["requirements"],
        "provision-owned in-progress leaf solely to test its terminal completion marker",
        "provision-time golden hash-order requirement",
    )
    require(sources["requirements"], "<tr><td>227</td>", "Appendix C #227 disposition")
    require(sources["requirements"], "<tr><td>268</td>", "Appendix C #268 disposition")
    require(
        sources["hardening"],
        "R-S11ch/R-S11e-100 — Windows helper container and KVM authority",
        "hardening-ledger disposition",
    )
    require(
        sources["hardening"],
        "R-S11do/R-S11e-133 — Windows-helper fixed local-Docker, mount, resource, KVM, and cleanup authority",
        "current Windows-helper hardening-ledger disposition",
    )
    require(
        sources["workspace"],
        '"windows_helper_authority_verifier": (\n'
        '                repo / "scripts/verify-windows-helper-authority.py"',
        "workspace-verifier source ownership",
    )
    require(
        sources["workspace"],
        "Windows helper focused authority verifier",
        "workspace-verifier semantic binding",
    )
    require(
        sources["readme"],
        "`windows-helper-runtime.sh`",
        "operator documentation",
    )


MUTATIONS: Tuple[Mutation, ...] = (
    Mutation(
        "runtime",
        'initialize_local_docker_authority \\\n'
        '        "$WINDOWS_HELPER_RUNTIME_ROOT/docker-config" \\\n'
        '        "Windows helper runtime"',
        "true # shared local-Docker authority removed",
        "shared local-Docker authority initialization",
    ),
    Mutation(
        "runtime",
        'initialize_local_docker_authority \\\n'
        '        "$WINDOWS_HELPER_RUNTIME_ROOT/docker-config" \\\n'
        '        "Windows helper runtime"',
        'initialize_local_docker_authority \\\n'
        '        "$WINDOWS_HELPER_RUNTIME_ROOT/docker-config" \\\n'
        '        "Windows helper runtime"\n'
        '    initialize_local_docker_authority \\\n'
        '        "$WINDOWS_HELPER_RUNTIME_ROOT/docker-config" \\\n'
        '        "Windows helper runtime"',
        "single shared Docker-authority initialization",
    ),
    Mutation("runtime", "refuse host or container-root execution",
             "permit host root execution", "root execution refusal"),
    Mutation(
        "runtime",
        '[ "$WINDOWS_HELPER_DOCKER_AUTHORITY_OPEN" -eq 0 ] \\\n'
        '        || die "Windows helper Docker authority state is already open"',
        "true # stale runtime-owned authority state accepted",
        "authority-open state precondition",
    ),
    Mutation(
        "runtime",
        '[ "$LOCAL_DOCKER_AUTHORITY_INITIALIZED" -eq 0 ] \\\n'
        '        || die "Windows helper refuses an existing process-local Docker authority"',
        "true # foreign process-local authority accepted",
        "foreign process-local authority refusal",
    ),
    Mutation(
        "runtime",
        '[ "$WINDOWS_HELPER_DOCKER_AUTHORITY_OPEN" -eq 0 ] \\\n'
        '            && [ "$LOCAL_DOCKER_AUTHORITY_INITIALIZED" -eq 0 ] \\\n'
        '            || { echo "Windows helper empty runtime has live Docker authority state"',
        "true # empty-runtime live Docker state accepted",
        "empty-runtime authority-state refusal",
    ),
    Mutation(
        "runtime",
        '[ "$WINDOWS_HELPER_BUILD_UID" -ne 0 ]',
        "true # runtime UID zero accepted",
        "runtime host-UID root refusal",
    ),
    Mutation(
        "runtime",
        '[ "$WINDOWS_HELPER_BUILD_GID" -ne 0 ]',
        "true # runtime primary-GID zero accepted",
        "runtime primary-GID root refusal",
    ),
    Mutation(
        "runtime",
        "WINDOWS_HELPER_DOCKER_AUTHORITY_OPEN=1",
        "true # successful Docker authority is not recorded",
        "successful authority-open commit",
    ),
    Mutation(
        "runtime",
        'if [ "$WINDOWS_HELPER_DOCKER_AUTHORITY_OPEN" -eq 1 ]; then',
        'if [ "$LOCAL_DOCKER_AUTHORITY_INITIALIZED" -eq 1 ]; then',
        "runtime-owned Docker cleanup selection",
    ),
    Mutation(
        "runtime",
        '[ "$LOCAL_DOCKER_AUTHORITY_INITIALIZED" -eq 1 ] \\\n'
        '            || { echo "Windows helper preserving runtime after premature Docker authority loss"',
        'true # premature Docker authority loss accepted',
        "premature Docker-authority loss refusal",
    ),
    Mutation(
        "runtime",
        "remove_local_docker_authority || return 1",
        "true # Docker authority retirement removed",
        "Docker-first authority retirement",
    ),
    Mutation(
        "runtime",
        "remove_local_docker_authority || return 1",
        "remove_local_docker_authority || return 1\n"
        "        remove_local_docker_authority || return 1",
        "single exact Docker-authority retirement",
    ),
    Mutation(
        "runtime",
        '--remove-private-root "$WINDOWS_HELPER_RUNTIME_ROOT"',
        '--remove-empty-private-root "$WINDOWS_HELPER_RUNTIME_ROOT"',
        "descriptor-safe runtime-root removal",
    ),
    Mutation(
        "runtime",
        '--remove-private-root "$WINDOWS_HELPER_RUNTIME_ROOT"',
        '--remove-private-root "$WINDOWS_HELPER_RUNTIME_ROOT" \\\n'
        '            --remove-private-root "$WINDOWS_HELPER_RUNTIME_ROOT"',
        "single exact runtime-root closer",
    ),
    Mutation(
        "runtime",
        '--expected-identity "$WINDOWS_HELPER_RUNTIME_ROOT_ID"',
        "--expected-identity 1:1",
        "runtime-root cleanup identity",
    ),
    Mutation(
        "runtime",
        'WINDOWS_HELPER_RUNTIME_ROOT_ID="$(\n'
        '        /usr/bin/stat -c \'%d:%i\' -- "$WINDOWS_HELPER_RUNTIME_ROOT"',
        'WINDOWS_HELPER_RUNTIME_ROOT_ID="1:1" # runtime identity not recorded',
        "recorded runtime-root identity",
    ),
    Mutation(
        "runtime",
        'WINDOWS_HELPER_RUNTIME_ROOT_ID="$(\n'
        '        /usr/bin/stat -c \'%d:%i\' -- "$WINDOWS_HELPER_RUNTIME_ROOT"\n'
        '    )" || die "cannot record Windows helper runtime-root identity"\n'
        '    /usr/bin/install -d -m 0700 \\\n'
        '        "$WINDOWS_HELPER_RUNTIME_ROOT/authority" \\\n'
        '        "$WINDOWS_HELPER_RUNTIME_ROOT/kernel"\n'
        '    initialize_local_docker_authority \\\n'
        '        "$WINDOWS_HELPER_RUNTIME_ROOT/docker-config" \\\n'
        '        "Windows helper runtime"',
        '/usr/bin/install -d -m 0700 \\\n'
        '        "$WINDOWS_HELPER_RUNTIME_ROOT/authority" \\\n'
        '        "$WINDOWS_HELPER_RUNTIME_ROOT/kernel"\n'
        '    initialize_local_docker_authority \\\n'
        '        "$WINDOWS_HELPER_RUNTIME_ROOT/docker-config" \\\n'
        '        "Windows helper runtime"\n'
        '    WINDOWS_HELPER_RUNTIME_ROOT_ID="$(\n'
        '        /usr/bin/stat -c \'%d:%i\' -- "$WINDOWS_HELPER_RUNTIME_ROOT"\n'
        '    )" || die "cannot record Windows helper runtime-root identity"',
        "runtime-root identity before population and Docker-authority commit",
    ),
    Mutation(
        "runtime",
        "remove_local_docker_authority || return 1\n"
        "        WINDOWS_HELPER_DOCKER_AUTHORITY_OPEN=0\n"
        '    elif [ "$LOCAL_DOCKER_AUTHORITY_INITIALIZED" -eq 1 ]; then\n'
        '        echo "Windows helper preserving runtime with unowned Docker authority" >&2\n'
        "        return 1\n"
        "    fi\n"
        "    /usr/bin/env -i PATH=/usr/bin:/bin \\\n",
        "/usr/bin/env -i PATH=/usr/bin:/bin \\\n"
        "            /usr/bin/true\n"
        "        WINDOWS_HELPER_DOCKER_AUTHORITY_OPEN=0\n"
        '    elif [ "$LOCAL_DOCKER_AUTHORITY_INITIALIZED" -eq 1 ]; then\n'
        '        echo "Windows helper preserving runtime with unowned Docker authority" >&2\n'
        "        return 1\n"
        "    fi\n"
        "    remove_local_docker_authority || return 1\n",
        "Docker-first cleanup before runtime-root retirement",
    ),
    Mutation("runtime", 'require_pinned_builder_image win-helper "$WIN_HELPER_IMAGE_ID"',
             "true # helper image provenance removed", "immutable image provenance"),
    Mutation("runtime", "local_docker run --rm --pull=never --network=none --read-only",
             "run --rm", "common container confinement"),
    Mutation(
        "runtime",
        "local_docker run --rm --pull=never --network=none --read-only",
        "/usr/bin/docker run --rm --pull=never --network=none --read-only",
        "direct Docker client execution",
    ),
    Mutation("runtime", '--user "$WINDOWS_HELPER_BUILD_UID:$WINDOWS_HELPER_BUILD_GID"',
             "--user 0:0", "numeric nonroot identity"),
    Mutation("runtime", "--cap-drop=ALL --security-opt=no-new-privileges",
             "--cap-drop=NET_RAW", "privilege confinement"),
    Mutation("runtime", "--memory=4g --memory-swap=4g",
             "--memory=4g --memory-swap=-1", "libguestfs no-swap ceiling"),
    Mutation("runtime", "--tmpfs /var/tmp:rw,exec,nosuid,nodev,mode=1777,size=512m",
             "--tmpfs /var/tmp:rw,exec,dev,mode=1777,size=8g", "QEMU scratch ceiling"),
    Mutation("runtime", "--device /dev/kvm:/dev/kvm:rw",
             "--privileged", "narrow KVM device authorization"),
    Mutation(
        "runtime",
        'WINDOWS_HELPER_VALIDATED_MOUNT_VALUE="$value,bind-recursive=disabled"',
        'WINDOWS_HELPER_VALIDATED_MOUNT_VALUE="$value"',
        "recursive caller-bind exclusion",
    ),
    Mutation(
        "runtime",
        "source=$WINDOWS_HELPER_RUNTIME_ROOT/kernel/vmlinuz,target=/authority/kernel/vmlinuz,readonly,bind-recursive=disabled",
        "source=$WINDOWS_HELPER_RUNTIME_ROOT/kernel/vmlinuz,target=/authority/kernel/vmlinuz,readonly",
        "fixed kernel recursive-bind exclusion",
    ),
    Mutation(
        "runtime",
        "--ulimit core=0:0 --ulimit nofile=4096:4096",
        "--ulimit core=-1:-1 --ulimit nofile=1048576:1048576",
        "core and descriptor ceilings",
    ),
    Mutation(
        "runtime",
        "--ulimit fsize=137438953472:137438953472",
        "--ulimit fsize=-1:-1",
        "finite file-size ceiling",
    ),
    Mutation("runtime", "Windows helper bind source must be a regular file or directory",
             "Windows helper bind source may be any filesystem object",
             "special-file mount refusal"),
    Mutation("runtime", "Windows helper bind target must be lexically canonical",
             "Windows helper bind target may contain traversal",
             "canonical container target"),
    Mutation("runtime", "/authority/windows-golden-inspect.sh)",
             "/authority/windows-golden-inspect-unprotected.sh)",
             "fixed inspector target protection"),
    Mutation("runtime", "writable Windows helper bind source must be current-UID owned",
             "writable Windows helper bind source may be foreign-owned", "writable mount owner"),
    Mutation("runtime", "writable Windows helper file must be single-link",
             "writable Windows helper file may have aliases", "writable hard-link refusal"),
    Mutation(
        "runtime",
        'windows_helper_verify_archive "$archive" \\\n'
        '        || die "pinned Windows helper image archive provenance '
        'verification failed"\n'
        '    require_pinned_builder_image win-helper "$WIN_HELPER_IMAGE_ID"',
        'true # structural archive proof removed\n'
        '    require_pinned_builder_image win-helper "$WIN_HELPER_IMAGE_ID"',
        "archive pre/post verification",
    ),
    Mutation(
        "runtime",
        '--archive-size "$WIN_HELPER_IMAGE_ARCHIVE_SIZE"',
        '--archive-size "$WIN_HELPER_BOOTSTRAP_IMAGE_ARCHIVE_SIZE"',
        "structural archive size authority",
    ),
    Mutation("runtime", '--kernel-sha256 "$SHA256_WIN_HELPER_KERNEL"',
             '--kernel-sha256 "$SHA256_WIN_HELPER_IMAGE_ARCHIVE"', "independent kernel pin"),
    Mutation(
        "build",
        'readonly WINDOWS_HELPER_BUILD_UID="$(/usr/bin/id -u)"',
        'readonly WINDOWS_HELPER_BUILD_UID="${UID:-0}"',
        "build pre-source numeric UID",
    ),
    Mutation(
        "build",
        "build-windows-vm refuses host or container-root execution",
        "build-windows-vm permits host root execution",
        "build pre-source root refusal",
    ),
    Mutation(
        "build",
        '[ "$WINDOWS_HELPER_BUILD_UID" -ne 0 ]',
        "true # build host UID zero accepted",
        "build exact host-UID root refusal",
    ),
    Mutation(
        "build",
        '[ "$WINDOWS_HELPER_BUILD_GID" -ne 0 ]',
        "true # build primary-GID zero accepted",
        "build exact primary-GID root refusal",
    ),
    Mutation(
        "provision",
        "provision-windows-vm refuses host or container-root execution",
        "provision-windows-vm permits host root execution",
        "provision pre-source root refusal",
    ),
    Mutation(
        "provision",
        '[ "$WINDOWS_HELPER_BUILD_UID" -ne 0 ]',
        "true # provision host UID zero accepted",
        "provision exact host-UID root refusal",
    ),
    Mutation(
        "provision",
        '[ "$WINDOWS_HELPER_BUILD_GID" -ne 0 ]',
        "true # provision primary-GID zero accepted",
        "provision exact primary-GID root refusal",
    ),
    Mutation(
        "golden_verify",
        "verify-windows-golden refuses host or container-root execution",
        "verify-windows-golden permits host root execution",
        "golden verifier pre-source root refusal",
    ),
    Mutation(
        "golden_verify",
        '[ "$WINDOWS_HELPER_BUILD_UID" -ne 0 ]',
        "true # golden verifier host UID zero accepted",
        "golden verification exact host-UID root refusal",
    ),
    Mutation(
        "golden_verify",
        '[ "$WINDOWS_HELPER_BUILD_GID" -ne 0 ]',
        "true # golden verifier primary-GID zero accepted",
        "golden verification exact primary-GID root refusal",
    ),
    Mutation(
        "library",
        "local_docker() {",
        "ambient_docker() {",
        "shared exact-environment Docker wrapper",
    ),
    Mutation(
        "library",
        "DOCKER_HOST DOCKER_CONTEXT DOCKER_CONFIG DOCKER_CERT_PATH DOCKER_TLS_VERIFY DOCKER_TLS",
        "DOCKER_HOST DOCKER_CONFIG DOCKER_CERT_PATH DOCKER_TLS_VERIFY DOCKER_TLS",
        "shared inherited Docker-context refusal",
    ),
    Mutation(
        "build",
        'windows_helper_small_run \\\n'
        '        --mount "type=bind,source=$msi_input,target=/authority/input.msi,readonly"',
        'docker run \\\n'
        '        --mount "type=bind,source=$msi_input,target=/authority/input.msi,readonly"',
        "small-operation wrapper",
    ),
    Mutation("build", "windows_helper_media_run", "docker run", "media-operation wrapper"),
    Mutation(
        "build",
        'windows_helper_guestfish_run \\\n'
        '        --mount "type=bind,source=$CURRENT_PASS_ROOT/output.img,target=/authority/output.img"',
        'docker run \\\n'
        '        --mount "type=bind,source=$CURRENT_PASS_ROOT/output.img,target=/authority/output.img"',
        "guestfish wrapper",
    ),
    Mutation("build", "qemu-img create -f qcow2 -F qcow2 -b ../golden.qcow2 overlay.qcow2",
             'qemu-img create -f qcow2 -F qcow2 -b "$PRIVATE_GOLDEN" overlay.qcow2',
             "relative overlay backing path"),
    Mutation("build", 'source=$msi_input,target=/authority/input.msi,readonly',
             'source=$extracted,target=/out"', "narrow MSI input"),
    Mutation(
        "provision",
        'windows_helper_runtime_resolve "$ONLINE_DIR/build-images/win-helper.docker.tar.gz"',
        "true # provision helper authority resolution removed",
        "provision immutable image/archive resolution",
    ),
    Mutation("provision", 'source=$GOLDEN,target=/authority/golden.qcow2,readonly',
             'source=$STATE_DIR,target=/state,readonly', "provision exact golden mount"),
    Mutation(
        "provision",
        '                    if golden_has_done_marker; then\n'
        '                        verify_sha256 "$GOLDEN" "${SHA256_WIN11_GOLDEN_QCOW2}"',
        '                    if golden_has_done_marker; then\n'
        "                        true # final golden hash removed",
        "provision final hash before acceptance",
    ),
    Mutation(
        "golden_verify",
        'windows_helper_runtime_resolve "$ONLINE_DIR/build-images/win-helper.docker.tar.gz"',
        "true # golden verifier helper authority resolution removed",
        "verifier immutable image/archive resolution",
    ),
    Mutation("golden_verify", 'source=$GOLDEN,target=/authority/golden.qcow2,readonly',
             'source=$STATE_DIR,target=/state,readonly', "verifier exact golden mount"),
    Mutation(
        "golden_verify",
        'verify_sha256 "$GOLDEN" "${SHA256_WIN11_GOLDEN_QCOW2}"',
        "true # diagnostic golden prehash removed",
        "diagnostic golden hash-before-inspection",
    ),
    Mutation("extractor", 'opaque_whiteout = "boot/.wh..wh..opq"',
             'opaque_whiteout = "boot/.wh..wh..opq-disabled"',
             "opaque boot-whiteout refusal"),
    Mutation("extractor", "digest.hexdigest() != expected_sha256",
             "False", "kernel byte verification"),
    Mutation("extractor", "if found != 1:", "if found < 1:", "single kernel member"),
    Mutation("provenance", 'DOCKER = "/usr/bin/docker"', 'DOCKER = "docker"',
             "provenance fixed Docker client"),
    Mutation(
        "provenance",
        '"--rm",\n'
        '            "--pull=never",\n'
        '            "--network=none",\n'
        '            "--read-only",\n'
        '            "--user",\n'
        '            f"{os.getuid()}:{os.getgid()}",\n'
        '            "--cap-drop=ALL",\n'
        '            "--security-opt=no-new-privileges",\n'
        '            "--pids-limit=64",',
        '"--rm",\n'
        '            "--pull=always",\n'
        '            "--network=none",\n'
        '            "--read-only",\n'
        '            "--user",\n'
        '            f"{os.getuid()}:{os.getgid()}",\n'
        '            "--cap-drop=ALL",\n'
        '            "--security-opt=no-new-privileges",\n'
        '            "--pids-limit=64",',
        "provenance no-pull launch",
    ),
    Mutation(
        "provenance",
        '"--rm",\n'
        '            "--pull=never",\n'
        '            "--network=none",\n'
        '            "--read-only",\n'
        '            "--user",\n'
        '            f"{os.getuid()}:{os.getgid()}",\n'
        '            "--cap-drop=ALL",\n'
        '            "--security-opt=no-new-privileges",\n'
        '            "--pids-limit=64",',
        '"--rm",\n'
        '            "--pull=never",\n'
        '            "--network=none",\n'
        '            "--read-only",\n'
        '            "--user",\n'
        '            f"{os.getuid()}:{os.getgid()}",\n'
        '            "--cap-add=ALL",\n'
        '            "--security-opt=no-new-privileges",\n'
        '            "--pids-limit=64",',
        "provenance capability drop",
    ),
    Mutation("verify", "python3 scripts/verify-windows-helper-authority.py --repo . --self-test",
             "true # Windows helper authority verifier removed", "shared verifier wiring"),
    Mutation("requirements", '<span class="id">R-S11ch</span>',
             '<span class="id">R-S11ch-disabled</span>', "R-S11ch requirement"),
    Mutation("requirements", '<span class="id">R-S11do</span>',
             '<span class="id">R-S11do-disabled</span>', "R-S11do requirement"),
    Mutation(
        "requirements",
        "provision-owned in-progress leaf solely to test its terminal completion marker",
        "arbitrary in-progress tree before accepting any state",
        "provision-time golden hash-order requirement",
    ),
    Mutation("requirements", "<tr><td>227</td>", "<tr><td>227-disabled</td>",
             "Appendix C #227 disposition"),
    Mutation("requirements", "<tr><td>268</td>", "<tr><td>268-disabled</td>",
             "Appendix C #268 disposition"),
    Mutation("hardening", "R-S11ch/R-S11e-100 — Windows helper container and KVM authority",
             "R-S11ch/R-S11e-100 — Windows ambient helper authority",
             "hardening ledger"),
    Mutation(
        "hardening",
        "R-S11do/R-S11e-133 — Windows-helper fixed local-Docker, mount, resource, KVM, and cleanup authority",
        "R-S11do/R-S11e-133 — Windows-helper ambient authority",
        "current Windows-helper hardening ledger",
    ),
    Mutation(
        "workspace",
        '"windows_helper_authority_verifier": (\n'
        '                repo / "scripts/verify-windows-helper-authority.py"',
        '"windows_helper_authority_verifier": (\n'
        '                repo / "scripts/verify-windows-helper-authority-disabled.py"',
        "workspace source ownership",
    ),
    Mutation("readme", "`windows-helper-runtime.sh`",
             "`windows-helper-runtime-disabled.sh`", "operator documentation"),
)


def load_sources(repo: pathlib.Path) -> Dict[str, str]:
    return {
        "runtime": (repo / "scripts/windows-helper-runtime.sh").read_text(encoding="utf-8"),
        "build": (repo / "scripts/build-windows-vm.sh").read_text(encoding="utf-8"),
        "provision": (repo / "scripts/provision-windows-vm.sh").read_text(encoding="utf-8"),
        "golden_verify": (repo / "scripts/verify-windows-golden.sh").read_text(encoding="utf-8"),
        "extractor": (repo / "scripts/windows-helper-extract-kernel.py").read_text(encoding="utf-8"),
        "inspector": (repo / "scripts/windows-golden-inspect.sh").read_text(encoding="utf-8"),
        "provenance": (repo / "scripts/offline-image-provenance.py").read_text(encoding="utf-8"),
        "library": (repo / "scripts/lib.sh").read_text(encoding="utf-8"),
        "pins": (repo / "scripts/pins.env").read_text(encoding="utf-8"),
        "verify": (repo / "scripts/verify.sh").read_text(encoding="utf-8"),
        "requirements": (repo / "requirements.html").read_text(encoding="utf-8"),
        "hardening": (repo / "HARDENING_STATUS.md").read_text(encoding="utf-8"),
        "workspace": (repo / "scripts/verify-verifier-workspace.py").read_text(encoding="utf-8"),
        "readme": (repo / "scripts/README.md").read_text(encoding="utf-8"),
    }


def run_mutations(sources: Dict[str, str]) -> None:
    for mutation in MUTATIONS:
        original = sources[mutation.source]
        observed = original.count(mutation.old)
        if observed != 1:
            raise AuthorityError(
                "mutation target for {} occurs {} times".format(mutation.label, observed)
            )
        changed = dict(sources)
        changed[mutation.source] = original.replace(mutation.old, mutation.new, 1)
        try:
            validate(changed)
        except AuthorityError:
            continue
        raise AuthorityError("mutation was accepted: {}".format(mutation.label))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=pathlib.Path, default=pathlib.Path("."))
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    sources = load_sources(args.repo.resolve())
    validate(sources)
    if args.self_test:
        run_mutations(sources)
        print(
            "Windows helper authority verifier self-test: PASS "
            "({} mutations)".format(len(MUTATIONS))
        )
    else:
        print("Windows helper authority verifier: PASS")


if __name__ == "__main__":
    try:
        main()
    except AuthorityError as error:
        raise SystemExit("Windows helper authority verifier: FAIL: {}".format(error))
