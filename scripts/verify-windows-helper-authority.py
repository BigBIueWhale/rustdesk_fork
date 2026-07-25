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

    for token, label in (
        ("WINDOWS_HELPER_DOCKER_BIN=/usr/bin/docker", "fixed Docker client"),
        ("WINDOWS_HELPER_DOCKER_HOST=unix:///var/run/docker.sock", "fixed local Docker daemon"),
        ("export PATH=/usr/bin:/bin", "closed host command path"),
        ("refuse host or container-root execution", "root execution refusal"),
        ("refuse a root primary group", "root primary-group refusal"),
        ("DOCKER_CONTEXT DOCKER_CERT_PATH DOCKER_TLS_VERIFY DOCKER_TLS \\\n"
         "        DOCKER_API_VERSION DOCKER_DEFAULT_PLATFORM DOCKER_CONTENT_TRUST",
         "ambient Docker endpoint/protocol/platform/trust refusal"),
        ("mktemp -d /tmp/rustdesk-windows-helper.XXXXXXXXXX",
         "private random runtime root"),
        ('printf \'{}\\n\' >"$WINDOWS_HELPER_RUNTIME_ROOT/docker-config/config.json"',
         "canonical empty Docker configuration"),
        ("Windows helper Docker config.json must remain the canonical empty configuration",
         "Docker configuration byte postcondition"),
        ('--host "$WINDOWS_HELPER_DOCKER_HOST"', "explicit Docker host"),
        ('--config "$WINDOWS_HELPER_RUNTIME_ROOT/docker-config"', "explicit Docker configuration"),
        ('require_pinned_builder_image win-helper "$WIN_HELPER_IMAGE_ID"',
         "immutable helper image provenance"),
        ('verify_sha256 "$archive" "$SHA256_WIN_HELPER_IMAGE_ARCHIVE"',
         "captured helper archive verification"),
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
        ("source=$WINDOWS_HELPER_RUNTIME_ROOT/kernel/vmlinuz,target=/authority/kernel/vmlinuz,readonly",
         "read-only derived-kernel mount"),
        ("source=$WINDOWS_HELPER_RUNTIME_ROOT/authority/windows-golden-inspect.sh,target=/authority/windows-golden-inspect.sh,readonly",
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
        ("--group-add \"$WINDOWS_HELPER_KVM_GID\"", "narrow KVM group authorization"),
        ("--device /dev/kvm:/dev/kvm:rwm", "sole KVM device authorization"),
        ('\'\'|*[!0-9]*|0) die "/dev/kvm must have one non-root numeric group"',
         "root KVM-group refusal"),
    ):
        require(runtime, token, label)

    require_count(
        runtime,
        'verify_sha256 "$archive" "$SHA256_WIN_HELPER_IMAGE_ARCHIVE"',
        2,
        "archive pre/post verification",
    )
    require_count(runtime, "--device /dev/kvm:/dev/kvm:rwm", 1, "single exact device grant")
    require_count(runtime, "--network=none", 1, "single common network policy")
    require_count(runtime, "--pull=never", 1, "single common pull policy")
    require_count(runtime, "--cap-drop=ALL", 1, "single common capability policy")

    for token, label in (
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
    ):
        forbid(runtime, token, label)

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
        ('"--pull=never"', "provenance no-pull launch"),
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
    require(
        sources["requirements"],
        "provision-owned in-progress leaf solely to test its terminal completion marker",
        "provision-time golden hash-order requirement",
    )
    require(sources["requirements"], "<tr><td>227</td>", "Appendix C #227 disposition")
    require(
        sources["hardening"],
        "R-S11ch/R-S11e-100 — Windows helper container and KVM authority",
        "hardening-ledger disposition",
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
    Mutation("runtime", "WINDOWS_HELPER_DOCKER_BIN=/usr/bin/docker",
             "WINDOWS_HELPER_DOCKER_BIN=docker", "fixed Docker client"),
    Mutation("runtime", "refuse host or container-root execution",
             "permit host root execution", "root execution refusal"),
    Mutation(
        "runtime",
        "DOCKER_CONTEXT DOCKER_CERT_PATH DOCKER_TLS_VERIFY DOCKER_TLS \\\n"
        "        DOCKER_API_VERSION DOCKER_DEFAULT_PLATFORM DOCKER_CONTENT_TRUST",
        "DOCKER_CERT_PATH DOCKER_TLS_VERIFY DOCKER_TLS \\\n"
        "        DOCKER_API_VERSION DOCKER_DEFAULT_PLATFORM DOCKER_CONTENT_TRUST",
        "ambient Docker context refusal",
    ),
    Mutation("runtime", "must remain the canonical empty configuration",
             "may contain caller configuration", "empty Docker configuration"),
    Mutation("runtime", 'require_pinned_builder_image win-helper "$WIN_HELPER_IMAGE_ID"',
             "true # helper image provenance removed", "immutable image provenance"),
    Mutation("runtime", "run --rm --pull=never --network=none --read-only",
             "run --rm", "common container confinement"),
    Mutation("runtime", '--user "$WINDOWS_HELPER_BUILD_UID:$WINDOWS_HELPER_BUILD_GID"',
             "--user 0:0", "numeric nonroot identity"),
    Mutation("runtime", "--cap-drop=ALL --security-opt=no-new-privileges",
             "--cap-drop=NET_RAW", "privilege confinement"),
    Mutation("runtime", "--memory=4g --memory-swap=4g",
             "--memory=4g --memory-swap=-1", "libguestfs no-swap ceiling"),
    Mutation("runtime", "--tmpfs /var/tmp:rw,exec,nosuid,nodev,mode=1777,size=512m",
             "--tmpfs /var/tmp:rw,exec,dev,mode=1777,size=8g", "QEMU scratch ceiling"),
    Mutation("runtime", "--device /dev/kvm:/dev/kvm:rwm",
             "--privileged", "narrow KVM device authorization"),
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
        'verify_sha256 "$archive" "$SHA256_WIN_HELPER_IMAGE_ARCHIVE"\n'
        '    require_pinned_builder_image win-helper "$WIN_HELPER_IMAGE_ID"',
        'true # archive hash removed\n'
        '    require_pinned_builder_image win-helper "$WIN_HELPER_IMAGE_ID"',
        "archive pre/post verification",
    ),
    Mutation("runtime", '--kernel-sha256 "$SHA256_WIN_HELPER_KERNEL"',
             '--kernel-sha256 "$SHA256_WIN_HELPER_IMAGE_ARCHIVE"', "independent kernel pin"),
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
        '                if golden_has_done_marker; then\n'
        '                    verify_sha256 "$GOLDEN" "${SHA256_WIN11_GOLDEN_QCOW2}"',
        '                if golden_has_done_marker; then\n'
        "                    true # final golden hash removed",
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
    Mutation("provenance", '"--pull=never"', '"--pull=always"',
             "provenance no-pull launch"),
    Mutation("provenance", '"--cap-drop=ALL"', '"--cap-add=ALL"',
             "provenance capability drop"),
    Mutation("verify", "python3 scripts/verify-windows-helper-authority.py --repo . --self-test",
             "true # Windows helper authority verifier removed", "shared verifier wiring"),
    Mutation("requirements", '<span class="id">R-S11ch</span>',
             '<span class="id">R-S11ch-disabled</span>', "R-S11ch requirement"),
    Mutation(
        "requirements",
        "provision-owned in-progress leaf solely to test its terminal completion marker",
        "arbitrary in-progress tree before accepting any state",
        "provision-time golden hash-order requirement",
    ),
    Mutation("requirements", "<tr><td>227</td>", "<tr><td>227-disabled</td>",
             "Appendix C #227 disposition"),
    Mutation("hardening", "R-S11ch/R-S11e-100 — Windows helper container and KVM authority",
             "R-S11ch/R-S11e-100 — Windows ambient helper authority",
             "hardening ledger"),
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
