#!/usr/bin/env python3
"""Validate the release parent's fixed local-Docker authority."""

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
        raise AuthorityError(
            "{} count is {}, expected {}".format(label, observed, count)
        )


def forbid(source: str, token: str, label: str) -> None:
    if token in source:
        raise AuthorityError("forbidden {}".format(label))


def extract(source: str, start: str, end: str, label: str) -> str:
    try:
        begin = source.index(start)
        finish = source.index(end, begin)
    except ValueError as error:
        raise AuthorityError("missing {}".format(label)) from error
    return source[begin:finish]


def require_order(source: str, tokens: Tuple[str, ...], label: str) -> None:
    try:
        positions = tuple(source.index(token) for token in tokens)
    except ValueError as error:
        raise AuthorityError("{} is incomplete or misordered".format(label)) from error
    if positions != tuple(sorted(positions)) or len(set(positions)) != len(positions):
        raise AuthorityError("{} is incomplete or misordered".format(label))


def validate_shared_authority(lib: str) -> None:
    initializer = extract(
        lib,
        "initialize_local_docker_authority() {",
        "\n}\n\nassert_local_docker_authority() {",
        "shared Docker-authority initializer",
    )
    for token, label in (
        ('[ "$(/usr/bin/id -u)" -ne 0 ]', "shared UID-root refusal"),
        ('[ "$(/usr/bin/id -g)" -ne 0 ]', "shared primary-GID-root refusal"),
        (
            "[ -f /usr/bin/docker ] && [ ! -L /usr/bin/docker ] && [ -x /usr/bin/docker ]",
            "fixed absolute Docker client",
        ),
        (
            "0:0:755:1) ;;",
            "root-owned mode-0755 single-link Docker client",
        ),
        (
            "[ -S /var/run/docker.sock ] && [ ! -L /var/run/docker.sock ]",
            "fixed local Docker socket",
        ),
        (
            "DOCKER_HOST DOCKER_CONTEXT DOCKER_CONFIG DOCKER_CERT_PATH DOCKER_TLS_VERIFY DOCKER_TLS",
            "Docker routing/configuration/TLS refusal",
        ),
        (
            "DOCKER_API_VERSION DOCKER_DEFAULT_PLATFORM DOCKER_CONTENT_TRUST",
            "Docker API/platform/trust refusal",
        ),
        (
            "DOCKER_CONTENT_TRUST_SERVER DOCKER_CUSTOM_HEADERS",
            "Docker trust-server/header refusal",
        ),
        (
            "(umask 077 && set -o noclobber && printf '{}\\n' >\"$config/config.json\")",
            "canonical no-clobber Docker configuration",
        ),
        ("LOCAL_DOCKER_AUTHORITY_PARENT_ID=", "authority-parent identity"),
        ("LOCAL_DOCKER_AUTHORITY_CONFIG_ID=", "configuration identity"),
        ("LOCAL_DOCKER_AUTHORITY_CONFIG_FILE_ID=", "configuration-file identity"),
        ("LOCAL_DOCKER_AUTHORITY_CLIENT_ID=", "client identity"),
        ("LOCAL_DOCKER_AUTHORITY_SOCKET_ID=", "socket identity"),
    ):
        require(initializer, token, label)

    assertion = extract(
        lib,
        "assert_local_docker_authority() {",
        "\n}\n\nlocal_docker() {",
        "shared Docker-authority assertion",
    )
    for token, label in (
        ("LOCAL_DOCKER_AUTHORITY_PARENT_ID", "authority-parent recheck"),
        ("LOCAL_DOCKER_AUTHORITY_CONFIG_ID", "configuration recheck"),
        ("LOCAL_DOCKER_AUTHORITY_CONFIG_FILE_ID", "configuration-file recheck"),
        ("LOCAL_DOCKER_AUTHORITY_CLIENT_ID", "client recheck"),
        ("LOCAL_DOCKER_AUTHORITY_SOCKET_ID", "socket recheck"),
        (
            '/usr/bin/cmp -s -- "$LOCAL_DOCKER_AUTHORITY_CONFIG/config.json"',
            "configuration-byte recheck",
        ),
    ):
        require(assertion, token, label)

    launcher = extract(
        lib,
        "local_docker() {",
        "\n}\n\nlocal_docker_image_provenance() {",
        "shared Docker launcher",
    )
    for token, label in (
        ("/usr/bin/env -i", "empty Docker-client environment"),
        ("PATH=/usr/bin:/bin", "fixed Docker-client path"),
        ('HOME="$LOCAL_DOCKER_AUTHORITY_PARENT"', "private Docker-client home"),
        ("DOCKER_HOST=unix:///var/run/docker.sock", "fixed Docker endpoint"),
        ('DOCKER_CONFIG="$LOCAL_DOCKER_AUTHORITY_CONFIG"', "private Docker config"),
        ("/usr/bin/docker", "absolute Docker client launch"),
        ("--host unix:///var/run/docker.sock", "explicit Docker endpoint"),
        ('--config "$LOCAL_DOCKER_AUTHORITY_CONFIG"', "explicit Docker config"),
    ):
        require(launcher, token, label)
    require_count(
        launcher,
        "assert_local_docker_authority",
        2,
        "Docker launcher pre/post authority proof",
    )

    provenance = extract(
        lib,
        "local_docker_image_provenance() {",
        "\n}\n\nremove_local_docker_authority() {",
        "shared image-provenance launcher",
    )
    require(provenance, "/usr/bin/env -i", "empty provenance environment")
    require(
        provenance,
        '/usr/bin/python3 -I -S "$LIB_DIR/offline-image-provenance.py"',
        "fixed isolated provenance implementation",
    )
    require_count(
        provenance,
        "assert_local_docker_authority",
        2,
        "provenance pre/post authority proof",
    )

    removal = extract(
        lib,
        "remove_local_docker_authority() {",
        "\n}\n\nrequire_pinned_builder_image() {",
        "shared Docker-authority retirement",
    )
    require_order(
        removal,
        (
            "assert_local_docker_authority",
            '/usr/bin/rm -- "$LOCAL_DOCKER_AUTHORITY_CONFIG/config.json"',
            '/usr/bin/rmdir -- "$LOCAL_DOCKER_AUTHORITY_CONFIG"',
            "LOCAL_DOCKER_AUTHORITY_INITIALIZED=0",
        ),
        "exact shared Docker-authority retirement",
    )


def validate(sources: Dict[str, str]) -> None:
    release = sources["release"]
    lib = sources["lib"]
    verify = sources["verify"]
    workspace = sources["workspace"]
    requirements = sources["requirements"]
    hardening = sources["hardening"]

    validate_shared_authority(lib)

    bootstrap = extract(
        release,
        "bootstrap_closed_environment() {",
        "\n}\n\nbootstrap_closed_environment",
        "release bootstrap",
    )
    for token, label in (
        ('uid="$(/usr/bin/id -u)"', "absolute numeric UID capture"),
        ('gid="$(/usr/bin/id -g)"', "absolute numeric primary-GID capture"),
        ('[ "$uid" -ne 0 ]', "host UID-root refusal"),
        ('[ "$gid" -ne 0 ]', "host primary-GID-root refusal"),
        (
            "refuses host or container-root release authority",
            "UID-root refusal diagnostic",
        ),
        (
            "refuses a root primary group for release authority",
            "primary-GID-root refusal diagnostic",
        ),
        ("/usr/bin/env -i", "closed release re-exec environment"),
    ):
        require(bootstrap, token, label)
    require(
        release,
        "GIT_*|DOCKER_*|BUILDKIT_*|COMPOSE_*",
        "closed Docker environment",
    )
    require_order(
        release,
        (
            "bootstrap_closed_environment() {",
            'uid="$(/usr/bin/id -u)"',
            'gid="$(/usr/bin/id -g)"',
            '[ "$uid" -ne 0 ]',
            '[ "$gid" -ne 0 ]',
            'SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"',
            'source "$SCRIPT_DIR/lib.sh"',
            "load_pins",
        ),
        "pre-source numeric root refusal",
    )

    create = extract(
        release,
        "create_workspace() {",
        "\n}\n\nassert_release_online_snapshot() {",
        "release private-workspace construction",
    )
    for token, label in (
        (
            'DOCKER_AUTHORITY_ROOT="$(umask 077 && mktemp -d '
            "/tmp/rustdesk-release-docker.XXXXXXXXXX)\"",
            "unpredictable independent Docker-authority root",
        ),
        (
            "$(/usr/bin/id -u):$(/usr/bin/id -g):700",
            "current-user/current-group private authority root",
        ),
        (
            'DOCKER_AUTHORITY_ROOT_ID="$(/usr/bin/stat -c '
            '\'%d:%i:%u:%g:%a\' -- "$DOCKER_AUTHORITY_ROOT")"',
            "Docker-authority root identity",
        ),
        (
            'initialize_local_docker_authority \\\n'
            '            "$DOCKER_AUTHORITY_ROOT/docker-config" "release parent"',
            "release-parent shared Docker authority",
        ),
    ):
        require(create, token, label)
    require_order(
        create,
        (
            'WORKSPACE="$(umask 077 && mktemp -d /tmp/rustdesk-release.',
            'DOCKER_AUTHORITY_ROOT="$(umask 077 && mktemp -d '
            "/tmp/rustdesk-release-docker.",
            "DOCKER_AUTHORITY_ROOT_ID=",
            "initialize_local_docker_authority",
        ),
        "separate workspace and Docker-authority construction",
    )
    require(
        create,
        '[ "$SELF_TEST" -eq 0 ] && [ "$SELF_TEST_CLEANUP_MISSING" -eq 0 ]',
        "Docker-free non-Docker self-test exception",
    )

    image_proof = extract(
        release,
        "verify_release_builder_image() {",
        "\n}\n\nverify_all_release_builder_images() {",
        "release image-provenance funnel",
    )
    require(
        image_proof,
        'require_pinned_builder_image "$role" "$image_id"',
        "shared isolated image provenance",
    )
    for token, label in (
        ("DOCKER_HOST=", "exported Docker host in image proof"),
        ("DOCKER_CONFIG=", "exported Docker config in image proof"),
        ("docker image inspect", "direct image inspection"),
    ):
        forbid(image_proof, token, label)

    require_count(release, "local_docker run ", 5, "complete release-parent launch inventory")
    require_count(
        release,
        "local_docker version ",
        2,
        "release/reset local-daemon checks",
    )
    for token, label in (
        ("docker_local() {", "bespoke Docker wrapper"),
        ("assert_release_docker_config() {", "bespoke Docker-config assertion"),
        ("DOCKER_HOST_URI=", "bespoke Docker endpoint"),
        ("DOCKER_CONFIG_DIR=", "bespoke Docker-config variable"),
        ("command docker --host", "PATH-selected Docker launch"),
        ("\ndocker run ", "direct Docker run"),
        ("\ndocker image inspect", "direct Docker inspection"),
    ):
        forbid(release, token, label)

    for start, end, label in (
        (
            "offline_normalize_exact_tree() {",
            "\n}\n\nverify_private_tree_authority_capacity() {",
            "ownership normalization launch",
        ),
        (
            "verify_private_tree_authority_capacity() {",
            "\n}\n\nacquire_private_tree_closure_execution() {",
            "retained-authority capacity launch",
        ),
        (
            "offline_remove_exact_tree_contents() {",
            "\n}\n\nverify_private_tree_removal_capability() {",
            "terminal content-removal launch",
        ),
        (
            "verify_private_tree_removal_capability() {",
            "\n}\n\nverify_private_tree_cleanup_preflight() {",
            "removal-capability fixture launch",
        ),
    ):
        block = extract(release, start, end, label)
        for token, item in (
            ("local_docker run", "shared Docker launcher"),
            ("--pull=never", "no implicit pull"),
            ("--network=none", "networkless container"),
            ("--read-only", "read-only container root"),
            ("--user 0:0", "explicit artifact-only root identity"),
            ("--cap-drop=ALL", "default capability removal"),
            ("--security-opt no-new-privileges", "no-new-privileges"),
        ):
            require(block, token, "{} {}".format(label, item))
        for token, item in (
            ("--privileged", "privileged mode"),
            ("--network=host", "host network"),
            ("--pid=host", "host PID namespace"),
            ("--ipc=host", "host IPC namespace"),
            ("--uts=host", "host UTS namespace"),
            ("/var/run/docker.sock", "Docker socket mount"),
            ("--publish", "published port"),
        ):
            forbid(block, token, "{} {}".format(label, item))

    reset_fixture = extract(
        release,
        "run_reset_self_test() {",
        "\n}\n\nrun_cleanup_missing_self_test() {",
        "root-owned reset fixture",
    )
    for token, label in (
        ("local_docker version", "reset fixed-daemon check"),
        ("verify_release_builder_image", "reset immutable image proof"),
        ("local_docker run", "reset shared Docker launcher"),
        ("--pull=never", "reset no-pull"),
        ("--network=none", "reset networkless launch"),
        ("--read-only", "reset read-only root"),
        ("--user 0:0", "reset explicit root fixture"),
        ("--cap-drop=ALL --cap-add=CHOWN", "reset narrow capability"),
        ("--security-opt no-new-privileges", "reset no-new-privileges"),
        ("bind-recursive=disabled", "reset no recursive bind inclusion"),
    ):
        require(reset_fixture, token, label)

    cleanup = extract(
        release,
        "cleanup_release_workspace() {",
        "\n}\n\nretire_release_docker_authority() {",
        "release workspace cleanup",
    )
    for token, label in (
        (
            '[ "$LOCAL_DOCKER_AUTHORITY_INITIALIZED" -eq 1 ]',
            "no ambient cleanup fallback",
        ),
        (
            "production cleanup lacks exact terminal-removal image/Docker authority",
            "missing-authority preservation diagnostic",
        ),
        (
            'offline_remove_exact_tree_contents "$WORKSPACE" "$WORKSPACE_ID"',
            "workspace removal through exact authority",
        ),
        (
            "retire_release_docker_authority || cleanup_failed=1",
            "mandatory authority retirement",
        ),
        (
            "retire_release_docker_authority || status=1",
            "preserved-workspace authority retirement",
        ),
    ):
        require(cleanup, token, label)
    require_order(
        cleanup,
        (
            'offline_remove_exact_tree_contents "$WORKSPACE" "$WORKSPACE_ID"',
            "--remove-empty-private-root",
            "close_private_tree_closure_execution",
            "retire_release_docker_authority || cleanup_failed=1",
        ),
        "terminal workspace cleanup before exact Docker-authority retirement",
    )

    retirement = extract(
        release,
        "retire_release_docker_authority() {",
        "\n}\n\nrelease_preflight() {",
        "release Docker-authority retirement",
    )
    require_order(
        retirement,
        (
            '[ "$LOCAL_DOCKER_AUTHORITY_INITIALIZED" -eq 1 ]',
            "remove_local_docker_authority",
            'observed="$(/usr/bin/stat -c',
            '[ "$observed" = "$DOCKER_AUTHORITY_ROOT_ID" ]',
            '/usr/bin/rmdir -- "$DOCKER_AUTHORITY_ROOT"',
            'DOCKER_AUTHORITY_ROOT=""',
        ),
        "exact independent Docker-authority retirement",
    )
    require(
        retirement,
        "release parent Docker authority state was lost; retained path",
        "changed-authority preservation",
    )

    run_child = extract(
        release,
        "run_child() {",
        "\n}\n\nrun_verification() {",
        "release-child launcher",
    )
    require(run_child, "/usr/bin/env -i", "empty child environment")
    for token, label in (
        ("DOCKER_HOST=", "parent Docker host inheritance"),
        ("DOCKER_CONFIG=", "parent Docker config inheritance"),
        ("DOCKER_CONTEXT=", "parent Docker context inheritance"),
        ("LOCAL_DOCKER_", "parent shared-authority inheritance"),
    ):
        forbid(run_child, token, label)

    for token, label in (
        (
            "python3 scripts/verify-release-parent-docker-authority.py "
            "--repo . --self-test",
            "focused release-parent authority gate wiring",
        ),
        (
            "R-S11e-131 release parent owns one exact fixed local Docker "
            "authority without sharing it with children",
            "shared release-parent authority disposition",
        ),
    ):
        require(verify, token, label)

    for token, label in (
        (
            '"release_parent_authority": (\n'
            '                repo / "scripts/verify-release-parent-docker-authority.py"\n'
            "            ).read_text",
            "independent release-parent verifier source catalog",
        ),
        (
            "validate_release_parent_docker_authority_contract(sources)",
            "independent release-parent authority validation",
        ),
        ("R-S11n through R-S11dn", "independent requirement range"),
        ("Appendix C #192–#267", "independent Appendix range"),
    ):
        require(workspace, token, label)

    require(
        requirements,
        '<span class="id">R-S11dm</span>',
        "R-S11dm normative requirement",
    )
    require(requirements, "<tr><td>266</td>", "Appendix C #266 disposition")
    require(
        hardening,
        "R-S11dm/R-S11e-131 — release-parent Docker client, daemon,\n"
        "  configuration, root-fixture, and cleanup authority",
        "R-S11e-131 hardening ledger",
    )


MUTATIONS = (
    Mutation(
        "release",
        'uid="$(/usr/bin/id -u)"',
        'uid="$(id -u)"',
        "absolute UID capture",
    ),
    Mutation(
        "release",
        'gid="$(/usr/bin/id -g)"',
        'gid="$(id -g)"',
        "absolute primary-GID capture",
    ),
    Mutation(
        "release",
        '[ "$uid" -ne 0 ]',
        "true # UID zero accepted",
        "host UID-root refusal",
    ),
    Mutation(
        "release",
        '[ "$gid" -ne 0 ]',
        "true # primary GID zero accepted",
        "host primary-GID-root refusal",
    ),
    Mutation(
        "release",
        "GIT_*|DOCKER_*|BUILDKIT_*|COMPOSE_*",
        "GIT_*|BUILDKIT_*|COMPOSE_*",
        "closed Docker environment",
    ),
    Mutation(
        "release",
        'DOCKER_AUTHORITY_ROOT="$(umask 077 && mktemp -d '
        '/tmp/rustdesk-release-docker.XXXXXXXXXX)"',
        'DOCKER_AUTHORITY_ROOT="$WORKSPACE/docker-authority"',
        "independent Docker-authority root",
    ),
    Mutation(
        "release",
        'DOCKER_AUTHORITY_ROOT_ID="$(/usr/bin/stat -c '
        '\'%d:%i:%u:%g:%a\' -- "$DOCKER_AUTHORITY_ROOT")"',
        "DOCKER_AUTHORITY_ROOT_ID=unchecked",
        "Docker-authority root identity",
    ),
    Mutation(
        "release",
        'initialize_local_docker_authority \\\n'
        '            "$DOCKER_AUTHORITY_ROOT/docker-config" "release parent"',
        "true # release-parent Docker authority omitted",
        "release-parent authority initialization",
    ),
    Mutation(
        "release",
        'require_pinned_builder_image "$role" "$image_id"',
        'python3 scripts/offline-image-provenance.py "$role" "$image_id"',
        "isolated image provenance",
    ),
    Mutation(
        "release",
        "local_docker run --interactive --rm --pull=never --network=none "
        "--read-only --user 0:0 \\\n"
        "            --cap-drop=ALL --cap-add=DAC_READ_SEARCH",
        "docker run --interactive --rm --pull=never --network=none "
        "--read-only --user 0:0 \\\n"
        "            --cap-drop=ALL --cap-add=DAC_READ_SEARCH",
        "shared Docker launch funnel",
    ),
    Mutation(
        "release",
        '&& [ "$LOCAL_DOCKER_AUTHORITY_INITIALIZED" -eq 1 ]; then',
        "; then # ambient cleanup fallback admitted",
        "cleanup authority requirement",
    ),
    Mutation(
        "release",
        "retire_release_docker_authority || cleanup_failed=1",
        "true # Docker authority retained",
        "mandatory authority retirement",
    ),
    Mutation(
        "release",
        "remove_local_docker_authority || return 125",
        "true # shared authority retained",
        "shared authority retirement call",
    ),
    Mutation(
        "release",
        '[ "$observed" = "$DOCKER_AUTHORITY_ROOT_ID" ]',
        "true # authority-root substitution accepted",
        "authority-root identity recheck",
    ),
    Mutation(
        "release",
        '/usr/bin/rmdir -- "$DOCKER_AUTHORITY_ROOT" || return 125',
        'rm -rf -- "$DOCKER_AUTHORITY_ROOT" || return 125',
        "nonrecursive authority-root retirement",
    ),
    Mutation(
        "release",
        "run_child() {\n    /usr/bin/env -i",
        "run_child() {\n    /usr/bin/env",
        "empty release-child environment",
    ),
    Mutation(
        "lib",
        "[ -f /usr/bin/docker ] && [ ! -L /usr/bin/docker ] && [ -x /usr/bin/docker ]",
        "[ -x \"$(command -v docker)\" ]",
        "fixed absolute Docker client",
    ),
    Mutation(
        "lib",
        "[ -S /var/run/docker.sock ] && [ ! -L /var/run/docker.sock ] \\\n"
        '        || die "$label fixed local Docker Unix socket is unavailable"',
        "[ -e /var/run/docker.sock ] \\\n"
        '        || die "$label fixed local Docker Unix socket is unavailable"',
        "fixed Docker socket shape",
    ),
    Mutation(
        "lib",
        "DOCKER_HOST DOCKER_CONTEXT DOCKER_CONFIG DOCKER_CERT_PATH DOCKER_TLS_VERIFY DOCKER_TLS",
        "DOCKER_HOST DOCKER_CONFIG DOCKER_CERT_PATH DOCKER_TLS_VERIFY DOCKER_TLS",
        "complete Docker input refusal",
    ),
    Mutation(
        "lib",
        "(umask 077 && set -o noclobber && printf '{}\\n' >\"$config/config.json\")",
        "printf '{}\\n' >\"$config/config.json\"",
        "no-clobber Docker configuration",
    ),
    Mutation(
        "lib",
        "local_docker() {\n    local status=0\n"
        "    assert_local_docker_authority || return 1\n    /usr/bin/env -i",
        "local_docker() {\n    local status=0\n"
        "    assert_local_docker_authority || return 1\n    /usr/bin/env",
        "empty Docker client environment",
    ),
    Mutation(
        "lib",
        "--host unix:///var/run/docker.sock",
        "--host tcp://127.0.0.1:2375",
        "explicit local Docker endpoint",
    ),
    Mutation(
        "lib",
        '/usr/bin/rm -- "$LOCAL_DOCKER_AUTHORITY_CONFIG/config.json" || return 125',
        "true # configuration retained",
        "exact shared configuration retirement",
    ),
    Mutation(
        "verify",
        "python3 scripts/verify-release-parent-docker-authority.py "
        "--repo . --self-test",
        "true # release-parent authority gate removed",
        "shared focused-gate wiring",
    ),
    Mutation(
        "requirements",
        '<span class="id">R-S11dm</span>',
        '<span class="id">R-S11dm-disabled</span>',
        "R-S11dm requirement",
    ),
    Mutation(
        "requirements",
        "<tr><td>266</td>",
        "<tr><td>266-disabled</td>",
        "Appendix C #266",
    ),
    Mutation(
        "hardening",
        "R-S11dm/R-S11e-131 — release-parent Docker client, daemon,\n"
        "  configuration, root-fixture, and cleanup authority",
        "R-S11dm/R-S11e-XXX — release-parent Docker authority deferred",
        "R-S11e-131 hardening ledger",
    ),
)


def run_mutations(sources: Dict[str, str]) -> None:
    for mutation in MUTATIONS:
        original = sources[mutation.source]
        count = original.count(mutation.old)
        if count != 1:
            raise AuthorityError(
                "mutation '{}' expected one source token, found {}".format(
                    mutation.label, count
                )
            )
        changed = dict(sources)
        changed[mutation.source] = original.replace(mutation.old, mutation.new, 1)
        try:
            validate(changed)
        except AuthorityError:
            continue
        raise AuthorityError("mutation survived: {}".format(mutation.label))


def read_regular(repo: pathlib.Path, relative: str) -> str:
    path = repo / relative
    if path.is_symlink() or not path.is_file():
        raise AuthorityError("required source is not a regular file: {}".format(relative))
    return path.read_text(encoding="utf-8")


def load_sources(repo: pathlib.Path) -> Dict[str, str]:
    return {
        "release": read_regular(repo, "scripts/build-release.sh"),
        "lib": read_regular(repo, "scripts/lib.sh"),
        "verify": read_regular(repo, "scripts/verify.sh"),
        "workspace": read_regular(repo, "scripts/verify-verifier-workspace.py"),
        "requirements": read_regular(repo, "requirements.html"),
        "hardening": read_regular(repo, "HARDENING_STATUS.md"),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", default=".")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    sources = load_sources(pathlib.Path(args.repo).resolve())
    validate(sources)
    if args.self_test:
        run_mutations(sources)
    print(
        "RELEASE-PARENT-DOCKER-AUTHORITY: pre-source root refusal, isolated "
        "fixed client/daemon/configuration, root-fixture funnel, child "
        "separation, and exact cleanup are GREEN ({} mutations)".format(
            len(MUTATIONS) if args.self_test else 0
        )
    )


if __name__ == "__main__":
    try:
        main()
    except (AuthorityError, OSError, UnicodeError) as error:
        raise SystemExit("verify-release-parent-docker-authority: {}".format(error))
