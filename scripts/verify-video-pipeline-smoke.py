#!/usr/bin/env python3
"""Semantic and mutation checks for the opt-in real video-pipeline smoke harness."""

import argparse
import pathlib
import re
import sys


class VerificationError(Exception):
    pass


def fail(message):
    raise VerificationError(message)


def require(text, needle, label):
    if needle not in text:
        fail("missing {}".format(label))


def scoped(text, start, end, label):
    begin = text.find(start)
    if begin < 0:
        fail("missing {} start".format(label))
    finish = text.find(end, begin + len(start))
    if finish < 0:
        fail("missing {} end".format(label))
    return text[begin:finish]


def parse_manifest(text, fields, label):
    rows = []
    for line_number, line in enumerate(text.splitlines(), 1):
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) != fields:
            fail("{} row {} does not have {} fields".format(label, line_number, fields))
        rows.append(parts)
    return rows


def validate(sources):
    probe = sources["probe"]
    viewer = sources["viewer"]
    lib = sources["lib"]
    motion = sources["motion"]
    stage = sources["stage"]
    smoke = sources["smoke"]
    prepare = sources["prepare"]
    packages = sources["packages"]
    files = sources["files"]

    for needle, label in (
        ("Ipv4Addr::LOCALHOST), 21_118", "exact IPv4 loopback endpoint"),
        ("if endpoint != LOOPBACK_ENDPOINT", "closed endpoint admission"),
        ("const MAX_PASSWORD_BYTES: usize = 1_024;", "bounded password input"),
        (".take((MAX_PASSWORD_BYTES + 2) as u64)", "bounded stdin read"),
        ("sodiumoxide::utils::memzero", "secret zeroization"),
        ("video_frame_receipt_version: VIDEO_FRAME_RECEIPT_VERSION", "receipt negotiation"),
        ("supported.prefer = supported_decoding::PreferCodec::VP9.into();", "software codec preference"),
        ("ability_h264 != 0", "native codec refusal assertion"),
        ("const MIN_DECODED_FRAMES: usize = 30;", "minimum decoded-frame budget"),
        ("const MIN_DISTINCT_FRAMES: usize = 10;", "minimum distinct-frame budget"),
        ("const MIN_PTS_SPAN_MS: i64 = 4_000;", "minimum observation span"),
        ("const SESSION_DEADLINE: Duration = Duration::from_secs(25);", "finite session deadline"),
        ("const MAX_RECEIVE_BACKLOG_DRIFT_MS: i64 = 2_000;", "backlog-drift budget"),
        ("Decoder::new(format, None)", "real software decoder construction"),
        ("Sha256::digest(&rgb.raw)", "decoded-frame distinction"),
        ("VIDEO_PIPELINE_OK codec=", "success transcript"),
        ("endpoint_is_exact_ipv4_loopback_and_port", "endpoint regression test"),
        ("receipt_tracker_requires_bounded_strict_generation_identity", "receipt regression test"),
    ):
        require(probe, needle, label)
    if "std::thread::sleep" in probe or "0.0.0.0:21118" in probe.split("#[cfg(test)]", 1)[0]:
        fail("probe contains blocking sleep or a non-loopback runtime endpoint")
    frame_branch = scoped(
        probe,
        "Some(message::Union::VideoFrame(frame)) => {",
        "\n            Some(_) => {}",
        "video-frame branch",
    )
    receipt_position = frame_branch.find(".send(&receipt_message)")
    decode_position = frame_branch.find(".handle_video_frame(")
    if receipt_position < 0 or decode_position < 0 or receipt_position >= decode_position:
        fail("exact receipt is not sent before the real decode call")
    for needle in (
        "receipts.admit(&frame)?",
        "if !peer_admitted",
        "if frame.display != 0",
        "if format != decoder_format",
        "decoded_image_bytes(&rgb)?",
        "max_receive_backlog_drift_ms > MAX_RECEIVE_BACKLOG_DRIFT_MS",
    ):
        require(frame_branch + probe, needle, "video admission invariant {}".format(needle))

    for needle, label in (
        ('#[ignore = "runs only in the exact rootless video-pipeline smoke container"]', "ignored integration test"),
        ('const EXACT_TEST_EXECUTABLE: &str = "/smoke-target/production-viewer-pipeline-tests";', "fixed test artifact path"),
        ('const EXACT_WORKING_DIRECTORY: &str = "/work";', "fixed test working directory"),
        ('const EXACT_HOME: &str = "/tmp/rd-video-pipeline";', "private test HOME"),
        ('const EXACT_PEER: &str = "127.0.0.1:21118";', "exact production-viewer endpoint"),
        ('std::env::var("RUSTDESK_PRODUCTION_VIEWER_PIPELINE_SMOKE")', "explicit runtime gate"),
        ('std::env::current_exe().expect("the production viewer smoke must resolve its executable")', "test artifact identity gate"),
        ('current_executable.as_path()', "resolved test artifact comparison"),
        ('std::env::current_dir()', "working-directory identity gate"),
        ('current_directory.as_path()', "resolved working-directory comparison"),
        ('std::env::var("HOME").as_deref()', "configuration-home identity gate"),
        ("login.initialize(EXACT_PEER.to_owned(), ConnType::DEFAULT_CONN, None, None);", "real Remote session initialization"),
        ("let config = login.get_config();", "narrow mutable peer-configuration access"),
        ("config.disable_audio.v = true;", "unrelated audio refusal"),
        ("config.disable_clipboard.v = true;", "unrelated clipboard refusal"),
        ("const PUBLICATION_STALL: Duration = Duration::from_millis(1_500);", "deliberate publication stall"),
        ("const MAX_POST_STALL_RECOVERY: Duration = Duration::from_millis(2_500);", "post-stall recovery budget"),
        ("const PIPELINE_DEADLINE: Duration = Duration::from_secs(25);", "finite integration deadline"),
        ("const MIN_PUBLISHED_FRAMES: usize = 20;", "minimum production publications"),
        ("const MIN_DISTINCT_FRAMES: usize = 10;", "minimum distinct production publications"),
        ("Sha256::digest(&rgba.raw)", "production RGBA distinction"),
        ("let start = session.start_io_thread();", "production viewer I/O start"),
        ("ui.wait_for_completion(PIPELINE_DEADLINE)", "bounded production viewer observation"),
        ("let joined = started && session.close_and_join();", "exact production viewer teardown"),
        ("a production viewer or owned media worker panicked", "owned-worker panic assertion"),
        ("PRODUCTION_VIEWER_PIPELINE_OK dimensions=", "production integration success transcript"),
        ("teardown=io-and-media-joined", "production integration teardown transcript"),
    ):
        require(viewer, needle, label)
    if ".reconnect(" in viewer:
        fail("production viewer recovery test uses reconnect")
    require(
        lib,
        '#[cfg(all(test, target_os = "linux"))]\nmod viewer_pipeline_smoke_tests;',
        "Linux test-only production viewer module",
    )

    for needle, label in (
        ("#define FIXTURE_WIDTH 640U", "fixture width"),
        ("#define FIXTURE_HEIGHT 480U", "fixture height"),
        ("#define FIXTURE_FRAMES 240U", "finite fixture frames"),
        ("#define FIXTURE_INTERVAL_MS 100U", "finite fixture pacing"),
        ("XCreateWindow", "real X11 window"),
        ("XFillRectangle", "changing X11 pixels"),
        ("XSync(display, False)", "X11 change flush"),
        ("X11_MOTION_COMPLETE", "finite fixture completion"),
    ):
        require(motion, needle, label)
    if any(token in motion for token in ("socket(", "listen(", "bind(")):
        fail("motion fixture contains a network-socket primitive")

    video_stage = scoped(stage, "  video-pipeline)\n", "  port-forward)\n", "video stage")
    for needle, label in (
        ("-nolisten tcp -ac -noreset", "Xvfb TCP refusal"),
        ("X11_NETWORK_SURFACE=unix-only tcp=0 udp=0", "pre-server socket proof"),
        ("start_server /smoke-target/debug/rustdesk", "real server launch"),
        ("$VIDEO_PROBE\" 127.0.0.1:21118 <<<", "password-stdin probe launch"),
        ("readonly VIEWER_PIPELINE_TESTS=/smoke-target/production-viewer-pipeline-tests", "fixed production viewer artifact"),
        ("RUSTDESK_PRODUCTION_VIEWER_PIPELINE_SMOKE=1", "production viewer runtime gate"),
        ("viewer_pipeline_smoke_tests::production_viewer_pipeline_recovers_after_stalled_publication_without_reconnect", "exact production viewer test"),
        ("^PRODUCTION_VIEWER_PIPELINE_OK dimensions=640x480", "production viewer stage verdict"),
        ("VIDEO_PIPELINE_CLEANUP=server,motion,xvfb-joined", "joined-owner transcript"),
        ("trap cleanup_video_pipeline EXIT", "failure cleanup"),
        ("$READY\" --terminate-server", "exact server termination"),
        ("$READY\" --stop \"$MOTION_PID\"", "exact motion termination"),
        ("$READY\" --stop \"$XVFB_PID\"", "exact Xvfb termination"),
        ("sha256sum \"$xvfb_file\"", "runtime tool digest recheck"),
        ("[ \"$xvfb_file_count\" -eq 5 ]", "runtime tool cardinality"),
    ):
        require(video_stage, needle, label)
    if re.search(r'\$VIDEO_PROBE[^\n<]*Str0ng-Test-Pw', video_stage):
        fail("video probe password appears in its process arguments")
    require(
        stage,
        "--example mdwe_codec_probe --example video_pipeline_probe --color never",
        "video probe in the offline smoke build",
    )
    require(
        stage,
        "cargo test --locked --offline --features linux-pkg-config --example video_pipeline_probe --color never",
        "video probe unit tests in the offline smoke build",
    )
    for needle, label in (
        ("cargo test --locked --offline --features linux-pkg-config --lib --no-run --color never", "offline library test build"),
        ("find /smoke-target/debug/deps -maxdepth 1 -type f -name 'librustdesk-*' -perm -u+x -print", "exact library test artifact discovery"),
        ('[ "${#viewer_pipeline_test_artifacts[@]}" -eq 1 ]', "library test artifact cardinality"),
        ("[ ! -e /smoke-target/production-viewer-pipeline-tests ]", "fixed artifact no-clobber gate"),
        ("/usr/bin/install -m 0555", "read-only fixed test artifact"),
        ("PRODUCTION_VIEWER_TEST_ARTIFACT sha256=", "test artifact digest transcript"),
    ):
        require(stage, needle, label)
    require(stage, "scripts/smoke-x11-motion.c -lX11", "motion helper build")

    video_run = scoped(smoke, "VIDEO_RUN=(", "PORT_HEX=", "video Docker authority")
    for needle, label in (
        ("--network none", "networkless runtime"),
        ("--read-only", "read-only runtime root"),
        ("--user \"$BUILD_UID:$BUILD_GID\"", "numeric non-root runtime uid"),
        ("--cap-drop ALL", "runtime capability drop"),
        ("--security-opt no-new-privileges", "runtime no-new-privileges"),
        ("--pids-limit=1024", "runtime PID ceiling"),
        ("--memory=4g", "runtime memory ceiling"),
        ("--memory-swap=4g", "runtime no-swap ceiling"),
        ("--cpus=2", "runtime CPU ceiling"),
        ("--tmpfs /tmp/.X11-unix:", "private X11 Unix socket"),
        ("target=/xvfb-root,readonly", "read-only Xvfb closure"),
        ("target=/usr/bin/xkbcomp,readonly", "exact XKB compiler mount"),
    ):
        require(video_run, needle, label)
    for forbidden in (
        "--privileged",
        "--network host",
        "--pid host",
        "--ipc host",
        "--cap-add",
        "--device",
        "/var/run/docker.sock",
        "--publish",
    ):
        if forbidden in video_run:
            fail("video runtime contains forbidden authority: {}".format(forbidden))
    if re.search(r"(^|\s)-p(\s|$)", video_run):
        fail("video runtime publishes a port")
    prepare_run = scoped(smoke, "XVFB_PREPARE_RUN=(", "VIDEO_RUN=(", "Xvfb producer authority")
    for needle in (
        "--network bridge",
        "--read-only",
        "--user \"$BUILD_UID:$BUILD_GID\"",
        "--cap-drop ALL",
        "--security-opt no-new-privileges",
    ):
        require(prepare_run, needle, "bounded producer authority {}".format(needle))
    for forbidden in ("--privileged", "--network host", "--cap-add", "--device", "--publish"):
        if forbidden in prepare_run:
            fail("Xvfb producer contains forbidden authority: {}".format(forbidden))
    for needle in (
        "--video-pipeline) SMOKE_MODE=video-pipeline-rootless",
        '"${XVFB_PREPARE_RUN[@]}"',
        '"${VIDEO_RUN[@]}"',
        "smoke-server-stage.sh video-pipeline",
        "production viewer integration/recovery evidence is missing",
        "SMOKE VIDEO PIPELINE OK:",
    ):
        require(smoke, needle, "opt-in orchestration {}".format(needle))

    for needle, label in (
        ("[ \"$(id -u)\" -ne 0 ]", "producer root refusal"),
        ("--proto '=https' --tlsv1.2", "HTTPS-only acquisition"),
        ("--connect-timeout 15 --max-time 90", "bounded acquisition"),
        ("sha256sum \"$output\"", "package digest verification"),
        ("dpkg-deb --field \"$output\" Package", "package identity verification"),
        ("dpkg-deb --field \"$output\" Architecture", "architecture verification"),
        ("XVFB_ACQUISITION_NETWORK_SURFACE=tcp-listen:%s udp:%s", "producer socket proof"),
        ("[ \"$tcp_listeners\" -eq 0 ]", "producer TCP-listener refusal"),
        ("[ \"$udp_sockets\" -eq 0 ]", "producer UDP refusal"),
        ("file manifest cardinality is $file_count, expected 5", "file manifest cardinality"),
    ):
        require(prepare, needle, label)
    if "sudo" in prepare or "apt-get install" in prepare:
        fail("Xvfb producer attempts privileged installation")

    package_rows = parse_manifest(packages, 4, "package manifest")
    expected_packages = {
        "xvfb": (
            "3153788",
            "7f98f5ddc39593249330fa2612949b6298618b945becb2d9d7b598e7ca789ea0",
            "https://deb.debian.org/debian/pool/main/x/xorg-server/xvfb_21.1.7-3+deb12u12_amd64.deb",
        ),
        "libxfont2": (
            "131728",
            "96ca8e9e1d913dd9855f46f1f09d0e0aec964b70d428da9f032250fc7a400419",
            "https://security.debian.org/debian-security/pool/updates/main/libx/libxfont/libxfont2_2.0.6-1+deb12u1_amd64.deb",
        ),
        "libfontenc1": (
            "24328",
            "1d0aa6ea16a34a8de1ea170360c4cb699f3239aeddb292df2d2c4eb6e835de4b",
            "https://deb.debian.org/debian/pool/main/libf/libfontenc/libfontenc1_1.1.4-1_amd64.deb",
        ),
        "x11-xkb-utils": (
            "164876",
            "b25970e444fadf4717e5624bc2a2eecef785d09d731b571da8d43f5297b43b12",
            "https://deb.debian.org/debian/pool/main/x/x11-xkb-utils/x11-xkb-utils_7.7+7_amd64.deb",
        ),
        "libxkbfile1": (
            "75176",
            "7c58d9986f918b71568ad83dbb6f4ab22c185f243461d41acee920cc5e13d347",
            "https://deb.debian.org/debian/pool/main/libx/libxkbfile/libxkbfile1_1.1.0-1_amd64.deb",
        ),
    }
    if len(package_rows) != 5 or {row[0] for row in package_rows} != set(expected_packages):
        fail("package manifest does not contain the exact five-package closure")
    for name, size, digest, url in package_rows:
        if not size.isdigit() or int(size) <= 0 or not re.fullmatch(r"[0-9a-f]{64}", digest):
            fail("package manifest has an invalid size or digest: {}".format(name))
        if not re.fullmatch(
            r"https://(?:deb\.debian\.org/debian|security\.debian\.org/debian-security)/pool/.+\.deb",
            url,
        ):
            fail("package manifest has a non-exact Debian pool URL: {}".format(name))
        if (size, digest, url) != expected_packages[name]:
            fail("package manifest differs from the reviewed exact pin: {}".format(name))

    file_rows = parse_manifest(files, 4, "file manifest")
    expected_files = {
        "usr/bin/Xvfb": (
            "2057824",
            "755",
            "c50687113cd5232844b8fa3a49276a48a022fa7fc4275b983ae8f88158efed72",
        ),
        "usr/bin/xkbcomp": (
            "222144",
            "755",
            "eca6986af7d15277394b8476b8ad85229ee1a1a879d43d2a526f106af3761550",
        ),
        "usr/lib/x86_64-linux-gnu/libXfont2.so.2.0.0": (
            "186112",
            "644",
            "36a98a0e7303d3782bdadd09ec9efc5b38a5cf1ba026197e4ea8b5adc6bac5c2",
        ),
        "usr/lib/x86_64-linux-gnu/libfontenc.so.1.0.0": (
            "34664",
            "644",
            "17c5f578e9c6b1a4fe79a2155e63676c9041e7633a5a5d8ddd769986c9b513a0",
        ),
        "usr/lib/x86_64-linux-gnu/libxkbfile.so.1.0.2": (
            "155744",
            "644",
            "e48b41d06c82ee1f5a9b58e5dae109048ceed7fb7d86a707beffd554326eb3b1",
        ),
    }
    if len(file_rows) != 5 or {row[0] for row in file_rows} != set(expected_files):
        fail("file manifest does not contain the exact five-file runtime closure")
    for path, size, mode, digest in file_rows:
        if (
            not size.isdigit()
            or int(size) <= 0
            or mode not in ("644", "755")
            or not re.fullmatch(r"[0-9a-f]{64}", digest)
        ):
            fail("file manifest has invalid metadata: {}".format(path))
        if (size, mode, digest) != expected_files[path]:
            fail("file manifest differs from the reviewed exact pin: {}".format(path))


def mutate(sources, source_name, old, new):
    mutated = dict(sources)
    if old not in mutated[source_name]:
        fail("self-test mutation anchor is absent: {} {!r}".format(source_name, old))
    mutated[source_name] = mutated[source_name].replace(old, new, 1)
    return mutated


def self_test(sources):
    validate(sources)
    cases = (
        ("probe", "Ipv4Addr::LOCALHOST), 21_118", "Ipv4Addr::UNSPECIFIED), 21_118"),
        ("probe", "if endpoint != LOOPBACK_ENDPOINT", "if false"),
        ("probe", ".send(&receipt_message)", ".send(&Message::new())"),
        ("probe", "const MIN_DECODED_FRAMES: usize = 30;", "const MIN_DECODED_FRAMES: usize = 1;"),
        ("probe", "const MIN_PTS_SPAN_MS: i64 = 4_000;", "const MIN_PTS_SPAN_MS: i64 = 0;"),
        ("viewer", 'const EXACT_PEER: &str = "127.0.0.1:21118";', 'const EXACT_PEER: &str = "0.0.0.0:21118";'),
        ("viewer", 'current_executable.as_path()', 'Path::new(EXACT_TEST_EXECUTABLE)'),
        ("viewer", "const PUBLICATION_STALL: Duration = Duration::from_millis(1_500);", "const PUBLICATION_STALL: Duration = Duration::ZERO;"),
        ("viewer", "const MAX_POST_STALL_RECOVERY: Duration = Duration::from_millis(2_500);", "const MAX_POST_STALL_RECOVERY: Duration = Duration::from_secs(25);"),
        ("viewer", "let joined = started && session.close_and_join();", "let joined = started;"),
        ("viewer", "ui.wait_for_completion(PIPELINE_DEADLINE)", "ViewerPipelineState::default()"),
        ("lib", '#[cfg(all(test, target_os = "linux"))]\nmod viewer_pipeline_smoke_tests;', 'mod viewer_pipeline_smoke_tests;'),
        ("motion", "#define FIXTURE_FRAMES 240U", "#define FIXTURE_FRAMES 0U"),
        ("stage", "-nolisten tcp -ac -noreset", "-listen tcp -ac -noreset"),
        ("stage", "trap cleanup_video_pipeline EXIT", "trap - EXIT"),
        ("stage", "--example mdwe_codec_probe --example video_pipeline_probe", "--example mdwe_codec_probe"),
        ("stage", "cargo test --locked --offline --features linux-pkg-config --example video_pipeline_probe", "true # video probe tests removed"),
        ("stage", "cargo test --locked --offline --features linux-pkg-config --lib --no-run --color never", "true # production viewer tests removed"),
        ("stage", "RUSTDESK_PRODUCTION_VIEWER_PIPELINE_SMOKE=1", "RUSTDESK_PRODUCTION_VIEWER_PIPELINE_SMOKE=0"),
        ("smoke", "VIDEO_RUN=(smoke_docker run --rm --network none", "VIDEO_RUN=(smoke_docker run --rm --network host"),
        ("smoke", "VIDEO_RUN=(smoke_docker run --rm --network none --pull=never --read-only", "VIDEO_RUN=(smoke_docker run --rm --network none --pull=never"),
        ("smoke", "--pids-limit=1024", "--pids-limit=4096"),
        ("smoke", "--memory=4g", "--memory=8g"),
        ("smoke", "--memory-swap=4g", "--memory-swap=8g"),
        ("smoke", "--cpus=2", "--cpus=8"),
        ("smoke", "--tmpfs /tmp/.X11-unix:rw,nosuid,nodev,noexec", "--tmpfs /tmp/x11:rw,nosuid,nodev,noexec"),
        ("prepare", "[ \"$(id -u)\" -ne 0 ]", "[ \"$(id -u)\" -ge 0 ]"),
        ("prepare", "[ \"$tcp_listeners\" -eq 0 ]", "[ \"$tcp_listeners\" -ge 0 ]"),
        ("packages", "7f98f5ddc39593249330fa2612949b629", "0f98f5ddc39593249330fa2612949b629"),
        ("files", "c50687113cd5232844b8fa3a49276a48", "050687113cd5232844b8fa3a49276a48"),
    )
    for source_name, old, new in cases:
        try:
            validate(mutate(sources, source_name, old, new))
        except VerificationError:
            continue
        fail("self-test mutation survived: {} {!r}".format(source_name, old))


def load_sources(repo):
    paths = {
        "probe": "examples/video_pipeline_probe.rs",
        "viewer": "src/viewer_pipeline_smoke_tests.rs",
        "lib": "src/lib.rs",
        "motion": "scripts/smoke-x11-motion.c",
        "stage": "scripts/smoke-server-stage.sh",
        "smoke": "scripts/smoke-server.sh",
        "prepare": "scripts/smoke-xvfb-prepare.sh",
        "packages": "scripts/smoke-xvfb-packages.tsv",
        "files": "scripts/smoke-xvfb-files.tsv",
    }
    sources = {}
    for name, relative in paths.items():
        path = repo / relative
        try:
            sources[name] = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as error:
            fail("cannot read {}: {}".format(relative, error))
    return sources


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", default=".")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    try:
        sources = load_sources(pathlib.Path(args.repo).resolve())
        if args.self_test:
            self_test(sources)
        else:
            validate(sources)
    except VerificationError as error:
        print("verify-video-pipeline-smoke: FAIL: {}".format(error), file=sys.stderr)
        return 1
    print("verify-video-pipeline-smoke: ok{}".format(" (self-test)" if args.self_test else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
