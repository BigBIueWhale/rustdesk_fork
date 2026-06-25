<p align="center">
  <img src="res/logo-header.svg" alt="RustDesk - Your remote desktop"><br>
  <a href="#raw-steps-to-build">Build</a> •
  <a href="#how-to-build-with-docker">Docker</a> •
  <a href="#file-structure">Structure</a> •
  <a href="#snapshot">Snapshot</a><br>
  [<a href="docs/README-UA.md">Українська</a>] | [<a href="docs/README-CS.md">česky</a>] | [<a href="docs/README-ZH.md">中文</a>] | [<a href="docs/README-HU.md">Magyar</a>] | [<a href="docs/README-ES.md">Español</a>] | [<a href="docs/README-FA.md">فارسی</a>] | [<a href="docs/README-FR.md">Français</a>] | [<a href="docs/README-DE.md">Deutsch</a>] | [<a href="docs/README-PL.md">Polski</a>] | [<a href="docs/README-ID.md">Indonesian</a>] | [<a href="docs/README-FI.md">Suomi</a>] | [<a href="docs/README-ML.md">മലയാളം</a>] | [<a href="docs/README-JP.md">日本語</a>] | [<a href="docs/README-NL.md">Nederlands</a>] | [<a href="docs/README-IT.md">Italiano</a>] | [<a href="docs/README-RU.md">Русский</a>] | [<a href="docs/README-PTBR.md">Português (Brasil)</a>] | [<a href="docs/README-EO.md">Esperanto</a>] | [<a href="docs/README-KR.md">한국어</a>] | [<a href="docs/README-AR.md">العربي</a>] | [<a href="docs/README-VN.md">Tiếng Việt</a>] | [<a href="docs/README-DA.md">Dansk</a>] | [<a href="docs/README-GR.md">Ελληνικά</a>] | [<a href="docs/README-TR.md">Türkçe</a>] | [<a href="docs/README-NO.md">Norsk</a>] | [<a href="docs/README-RO.md">Română</a>]<br>
  <b>We need your help to translate this README, <a href="https://github.com/rustdesk/rustdesk/tree/master/src/lang">RustDesk UI</a> and <a href="https://github.com/rustdesk/doc.rustdesk.com">RustDesk Doc</a> to your native language</b>
</p>

> [!Caution]
> **Misuse Disclaimer:** <br>
> The developers of RustDesk do not condone or support any unethical or illegal use of this software. Misuse, such as unauthorized access, control or invasion of privacy, is strictly against our guidelines. The authors are not responsible for any misuse of the application.


Chat with us: [Discord](https://discord.gg/nDceKgxnkV) | [Twitter](https://twitter.com/rustdesk) | [Reddit](https://www.reddit.com/r/rustdesk) | [YouTube](https://www.youtube.com/@rustdesk)

> [!WARNING]
> **This is not upstream RustDesk, and the tagline above does not describe it.** This is a hardened,
> opinionated, **direct-IP-only** fork — built to reach a *known* host by address and to be, on the
> wire, **as defensible as SSH**. It is the opposite of "zero-config, no concerns about security":
> there is **no rendezvous/relay server, no public ID, no LAN discovery, no auto-updater, no plugin
> loader, no one-time passwords, and no key/server override** — those paths are **deleted from the
> source tree** (removed, not merely disabled). Every inbound connection is mutually
> password-authenticated by a **CPace PAKE** before any application byte crosses the wire, and the
> program **refuses to start** unless that — and its sovereign, zero-egress posture — can be asserted
> at runtime (R-A4). There are **no prebuilt downloads**: you build the single binary yourself,
> locally and reproducibly (see the build section below), and connect to a box by its IP address.

### Security assurance — read before you expose a box

The sole transport authenticator is one mandatory **CPace** balanced PAKE (CFRG draft-21), specified
to the byte and pinned to its published **and** fork test vectors (16 known-answer tests, R-V2); the
construction's assurance rests on that byte-level spec, those vectors, and an in-tree adversarial test
suite (R-V3). The design and implementation were reviewed adversarially from independent angles —
first-contact MITM, replay, downgrade, timing, and transcript/nonce reuse (R-V1). **The in-tree CPace
implementation has NOT been independently audited by an outside cryptography expert** (R-V3); treat
that as the standing limitation until such an audit is obtained. The full, honest implementation
status — what is verified, what is deferred, and the known residuals — is in
[`HARDENING_STATUS.md`](./HARDENING_STATUS.md).

## Building this hardened fork — local-only & reproducible (§12)

> [!Important]
> This is a hardened, **direct-IP-only** fork. It is **built locally on the operator's own
> host, never in the cloud** — every GitHub Actions workflow is **disabled** (renamed to
> `*.yml.disabled`; see [`.github/workflows/DISABLED.md`](.github/workflows/DISABLED.md)),
> and Dependabot is off (the dependency world is exactly pinned, not auto-bumped). Builds are
> off-line and SHA-pinned via [`scripts/pins.env`](scripts/pins.env).

**Shipped build targets (the only ones):**

| Target | How |
| --- | --- |
| Debian `.deb` (x86_64) | `scripts/build-debian.sh` — containerized (§12.1) |
| Windows (x86_64) | an ephemeral **KVM Windows 11 VM** on the same Linux host: `scripts/host-provision.sh` → `scripts/online-fetch.sh` → `scripts/provision-windows-vm.sh` → `scripts/build-windows.ps1` (§12.2) |
| Android (aarch64) | the §12 Docker flow |

### The Windows 11 ISO you must supply

Windows cannot be cross-built from Linux (MSVC + WiX are Windows-only), so the Windows
artifact is produced inside a throwaway Win11 VM on the build host. Microsoft's ISO is
*evergreen* (re-issued over time, not stably published at a fixed URL), so **you acquire it
yourself and prove it by SHA-256** — the hash, not a URL, is the reproducibility anchor
(R-B12(c)). Anyone cloning this repo must obtain the **byte-identical** image below:

| Field | Value |
| --- | --- |
| **Product / name** | Windows 11, version **22H2** (released 2022-09), **x64**, **English (United States)** — the multi-edition consumer ISO |
| **SHA-256** | `0df2f173d84d00743dc08ed824fbd174d972929bd84b87fe384ed950f5bdab22` |
| **Size** | `5,557,432,320` bytes (≈ 5.18 GiB) |
| **Acquire from** | Microsoft — <https://www.microsoft.com/software-download/windows11> → *Download Windows 11 Disk Image (ISO) for x64 devices* → English (United States) |
| **Place at** | `online/win11.iso` (git-ignored: pinned, **not** vendored — R-R1) |

Verify it before building:

```sh
sha256sum online/win11.iso
# must print exactly:
# 0df2f173d84d00743dc08ed824fbd174d972929bd84b87fe384ed950f5bdab22  online/win11.iso
```

If Microsoft's current download yields a different hash (they re-issue the 22H2 media), obtain
the matching image or re-establish the pin via the audited dual-source bootstrap that
`scripts/pins.env` documents (R-B12). The remaining pinned resources — the **VS Build Tools**
offline layout, Rust 1.75, Flutter 3.24.5, LLVM 15.0.6, vcpkg @`120deac3`, the Android NDK — are
fetched and SHA-verified by `scripts/online-fetch.sh` into the git-ignored `online/` cache;
`scripts/pins.env` is the authoritative pin list.

---

> [!NOTE]
> **Everything below is upstream RustDesk's original build documentation**, kept for development
> reference only. It describes the **legacy Sciter** GUI and several Linux distributions — but the
> hardened fork **ships Flutter-only** (Sciter is not shipped, R-B6) and its **reproducible release
> build is the containerized per-host scripts documented above** (and in `AGENTS.md` / `scripts/`).
> Treat the `sciter.dll` downloads and the non-Debian package steps below as upstream history, not
> the fork's shipped path.

## Dependencies (upstream legacy)

Desktop versions use Flutter or Sciter (deprecated) for GUI, this tutorial is for Sciter only, since it is easier and more friendly to start. Check out our [CI](https://github.com/rustdesk/rustdesk/blob/master/.github/workflows/flutter-build.yml) for building Flutter version.

Please download Sciter dynamic library yourself.

[Windows](https://raw.githubusercontent.com/c-smile/sciter-sdk/master/bin.win/x64/sciter.dll) |
[Linux](https://raw.githubusercontent.com/c-smile/sciter-sdk/master/bin.lnx/x64/libsciter-gtk.so) |
[macOS](https://raw.githubusercontent.com/c-smile/sciter-sdk/master/bin.osx/libsciter.dylib)

## Raw Steps to build

- Prepare your Rust development env and C++ build env

- Install [vcpkg](https://github.com/microsoft/vcpkg), and set `VCPKG_ROOT` env variable correctly

  - Windows: vcpkg install libvpx:x64-windows-static libyuv:x64-windows-static opus:x64-windows-static aom:x64-windows-static
  - Linux/macOS: vcpkg install libvpx libyuv opus aom

- run `cargo run`

## [Build](https://rustdesk.com/docs/en/dev/build/)

## How to Build on Linux

### Ubuntu 18 (Debian 10)

```sh
sudo apt install -y zip g++ gcc git curl wget nasm yasm libgtk-3-dev clang libxcb-randr0-dev libxdo-dev \
        libxfixes-dev libxcb-shape0-dev libxcb-xfixes0-dev libasound2-dev libpulse-dev cmake make \
        libclang-dev ninja-build libgstreamer1.0-dev libgstreamer-plugins-base1.0-dev libpam0g-dev
```

### openSUSE Tumbleweed

```sh
sudo zypper install gcc-c++ git curl wget nasm yasm gcc gtk3-devel clang libxcb-devel libXfixes-devel cmake alsa-lib-devel gstreamer-devel gstreamer-plugins-base-devel xdotool-devel pam-devel
```

### Fedora 28 (CentOS 8)

```sh
sudo yum -y install gcc-c++ git curl wget nasm yasm gcc gtk3-devel clang libxcb-devel libxdo-devel libXfixes-devel pulseaudio-libs-devel cmake alsa-lib-devel gstreamer1-devel gstreamer1-plugins-base-devel pam-devel
```

### Arch (Manjaro)

```sh
sudo pacman -Syu --needed unzip git cmake gcc curl wget yasm nasm zip make pkg-config clang gtk3 xdotool libxcb libxfixes alsa-lib pipewire
```

### Install vcpkg

```sh
git clone https://github.com/microsoft/vcpkg
cd vcpkg
git checkout 2023.04.15
cd ..
vcpkg/bootstrap-vcpkg.sh
export VCPKG_ROOT=$HOME/vcpkg
vcpkg/vcpkg install libvpx libyuv opus aom
```

### Fix libvpx (For Fedora)

```sh
cd vcpkg/buildtrees/libvpx/src
cd *
./configure
sed -i 's/CFLAGS+=-I/CFLAGS+=-fPIC -I/g' Makefile
sed -i 's/CXXFLAGS+=-I/CXXFLAGS+=-fPIC -I/g' Makefile
make
cp libvpx.a $HOME/vcpkg/installed/x64-linux/lib/
cd
```

### Build

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
git clone --recurse-submodules https://github.com/rustdesk/rustdesk
cd rustdesk
mkdir -p target/debug
wget https://raw.githubusercontent.com/c-smile/sciter-sdk/master/bin.lnx/x64/libsciter-gtk.so
mv libsciter-gtk.so target/debug
VCPKG_ROOT=$HOME/vcpkg cargo run
```

## How to build with Docker

Begin by cloning the repository and building the Docker container:

```sh
git clone https://github.com/rustdesk/rustdesk
cd rustdesk
git submodule update --init --recursive
docker build -t "rustdesk-builder" .
```

Then, each time you need to build the application, run the following command:

```sh
docker run --rm -it -v $PWD:/home/user/rustdesk -v rustdesk-git-cache:/home/user/.cargo/git -v rustdesk-registry-cache:/home/user/.cargo/registry -e PUID="$(id -u)" -e PGID="$(id -g)" rustdesk-builder
```

Note that the first build may take longer before dependencies are cached, subsequent builds will be faster. Additionally, if you need to specify different arguments to the build command, you may do so at the end of the command in the `<OPTIONAL-ARGS>` position. For instance, if you wanted to build an optimized release version, you would run the command above followed by `--release`. The resulting executable will be available in the target folder on your system, and can be run with:

```sh
target/debug/rustdesk
```

Or, if you're running a release executable:

```sh
target/release/rustdesk
```

Please ensure that you run these commands from the root of the RustDesk repository, or the application may not find the required resources. Also note that other cargo subcommands such as `install` or `run` are not currently supported via this method as they would install or run the program inside the container instead of the host.

## File Structure

Paths are relative to this repository — a self-contained monorepo (`hbb_common` is absorbed in-tree, not a submodule; R-R1).

- **[libs/hbb_common](libs/hbb_common)**: video codec, config, tcp/udp wrapper, protobuf, fs functions for file transfer, and the shared utility functions
- **[libs/pake](libs/pake)**: the **CPace PAKE** — the fork's sole transport authenticator (KAT-verified; R-V2/R-V3)
- **[libs/scrap](libs/scrap)**: screen capture
- **[libs/enigo](libs/enigo)**: platform-specific keyboard/mouse control
- **[libs/clipboard](libs/clipboard)**: file copy/paste for Windows, Linux, macOS
- **[src/server](src/server)**: audio/clipboard/input/video services and inbound `--server` connection handling
- **[src/client.rs](src/client.rs)**: start a direct, PAKE-keyed peer connection by IP
- **[src/platform](src/platform)**: platform-specific code
- **[flutter](flutter)**: Flutter code for desktop and mobile — **the shipped UI**
- **[src/ui](src/ui)** / `src/ui.rs`: the legacy Sciter UI — **not shipped** (binaries are Flutter-only, R-B6); kept buildable only for the docker verify/smoke harness

**Removed from upstream** (direct-IP-only, §8 — CI-proven absent by `scripts/verify.sh`): `src/rendezvous_mediator.rs` (the rendezvous/relay client), the web client (`flutter/web`), the auto-updater, the plugin loader, and the LAN-discovery, switch-sides, and one-time-password paths. See [`HARDENING_STATUS.md`](./HARDENING_STATUS.md).

## Screenshots

![Connection Manager](https://github.com/rustdesk/rustdesk/assets/28412477/db82d4e7-c4bc-4823-8e6f-6af7eadf7651)

![Connected to a Windows PC](https://github.com/rustdesk/rustdesk/assets/28412477/9baa91e9-3362-4d06-aa1a-7518edcbd7ea)

![File Transfer](https://github.com/rustdesk/rustdesk/assets/28412477/39511ad3-aa9a-4f8c-8947-1cce286a46ad)

![TCP Tunneling](https://github.com/rustdesk/rustdesk/assets/28412477/78e8708f-e87e-4570-8373-1360033ea6c5)

