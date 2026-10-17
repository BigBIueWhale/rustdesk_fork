# Deploying the hardened RustDesk fork (Debian/Ubuntu host)

This guide covers installing and operating the fork as an **unattended remote-access
host** on a Debian/Ubuntu machine. It reflects the fork's hardened, direct-IP-only
model — there is **no rendezvous server, no relay, no UDP, and no auto-update**. A
viewer dials the host's IP directly and authenticates with a **balanced CPace PAKE**
over a sealed two-key channel — the shared permanent password is the **sole**
authenticator. There is no host-key/fingerprint setup. Authenticate the software
package separately through the independent release-verification procedure below.
Current installed-service, artifact and native acceptance is tracked in
[`HARDENING_STATUS.md`](../HARDENING_STATUS.md#current-verdict).

Related: the [transport requirements](../requirements.html#tcp),
the [normative threat model](../requirements.html#threat).

---

## 0. What you are deploying

- **Controlled-side direct listener:** IPv4 TCP **21118** (`DIRECT_PORT`), with no UDP
  transport. Other host programs have their own network surface.
- **Authentication:** a CPace PAKE keyed by the host's permanent password. There is
  no anonymous access and no "accept once" prompt — every session is authenticated.
- **Reachable, CPace-gated:** the direct listener binds 21118 on all IPv4 interfaces and admits a peer
  that completes the CPace handshake — like SSH, there is **no in-app source allow-list**.
  To restrict by source IP, do it at the **firewall** (§3), where the kernel sheds the
  packet before it ever reaches RustDesk.
- **Fail-closed credential state:** an empty or undecryptable permanent credential
  parks the direct listener. A running supervisor can therefore be non-listening.

---

## 1. Install

Install only a `.deb` from a complete R-B2 release set whose independently authenticated
`dist/SHA256SUMS` records `independent-snapshots-a-equals-b`. Verify the complete set
as specified in [`RELEASE-VERIFICATION.md`](./RELEASE-VERIFICATION.md) before running
the installer. A checksum downloaded beside the package from the same host is not
independent authentication.

```sh
sudo apt install ./rustdesk-x86_64.deb
```

`apt` resolves the GUI/runtime dependencies. The package contains:

- the dpkg-owned relative symlink `/usr/bin/rustdesk -> ../share/rustdesk/rustdesk`,
- installs `/usr/lib/systemd/system/rustdesk.service` (`ExecStart=/usr/bin/rustdesk --service`),

On a systemd host, `postinst` runs `systemctl daemon-reload`, `enable`, and `start` through
the checked Debian helper policy. Maintainer scripts never create or remove the command
symlink or another `/usr/bin` path; dpkg owns command installation, conflicts, upgrades,
and removal.

The vendor unit is a dpkg-owned file. Package scripts do not replace or remove
`/etc/systemd/system/rustdesk.service`, so an administrator replacement, primary-unit
link, or `/dev/null` mask remains administrator-owned across install and removal.

The package requests startup through Debian's service policy. A policy refusal,
mask, administrator override or startup failure can leave the unit stopped; inspect
the selected unit before provisioning. Installation alone does not prove that its
supervisor or direct listener is running. The
[Debian service helper](https://manpages.debian.org/bookworm/init-system-helpers/deb-systemd-invoke.1p.en.html)
respects local package-start policy.

### Native non-systemd service templates

The Debian payload also ships exact downstream-integration templates at:

- `/usr/share/rustdesk/files/openrc/rustdesk`
- `/usr/share/rustdesk/files/runit/run`
- `/usr/share/rustdesk/files/manual/rustdesk-service`

The OpenRC template uses a fixed root-owned `/run/rustdesk.pid` and OpenRC's bounded
`TERM/30/KILL/5` retry schedule. The runit and manual templates are exact foreground
`exec /usr/bin/rustdesk --service` wrappers. All three select only the top-level service
supervisor; RustDesk itself owns, revalidates, drains, and reaps its service-owned server child.
None of the templates searches for a child by name, argv, or process-table text.

These files are packaged inputs for an administrator or downstream package that has already
selected its native service manager. They are deliberately not auto-installed into OpenRC
runlevels, runit service directories, or an administrator's manual supervisor topology by the
Debian maintainer scripts. Only one service manager may own `rustdesk --service`; stop the
currently selected systemd/SysV service before installing or enabling a native replacement.
For OpenRC, install the template as `/etc/init.d/rustdesk`. For runit, install `run` as the
mode-0755 `/etc/sv/rustdesk/run` file and expose that service directory through the host's
administrator-owned runsvdir layout. For another process supervisor, use
`rustdesk-service` as its exact foreground command and have the supervisor send `TERM` to that
owned process for normal stop. Do not add a separate `rustdesk --server` cleanup command.

---

## 2. Configure (mandatory — the host stays fail-closed until the password is set)

### 2a. Set the host password (the CPace credential)

```sh
sudo /usr/bin/rustdesk --password
```

Enter and confirm a strong password at the hidden terminal prompts; do not put the
secret in command arguments. In installed mode, this command requests the privileged
service-owned credential transaction. It does not write a substitute user-profile
credential when the service is unavailable or rejects authorization. The durable
value is a memory-hard CPace password-equivalent (PRS), never the plaintext password.
Protect that value as a credential and use an independent password for each host.

### 2b. Confirm the transaction and listener state

Wait for the command's terminal result. `Done!` follows an acknowledged applied
transaction, including the service-owned runtime credential update. A separate
restart is not a password-application step. The direct listener tracks whether the
runtime credential is usable; it can bind when provisioning succeeds and park when
the credential is absent or unreadable.

An error reporting an unknown outcome or runtime-update failure does not establish
that the durable credential stayed unchanged. Diagnose the selected service and
credential state before another change; a restart is not proof of the prior
transaction's result. Continue with the deployment observations in §6 and a fresh
viewer connection using the password just set.

---

## 3. Firewall

Open **only** TCP 21118 (zero UDP). This is the layer where you scope by source IP, if
you want to — the same place you'd scope SSH:

- **Reach-from-anywhere — the sovereign direct-IP box:** allow inbound TCP 21118;
  every admitted RustDesk session still requires CPace authentication.
  ```sh
  sudo ufw allow 21118/tcp
  ```
- **Scope to a known network:** restrict the port to the viewer's CIDR, so non-allowlisted
  IPs are dropped in the kernel before they reach RustDesk (defense-in-depth, never a substitute for CPace).
  Replace the quoted placeholder below with your authorized viewer CIDR.
  ```sh
  sudo ufw allow from '<viewer-CIDR>' to any port 21118 proto tcp
  ```

No UDP rule is needed.

---

## 4. Connect (viewer)

Enter `<host-ip>:21118` as the destination (a bare numeric ID is rejected — this is a
direct-IP build), supply the password from step 2a, and connect. The session runs over
the CPace-keyed, per-direction-keyed, AEAD-sealed channel.

---

## 5. Harden the host itself

Maintain the host OS and secure every other exposed service under its own policy.
RustDesk's authentication does not protect another daemon or a compromised endpoint;
the applicable threat boundaries are in the linked normative model.

---

## 6. Verify the deployment

```sh
# selected unit state and recent service-manager/process output:
systemctl status rustdesk.service --no-pager
sudo journalctl -u rustdesk.service -n 50 --no-pager

# IPv4 TCP listening endpoints at the direct port; endpoint observation only:
ss -H -4 -lnt 'sport = :21118'
```

The unit's state describes the supervisor, which can remain running while its
listener is parked. An endpoint at `0.0.0.0:21118` matches the expected direct bind,
but this observation does not identify its owner, prove authentication or establish
RustDesk's complete socket surface. Do not attribute other programs' sockets to
RustDesk. See the [socket-filter syntax](https://manpages.debian.org/bookworm/iproute2/ss.8.en.html)
and [unit-state semantics](https://manpages.debian.org/bookworm/systemd/systemctl.1.en.html).

Release builds also write RustDesk file logs under the relevant process home's
`.local/share/logs/<app-name>/`, with role-specific subdirectories. The journal is
not the complete RustDesk log stream. Review the applicable logs when diagnosing
credential parking, authorization failure or a bind error.

From a trusted viewer, open a fresh connection with the current password and
exercise the intended capability, including changing presented frames for remote
viewing. An existing authenticated connection is not a test of the newly provisioned
credential. These operational observations do not prove installed privilege
boundaries, the absence of UDP in owned processes, or release correctness.

Build and verification execute through the authenticated no-NIC verifier VM. Portable smoke
uses nonroot, capability-free guest containers; installed-service and other privileged
acceptance runs directly inside disposable VMs. The final Debian artifact lifecycle gate
runs after cold A==B comparison. Deployment checks do not supply that release evidence.

---

## Operational notes

- **Updates:** authenticate each complete release set before installing its `.deb`.
  Package upgrade scripts request stop/start through the selected service manager
  and preserve administrator-owned unit files and masks. There is no auto-updater.
- **Stop/disable:** `sudo systemctl disable --now rustdesk`. The `prerm` stops/disables
  the unit on package removal.
- **Logs:** use the selected supervisor's output and RustDesk's process-specific file
  logs described in §6.
- **Migration:** machine-identifier wrapping is reversible storage protection, not a
  hardware-authentication or secrecy boundary. Do not assume a clone loses the credential.
  Provision an independent service-owned password on each host. If stored PRS cannot be
  decrypted, the listener parks until authorized provisioning succeeds; do not repair that
  state by importing another user's configuration or writing a shadow credential file.
- **Android/Windows clients** connect to the same `<host-ip>:21118` with the same
  password (no fingerprint to pin). Using an **Android phone as the controlled host** is a
  foreground-service and OS-capture-grant model — see [`ANDROID-SERVER.md`](./ANDROID-SERVER.md).
