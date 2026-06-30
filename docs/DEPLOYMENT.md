# Deploying the hardened RustDesk fork (Debian/Ubuntu host)

This guide covers installing and operating the fork as an **unattended remote-access
host** on a Debian/Ubuntu machine. It reflects the fork's hardened, direct-IP-only
model — there is **no rendezvous server, no relay, no UDP, and no auto-update**. A
viewer dials the host's IP directly, authenticates with a CPace PAKE over a sealed
two-key channel, and pins the host's Ed25519 identity.

The steps below were validated by installing the built `.deb` in a clean
`ubuntu:22.04` container (clean install, binary + systemd unit placement, headless
`--get-fingerprint`), and the runtime behaviour by `scripts/smoke-server.sh`
(one v4 TCP listener on 21118, zero UDP, fail-closed startup).

Related: [`HOST-KEY-PIN.md`](./HOST-KEY-PIN.md) (identity pinning),
[`TRANSPORT-SECURITY.md`](./TRANSPORT-SECURITY.md) (the wire protocol),
[`SECURITY.md`](./SECURITY.md).

---

## 0. What you are deploying

- **One inbound port:** TCP **21118** (`DIRECT_PORT`). Zero UDP. No other listener.
- **Authentication:** a CPace PAKE keyed by the host's permanent password. There is
  no anonymous access and no "accept once" prompt — every session is authenticated.
- **Reachable, CPace-gated:** the host binds 21118 on all interfaces and admits any peer
  that completes the CPace handshake — like SSH, there is **no in-app source allow-list**.
  To restrict by source IP, do it at the **firewall** (§3), where the kernel sheds the
  packet before it ever reaches RustDesk.
- **Fail-closed:** with no password set the host **refuses to listen at all** and logs
  the reason. Misconfiguration cannot silently expose the box.

---

## 1. Install

```sh
sudo apt install ./rustdesk-x86_64.deb
```

`apt` resolves the GUI/runtime dependencies. The package's `postinst` (on a systemd
host) automatically:

- symlinks `/usr/bin/rustdesk -> /usr/share/rustdesk/rustdesk`,
- installs `/usr/lib/systemd/system/rustdesk.service` (`ExecStart=/usr/bin/rustdesk --service`),
- runs `systemctl daemon-reload`, `enable`, and `start`.

So the service is **already running after install** — but, being fail-closed, it will
not listen until you complete step 2.

> Reproducibility: the `.deb` is byte-reproducible (R-B2, `scripts/build-debian.sh`
> double-build). Verify your artifact against `dist/SHA256SUMS-HEAD.txt`.

---

## 2. Configure (mandatory — the host stays fail-closed until the password is set)

### 2a. Set the host password (the CPace credential)

```sh
sudo rustdesk --password '<a-strong-password>'
```

This is the shared secret a viewer must know. It is stored only as a salted
password-equivalent, never in cleartext. Without it the service logs
*"no permanent password is set — refusing to listen"* and does not bind.

### 2b. Apply

```sh
sudo systemctl restart rustdesk
```

After the restart the service re-evaluates its config, passes the fail-closed checks,
and begins listening on TCP 21118.

---

## 3. Firewall

Open **only** TCP 21118 (zero UDP). This is the layer where you scope by source IP, if
you want to — the same place you'd scope SSH:

- **Reach-from-anywhere — the sovereign direct-IP box:** open 21118 to the internet — CPace is
  the authentication gate, the same exposure as a public password-SSH on `:22`.
  ```sh
  sudo ufw allow 21118/tcp
  ```
- **Scope to a known network:** restrict the port to the viewer's CIDR, so non-allowlisted
  IPs are dropped in the kernel before they reach RustDesk (defense-in-depth, never a substitute for CPace).
  ```sh
  sudo ufw allow from <viewer-CIDR> to any port 21118 proto tcp
  ```

No UDP rule is needed.

---

## 4. Pin the host identity (do this once, out-of-band)

The host has a long-term Ed25519 key. Read its fingerprint **on the box**:

```sh
sudo rustdesk --get-fingerprint
# e.g. b008 45ec e2df e9ea 83ca 5f42 e645 0a3b 2ee9 1883 d019 720a 7ced e29d 44d5 cd0c
```

Transfer that fingerprint to the operator through a trusted channel (not over the
remote-desktop connection itself). On the **viewer**, pin it before connecting:

```sh
rustdesk --pin-host <host-ip>:21118 <fingerprint-from-the-box>
```

The viewer fail-closes on a fingerprint mismatch — there is no trust-on-first-use and
no "accept anyway". See [`HOST-KEY-PIN.md`](./HOST-KEY-PIN.md).

---

## 5. Connect (viewer)

Enter `<host-ip>:21118` as the destination (a bare numeric ID is rejected — this is a
direct-IP build), supply the password from step 2a, and connect. The session runs over
the CPace-keyed, per-direction-keyed, AEAD-sealed channel.

---

## 6. Harden the host itself

The fork's own surface is minimal (one authenticated TCP port, fail-closed). On a
real internet-facing/DMZ box the **larger residual exposure is the host OS**, not
RustDesk — in particular password-based SSH on port 22:

- Use key-only SSH (`PasswordAuthentication no`), and/or restrict `:22` to admin IPs.
- Run `fail2ban`.
- Keep the OS patched.

---

## 7. Verify the deployment

```sh
# exactly one v4 TCP listener on 21118, zero UDP:
sudo ss -ltnup | grep -E ':21118|:.*udp' || true

# service healthy:
systemctl status rustdesk --no-pager

# the box's own pre-ship assurance (run from the source tree, in Docker):
bash scripts/verify.sh         # KATs + handshake + two-key cipher + compile + R-A6 gates
bash scripts/smoke-server.sh   # runtime: one-TCP/zero-UDP, fail-closed, no-plaintext wire
```

A correctly-deployed host shows a single `127-or-host:21118` TCP LISTEN line and no UDP.

---

## Operational notes

- **Updates:** the fork has no auto-updater (by design). Deploy a new `.deb` with
  `apt install ./rustdesk-<ver>.deb`; the `postinst` reloads the service.
- **Stop/disable:** `sudo systemctl disable --now rustdesk`. The `prerm` stops/disables
  the unit on package removal.
- **Logs:** `journalctl -u rustdesk`. The fail-closed refusals (no password /
  managed-override) are logged at error level with their R-ID.
- **Android/Windows clients** connect to the same `<host-ip>:21118` with the same
  password + pinned fingerprint.
