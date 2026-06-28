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
- **Default-deny:** the host refuses every inbound peer unless it is admitted by an
  explicitly-configured IP whitelist.
- **Fail-closed:** with no password set, or with an empty/default-open whitelist, the
  host **refuses to listen at all** and logs the reason. Misconfiguration cannot
  silently expose the box.

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

## 2. Configure (mandatory — the host stays fail-closed until both are set)

### 2a. Set the host password (the CPace credential)

```sh
sudo rustdesk --password '<a-strong-password>'
```

This is the shared secret a viewer must know. It is stored only as a salted
password-equivalent, never in cleartext. Without it the service logs
*"no permanent password is set — refusing to listen"* and does not bind.

### 2b. Set the access whitelist (default-deny)

```sh
sudo rustdesk --option whitelist '<allowed-viewer-CIDRs>'
```

- Format: one or more IPs/CIDRs, **separated by comma, semicolon, spaces, or newlines**
  (e.g. `203.0.113.10, 198.51.100.0/24`).
- An **unset or empty** whitelist is rejected — the host will not default-open. To
  *deliberately* accept any source, set it explicitly to `0.0.0.0/0` (not recommended
  for a DMZ host).

### 2c. Apply

```sh
sudo systemctl restart rustdesk
```

After the restart the service re-evaluates its config, passes the fail-closed checks,
and begins listening on TCP 21118.

---

## 3. Firewall

Open **only** TCP 21118, and only to the operator/viewer networks:

```sh
sudo ufw allow from <viewer-CIDR> to any port 21118 proto tcp
```

No UDP rule is needed. Keep 21118 closed to the public internet; the whitelist is a
second layer, not a substitute for the firewall.

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
- **Logs:** `journalctl -u rustdesk`. The fail-closed refusals (no password / open
  whitelist / managed-override) are logged at error level with their R-ID.
- **Android/Windows clients** connect to the same `<host-ip>:21118` with the same
  password + pinned fingerprint.
