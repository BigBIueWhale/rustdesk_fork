# Using an Android phone as a controlled host (attended remote access)

This guide is for the case where the **Android phone is the machine being viewed /
controlled**. For the unattended Debian/Ubuntu host, see [`DEPLOYMENT.md`](./DEPLOYMENT.md);
the wire protocol and threat model are in [`TRANSPORT-SECURITY.md`](./TRANSPORT-SECURITY.md)
and [`SECURITY.md`](./SECURITY.md).

## The short version: an Android phone is *not* an unattended server

A Debian host runs the fork as a daemon — always up, always listening, controllable
whether or not anyone is at the keyboard. **An Android phone cannot do that.** Modern
Android is designed so that no app can silently watch or control the device: it can be a
remote host only **while its owner is present to grant consent**. Treat the phone as an
*attended* host (you unlock it and start a session), not a set‑and‑forget box. In
practice the phone's realistic role is the **viewer** — you sit at the phone and control
your Debian host — which needs none of the ceremony below.

## Why (this is the Android security model, not a fork limitation)

Four framework‑level walls, none of which the fork can or should remove:

1. **No background daemon.** Android owns process lifetime. The only persistence is a
   foreground service with a permanent notification, which the OS still kills under
   memory pressure or Doze, and which aggressive OEM builds (Xiaomi/Samsung/Huawei/
   OnePlus) terminate outright. A killed service does not reliably come back.
2. **Screen capture needs a per‑launch human tap.** `MediaProjection` requires you to
   tap "Start now" on a system dialog; the grant cannot be obtained without a person at
   the device and does not survive a reboot or an app kill.
3. **Remote control needs a manually‑enabled accessibility service**, and on Android 13+
   that toggle is deliberately blocked for sideloaded apps until you clear a
   "Restricted settings" gate with your lock‑screen credential.
4. **The device's human is always in the loop** — enforced by the OS, independent of the
   RustDesk password.

## Setting it up (the attended ceremony, in order)

1. **Set a permanent password.** The service **will not start without one** — it prompts
   you to set it. This password is the CPace credential and the *sole* authenticator
   (there is no fingerprint to pin, no one‑time password).
2. **Start the service and grant screen capture.** Tap **Start service**; Android shows
   **Start now** (the MediaProjection consent) — tap it. You grant this **once per app
   launch**: it is remembered for reconnects while the app keeps running, but **not**
   across a reboot or an OS kill (you'll re‑grant then).
3. **For remote CONTROL (not just viewing), enable the accessibility input service.**
   On **Android 13 and newer** the switch is greyed out for a sideloaded app until you:
   **App info → ⋮ (top‑right) → Allow restricted settings → authenticate (PIN/biometric)**,
   then return to **Accessibility → RustDesk Input → enable**. Viewing works without this;
   only keyboard/mouse/touch injection needs it. (The app shows these steps in‑place.)
4. **Grant the battery‑optimization exemption** when the app asks, so the OS is less
   likely to kill the service.

## Reliability (best‑effort — plan around it)

Even done correctly, an unattended Android host is best‑effort. The battery‑optimization
exemption plus a wake lock during active sessions help, but they do **not** defeat Doze
network suspension or OEM background killers. Expect to re‑open the app and re‑start the
service after the phone sits idle. For per‑vendor autostart/battery steps see
[dontkillmyapp.com](https://dontkillmyapp.com/). If you need genuine unattendedness, use a
Debian host (`DEPLOYMENT.md`); the phone is best used as the viewer.

## What doesn't work, and why (by design)

- **Screen off or locked → black/frozen image.** A service cannot keep the display awake,
  and Android 15 auto‑stops capture when the device locks. Keep the phone unlocked and
  awake during a session.
- **Banking / password‑manager / DRM screens show black.** Android's `FLAG_SECURE`
  excludes those windows from capture at the OS level — a remote viewer can never see them.
- **After a reboot or an OS kill you must re‑open the app and re‑grant screen capture** —
  the MediaProjection consent cannot survive a reboot.
- **Some lag / heat.** The phone software‑encodes its own screen (the fork ships **no**
  hardware codec / ffmpeg, a deliberate attack‑surface choice), so expect higher CPU/battery
  than a hardware‑encoded stream; the fork half‑scales large screens to compensate.

## The one unattended path (advanced, one‑time USB setup)

If you truly need the phone reachable unattended, a **one‑time, physically‑present ADB
grant** lets the app capture without the per‑session tap:

```sh
adb shell appops set <app-package> PROJECT_MEDIA allow
```

(plus, on Android ≤ 14, an ADB grant for the accessibility service). This needs USB
debugging and a computer **once**. Limits: it **degrades on Android 15+**, where capture
still auto‑stops when the screen locks, and Enhanced Confirmation Mode may block the ADB
accessibility grant on 15/16. It remains gated by physical device access — it is a local,
authenticated bootstrap, not a remote one.

## Security note (the phone is *safer* than a computer here)

The permanent password (CPace) is the authenticator: an attacker on your LAN — e.g. via a
compromised home router — who does not know it **gets nothing** (the handshake fails before
any connection is admitted). On Android you get a *bonus* gate on top: the OS itself
requires a local, un‑automatable consent tap before any screen capture or input, independent
of the password — so even a password‑knowing remote peer cannot silently turn the phone into
a spy‑cam. For capture and input the phone is strictly harder to abuse than a desktop.
(File transfer, clipboard, and audio, where enabled, are gated by the password alone.)

## Version notes

- **targetSdk is intentionally 33.** That dodges Android 14's per‑capture re‑consent and
  keeps the app working on Android 14 today; because the fork is sideloaded, Google Play's
  higher targetSdk floor does not apply. Bumping it is a deliberate, spec‑level change (it
  would otherwise break the model).
- **Android 15+**: capture auto‑stops on screen lock (no app opt‑out) — the main limit on
  unattended use.
