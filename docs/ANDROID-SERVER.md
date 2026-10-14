# Using an Android phone as a controlled host

Android controlled-host operation uses a foreground service for authenticated
direct-IP connections. Screen sharing also needs a live Android capture grant; remote input
needs the accessibility input service. The permanent password remains the sole
network authenticator. See the [threat model](../requirements.html#threat),
[R-S14](../requirements.html#sec), [R-D7a](../requirements.html#deploy), and the
[current platform evidence](../HARDENING_STATUS.md#current-verdict).

For a Debian/Ubuntu controlled host, see [DEPLOYMENT.md](./DEPLOYMENT.md).
Authenticate the APK and its signing identity using
[RELEASE-VERIFICATION.md](./RELEASE-VERIFICATION.md) before installation.

## Set up the controlled phone

1. **Set a strong permanent password.** The app requests one before its screen-sharing
   start command can proceed. There is no one-time password or host fingerprint.
2. **Tap Start screen sharing.** Follow the app's notification and power-management
   prompts, then approve Android's screen-capture dialog. Listener reachability and
   capture permission are separate status indicators; a running service alone does
   not show that screen capture is ready.
3. **Enable accessibility input if you need remote control.** Viewing does not require
   input permission. Use Android's Accessibility settings to enable RustDesk Input.
   If installation restrictions block the setting, follow Android's
   [restricted-settings procedure](https://support.google.com/android/answer/12623953)
   for the verified app. Menu names and available controls vary by device.

Connect from a trusted viewer to the phone's reachable IPv4 address on TCP 21118 and enter
the permanent password. Confirm that changing screen content reaches the viewer,
and that input works if you enabled it.

## Capture consent and reconnects

A RustDesk connection and an Android capture grant have different lifetimes. The
fork can retain a valid projection for later authenticated connections where the
OS permits it. Reopening the app or reconnecting does not by itself mean a new
capture grant is required. Capture work is tied to live authorized Remote sessions.

Android requires consent for a new media-projection session. When a projection
ends, its permission cannot authorize a replacement; use the app's screen-sharing
control to obtain fresh consent. Android defines this lifecycle around the
projection and virtual display, rather than an app-launch counter. See the
[MediaProjection lifecycle](https://developer.android.com/media/grow/media-projection).

Starting the service after boot does not recreate screen-capture consent. Listener
and non-capture functionality must be assessed separately from screen sharing.

## Service lifetime and loss of capture

The fork keeps the foreground service separate from its task's UI. Removing the
recent-apps task is intended to leave that service running; a service stop,
process death or reboot ends the old capture owner. Android's
[Active apps Stop control](https://developer.android.com/develop/background-work/services/fgs/handle-user-stopping)
can stop the whole process. Power-management settings do not guarantee continued
service or capture availability.

On Android 15 QPR1 and later, locking the screen stops projection, and the system's
screen-sharing indicator lets the user stop it directly. Restore capture through
fresh consent after it ends. See Android's
[screen-sharing changes](https://developer.android.com/about/versions/15/behavior-changes-all).

Check the phone's capture status after reconnect, task removal/reopen, lock/unlock
and service restart. A listener can remain reachable while capture is unavailable.
A frozen image after those transitions needs diagnosis against the exact APK,
device and OS; restarting the app is not evidence that the lifecycle defect is fixed.

## Authentication and device permissions

Android's capture and accessibility permissions authorize app capabilities on the
phone. They do not require a person to approve every authenticated RustDesk
connection, and do not restrict the trusted password holder to harmless actions.
Treat the permanent password as the full-control credential defined by the threat
model. Peer actions remain confined by their authenticated connection type (R-S19).
