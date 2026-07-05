import UIKit
import Flutter

@main
@objc class AppDelegate: FlutterAppDelegate {
  override func application(
    _ application: UIApplication,
    didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?
  ) -> Bool {
    // R-X6/R-S9 (iOS twin of Android `allowBackup="false"`): keep the fork's config
    // store out of iCloud and unencrypted iTunes/Finder device backups. Applied before
    // the Flutter engine boots, so the directory is flagged before Dart/Rust create any
    // config file inside it.
    excludeConfigStoreFromBackup()
    GeneratedPluginRegistrant.register(with: self)
    dummyMethodToEnforceBundling();
    return super.application(application, didFinishLaunchingWithOptions: launchOptions)
  }

  /// R-X6/R-S9: exclude the app's config store — the Documents directory that
  /// `getApplicationDocumentsDirectory()` (path_provider) → Rust `APP_DIR` →
  /// `Config::path` all resolve to — from device backups by setting the
  /// `NSURLIsExcludedFromBackupKey` resource value on it. That directory holds the
  /// per-remembered-peer connect-equivalent Argon2id PRS (`PeerConfig.password_prs`,
  /// under `peers/`) and the machine-UUID config wrapper key (`Config.key_pair`), so a
  /// local unencrypted backup would otherwise exfiltrate password-equivalent material —
  /// the exact vector Android's `allowBackup="false"` closes.
  ///
  /// This is a runtime resource value on the URL, not an Info.plist key. Setting it on
  /// the directory covers the directory's present and future contents (the `peers/`
  /// subtree included); a directory flag is stable across the config's atomic rewrites
  /// (`confy` writes via a temp file + rename), unlike per-file exclusion, which the OS
  /// resets whenever a file is replaced. Apple's "prefer a subdirectory over Documents"
  /// guidance exists to keep user-visible documents in the backup; this fork removed the
  /// file-sharing keys (`UIFileSharingEnabled`/`UISupportsDocumentBrowser`, APPLE-6), so
  /// Documents is exclusively the app's private store and nothing user-facing is held
  /// back. Re-applied on every launch to survive any reset; the Documents directory is
  /// created by the OS at install, so it always exists and there is no first-launch race.
  private func excludeConfigStoreFromBackup() {
    let fileManager = FileManager.default
    guard var configStoreURL = fileManager.urls(for: .documentDirectory, in: .userDomainMask).first,
          fileManager.fileExists(atPath: configStoreURL.path) else {
      NSLog("RustDesk: could not resolve the Documents directory to exclude from backup")
      return
    }
    do {
      var values = URLResourceValues()
      values.isExcludedFromBackup = true
      try configStoreURL.setResourceValues(values)
    } catch {
      NSLog("RustDesk: failed to exclude the config store from backup: \(error.localizedDescription)")
    }
  }

  public func dummyMethodToEnforceBundling() {
      dummy_method_to_enforce_bundling();
    session_get_rgba(nil, 0);
  }
}
