import UIKit
import Flutter
import Security

@main
@objc class AppDelegate: FlutterAppDelegate {
  private let mobileAtRestKeyService = "com.carriez.rustdesk.mobile-at-rest-storage"
  private let mobileAtRestKeyAccount = "storage-key-v1"
  private let mobileAtRestKeyLength = 32

  override func application(
    _ application: UIApplication,
    didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?
  ) -> Bool {
    installMobileAtRestStorageKey()
    // R-X6/R-S9 (iOS twin of Android `allowBackup="false"`): keep the fork's config
    // store out of iCloud and unencrypted iTunes/Finder device backups. Applied before
    // the Flutter engine boots, so the directory is flagged before Dart/Rust create any
    // config file inside it.
    excludeConfigStoreFromBackup()
    GeneratedPluginRegistrant.register(with: self)
    dummyMethodToEnforceBundling();
    return super.application(application, didFinishLaunchingWithOptions: launchOptions)
  }

  /// The mobile at-rest wrapper key is app/device state, not RustDesk config state. Store one
  /// random 32-byte key in the iOS Keychain as this-device-only data and inject it into Rust before
  /// Flutter/Rust config initialization. Existing config-keypair ciphertext is handled in Rust as a
  /// read-only legacy decrypt fallback only after this key was installed and tried, then re-stored
  /// under this key. If this key is unavailable, encrypted reads stay fail-closed; new encryption
  /// never uses the config keypair as its primary key.
  private func installMobileAtRestStorageKey() {
    guard let key = loadOrCreateMobileAtRestStorageKey() else {
      NSLog("RustDesk: mobile at-rest storage key unavailable; encrypted config reads fail closed")
      return
    }
    let accepted = key.withUnsafeBytes { rawBuffer -> Bool in
      guard let baseAddress = rawBuffer.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
        return false
      }
      return rustdesk_set_mobile_at_rest_storage_key(baseAddress, UInt(key.count))
    }
    if !accepted {
      NSLog("RustDesk: Rust rejected the iOS mobile at-rest storage key")
    }
  }

  private func mobileAtRestKeyQuery() -> [String: Any] {
    [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: mobileAtRestKeyService,
      kSecAttrAccount as String: mobileAtRestKeyAccount,
      kSecUseDataProtectionKeychain as String: true,
    ]
  }

  private func loadOrCreateMobileAtRestStorageKey() -> Data? {
    if let existing = loadMobileAtRestStorageKey() {
      return existing
    }

    var generated = [UInt8](repeating: 0, count: mobileAtRestKeyLength)
    let randomStatus = SecRandomCopyBytes(kSecRandomDefault, generated.count, &generated)
    guard randomStatus == errSecSuccess else {
      NSLog("RustDesk: failed to generate iOS mobile at-rest storage key: \(randomStatus)")
      return nil
    }

    var addQuery = mobileAtRestKeyQuery()
    addQuery[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
    addQuery[kSecValueData as String] = Data(generated)
    let addStatus = SecItemAdd(addQuery as CFDictionary, nil)
    if addStatus != errSecSuccess && addStatus != errSecDuplicateItem {
      NSLog("RustDesk: failed to store iOS mobile at-rest storage key: \(addStatus)")
      return nil
    }

    guard let reread = loadMobileAtRestStorageKey(),
          reread.count == mobileAtRestKeyLength,
          reread == Data(generated) else {
      NSLog("RustDesk: iOS mobile at-rest storage key round-trip self-test failed")
      return nil
    }
    return reread
  }

  private func loadMobileAtRestStorageKey() -> Data? {
    var query = mobileAtRestKeyQuery()
    query[kSecReturnData as String] = true
    query[kSecMatchLimit as String] = kSecMatchLimitOne

    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    if status == errSecItemNotFound {
      return nil
    }
    guard status == errSecSuccess else {
      NSLog("RustDesk: failed to read iOS mobile at-rest storage key: \(status)")
      return nil
    }
    guard let data = result as? Data, data.count == mobileAtRestKeyLength else {
      NSLog("RustDesk: refusing invalid iOS mobile at-rest storage key")
      return nil
    }
    return data
  }

  /// R-X6/R-S9: exclude the app's config store — the Documents directory that
  /// `getApplicationDocumentsDirectory()` (path_provider) → Rust `APP_DIR` →
  /// `Config::path` all resolve to — from device backups by setting the
  /// `NSURLIsExcludedFromBackupKey` resource value on it. That directory holds the
  /// per-remembered-peer connect-equivalent Argon2id PRS (`PeerConfig.password_prs`,
  /// under `peers/`), mobile at-rest ciphertext, and legacy config keypair/device-id
  /// metadata, so a local unencrypted backup would otherwise exfiltrate credential
  /// state outside the OS-protected storage boundary — the exact vector Android's
  /// `allowBackup="false"` closes.
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
  }
}
