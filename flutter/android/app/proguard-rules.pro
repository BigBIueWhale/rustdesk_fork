# Keep class members from protobuf generated code.
-keepclassmembers class * extends com.google.protobuf.GeneratedMessageLite {
  <fields>;
}

# Keep rustls-platform-verifier classes for JNI
-keep, includedescriptorclasses class org.rustls.platformverifier.** { *; }

# Keep the security-critical OS-key bootstrap structurally auditable in the final APK.
-keep class com.carriez.flutter_hbb.MainApplication { *; }
-keep class com.carriez.flutter_hbb.MobileAtRestStorageKey { *; }
