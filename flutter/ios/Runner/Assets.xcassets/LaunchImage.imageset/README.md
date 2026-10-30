# iOS launch-screen assets

The [launch storyboard](../../Base.lproj/LaunchScreen.storyboard) displays the
`LaunchImage` image set. Replace the three images listed in
[Contents.json](Contents.json): `LaunchImage.png` (1×), `LaunchImage@2x.png` (2×),
and `LaunchImage@3x.png` (3×). Keep the manifest filenames in sync with the assets.

To edit in Xcode on macOS, run this command from the repository root:

```sh
open flutter/ios/Runner.xcworkspace
```

Select `Runner/Assets.xcassets`, then the `LaunchImage` image set and its scale
slots. Edit the linked storyboard to change the image placement or background.
See Flutter's [launch-screen guide](https://docs.flutter.dev/platform-integration/ios/launch-screen)
for the Xcode workflow.
