import 'package:flutter_hbb/common/locked_t3_tunnel.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('locks non-RDP forwarding to the T3 peer', () {
    expect(
      resolvePortForwardPeer('wrong-peer', isRDP: false),
      lockedT3TunnelPeerId,
    );
  });

  test('does not change RDP peers', () {
    expect(
      resolvePortForwardPeer('rdp-peer', isRDP: true),
      'rdp-peer',
    );
  });

  test('keeps a hidden port-forward process alive', () {
    expect(
      shouldKeepLockedT3TunnelAlive(
        hasActiveWindows: false,
        hasPortForwardWindows: true,
      ),
      isTrue,
    );
    expect(
      shouldKeepLockedT3TunnelAlive(
        hasActiveWindows: true,
        hasPortForwardWindows: true,
      ),
      isFalse,
    );
    expect(
      shouldKeepLockedT3TunnelAlive(
        hasActiveWindows: false,
        hasPortForwardWindows: false,
      ),
      isFalse,
    );
  });
}
