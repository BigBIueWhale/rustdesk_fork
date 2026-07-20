const lockedT3TunnelPeerId = 'ronenzyroff.com:21128';
const lockedT3TunnelResetAfterInactivity = Duration(seconds: 30);

String resolvePortForwardPeer(String requestedPeerId, {required bool isRDP}) {
  return isRDP ? requestedPeerId : lockedT3TunnelPeerId;
}

bool shouldKeepLockedT3TunnelAlive({
  required bool hasActiveWindows,
  required bool hasPortForwardWindows,
}) {
  return !hasActiveWindows && hasPortForwardWindows;
}

bool shouldResetLockedT3TunnelAfterResume({
  required bool hasPortForwardWindows,
  required Duration inactiveFor,
}) {
  return hasPortForwardWindows &&
      inactiveFor >= lockedT3TunnelResetAfterInactivity;
}
