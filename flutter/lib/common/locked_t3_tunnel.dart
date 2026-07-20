const lockedT3TunnelPeerId = 'ronenzyroff.com:21128';

String resolvePortForwardPeer(String requestedPeerId, {required bool isRDP}) {
  return isRDP ? requestedPeerId : lockedT3TunnelPeerId;
}
