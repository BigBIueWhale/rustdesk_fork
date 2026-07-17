#!/bin/sh
set -eu

# Fixed active-seat fixture for the disposable Debian systemd VM. The installed
# RustDesk supervisor must discover this non-root user through its production
# fixed-path loginctl parser, then descriptor-exec the service-owned child after
# dropping every credential/capability set.
case "$#:$*" in
  "0:")
    printf '%s\n' '1 4001 rdseat seat0'
    ;;
  "4:show-session -p State 1")
    printf '%s\n' 'State=active'
    ;;
  "4:show-session -p Type 1")
    printf '%s\n' 'Type=x11'
    ;;
  "2:show-session 1")
    printf '%s\n' \
      'Id=1' \
      'User=4001' \
      'Name=rdseat' \
      'Seat=seat0' \
      'State=active' \
      'Type=x11'
    ;;
  *)
    printf 'systemd smoke loginctl: unexpected arguments: %s\n' "$*" >&2
    exit 64
    ;;
esac
