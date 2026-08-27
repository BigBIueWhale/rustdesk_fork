#!/bin/sh
set -eu

# Fixed active-seat fixture for the disposable Debian systemd VM. The installed
# RustDesk supervisor must discover this non-root user through its production
# fixed-path loginctl parser, then descriptor-exec the service-owned child after
# dropping every credential/capability set.
case "$#:$*" in
  "3:--no-pager --no-legend list-sessions")
    printf '%s\n' '1 4001 rdseat seat0'
    ;;
  "5:--no-pager --property=State show-session -- 1")
    printf '%s\n' 'State=active'
    ;;
  "5:--no-pager --property=Type show-session -- 1")
    printf '%s\n' 'Type=x11'
    ;;
  "6:--no-pager --property=Display --property=Scope show-session -- 1")
    printf '%s\n' 'Display=:0' 'Scope=session-1.scope'
    ;;
  "6:--no-pager --property=State --property=Seat show-session -- 1")
    printf '%s\n' 'State=active' 'Seat=seat0'
    ;;
  *)
    printf 'systemd smoke loginctl: unexpected arguments: %s\n' "$*" >&2
    exit 64
    ;;
esac
