#!/bin/sh
set -eu

readonly STATE=/tmp/rd-service-loginctl-state

[ -f "$STATE" ] && [ ! -L "$STATE" ] || {
  printf 'smoke loginctl: fixture state is unavailable\n' >&2
  exit 65
}
mode=$(sed -n '1p' "$STATE")
case "$mode" in
  root)
    uid=0
    username=root
    ;;
  user)
    uid=4001
    username=rdseat
    ;;
  *)
    printf 'smoke loginctl: invalid fixture state\n' >&2
    exit 65
    ;;
esac

case "$#:$*" in
  "3:--no-pager --no-legend list-sessions")
    printf '1 %s %s seat0\n' "$uid" "$username"
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
    printf 'smoke loginctl: unexpected arguments: %s\n' "$*" >&2
    exit 64
    ;;
esac
