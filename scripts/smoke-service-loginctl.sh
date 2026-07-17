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
  "0:")
    printf '1 %s %s seat0\n' "$uid" "$username"
    ;;
  "4:show-session -p State 1")
    printf '%s\n' 'State=active'
    ;;
  "4:show-session -p Type 1")
    printf '%s\n' 'Type=x11'
    ;;
  "2:show-session 1")
    printf '%s\n' 'Id=1' "User=$uid" "Name=$username" 'Seat=seat0' 'State=active' 'Type=x11'
    ;;
  *)
    printf 'smoke loginctl: unexpected arguments: %s\n' "$*" >&2
    exit 64
    ;;
esac
