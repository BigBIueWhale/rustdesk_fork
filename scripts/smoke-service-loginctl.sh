#!/bin/sh
set -eu

case "$#:$*" in
  "0:")
    printf '%s\n' '1 0 root seat0'
    ;;
  "4:show-session -p State 1")
    printf '%s\n' 'State=active'
    ;;
  "4:show-session -p Type 1")
    printf '%s\n' 'Type=x11'
    ;;
  "2:show-session 1")
    printf '%s\n' 'Id=1' 'User=0' 'Name=root' 'Seat=seat0' 'State=active' 'Type=x11'
    ;;
  *)
    printf 'smoke loginctl: unexpected arguments: %s\n' "$*" >&2
    exit 64
    ;;
esac
