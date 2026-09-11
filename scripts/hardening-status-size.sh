#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 [--check]" >&2
  exit 2
}

case "${1:-}" in
  "") check=false ;;
  --check) check=true ;;
  *) usage ;;
esac

script_dir=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
status_file="$script_dir/../HARDENING_STATUS.md"
budget=400000
bytes=$(LC_ALL=C wc -c < "$status_file")
words=$(LC_ALL=C wc -w < "$status_file")
estimated_tokens=$(((bytes + 2) / 3))

printf 'file=HARDENING_STATUS.md\n'
printf 'utf8_bytes=%s\n' "$bytes"
printf 'words=%s\n' "$words"
printf 'estimated_tokens=%s\n' "$estimated_tokens"
printf 'method=ceil(UTF-8 bytes / 3)\n'
printf 'budget=%s\n' "$budget"

if [[ "$check" == true ]] && ((estimated_tokens > budget)); then
  printf 'status=over-budget\n'
  exit 1
fi

if ((estimated_tokens <= budget)); then
  status=under-budget
else
  status=over-budget
fi
printf 'status=%s\n' "$status"
