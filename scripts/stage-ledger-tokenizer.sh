#!/usr/bin/env bash
set -euo pipefail
umask 077
export PATH=/usr/bin:/bin
export LC_ALL=C

[ "$#" -eq 1 ] && [ "$1" = /outputs ] || exit 2
[ "$(id -u)" = "$TOKENIZER_UID" ] && [ "$(id -g)" = "$TOKENIZER_GID" ] \
    && [ "$TOKENIZER_UID" -ne 0 ] && [ "$TOKENIZER_GID" -ne 0 ] \
    || { echo 'ledger tokenizer acquisition principal differs' >&2; exit 1; }
[ -d /outputs ] && [ ! -L /outputs ] \
    && [ "$(stat -c '%u:%g:%a' /outputs)" = "$TOKENIZER_UID:$TOKENIZER_GID:700" ] \
    && [ -z "$(find /outputs -mindepth 1 -print -quit)" ] \
    || { echo 'ledger tokenizer output authority differs' >&2; exit 1; }
[[ "$TOKENIZER_WHEEL_SHA256" =~ ^[0-9a-f]{64}$ ]] \
    && [[ "$TOKENIZER_RANKS_SHA256" =~ ^[0-9a-f]{64}$ ]] \
    && [[ "$TOKENIZER_WHEEL_URL" = https://files.pythonhosted.org/packages/*/tiktoken-0.12.0-cp311-cp311-manylinux_2_28_x86_64.whl ]] \
    && [ "$TOKENIZER_RANKS_URL" = https://openaipublic.blob.core.windows.net/encodings/cl100k_base.tiktoken ] \
    || { echo 'ledger tokenizer publisher pins differ' >&2; exit 1; }

for name in tiktoken-0.12.0-cp311-cp311-manylinux_2_28_x86_64.whl cl100k_base.tiktoken; do
    case "$name" in
        *.whl) url="$TOKENIZER_WHEEL_URL"; sha="$TOKENIZER_WHEEL_SHA256" ;;
        *) url="$TOKENIZER_RANKS_URL"; sha="$TOKENIZER_RANKS_SHA256" ;;
    esac
    /usr/bin/env -i PATH=/usr/bin:/bin HOME=/nonexistent LC_ALL=C \
        /usr/bin/curl -q --fail --location --proto '=https' --proto-redir '=https' \
            --connect-timeout 15 --max-time 90 --retry 0 --max-filesize 4194304 \
            --silent --show-error --output "/outputs/$name" "$url"
    [ -f "/outputs/$name" ] && [ ! -L "/outputs/$name" ] \
        && [ "$(stat -c '%u:%g:%h' "/outputs/$name")" = "$TOKENIZER_UID:$TOKENIZER_GID:1" ] \
        && [ "$(stat -c '%s' "/outputs/$name")" -gt 0 ] \
        && [ "$(stat -c '%s' "/outputs/$name")" -le 4194304 ] \
        && [ "$(sha256sum "/outputs/$name" | cut -d' ' -f1)" = "$sha" ] \
        || { echo 'ledger tokenizer bytes differ from publisher pin' >&2; exit 1; }
    chmod 0400 "/outputs/$name"
done
printf 'LEDGER_TOKENIZER_CANDIDATE=downloaded files=2 tokenizer=tiktoken-0.12.0 encoding=cl100k_base execution=absent\n'
