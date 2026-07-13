#!/usr/bin/env bash

fork_version_error() {
  printf 'fork-version: %s\n' "$*" >&2
  return 1
}

fork_version_real_date() {
  local value="$1" normalized
  normalized="$(LC_ALL=C date -u -d "$value 00:00:00Z" +%F 2>/dev/null)" || return 1
  [ "$normalized" = "$value" ]
}

fork_version_base_is_newer() {
  local newer="$1" older="$2"
  local newer_major newer_minor newer_patch older_major older_minor older_patch
  IFS=. read -r newer_major newer_minor newer_patch <<< "$newer"
  IFS=. read -r older_major older_minor older_patch <<< "$older"
  if [ "$newer_major" -ne "$older_major" ]; then
    [ "$newer_major" -gt "$older_major" ]
  elif [ "$newer_minor" -ne "$older_minor" ]; then
    [ "$newer_minor" -gt "$older_minor" ]
  else
    [ "$newer_patch" -gt "$older_patch" ]
  fi
}

fork_version() {
  local root version_file changelog fv cargo base counter heading
  local heading_base heading_counter heading_date newest_base newest_counter newest_date
  local previous_base="" previous_counter="" previous_date="" index=0
  local -a release_headings
  local -A seen_versions=()

  root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)" || return 1
  version_file="$root/FORK_VERSION"
  changelog="$root/CHANGELOG.md"

  if [ ! -f "$version_file" ] || [ -L "$version_file" ]; then
    fork_version_error "FORK_VERSION must be a regular file ($version_file)"
    return 1
  fi
  if [ "$(wc -l < "$version_file")" -ne 1 ] \
     || [ "$(tail -c 1 "$version_file" | od -An -tx1 | tr -d ' \n')" != 0a ]; then
    fork_version_error "FORK_VERSION must contain exactly one newline-terminated line"
    return 1
  fi
  IFS= read -r fv < "$version_file" || {
    fork_version_error "could not read $version_file"
    return 1
  }

  cargo="$(awk '
    $0 == "[package]" { in_package = 1; next }
    in_package && /^\[/ { exit }
    in_package && /^version[[:space:]]*=/ {
      count++
      if ($0 !~ /^version[[:space:]]*=[[:space:]]*"[^"]+"$/) bad = 1
      value = $0
      sub(/^version[[:space:]]*=[[:space:]]*"/, "", value)
      sub(/"$/, "", value)
    }
    END {
      if (count != 1 || bad) exit 1
      print value
    }
  ' "$root/Cargo.toml" 2>/dev/null)" || cargo=""
  if [[ ! "$cargo" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
    fork_version_error "Cargo.toml must contain one canonical numeric [package] version"
    return 1
  fi
  if [[ ! "$fv" =~ ^((0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*))-hardened\.([1-9][0-9]*)$ ]]; then
    fork_version_error "'$fv' must be '<Cargo version>-hardened.<positive canonical counter>'"
    return 1
  fi
  base="${BASH_REMATCH[1]}"
  counter="${BASH_REMATCH[5]}"
  if [ "$base" != "$cargo" ]; then
    fork_version_error "'$fv' base must equal Cargo.toml version '$cargo'"
    return 1
  fi

  if [ ! -f "$changelog" ] || [ -L "$changelog" ]; then
    fork_version_error "CHANGELOG.md must be a regular file"
    return 1
  fi
  mapfile -t release_headings < <(awk '/^## / { print }' "$changelog")
  if [ "${#release_headings[@]}" -eq 0 ]; then
    fork_version_error "CHANGELOG.md has no release heading"
    return 1
  fi

  for heading in "${release_headings[@]}"; do
    if [[ ! "$heading" =~ ^##\ ((0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*))-hardened\.([1-9][0-9]*)\ (-|—)\ ([0-9]{4}-[0-9]{2}-[0-9]{2})$ ]]; then
      fork_version_error "malformed release heading: $heading"
      return 1
    fi
    heading_base="${BASH_REMATCH[1]}"
    heading_counter="${BASH_REMATCH[5]}"
    heading_date="${BASH_REMATCH[7]}"
    if ! fork_version_real_date "$heading_date"; then
      fork_version_error "release heading has an invalid calendar date: $heading"
      return 1
    fi
    if [ -n "${seen_versions["$heading_base-hardened.$heading_counter"]+present}" ]; then
      fork_version_error "duplicate release version in CHANGELOG.md: $heading_base-hardened.$heading_counter"
      return 1
    fi
    seen_versions["$heading_base-hardened.$heading_counter"]=1

    if [ "$index" -eq 0 ]; then
      newest_base="$heading_base"
      newest_counter="$heading_counter"
      newest_date="$heading_date"
    else
      if [[ "$previous_date" < "$heading_date" ]]; then
        fork_version_error "release dates must be newest-first: $previous_date precedes $heading_date"
        return 1
      fi
      if [ "$previous_base" = "$heading_base" ]; then
        if [ "$previous_counter" -ne $((heading_counter + 1)) ]; then
          fork_version_error "$previous_base-hardened.$previous_counter must increment $heading_base-hardened.$heading_counter by exactly one"
          return 1
        fi
      else
        if [ "$previous_counter" -ne 1 ]; then
          fork_version_error "a new app-version base must start at hardened.1 ($previous_base-hardened.$previous_counter)"
          return 1
        fi
        if ! fork_version_base_is_newer "$previous_base" "$heading_base"; then
          fork_version_error "app-version bases must be newest-first ($previous_base is not newer than $heading_base)"
          return 1
        fi
      fi
    fi
    previous_base="$heading_base"
    previous_counter="$heading_counter"
    previous_date="$heading_date"
    index=$((index + 1))
  done

  if [ "$newest_base-hardened.$newest_counter" != "$fv" ]; then
    fork_version_error "CHANGELOG.md top release must be '$fv'"
    return 1
  fi
  [ -n "$newest_date" ] || return 1
  printf '%s' "$fv"
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  fork_version || exit 1
  printf '\n'
fi
