#!/usr/bin/env python3
"""Verify complete account/address-book/group storage compatibility excision."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
from typing import Dict, Tuple


class VerificationError(RuntimeError):
    pass


def require(source: str, needle: str, label: str) -> None:
    if needle not in source:
        raise VerificationError(f"missing {label}: {needle!r}")


def forbid(source: str, needle: str, label: str) -> None:
    if needle in source:
        raise VerificationError(f"forbidden {label} remains: {needle!r}")


def load_sources(repo: Path) -> Dict[str, str]:
    paths = {
        "config": "libs/hbb_common/src/config.rs",
        "flutter_ffi": "src/flutter_ffi.rs",
        "client": "src/client.rs",
        "ipc": "src/ipc.rs",
        "web_bridge": "flutter/lib/web/bridge.dart",
        "consts": "flutter/lib/consts.dart",
        "common": "flutter/lib/common.dart",
        "pubspec": "flutter/pubspec.yaml",
        "requirements": "requirements.html",
        "hardening": "HARDENING_STATUS.md",
        "verify": "scripts/verify.sh",
        "apple": "scripts/apple-conform-check.sh",
        "workspace": "scripts/verify-verifier-workspace.py",
    }
    return {
        key: (repo / relative).read_text(encoding="utf-8")
        for key, relative in paths.items()
    }


def validate(sources: Dict[str, str]) -> None:
    config = sources["config"]
    for needle in (
        "pub struct AbPeer",
        "pub struct AbEntry",
        "pub struct Ab {",
        "impl Ab {",
        "pub struct GroupPeer",
        "pub struct GroupUser",
        "pub struct DeviceGroup",
        "pub struct Group {",
        "impl Group {",
        "deserialize_vec_abpeer",
        "deserialize_vec_abentry",
        "deserialize_vec_groupuser",
        "deserialize_vec_grouppeer",
        "deserialize_vec_devicegroup",
    ):
        forbid(config, needle, "retired account data model")
    for needle in (
        "fn load_raw_config_bytes(",
        "fn store_raw_config_bytes(",
        "fn encrypted_json_config_bytes(",
        "fn load_encrypted_json_config",
        "fn remove_raw_config_file(",
        "fn preserve_raw_config_file(",
        "store_raw_config_bytes_writes_owner_only_permissions",
        "store_raw_config_bytes_replaces_existing_file",
        "raw_encrypted_json_load_failure_preserves_payload_for_recovery",
    ):
        forbid(config, needle, "account-only raw persistence helper or regression")

    retired_options = (
        "OPTION_HIDE_AB_TAGS_PANEL",
        "OPTION_SYNC_AB_WITH_RECENT_SESSIONS",
        "OPTION_SYNC_AB_TAGS",
        "OPTION_FILTER_AB_BY_INTERSECTION",
        "OPTION_PRESET_ADDRESS_BOOK_NAME",
        "OPTION_PRESET_ADDRESS_BOOK_TAG",
        "OPTION_PRESET_ADDRESS_BOOK_ALIAS",
        "OPTION_PRESET_ADDRESS_BOOK_PASSWORD",
        "OPTION_PRESET_ADDRESS_BOOK_NOTE",
        "OPTION_FLUTTER_CURRENT_AB_NAME",
        "OPTION_DISABLE_GROUP_PANEL",
        "OPTION_PRESET_DEVICE_USERNAME",
        "OPTION_PRESET_DEVICE_NAME",
        "OPTION_PRESET_NOTE",
        "OPTION_PRESET_DEVICE_GROUP_NAME",
        "OPTION_PRESET_USERNAME",
        "OPTION_PRESET_STRATEGY_NAME",
        "OPTION_ALLOW_ASK_FOR_NOTE",
    )
    for needle in retired_options:
        forbid(config + sources["ipc"], needle, "retired account option authority")
    for needle in (
        "hideAbTagsPanel",
        "sync-ab-with-recent-sessions",
        "sync-ab-tags",
        "filter-ab-by-intersection",
        "preset-address-book-",
        "current-ab-name",
        "disable-group-panel",
        "preset-device-username",
        "preset-device-name",
        "preset-note",
        "preset-device-group-name",
        "preset-user-name",
        "preset-strategy-name",
        "allow-ask-for-note",
    ):
        forbid(config + sources["ipc"] + sources["consts"], needle, "retired account option value")

    ffi = sources["flutter_ffi"]
    for needle in (
        "main_save_ab",
        "main_clear_ab",
        "main_load_ab",
        "main_save_group",
        "main_clear_group",
        "main_load_group",
        "config::Ab",
        "config::Group",
    ):
        forbid(ffi, needle, "retired native account-storage FFI")
    for needle in (
        "mainSaveAb",
        "mainClearAb",
        "mainLoadAb",
        "mainSaveGroup",
        "mainClearGroup",
        "mainLoadGroup",
        "save_ab",
        "clear_ab",
        "load_ab",
        "save_group",
        "clear_group",
        "load_group",
        "onLoadAbFinished",
        "onLoadGroupFinished",
    ):
        forbid(sources["web_bridge"], needle, "retired web account-storage bridge")
    forbid(
        sources["client"],
        "save_ab_password_to_recent",
        "retired address-book password provenance flag",
    )
    for needle in (
        "PresetAddressBookName",
        "PresetAddressBookTag",
        "PresetAddressBookAlias",
        "PresetAddressBookNote",
        "PresetDeviceUsername",
        "PresetDeviceName",
        "PresetNote",
    ):
        forbid(sources["ipc"], needle, "retired main-status account option")
    for needle in ("kOptionCurrentAbName", "kOptionAllowAskForNoteAtEndOfConnection"):
        forbid(sources["consts"], needle, "retired Dart account option")

    presentation = sources["common"] + sources["pubspec"]
    for needle in (
        "AddressBook",
        "DeviceGroup",
        "assets/address_book.ttf",
        "assets/device_group.ttf",
    ):
        forbid(presentation, needle, "retired packaged account glyph family")
    forbid(sources["pubspec"], "    - assets/\n", "recursive asset packaging authority")
    for needle in (
        "    - assets/actions.svg",
        "    - assets/win.svg",
        "    - family: GestureIcons",
        "    - family: Tabbar",
        "    - family: PeerSearchbar",
        "    - family: More",
    ):
        require(sources["pubspec"], needle, "explicit retained Flutter asset/font manifest")

    for needle in (
        "cargo test -p hbb_common --lib config::tests::store_raw_config_bytes",
        "config::tests::raw_encrypted_json_load_failure_preserves_payload_for_recovery",
        "address-book-or-group-raw-store-not-used",
        "address-book-raw-load-not-used",
        "group-raw-load-not-used",
        "raw-corrupt-preserve-helper-missing",
    ):
        forbid(sources["verify"], needle, "superseded raw account-store gate")
    require(
        sources["verify"],
        "config::tests::store_path_writes_owner_only_permissions",
        "retained peer TOML owner-only regression",
    )
    require(
        sources["verify"],
        "retired account raw stores are absent under R-S11hj",
        "R-S11b-4d supersession disposition",
    )

    for key, needle, label in (
        (
            "requirements",
            '<div class="req"><span class="id">R-S11hj</span>',
            "R-S11hj normative requirement",
        ),
        ("requirements", "<tr><td>370</td>", "Appendix C #370"),
        (
            "hardening",
            "### R-S11hj/R-S11e-247 — complete account storage and presentation authority excision",
            "R-S11hj hardening ledger",
        ),
        (
            "verify",
            "python3 scripts/verify-account-storage-excision.py --repo . --self-test",
            "shared focused-verifier wiring",
        ),
        (
            "apple",
            "python3 scripts/verify-account-storage-excision.py --repo . --self-test",
            "Apple/shared focused-verifier wiring",
        ),
        (
            "workspace",
            '            "account_storage_excision_verifier": (\n'
            '                repo / "scripts/verify-account-storage-excision.py"\n'
            '            ).read_text(encoding="utf-8"),',
            "independent focused-verifier source binding",
        ),
        (
            "workspace",
            "    validate_account_storage_excision_contract(sources)\n",
            "independent validator dispatch",
        ),
    ):
        require(sources[key], needle, label)

    requirements_digest = hashlib.sha256(
        sources["requirements"].encode("utf-8")
    ).hexdigest()
    require(
        sources["hardening"],
        f"{requirements_digest}  requirements.html",
        "exact requirements digest binding",
    )


Mutation = Tuple[str, str, str, str]

MUTATIONS: Tuple[Mutation, ...] = (
    ("config", "pub const OPTION_DISPLAY_NAME", "pub struct Ab { access_token: String }\npub const OPTION_DISPLAY_NAME", "account data model"),
    ("config", "enum ConfigStoreFault", "fn store_raw_config_bytes() {}\nenum ConfigStoreFault", "raw persistence helper"),
    ("config", "pub const OPTION_DISPLAY_NAME", "pub const OPTION_PRESET_ADDRESS_BOOK_NAME: &str = \"preset-address-book-name\";\npub const OPTION_DISPLAY_NAME", "account option authority"),
    ("flutter_ffi", "pub fn main_start_dbus_server()", "pub fn main_save_ab() {}\npub fn main_start_dbus_server()", "native storage FFI"),
    ("web_bridge", "Future<void> mainStartDbusServer", "Future<void> mainSaveAb({dynamic hint}) async {}\n  Future<void> mainStartDbusServer", "web storage bridge"),
    ("client", "pub received: bool,", "pub received: bool,\n    pub save_ab_password_to_recent: bool,", "password provenance flag"),
    ("ipc", "    AllowWebsocket,", "    AllowWebsocket,\n    PresetAddressBookName,", "main-status option"),
    ("consts", "const String kOptionPeerCardUiType", "const String kOptionCurrentAbName = \"current-ab-name\";\nconst String kOptionPeerCardUiType", "Dart account option"),
    ("pubspec", "  assets:\n", "  assets:\n    - assets/\n", "recursive asset packaging"),
    ("pubspec", "    - family: More", "    - family: AddressBook\n      fonts:\n        - asset: assets/address_book.ttf\n    - family: More", "packaged account glyph"),
    ("requirements", '<span class="id">R-S11hj</span>', '<span class="id">R-S11hj-disabled</span>', "normative requirement"),
    ("requirements", "<tr><td>370</td>", "<tr><td>370-disabled</td>", "Appendix C row"),
    ("hardening", "R-S11hj/R-S11e-247 — complete account storage and presentation authority excision", "R-S11hj-disabled/R-S11e-247 — complete account storage and presentation authority excision", "hardening ledger"),
    ("verify", "python3 scripts/verify-account-storage-excision.py --repo . --self-test", "true # account storage verifier disabled", "shared gate"),
    ("apple", "python3 scripts/verify-account-storage-excision.py --repo . --self-test", "true # account storage verifier disabled", "Apple gate"),
    (
        "workspace",
        '            "account_storage_excision_verifier": (\n'
        '                repo / "scripts/verify-account-storage-excision.py"\n'
        '            ).read_text(encoding="utf-8"),',
        '            "account_storage_excision_verifier_disabled": (\n'
        '                repo / "scripts/verify-account-storage-excision.py"\n'
        '            ).read_text(encoding="utf-8"),',
        "independent source binding",
    ),
    (
        "workspace",
        "    validate_account_storage_excision_contract(sources)\n",
        "    validate_account_storage_excision_contract_disabled(sources)\n",
        "independent dispatch",
    ),
)


def run_self_test(sources: Dict[str, str]) -> None:
    for key, old, new, label in MUTATIONS:
        if old not in sources[key]:
            raise VerificationError(f"self-test fixture missing for {label}")
        mutated = dict(sources)
        mutated[key] = sources[key].replace(old, new, 1)
        try:
            validate(mutated)
        except VerificationError:
            continue
        raise VerificationError(f"self-test mutation survived: {label}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, default=Path("."))
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    sources = load_sources(args.repo.resolve())
    validate(sources)
    if args.self_test:
        run_self_test(sources)
        print(
            "account storage excision verifier self-test passed "
            f"({len(MUTATIONS)} mutations)"
        )
    else:
        print("account storage excision verifier passed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except VerificationError as error:
        print(f"account storage excision verifier failed: {error}")
        raise SystemExit(1)
