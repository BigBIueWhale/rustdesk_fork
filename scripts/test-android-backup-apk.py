#!/usr/bin/env python3
"""Exercise backup-policy binding against actual linked/optimized AAPT2 resources."""
import argparse
import copy
import importlib.util
import pathlib
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
import zipfile


def run(*args):
    return subprocess.run([str(arg) for arg in args], check=True, text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--aapt2", required=True, type=pathlib.Path)
    parser.add_argument("--android-jar", required=True, type=pathlib.Path)
    args = parser.parse_args()
    source = pathlib.Path(__file__).resolve().parent.parent
    spec = importlib.util.spec_from_file_location(
        "apk_manifest", source / "scripts/verify-android-apk-manifest.py")
    checker = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = checker
    spec.loader.exec_module(checker)
    policy = ET.parse(source / "flutter/android/app/src/main/res/xml/data_extraction_rules.xml").getroot()
    cases = ("original", "optimized", "missing-cloud", "missing-transfer",
             "missing-domain", "partial-domain", "wrong-binding", "qualified-policy")
    with tempfile.TemporaryDirectory(prefix="android-backup-apk-") as temporary:
        for case in cases:
            work = pathlib.Path(temporary) / case
            resources = work / "res"
            (resources / "xml").mkdir(parents=True)
            rules = copy.deepcopy(policy)
            if case == "missing-cloud":
                rules.remove(rules.find("cloud-backup"))
            elif case == "missing-transfer":
                rules.remove(rules.find("device-transfer"))
            elif case == "missing-domain":
                rules.find("device-transfer").remove(rules.find("device-transfer/exclude"))
            elif case == "partial-domain":
                rules.find("device-transfer/exclude").set("path", "one-file")
            ET.ElementTree(rules).write(resources / "xml/data_extraction_rules.xml")
            selected = "data_extraction_rules"
            if case == "wrong-binding":
                selected = "other_rules"
                ET.ElementTree(ET.Element("data-extraction-rules")).write(resources / "xml/other_rules.xml")
            elif case == "qualified-policy":
                (resources / "xml-v34").mkdir()
                ET.ElementTree(ET.Element("data-extraction-rules")).write(
                    resources / "xml-v34/data_extraction_rules.xml")
            manifest = work / "AndroidManifest.xml"
            manifest.write_text(
                '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
                'package="org.rustdesk.backupfixture"><uses-sdk android:minSdkVersion="24" '
                'android:targetSdkVersion="33"/><application android:allowBackup="false" '
                f'android:fullBackupContent="false" android:dataExtractionRules="@xml/{selected}"/>'
                '</manifest>', encoding="utf-8")
            compiled = work / "compiled.zip"
            apk = work / "linked.apk"
            run(args.aapt2, "compile", "--dir", resources, "-o", compiled)
            run(args.aapt2, "link", "-I", args.android_jar, "--manifest", manifest,
                "-o", apk, compiled)
            if case != "original":
                optimized = work / "optimized.apk"
                run(args.aapt2, "optimize", "--shorten-resource-paths", "--collapse-resource-names",
                    "-o", optimized, apk)
                apk = optimized
                with zipfile.ZipFile(apk) as archive:
                    if "res/xml/data_extraction_rules.xml" in archive.namelist():
                        raise AssertionError("AAPT2 did not shorten the fixture policy path")
            dump = checker.run_aapt2(args.aapt2, apk)
            if dump.returncode:
                raise AssertionError(dump.stderr)
            errors = checker.validate_apk_backup(args.aapt2, apk, checker.parse_xmltree(dump.stdout))
            expected = case in {"original", "optimized"}
            if (not errors) != expected:
                raise AssertionError(f"{case}: expected accepted={expected}, got {errors}")
            print(f"ANDROID_BACKUP_APK_CASE=pass case={case} accepted={str(expected).lower()}", flush=True)
    print(f"ANDROID_BACKUP_APK_CHECK=pass cases={len(cases)}")


if __name__ == "__main__":
    main()
