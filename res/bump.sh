#! /usr/bin/env bash
sed -i "s/$1/$2/g" flutter/pubspec.yaml Cargo.toml .github/workflows/*yml libs/portable/Cargo.toml
cargo run # to bump version in cargo lock
