#!/usr/bin/env bash
# TODO(one-binary): iOS is not built (source-conformance only, R-R2); delete with the
# target-pruning. If kept, drop hwcodec (software codec only, R-R2b).
cargo build --locked --features flutter,hwcodec --release --target aarch64-apple-ios --lib
