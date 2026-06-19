#!/usr/bin/env bash
# TODO(one-binary): non-shipped target — the fork builds aarch64 Android only (R-R2);
# delete with the target-pruning. If kept, drop hwcodec (software codec only, R-R2b).
cargo ndk --platform 21 --target armv7-linux-androideabi build --locked --release --features flutter,hwcodec
