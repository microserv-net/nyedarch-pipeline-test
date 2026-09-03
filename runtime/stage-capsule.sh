#!/bin/sh
# Stage the compiled capsule as a NYEDArch capsule (.nyarch).
set -e
cargo build --release
bin="target/release/nyedarch-capsule"
[ -f "$bin.exe" ] && bin="$bin.exe"
out="nyedarch-5ab657e5451710b0.nyarch"
cp "$bin" "$out"
chmod +x "$out" 2>/dev/null || true
echo "capsule: $out"
