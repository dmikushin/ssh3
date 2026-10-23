#!/usr/bin/env bash
# Release build for ssh3-rs: fully static x86_64 musl binaries, byte-reproducible.
#
# Why static, and why these exact flags (all established by experiment, see
# ~/scratch/ssh-udp/qa-static-musl.log):
#
#   - The deployment target `oracle` (gateway.mikush.in, Ubuntu 20.04, glibc
#     2.31) has no musl loader: `/lib/ld-musl-x86_64.so.1` does not exist.
#   - A plain `cargo build --target x86_64-unknown-linux-musl` produces a
#     static-PIE that still carries an INTERP segment naming that loader. It
#     has zero DT_NEEDED entries, `ldd` prints "statically linked", and it
#     still fails on oracle with `No such file or directory` (exit 127),
#     because the kernel honours INTERP. Verified 2026-10-23.
#   - `-C relocation-model=static` drops the INTERP segment; the resulting
#     non-PIE executable runs on oracle. Verified by running it there.
#   - `-C target-feature=+crt-static` is NOT passed: it is already the default
#     for the musl target, and the binary built without it runs on oracle.
#     (Minimality shown by removal, not assumed.)
#   - jemalloc with `background_thread:true` (SPEC.md §1) initialises and
#     purges correctly in this configuration under musl; verified on oracle by
#     ~/scratch/ssh-udp/static-probe.
#
# Reproducibility: --remap-path-prefix erases the build directory and the
# cargo registry path from debuginfo and panic messages, so the artifact does
# not depend on who built it or where.
#
# Usage:
#   scripts/build-release.sh              build release binaries
#   scripts/build-release.sh --repro      build twice into separate target
#                                         dirs and compare sha256
set -euo pipefail

TARGET=x86_64-unknown-linux-musl
WS=${SSH3_RELEASE_WS:-"$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"}
OUT=${SSH3_RELEASE_OUT:-"$WS/dist"}

command -v musl-gcc >/dev/null || {
    echo "build-release.sh: musl-gcc not found; install the 'musl' package" >&2
    exit 1
}
rustup target list --installed | grep -qx "$TARGET" || {
    echo "build-release.sh: rust target $TARGET not installed; run: rustup target add $TARGET" >&2
    exit 1
}

export CC_x86_64_unknown_linux_musl=musl-gcc
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=musl-gcc
# Deterministic: no absolute paths from this machine inside the artifact.
export RUSTFLAGS="-C relocation-model=static --remap-path-prefix=$WS=/ssh3-rs --remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/cargo"
# Cargo does not pass RUSTFLAGS to rustdoc. Without this, the merged doctest
# harness for the musl target is linked as a static-PIE and SIGSEGVs at
# startup; rustdoc swallows the signal and reports a bare `error: doctest
# failed` with no diagnostic. Evidence: ~/scratch/ssh-udp/qa-doctest-musl.log.
export RUSTDOCFLAGS="-C relocation-model=static"
export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(cd "$WS" && git log -1 --format=%ct 2>/dev/null || echo 0)}

build_into() {
    local td=$1
    (cd "$WS" && cargo build --release --locked --workspace --bins --target "$TARGET" --target-dir "$td")
}

bins_in() {
    find "$1/$TARGET/release" -maxdepth 1 -type f -executable -printf '%f\n' 2>/dev/null | sort
}

if [[ ${1:-} == --test ]]; then
    # Run the whole suite as it will be shipped: musl target, release profile.
    # A test that only ever ran on the host gnu target proves nothing about the
    # artifact that goes to oracle.
    td=${SSH3_RELEASE_TARGET_DIR:-/dev/shm/ssh3-musl-test}
    (cd "$WS" && cargo test --release --workspace --target "$TARGET" --target-dir "$td")
    exit $?
fi

if [[ ${1:-} == --repro ]]; then
    a=$(mktemp -d /dev/shm/ssh3-repro-a.XXXX)
    b=$(mktemp -d /dev/shm/ssh3-repro-b.XXXX)
    trap 'rm -rf "$a" "$b"' EXIT
    build_into "$a"
    build_into "$b"
    mapfile -t names < <(bins_in "$a")
    if [[ ${#names[@]} -eq 0 ]]; then
        echo "build-release.sh --repro: the workspace produced no binaries; nothing to compare" >&2
        exit 1
    fi
    rc=0
    for n in "${names[@]}"; do
        ha=$(sha256sum "$a/$TARGET/release/$n" | cut -d' ' -f1)
        hb=$(sha256sum "$b/$TARGET/release/$n" | cut -d' ' -f1)
        if [[ $ha == "$hb" ]]; then
            echo "reproducible $n $ha"
        else
            echo "NOT REPRODUCIBLE $n $ha != $hb" >&2
            rc=1
        fi
    done
    exit $rc
fi

TD=${SSH3_RELEASE_TARGET_DIR:-"$WS/target"}
build_into "$TD"
mkdir -p "$OUT"
mapfile -t names < <(bins_in "$TD")
for n in "${names[@]}"; do
    src="$TD/$TARGET/release/$n"
    install -m755 "$src" "$OUT/$n"
    # Reject any artifact that would fail on oracle for the INTERP reason
    # above: this check is the whole point of the build script.
    if readelf -lW "$src" | grep -q INTERP; then
        echo "build-release.sh: $n carries an INTERP segment and will not run on oracle" >&2
        exit 1
    fi
    if readelf -dW "$src" | grep -q NEEDED; then
        echo "build-release.sh: $n has dynamic dependencies" >&2
        exit 1
    fi
    echo "static $n $(stat -c%s "$src") bytes $(sha256sum "$src" | cut -d' ' -f1)"
done
echo "artifacts in $OUT"
