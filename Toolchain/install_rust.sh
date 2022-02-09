#!/bin/bash -ex
workdir=$(readlink -f $(dirname "${BASH_SOURCE[0]}"))
cd ${workdir}

pushd rust

CFLAGS="-Wa,-mrelax-relocations=no -Wa,--compress-debug-sections=none -Wl,--compress-debug-sections=none" \
    CXXFLAGS="-Wa,-mrelax-relocations=no -Wa,--compress-debug-sections=none -Wl,--compress-debug-sections=none" \
    REPLACE_CC=0 \
    bash ./src/ci/docker/scripts/musl-toolchain.sh x86_64
rm -rf build

./configure \
      --musl-root-fortanixvme=/usr/local/x86_64-linux-musl \
      --set target.x86_64-unknown-linux-fortanixvme.crt-static=true \
      --set install.prefix=${workdir}/rust/toolchain \
      --enable-extended \
      --enable-sanitizers \
      --enable-profiler \
      --enable-lld

# Newer binutils broke things on some vms/distros (i.e., linking against
# unknown relocs disabled by the following flag), so we need to go out of our
# way to produce "super compatible" binaries.
#
# See: https://github.com/rust-lang/rust/issues/34978
# And: https://github.com/rust-lang/rust/issues/59411
export CFLAGS_x86_64_unknown_linux_fortanixvme="-Wa,-mrelax-relocations=no -Wa,--compress-debug-sections=none \
    -Wl,--compress-debug-sections=none"
export CC_x86_64_unknown_linux_fortanixvme=x86_64-linux-musl-gcc
export CXX_x86_64_unknown_linux_fortanixvme=x86_64-linux-musl-g++
export LD_x86_64_unknown_linux_fortanixvme=x86_64-linux-musl-ld

python3 ./x.py install -i --stage 1 --target x86_64-unknown-linux-fortanixvme src library/std --verbose

# Test toolchain

curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source $HOME/.cargo/env
rustup toolchain link mybuild build/x86_64-unknown-linux-gnu/stage1
cd /tmp
cargo new app
cd app
cargo +mybuild run --target x86_64-unknown-linux-fortanixvme

popd
