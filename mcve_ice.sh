#!/bin/bash -ex

rm -rf build config.toml
./configure --enable-lld --set llvm.ninja=false --set rust.verbose-tests=true --set profile=compiler
# Fails with an ICE
./x.py test --stage=1 --target=x86_64-fortanix-unknown-sgx library/std --host='' --no-doc --exclude src/tools/linkchecker --verbose -j1 || true

# Mininal example triggering the ICE:
build_dir=$(pwd)/build

export RUSTC_LIBDIR="${build_dir}/x86_64-unknown-linux-gnu/stage1/lib"
export RUSTC_REAL="${build_dir}/x86_64-unknown-linux-gnu/stage1/bin/rustc"
export RUSTC_STAGE="1"
export RUSTC_SYSROOT="${build_dir}/x86_64-unknown-linux-gnu/stage1"

std=$(find ${build_dir}/x86_64-unknown-linux-gnu/stage1-std/x86_64-fortanix-unknown-sgx/release/deps/ -name "libstd-*.rlib")
${build_dir}/bootstrap/debug/rustc \
	./input.rs \
	--test \
	--target x86_64-fortanix-unknown-sgx \
        --extern std=${std} \
	-o $(mktemp)
