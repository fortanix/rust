#!/bin/bash -ex
RUST_BRANCH=fortanixvme-2023-05-07-alpha
RUST_SGX_BRANCH=fortanixvme-2023-05-07-alpha
MODE=test
WORKDIR=~/CI

if [ ! -d "${WORKDIR}" ]; then
    WORKDIR=$(mktemp -d /tmp/fortanixvme-ci-XXX)
fi

cd ${WORKDIR}

echo 'Update tools'
# TODO make sure rust-sgx branch compiles with latest nightly
#rustup update nightly
#rustup default nightly
rustup install nightly-2023-05-07
rustup default nightly-2023-05-07

echo 'Fetching fortanixvme tools'
if [ -d "./rust-sgx" ]; then
    pushd rust-sgx
    git reset
    git checkout ${RUST_SGX_BRANCH}
    git fetch
    git pull
    popd
else
    git clone https://github.com/fortanix/rust-sgx.git -b ${RUST_SGX_BRANCH}
fi

echo 'Building fortanixvme tools'
pushd rust-sgx/fortanix-vme/
cargo build --workspace --exclude dcap-provider
popd

echo 'Installing fortanixvme tools'
# clean up exiting tools
rm -f ~/.cargo/bin/ftxvme-elf2eif || true
rm -f ~/.cargo/bin/ftxvme-runner || true
rm -f ~/.cargo/bin/ftxvme-runner-cargo || true

# Set up tools
ln -fs ${WORKDIR}/rust-sgx/target/debug/ftxvme-elf2eif ~/.cargo/bin/ftxvme-elf2eif
ln -fs ${WORKDIR}/rust-sgx/target/debug/ftxvme-runner ~/.cargo/bin/ftxvme-runner
ln -fs ${WORKDIR}/rust-sgx/target/debug/ftxvme-runner-cargo ~/.cargo/bin/ftxvme-runner-cargo

# Specify cargo runner for fortanixvme target
touch ~/.cargo/config
sed -i '/ftxvme/d;/fortanixvme/d' ~/.cargo/config
echo >> ~/.cargo/config -e '[target.x86_64-unknown-linux-fortanixvme]\nrunner = ["ftxvme-runner-cargo", "--verbose"]'

echo 'Fetching Rust compiler'
if [ -d "./rust" ]; then
    pushd rust
    git reset
    git checkout ${RUST_BRANCH}
    git fetch
    git pull
    # https://github.com/rust-lang/rust/issues/72104
    git submodule foreach --recursive git reset
    git submodule update --init --recursive
    git submodule foreach --recursive git fetch --depth=2147483647 origin '+refs/heads/*:refs/remotes/origin/*'
    popd
else
    git clone https://github.com/fortanix/rust.git -b ${RUST_BRANCH}
    pushd rust
    git submodule update --init --recursive
    popd
fi

echo 'Installing musl toolchain'
musl_dir="${WORKDIR}/musl-toolchain"
mkdir -p ${musl_dir}

pushd rust
if [ -z "$(ls -A ${musl_dir})" ]; then
    # musl-toolchain installation directory is empty, install it
    CFLAGS="-Wa,-mrelax-relocations=no -Wa,--compress-debug-sections=none -Wl,--compress-debug-sections=none" \
        CXXFLAGS="-Wa,-mrelax-relocations=no -Wa,--compress-debug-sections=none -Wl,--compress-debug-sections=none" \
        REPLACE_CC=0 \
        INSTALL_DIR=${musl_dir} \
        bash ./src/ci/docker/scripts/musl-toolchain.sh x86_64
fi

if [ ! -f "config.toml" ]; then
    # Warning: when you want to build `lld` as well, you can add `--enable-lld`, but currently it fails when LLVM is
    #   downloaded from ci instead of rebuild. It can be resolved by removing `--set llvm.download-ci-llvm=true`
    # This version of llvm is too old to be downloaded. We'll need to compile it ourselves.
    # We also need an older version of `cargo` that doesn't add unknown flags when it calls `rustc`
    ./configure \
        --target=x86_64-unknown-linux-fortanixvme,x86_64-unknown-linux-fortanixvme \
        --musl-root-fortanixvme=${musl_dir}/x86_64-linux-musl/ \
        --set target.x86_64-unknown-linux-fortanixvme.crt-static=true \
        --set install.prefix=${workdir}/rust/toolchain \
        --set llvm.targets=X86 \
        --set llvm.download-ci-llvm=false \
	--set rust.verbose-tests=true \
        --enable-extended \
        --tools=cargo
fi

# Newer binutils broke things on some vms/distros (i.e., linking against
# unknown relocs disabled by the following flag), so we need to go out of our
# way to produce "super compatible" binaries.
#
# See: https://github.com/rust-lang/rust/issues/34978
# And: https://github.com/rust-lang/rust/issues/59411
export CFLAGS_x86_64_unknown_linux_fortanixvme="-Wa,-mrelax-relocations=no -Wa,--compress-debug-sections=none \
    -Wl,--compress-debug-sections=none"
export CC_x86_64_unknown_linux_fortanixvme=${musl_dir}/bin/x86_64-linux-musl-gcc
export CXX_x86_64_unknown_linux_fortanixvme=${musl_dir}/bin/x86_64-linux-musl-g++
export LD_x86_64_unknown_linux_fortanixvme=${musl_dir}/bin/x86_64-linux-musl-ld

if [ "${MODE}" == "test" ]; then
    RUST_TEST_THREADS=1 nice -n 19 ionice -c idle ./x.py test --stage=1 --target=x86_64-unknown-linux-fortanixvme library/std --host='' --no-doc --exclude src/tools/linkchecker ${testname}
else
    nice -n 19 ionice -c idle python3 ./x.py build

    source $HOME/.cargo/env
    rustup uninstall fortanixvme
    rustup toolchain link fortanixvme build/x86_64-unknown-linux-gnu/stage2
    app_dir=$(mktemp -d /tmp/app-XXX)
    pushd ${app_dir}
    cargo +fortanixvme new my_app
    pushd my_app
    cargo +fortanixvme run --target x86_64-unknown-linux-fortanixvme
    popd
    popd
fi

popd
