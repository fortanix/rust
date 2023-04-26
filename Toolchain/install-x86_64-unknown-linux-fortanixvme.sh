#!/bin/bash -ex
arg=$1
testname=""

if [ "" != "$2" ]
then
    testname="--test-args $2"
fi

workdir=$(readlink -f $(dirname "${BASH_SOURCE[0]}"))
cd ${workdir}

if [ "${workdir}" == "/workdir" ]
then
    echo "Executing in Docker container"
    repo_root="${workdir}/rust"
    install_dir="/usr/local/"

    git config --global --add safe.directory ${workdir}/rust/src/tools/rust-installer
    git config --global --add safe.directory ${workdir}/rust/src/tools/cargo
    git config --global --add safe.directory ${workdir}/rust/src/tools/rls
    git config --global --add safe.directory ${workdir}/rust/src/tools/miri
    git config --global --add safe.directory ${workdir}/rust/library/backtrace
    git config --global --add safe.directory ${workdir}/rust/library/stdarch
    git config --global --add safe.directory ${workdir}/rust

    curl https://sh.rustup.rs -sSf | sh -s -- -y
else
    echo "Executing outside of container"
    repo_root=$(readlink -f "${workdir}/../")
    install_dir="${repo_root}/musl-toolchain"
    mkdir -p ${install_dir}
fi

pushd ${repo_root}

if [ -z "${install_dir}" ]; then
    # musl-toolchain installation directory is empty, install it
    CFLAGS="-Wa,-mrelax-relocations=no -Wa,--compress-debug-sections=none -Wl,--compress-debug-sections=none" \
        CXXFLAGS="-Wa,-mrelax-relocations=no -Wa,--compress-debug-sections=none -Wl,--compress-debug-sections=none" \
        REPLACE_CC=0 \
        INSTALL_DIR=${install_dir} \
        bash ./src/ci/docker/scripts/musl-toolchain.sh x86_64
fi

if [ ! -f "config.toml" ]; then
    # Warning: when you want to build `lld` as well, you can add `--enable-lld`, but currently it fails when LLVM is
    #   downloaded from ci instead of rebuild. It can be resolved by removing `--set llvm.download-ci-llvm=true`
    # This version of llvm is too old to be downloaded. We'll need to compile it ourselves.
    # We also need an older version of `cargo` that doesn't add unknown flags when it calls `rustc`
    ./configure \
        --target=x86_64-unknown-linux-fortanixvme,x86_64-unknown-linux-fortanixvme \
        --musl-root-fortanixvme=${install_dir}/x86_64-linux-musl/ \
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
export CC_x86_64_unknown_linux_fortanixvme=${install_dir}/bin/x86_64-linux-musl-gcc
export CXX_x86_64_unknown_linux_fortanixvme=${install_dir}/bin/x86_64-linux-musl-g++
export LD_x86_64_unknown_linux_fortanixvme=${install_dir}/bin/x86_64-linux-musl-ld

if [ "${arg}" == "test" ]; then
    RUST_TEST_THREADS=1 ./x.py test --stage=1 --target=x86_64-unknown-linux-fortanixvme library/std --host='' --no-doc --exclude src/tools/linkchecker ${testname}
else
    python3 ./x.py build

    source $HOME/.cargo/env
    # force use of older cargo that doesn't add unknown flags when it calls rustc
    cp build/x86_64-unknown-linux-gnu/stage1-tools-bin/cargo build/x86_64-unknown-linux-gnu/stage1/bin/
    rustup toolchain link mybuild build/x86_64-unknown-linux-gnu/stage1
    cd /tmp
    cargo +mybuild new app
    cd app
    cargo +mybuild run --target x86_64-unknown-linux-fortanixvme
fi

popd
