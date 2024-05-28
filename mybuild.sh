#!/bin/bash -ex
export AR_x86_64_fortanix_unknown_sgx=ar
export CC_x86_64_fortanix_unknown_sgx=clang-12
export CFLAGS_x86_64_fortanix_unknown_sgx="-D__ELF__ -isystem/usr/include/x86_64-linux-gnu -mlvi-hardening -mllvm -x86-experimental-lvi-inline-asm-hardening"
export CXX_x86_64_fortanix_unknown_sgx=clang++-12
export CXXFLAGS_x86_64_fortanix_unknown_sgx="-D__ELF__ -isystem/usr/include/x86_64-linux-gnu -mlvi-hardening -mllvm -x86-experimental-lvi-inline-asm-hardening"
export CC_x86_64_unknown_linux_gnu=clang-12
export CXX_x86_64_unknown_linux_gnu=clang++-12

git submodule update --init --recursive
        detect_cxx_include_path() {
            for path in $(clang++-12 -print-search-dirs|sed -n 's/^libraries:\s*=//p'|tr : ' '); do
                num_component="$(basename "$path")"
                if [[ "$num_component" =~ ^[0-9]+(\.[0-9]+)*$ ]]; then
                    if [[ "$(basename "$(dirname "$path")")" == 'x86_64-linux-gnu' ]]; then
                        echo $num_component
                        return
                    fi
                fi
            done
            exit 1
        }
export CXXFLAGS_x86_64_fortanix_unknown_sgx="-cxx-isystem/usr/include/c++/$(detect_cxx_include_path) -cxx-isystem/usr/include/x86_64-linux-gnu/c++/$(detect_cxx_include_path) $CFLAGS_x86_64_fortanix_unknown_sgx"

if [ ! -f config.toml ]; then
    rustup default nightly
    rustup update nightly
    rustup target add x86_64-fortanix-unknown-sgx

cargo install fortanix-sgx-tools
cargo install sgxs-tools

git submodule foreach git reset --hard
./configure --enable-lld --set profile=compiler

fi

./x dist --target=x86_64-fortanix-unknown-sgx,x86_64-unknown-linux-gnu --host=x86_64-unknown-linux-gnu
