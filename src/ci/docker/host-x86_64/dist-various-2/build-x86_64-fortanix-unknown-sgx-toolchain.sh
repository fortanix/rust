#!/bin/bash

set -eu
source shared.sh

target="x86_64-fortanix-unknown-sgx"

install_prereq() {
    curl https://apt.llvm.org/llvm-snapshot.gpg.key|apt-key add -
    add-apt-repository -y 'deb https://apt.llvm.org/focal/ llvm-toolchain-focal-11 main'
    apt-get update
    apt-get install -y --no-install-recommends \
            build-essential \
            ca-certificates \
            cmake \
            git \
            clang-11
}

detect_cxx_include_path() {
    for path in $(clang++-11 -print-search-dirs|sed -n 's/^libraries:\s*=//p'|tr : ' '); do
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

hide_output install_prereq

# Note - this overwrites the environment variable set in the Dockerfile
export CXXFLAGS_x86_64_fortanix_unknown_sgx="-cxx-isystem/usr/include/c++/$(detect_cxx_include_path) -cxx-isystem/usr/include/x86_64-linux-gnu/c++/$(detect_cxx_include_path) $CFLAGS_x86_64_fortanix_unknown_sgx"
