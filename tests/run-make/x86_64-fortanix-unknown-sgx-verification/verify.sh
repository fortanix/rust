#!/bin/bash -ex
set -exuo pipefail

script_dir=$(readlink -f $(dirname "${BASH_SOURCE[0]}"))
CRATE=test_enclave
WORK_DIR=${WORK_DIR:=$(mktemp -d /tmp/verify-enclave.XXX)}
RUSTC=${RUSTC:="rustc"}
TEST_DIR=${TEST_DIR:="${script_dir}"}
TARGET=${TARGET:="x86_64-fortanix-unknown-sgx"}

# pip3 install angr

function build {
    mkdir -p $WORK_DIR
    pushd $WORK_DIR
        rm -rf $CRATE
        cp -a $TEST_DIR/test_enclave .
        pushd $CRATE
            echo ${WORK_DIR}
            # HACK(eddyb) sets `RUSTC_BOOTSTRAP=1` so Cargo can accept nightly features.
            # These come from the top-level Rust workspace, that this crate is not a
            # member of, but Cargo tries to load the workspace `Cargo.toml` anyway.
            env RUSTC_BOOTSTRAP=1
                cargo +stage1 build --target ${TARGET} --release
	    enclave=$(pwd)/target/x86_64-fortanix-unknown-sgx/release/test_enclave
        popd
    popd
}

build

#python3 verification/main.py ${enclave} "image_base"
#python3 verification/main.py ${enclave} "is_enclave_range"
#python3 verification/main.py ${enclave} "copy_to_userspace"
#python3 verification/main.py ${enclave} "insecure_time"
python3 verification/main.py ${enclave} "raw_read"
python3 verification/main.py ${enclave} "raw_read_alloc"
python3 verification/main.py ${enclave} "raw_accept_stream"
python3 verification/main.py ${enclave} "raw_alloc"
python3 verification/main.py ${enclave} "raw_async_queues"
python3 verification/main.py ${enclave} "raw_bind_stream"
python3 verification/main.py ${enclave} "raw_close"
python3 verification/main.py ${enclave} "raw_connect_stream"
python3 verification/main.py ${enclave} "raw_exit"
python3 verification/main.py ${enclave} "raw_flush"
python3 verification/main.py ${enclave} "raw_free"

echo "Verification completed successfully!"
