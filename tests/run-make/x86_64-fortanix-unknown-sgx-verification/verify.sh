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

objdump -D ${enclave} > /tmp/dump
rm *.log || true

# Functional correctness special functions
python3 verification/verification_entry_code.py ${enclave}
exit 0
python3 verification/verification_image_base.py ${enclave}
python3 verification/verification_is_enclave_range.py ${enclave}
python3 verification/verification_copy_from_userspace.py ${enclave}
python3 verification/verification_copy_to_userspace.py ${enclave}

# Verification usercalls
python3 verification/verification_usercall.py ${enclave} "insecure_time"
python3 verification/verification_usercall.py ${enclave} "read_alloc"
python3 verification/verification_usercall.py ${enclave} "insecure_time"
python3 verification/verification_usercall.py ${enclave} "raw_read"
python3 verification/verification_usercall.py ${enclave} "raw_read_alloc"
python3 verification/verification_usercall.py ${enclave} "raw_accept_stream"
python3 verification/verification_usercall.py ${enclave} "raw_alloc"
python3 verification/verification_usercall.py ${enclave} "raw_async_queues"
python3 verification/verification_usercall.py ${enclave} "raw_bind_stream"
python3 verification/verification_usercall.py ${enclave} "raw_close"
python3 verification/verification_usercall.py ${enclave} "raw_connect_stream"
python3 verification/verification_usercall.py ${enclave} "raw_flush"
python3 verification/verification_usercall.py ${enclave} "raw_free"
python3 verification/verification_usercall.py ${enclave} "raw_launch_thread"
python3 verification/verification_usercall.py ${enclave} "raw_send"
python3 verification/verification_usercall.py ${enclave} "raw_wait"
python3 verification/verification_usercall.py ${enclave} "raw_write"
python3 verification/verification_usercall.py ${enclave} "flush"
python3 verification/verification_usercall.py ${enclave} "close"
python3 verification/verification_usercall.py ${enclave} "bind_stream"
python3 verification/verification_usercall.py ${enclave} "accept_stream"
python3 verification/verification_usercall.py ${enclave} "connect_stream"
python3 verification/verification_usercall.py ${enclave} "launch_thread"
python3 verification/verification_usercall.py ${enclave} "exit"
python3 verification/verification_usercall.py ${enclave} "send"
python3 verification/verification_usercall.py ${enclave} "wait"
python3 verification/verification_usercall.py ${enclave} "alloc"

echo "Verification completed successfully!"
