#!/bin/bash -ex
repo_root=$(readlink -f $(dirname "${BASH_SOURCE[0]}")/..)
cd ${repo_root}

docker build Toolchain/ -t fortanixvme #--no-cache
docker run --volume ${repo_root}:/workdir/rust -ti fortanixvme ./install-x86_64-unknown-linux-fortanixvme.sh

echo "Toolchain ready at ${repo_root}/build/x86_64-unknown-linux-gnu/stage1"
