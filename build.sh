#!/bin/bash -ex
repo_root=$(readlink -f $(dirname "${BASH_SOURCE[0]}"))
cd ${repo_root}
git submodule update --init --recursive
sudo rm -rf ./obj

# If this fails with:
# ```
# error: couldn't read /cargo/registry/src/github.com-1ecc6299db9ec823/xattr-0.2.2/src/lib.rs: Permission denied (os error 13)
# ```
# Continue with running
# ```
# ./src/ci/docker/run.sh dist-x86_64-fortanixvme --dev
# python3 ../x.py install -i --stage 1 --host ../x86_64-unknown-linux-fortanixvme.json --target x86_64-unknown-linux-fortanixvme src library/std --verbose
# ```
./src/ci/docker/run.sh dist-x86_64-fortanixvme

