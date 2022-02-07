#!/bin/bash -ex
repo_root=$(readlink -f $(dirname "${BASH_SOURCE[0]}"))
cd ${repo_root}
git submodule update --init --recursive
sudo rm -rf ./obj
./src/ci/docker/run.sh dist-x86_64-fortanixvme

