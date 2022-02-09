#!/bin/bash -ex
repo_root=$(readlink -f $(dirname "${BASH_SOURCE[0]}"))
cd ${repo_root}

sudo rm -rf ../musl-cross-make
sudo rm -rf ../build

docker build . -t fortanixvme
docker run --volume ${repo_root}/../../rust:/workdir/rust -ti fortanixvme
