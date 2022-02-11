FROM ubuntu:20.04
# make the tzdata prompt non-interactive.
ENV DEBIAN_FRONTEND=noninteractive

WORKDIR /workdir/

RUN apt-get update && apt-get upgrade -y

# Bugfix: Avoid installing ca-certificates as it causes Docker to hang
# https://bugzilla.redhat.com/show_bug.cgi?id=2022201
RUN apt-get update && apt-get install -y -V libssl-dev

RUN apt-get update && apt-get install -y --no-install-recommends \
  g++ \
  make \
  ninja-build \
  file \
  wget \
  curl \
  python3 \
  git \
  cmake \
  xz-utils \
  sudo \
  gdb \
  patch \
  libssl-dev \
  pkg-config \
  strace

COPY install-x86_64-unknown-linux-fortanixvme.sh /workdir
