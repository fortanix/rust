FROM ubuntu:20.04
# make the tzdata prompt non-interactive.
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
  g++ \
  make \
  ninja-build \
  file \
  wget \
  curl \
  ca-certificates \
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

WORKDIR /workdir/
COPY install_rust.sh /workdir
#RUN bash ./install_rust.sh
ENTRYPOINT bash
