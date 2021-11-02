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

WORKDIR /build/

# Build cmake before musl toolchain, as we replace the compiler during that step.
COPY scripts/cmake.sh /scripts/
RUN /scripts/cmake.sh

COPY scripts/musl-toolchain.sh /build/
# We need to mitigate rust-lang/rust#34978 when compiling musl itself as well
RUN CFLAGS="-Wa,-mrelax-relocations=no -Wa,--compress-debug-sections=none -Wl,--compress-debug-sections=none" \
    CXXFLAGS="-Wa,-mrelax-relocations=no -Wa,--compress-debug-sections=none -Wl,--compress-debug-sections=none" \
    REPLACE_CC=1 bash musl-toolchain.sh x86_64 && rm -rf build

#RUN cp -r /usr/local/x86_64-linux-musl/ /usr/local/x86_64-linux-fortanixvme/

COPY scripts/sccache.sh /scripts/
RUN sh /scripts/sccache.sh

ENV HOSTS=x86_64-unknown-linux-musl

ENV RUST_CONFIGURE_ARGS \
      --musl-root-x86_64=/usr/local/x86_64-linux-musl \
      --enable-extended \
      --enable-sanitizers \
      --enable-profiler \
      --enable-lld \
      --target=x86_64-unknown-linux-fortanixvme \
      --set target.x86_64-unknown-linux-fortanixvme.crt-static=false \
      --set target.x86_64-unknown-linux-musl.crt-static=false \
      --set=llvm.download-ci-llvm=if-available \
      --set build.build-stage=1 \
      --build $HOSTS
      #--set build.verbose=3\

# Newer binutils broke things on some vms/distros (i.e., linking against
# unknown relocs disabled by the following flag), so we need to go out of our
# way to produce "super compatible" binaries.
#
# See: https://github.com/rust-lang/rust/issues/34978
# And: https://github.com/rust-lang/rust/issues/59411
ENV CFLAGS_x86_64_unknown_linux_fortanixvme="-Wa,-mrelax-relocations=no -Wa,--compress-debug-sections=none \
    -Wl,--compress-debug-sections=none"

# To run native tests replace `dist` below with `test`
#ENV SCRIPT python3 ../x.py build --build $HOSTS
ENV SCRIPT python3 ../x.py build --target x86_64-unknown-linux-fortanixvme 

RUN sh curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh 
#RUN source /cargo/env
#RUN sh rustup toolchain link vme build/x86_64-unknown-linux-musl/stage1

