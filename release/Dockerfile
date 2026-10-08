# The pinned image `make release` builds in. Everything that reaches the
# artifacts has a fixed version, so anyone can rebuild them and compare the
# sha256 sums.
FROM --platform=linux/amd64 debian:bookworm-20260518-slim

ENV DEBIAN_FRONTEND=noninteractive
ENV RUSTUP_HOME=/opt/rustup
ENV CARGO_HOME=/opt/cargo
ENV RUST_VERSION=1.91.1
ENV ZIG_VERSION=0.16.0
ENV ZIG_SHA256=70e49664a74374b48b51e6f3fdfbf437f6395d42509050588bd49abe52ba3d00

RUN apt-get -yq update && \
    apt-get -yqq install --no-install-recommends curl ca-certificates xz-utils \
    build-essential pkg-config clang && \
    rm -rf /var/lib/apt/lists/*

RUN curl --fail -sSf https://sh.rustup.rs | sh -s -- -y \
    --profile minimal \
    --default-toolchain ${RUST_VERSION} \
    --target wasm32-unknown-unknown \
    --target x86_64-unknown-linux-gnu \
    --target aarch64-unknown-linux-gnu \
    --no-modify-path

# zig links the Linux binaries for both architectures against an old glibc, so
# they run on any distribution from glibc 2.28 on, and cross-compiles the C code
# in ring and secp256k1-sys for arm64.
RUN curl --fail -sSfL -o /tmp/zig.tar.xz \
    https://ziglang.org/download/${ZIG_VERSION}/zig-x86_64-linux-${ZIG_VERSION}.tar.xz && \
    echo "${ZIG_SHA256}  /tmp/zig.tar.xz" | sha256sum -c - && \
    mkdir /opt/zig && tar -xJf /tmp/zig.tar.xz -C /opt/zig --strip-components=1 && \
    rm /tmp/zig.tar.xz

ENV PATH="/opt/cargo/bin:/opt/zig:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

RUN cargo install -j "$(nproc)" --locked --version 1.19.1 cargo-binstall && \
    cargo binstall -y --version 0.9.11 ic-wasm && \
    cargo binstall -y --version 0.1.6 candid-extractor && \
    cargo binstall -y --version 0.23.4 cargo-zigbuild

COPY . /src
WORKDIR /src

ENTRYPOINT ["bash", "release/entrypoint.sh"]
