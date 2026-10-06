# The pinned image `make release` builds in. Everything that reaches the
# artifacts has a fixed version, so anyone can rebuild them and compare the
# sha256 sums.
FROM --platform=linux/amd64 debian:bookworm-20260518-slim

ENV DEBIAN_FRONTEND=noninteractive
ENV RUSTUP_HOME=/opt/rustup
ENV CARGO_HOME=/opt/cargo
ENV RUST_VERSION=1.91.1

RUN apt-get -yq update && \
    apt-get -yqq install --no-install-recommends curl ca-certificates \
    build-essential pkg-config clang && \
    rm -rf /var/lib/apt/lists/*

RUN curl --fail -sSf https://sh.rustup.rs | sh -s -- -y \
    --profile minimal \
    --default-toolchain ${RUST_VERSION} \
    --target wasm32-unknown-unknown \
    --no-modify-path

ENV PATH="/opt/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

RUN cargo install -j "$(nproc)" --locked --version 1.19.1 cargo-binstall && \
    cargo binstall -y --version 0.9.11 ic-wasm && \
    cargo binstall -y --version 0.1.6 candid-extractor

COPY . /src
WORKDIR /src

ENTRYPOINT ["bash", "release/entrypoint.sh"]
