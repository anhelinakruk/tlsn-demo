FROM rust:1.95.0-alpine3.21 AS wasm-builder

RUN apk add --no-cache \
    build-base \
    clang \
    llvm-dev \
    lld \
    cmake \
    libressl-dev

RUN rustup toolchain install nightly-2026-04-01 \
      --component rust-src \
      --target wasm32-unknown-unknown \
  && cargo +nightly-2026-04-01 install wasm-bindgen-cli \
       --version 0.2.123 --locked

WORKDIR /app
COPY . .

ENV CC_wasm32_unknown_unknown=/usr/bin/clang \
    AR_wasm32_unknown_unknown=/usr/bin/llvm-ar

RUN RUSTUP_TOOLCHAIN=nightly-2026-04-01 \
    cargo build --release \
      --target wasm32-unknown-unknown \
      -p tlsn-prover \
  && wasm-bindgen \
       --target web \
       --out-name prover \
       --out-dir demo/assets/wasm \
       target/wasm32-unknown-unknown/release/tlsn_prover.wasm

FROM rust:1.95.0-alpine3.21 AS planner

RUN apk add --no-cache build-base \
  && cargo install cargo-chef --locked

WORKDIR /app
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM rust:1.95.0-alpine3.21 AS builder

RUN apk add --no-cache build-base cmake libressl-dev \
  && cargo install cargo-chef --locked

WORKDIR /app
COPY --from=planner /app/recipe.json recipe.json

RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    cargo chef cook --release -p demo --recipe-path recipe.json

COPY . .
COPY --from=wasm-builder /app/demo/assets/wasm demo/assets/wasm

RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    cargo build --release -p demo


FROM alpine:3.21 AS runtime

RUN apk add --no-cache su-exec \
  && adduser -D demo

COPY --from=builder /app/target/release/demo /usr/local/bin/demo
COPY --from=builder /app/demo/assets         /home/demo/assets
COPY --from=wasm-builder /app/demo/assets/wasm /home/demo/assets/wasm

WORKDIR /home/demo

EXPOSE 8444/udp
EXPOSE 8444/tcp

ENTRYPOINT ["su-exec", "demo", "/usr/local/bin/demo"]
