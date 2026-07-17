FROM rust:1.97.0-bookworm@sha256:8fa55b2f3ddf97471ab6a767bfa3f37e6bad0986ba823e75fea57e2a2a5c3073 AS build

WORKDIR /source
RUN rustup component add rustfmt clippy
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN mkdir tests
COPY tests/bip370_parse_invalid.rs tests/bip370_parse_invalid.rs
COPY tests/bip370_parse_valid.rs tests/bip370_parse_valid.rs
COPY tests/process.rs tests/process.rs
COPY tests/protocol.rs tests/protocol.rs
COPY tests/util.rs tests/util.rs
COPY tests/workflow.rs tests/workflow.rs
RUN cargo fmt --check \
    && cargo clippy --locked --all-targets -- -D warnings \
    && cargo test --locked \
    && cargo build --release --locked

FROM debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818

RUN groupadd --gid 10001 adapter \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin adapter
COPY --from=build --chown=10001:10001 \
    /source/target/release/psbt-lab-rust-psbt-v2-adapter \
    /usr/local/bin/psbt-lab-rust-psbt-v2-adapter

USER 10001:10001
ENV RUST_BACKTRACE=0
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/psbt-lab-rust-psbt-v2-adapter"]
