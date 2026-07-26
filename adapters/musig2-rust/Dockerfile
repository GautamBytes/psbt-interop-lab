FROM rust:1.97.0-bookworm@sha256:8fa55b2f3ddf97471ab6a767bfa3f37e6bad0986ba823e75fea57e2a2a5c3073 AS build

WORKDIR /source
RUN rustup component add rustfmt clippy
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY tests ./tests
RUN cargo fmt --check \
    && cargo clippy --locked --all-targets -- -D warnings \
    && cargo test --locked \
    && cargo build --release --locked

FROM debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818

RUN useradd --create-home --uid 10001 adapter
COPY --from=build /source/target/release/psbt-lab-musig2-adapter /usr/local/bin/psbt-lab-musig2-adapter

USER adapter
ENTRYPOINT ["/usr/local/bin/psbt-lab-musig2-adapter"]
