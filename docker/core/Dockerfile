FROM debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818 AS download

ARG TARGETARCH
ARG BITCOIN_VERSION=31.1

RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

RUN case "${TARGETARCH}" in \
      amd64) archive_arch="x86_64-linux-gnu"; checksum="b80d9c3e04da78fb6f0569685673418cf686fadba9042d926d13fb87ff503f9e" ;; \
      arm64) archive_arch="aarch64-linux-gnu"; checksum="dcf1873f2208ba4f962f3398d47e154c39c0084be8f4553e05c940d0ace3d004" ;; \
      *) echo "Unsupported Docker architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac \
    && archive="bitcoin-${BITCOIN_VERSION}-${archive_arch}.tar.gz" \
    && curl --fail --location --proto '=https' --tlsv1.2 \
      "https://bitcoincore.org/bin/bitcoin-core-${BITCOIN_VERSION}/${archive}" \
      --output "/tmp/${archive}" \
    && echo "${checksum}  /tmp/${archive}" | sha256sum --check --strict \
    && tar --extract --gzip --file "/tmp/${archive}" --directory /opt \
    && mv "/opt/bitcoin-${BITCOIN_VERSION}" /opt/bitcoin

FROM debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818

RUN apt-get update \
    && apt-get install --yes --no-install-recommends libatomic1 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 bitcoin \
    && install --directory --owner bitcoin --group bitcoin /home/bitcoin/.bitcoin

COPY --from=download /opt/bitcoin/bin/bitcoind /usr/local/bin/bitcoind
COPY --from=download /opt/bitcoin/bin/bitcoin-cli /usr/local/bin/bitcoin-cli

USER bitcoin
EXPOSE 18443
VOLUME ["/home/bitcoin/.bitcoin"]

ENTRYPOINT ["bitcoind"]
CMD ["-regtest=1", "-server=1", "-printtoconsole=1", "-datadir=/home/bitcoin/.bitcoin", "-rpcbind=0.0.0.0", "-rpcallowip=0.0.0.0/0", "-rpcport=18443", "-rpcuser=psbtlab", "-rpcpassword=psbtlab-regtest-only", "-listen=0", "-dnsseed=0", "-discover=0", "-fixedseeds=0", "-networkactive=0", "-txindex=1", "-fallbackfee=0.00001000"]
