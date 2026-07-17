FROM python:3.13-slim-bookworm@sha256:9d7f287598e1a5a978c015ee176d8216435aaf335ed69ac3c38dd1bbb10e8d64 AS build

ARG LIBWALLY_VERSION=1.5.4
ARG LIBWALLY_REVISION=c5591834b3ae4ee4c7db9e537a9c19104ab4bf0c

RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        autoconf \
        automake \
        build-essential \
        ca-certificates \
        git \
        libtool \
        pkg-config \
        swig \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY build-requirements.txt ./
RUN PYTHON_VERSION=3.13 python -m pip install \
        --disable-pip-version-check \
        --no-cache-dir \
        --no-deps \
        --require-hashes \
        --requirement build-requirements.txt
RUN git clone \
        --branch "release_${LIBWALLY_VERSION}" \
        --depth 1 \
        --recurse-submodules \
        --shallow-submodules \
        https://github.com/ElementsProject/libwally-core.git /source \
    && test "$(git -C /source rev-parse HEAD)" = "${LIBWALLY_REVISION}"

WORKDIR /source
RUN PYTHON_VERSION=3.13 python -m pip install \
        --disable-pip-version-check \
        --no-cache-dir \
        --no-deps \
        --no-build-isolation \
        --prefix=/install \
        .

WORKDIR /adapter
COPY adapter.py test_adapter.py ./
RUN PYTHONPATH=/install/lib/python3.13/site-packages \
    python -m unittest -v test_adapter.py

FROM python:3.13-slim-bookworm@sha256:9d7f287598e1a5a978c015ee176d8216435aaf335ed69ac3c38dd1bbb10e8d64

LABEL org.opencontainers.image.title="PSBT Interop Lab libwally adapter" \
      org.opencontainers.image.version="1.5.4" \
      org.opencontainers.image.revision="c5591834b3ae4ee4c7db9e537a9c19104ab4bf0c"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN useradd --create-home --uid 10001 adapter
COPY --from=build /install /usr/local
COPY --from=build /adapter/adapter.py /opt/psbt-lab/adapter.py

USER 10001:10001
STOPSIGNAL SIGTERM
ENTRYPOINT ["python", "/opt/psbt-lab/adapter.py"]
