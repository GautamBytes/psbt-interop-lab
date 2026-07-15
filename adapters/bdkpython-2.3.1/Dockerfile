FROM python:3.13-slim-bookworm@sha256:9d7f287598e1a5a978c015ee176d8216435aaf335ed69ac3c38dd1bbb10e8d64 AS build

WORKDIR /adapter
COPY requirements.txt ./
RUN python -m pip install \
      --disable-pip-version-check \
      --no-cache-dir \
      --no-deps \
      --require-hashes \
      --prefix=/install \
      --requirement requirements.txt

COPY adapter.py test_adapter.py ./
RUN PYTHONPATH=/install/lib/python3.13/site-packages \
    python -m unittest -v test_adapter.py

FROM python:3.13-slim-bookworm@sha256:9d7f287598e1a5a978c015ee176d8216435aaf335ed69ac3c38dd1bbb10e8d64

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN useradd --create-home --uid 10001 adapter
COPY --from=build /install /usr/local
COPY --from=build /adapter/adapter.py /opt/psbt-lab/adapter.py

USER adapter
ENTRYPOINT ["python", "/opt/psbt-lab/adapter.py"]
