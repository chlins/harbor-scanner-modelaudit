# syntax=docker/dockerfile:1
FROM python:3.12-slim AS build
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv
WORKDIR /src
COPY pyproject.toml README.md ./
COPY scanner ./scanner
# "full" installs modelaudit extras (h5py/tensorflow-free parsers for more formats); default keeps the image small.
ARG MODELAUDIT_EXTRAS=""
RUN uv venv /opt/venv && \
    VIRTUAL_ENV=/opt/venv uv pip install --no-cache . ${MODELAUDIT_EXTRAS:+"modelaudit[${MODELAUDIT_EXTRAS}]"}

FROM python:3.12-slim
LABEL org.opencontainers.image.source="https://github.com/chlins/harbor-scanner-modelaudit" \
      org.opencontainers.image.licenses="Apache-2.0"
RUN useradd --uid 10000 --create-home scanner && mkdir -p /tmp/scanner && chown scanner /tmp/scanner
COPY --from=build /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH" \
    SCANNER_API_SERVER_ADDR=0.0.0.0:8080 \
    SCANNER_SCRATCH_DIR=/tmp/scanner
USER scanner
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8080/probe/healthy')"
ENTRYPOINT ["harbor-scanner-modelaudit"]
