ARG PYTHON_BASE_IMAGE=python:3.14-slim-bookworm
FROM ${PYTHON_BASE_IMAGE}

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    HOME=/tmp

WORKDIR /opt/pika-runner
COPY requirements.txt /tmp/requirements.txt

RUN python -m pip install --upgrade pip \
    && python -m pip install -r /tmp/requirements.txt \
    && python -m pip install pytest==9.2.0 pytest-asyncio==1.5.0 cryptography==50.0.2 \
    && useradd --uid 65532 --create-home --shell /usr/sbin/nologin pika-runner

USER 65532:65532
WORKDIR /work
ENTRYPOINT []
CMD ["python", "--version"]
