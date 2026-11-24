# Build once on the PC. Runtime execution uses the immutable local image ID.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    HOME=/tmp

WORKDIR /opt/pika
COPY requirements.txt /opt/pika/requirements.txt

RUN python -m pip install --no-cache-dir --upgrade pip \
    && python -m pip install --no-cache-dir -r /opt/pika/requirements.txt \
       pytest==9.2.0 pytest-asyncio==1.5.0 \
    && useradd --uid 65532 --system --no-create-home --shell /usr/sbin/nologin pika

COPY sandbox/pc/worker.py /opt/pika/worker.py
RUN chmod 0555 /opt/pika/worker.py

USER 65532:65532
WORKDIR /work
ENTRYPOINT ["python", "-I", "/opt/pika/worker.py"]
