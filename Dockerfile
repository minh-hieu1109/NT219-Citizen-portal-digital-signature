FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

RUN rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/* && \
    apt-get clean && \
    apt-get update -o Acquire::Retries=5 && \
    apt-get install -y --no-install-recommends \
        build-essential \
        libpq-dev \
        softhsm2 \
        opensc \
        openssl \
        libengine-pkcs11-openssl \
        p11-kit \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*

COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

COPY . /app/

EXPOSE 8000