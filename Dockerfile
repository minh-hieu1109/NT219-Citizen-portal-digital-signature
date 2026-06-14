FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

ARG OPENSSL_VERSION=3.5.0
ENV OPENSSL_PREFIX=/opt/openssl-3.5
ENV PATH="${OPENSSL_PREFIX}/bin:${PATH}"
ENV LD_LIBRARY_PATH="${OPENSSL_PREFIX}/lib64:${OPENSSL_PREFIX}/lib:${LD_LIBRARY_PATH}"

WORKDIR /app

RUN apt-get update && apt-get install -y \
    build-essential \
    libpq-dev \
    softhsm2 \
    opensc \
    ca-certificates \
    wget \
    perl \
    make \
    && rm -rf /var/lib/apt/lists/*

RUN wget https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz -O /tmp/openssl.tar.gz \
    && tar -xzf /tmp/openssl.tar.gz -C /tmp \
    && cd /tmp/openssl-${OPENSSL_VERSION} \
    && ./Configure linux-x86_64 \
        --prefix=${OPENSSL_PREFIX} \
        --openssldir=${OPENSSL_PREFIX}/ssl \
        shared \
    && make -j"$(nproc)" \
    && make install_sw \
    && echo "${OPENSSL_PREFIX}/lib64" > /etc/ld.so.conf.d/openssl-3.5.conf \
    && echo "${OPENSSL_PREFIX}/lib" >> /etc/ld.so.conf.d/openssl-3.5.conf \
    && ldconfig \
    && ln -sf ${OPENSSL_PREFIX}/bin/openssl /usr/local/bin/openssl \
    && rm -rf /tmp/openssl*

RUN mkdir -p /opt/openssl-3.5/ssl \
    && printf '%s\n' \
    'openssl_conf = openssl_init' \
    '' \
    '[openssl_init]' \
    'providers = provider_sect' \
    '' \
    '[provider_sect]' \
    'default = default_sect' \
    '' \
    '[default_sect]' \
    'activate = 1' \
    '' \
    '[req]' \
    'distinguished_name = req_distinguished_name' \
    'prompt = no' \
    '' \
    '[req_distinguished_name]' \
    'CN = default' \
    > /opt/openssl-3.5/ssl/openssl.cnf
    
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

COPY . /app/

EXPOSE 8000