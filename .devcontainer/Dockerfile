FROM mcr.microsoft.com/devcontainers/base:1-bookworm

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        clang \
        cmake \
        curl \
        git \
        jq \
        less \
        libpq-dev \
        libsqlite3-dev \
        libssl-dev \
        lld \
        openssh-client \
        openssl \
        pkg-config \
        postgresql-client \
        protobuf-compiler \
        sqlite3 \
        unzip \
        zip \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*
