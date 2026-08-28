# Woodpecker CI runner image for .woodpecker/test.yml. Bundles git,
# just and git-pass-helper (needed to authenticate uv's fetch of the
# private enochecker-core/enochecker3 git dependencies via
# git.atklab.cloud) on top of a plain Python image, so a run pays for
# this setup once, at image build time, instead of on every push.
# Built and pushed automatically by .woodpecker/ci-image.yml whenever
# this file changes. Modelled on atklab/enochecker-cli's
# .woodpecker/Dockerfile.
FROM python:3.14-slim-bookworm

ARG JUST_VERSION=1.58.0
ARG GIT_PASS_HELPER_VERSION=0.2.1

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV UV_LINK_MODE=copy

RUN apt-get update \
    && apt-get install --no-install-recommends -y \
        ca-certificates \
        curl \
        git \
    && rm -rf /var/lib/apt/lists/*

COPY --from=ghcr.io/astral-sh/uv:0.8.5 /uv /uvx /usr/local/bin/

RUN curl -fsSL \
        "https://github.com/casey/just/releases/download/${JUST_VERSION}/just-${JUST_VERSION}-x86_64-unknown-linux-musl.tar.gz" \
        -o /tmp/just.tar.gz \
    && tar -xzf /tmp/just.tar.gz -C /usr/local/bin just \
    && rm /tmp/just.tar.gz

RUN pip install --no-cache-dir "git-pass-helper==${GIT_PASS_HELPER_VERSION}"

WORKDIR /woodpecker/src
