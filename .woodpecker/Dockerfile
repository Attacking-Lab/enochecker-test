# Woodpecker CI runner image for .woodpecker/test.yml. Bundles git,
# make and git-pass-helper (needed to authenticate uv's fetch of the
# private enochecker-core/enochecker3 git dependencies via
# git.atklab.cloud) on top of a plain Python image, so a run pays for
# this setup once, at image build time, instead of on every push.
# Built and pushed automatically by .woodpecker/ci-image.yml whenever
# this file changes. Modelled on atklab/enochecker-cli's
# .woodpecker/Dockerfile.
FROM python:3.14-slim-bookworm

ARG GIT_PASS_HELPER_VERSION=0.2.1

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV UV_LINK_MODE=copy

RUN apt-get update \
    && apt-get install --no-install-recommends -y \
        ca-certificates \
        curl \
        git \
        make \
    && rm -rf /var/lib/apt/lists/*

COPY --from=ghcr.io/astral-sh/uv:0.8.5 /uv /uvx /usr/local/bin/

RUN pip install --no-cache-dir "git-pass-helper==${GIT_PASS_HELPER_VERSION}"

WORKDIR /woodpecker/src
