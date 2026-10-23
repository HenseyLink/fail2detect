#!/usr/bin/env bash
# Запуск тестов fail2detect в изолированном Linux-контейнере.
# У контейнера своё сетевое пространство имён, поэтому nftables-правила
# тестов не трогают фаервол хоста.
#   tests/run.sh                — Debian 12
#   IMAGE=ubuntu:24.04 tests/run.sh
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${IMAGE:-debian:12}"

command -v docker >/dev/null || { echo "Нужен docker" >&2; exit 1; }
docker info >/dev/null 2>&1 || { echo "Docker-демон недоступен" >&2; exit 1; }

docker run --rm --cap-add NET_ADMIN -v "$ROOT:/src:ro" "$IMAGE" bash -c '
    set -e
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq >/dev/null
    apt-get install -y -qq nftables jq iproute2 gawk util-linux coreutils curl ca-certificates >/dev/null
    nft --version
    bash /src/tests/linux.sh
'

# конфиги Xray и nginx — настоящими образами (на хосте, нужен docker)
if [[ "${RUN_CONFIGS:-1}" == 1 ]]; then bash "$ROOT/tests/configs.sh"; fi
