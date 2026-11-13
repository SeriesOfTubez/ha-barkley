# Barkley app image. The build context is the *staged* add-on folder, which also
# carries the scanner's source in scanner/ (the Supervisor only sees this folder):
#   uv run python scripts/stage_addon.py && docker build dist/addon/sniff_test
#
# Debian, not Alpine: GuardDog 3.2 needs nono-py (its sandbox), which ships only
# manylinux wheels, and every tool here is installed from wheels only (nothing is
# compiled in the image). yara-python 4.5.4 has wheels up to cp313, so the tools run
# on Debian trixie's Python 3.13. The scanner resolves *scanned* dependencies for
# HA's musl platforms with uv regardless of the image's own libc.
#
# Two stages (M8, image slimming): tools are installed and trimmed in `build`, and only
# the results are copied into a fresh base, so build-only packages (binutils) and
# anything deleted never ship. Measured on amd64 before trimming: 695 MB unpacked, of
# which semgrep-core 255 MB and GuardDog 120 MB (boto3/botocore 33 MB, used only by its
# S3 upload helper, imported lazily there).
# Do NOT strip semgrep-core: its sections are laid out unusually (".dynstr not in
# segment"), and every binutils mode, even --strip-debug, leaves it failing with
# "symbol lookup error: undefined symbol: , version" (tried 2026-11-10).
FROM ghcr.io/home-assistant/base-debian:trixie AS build

# TARGETARCH comes from BuildKit (amd64/arm64); the Supervisor passes BUILD_ARCH
# (amd64/aarch64). Either is enough.
ARG TARGETARCH
ARG BUILD_VERSION=0.3.0
ARG BUILD_ARCH

ARG SEMGREP_VERSION=1.185.0
ARG GUARDDOG_VERSION=3.2.0
ARG OSV_SCANNER_VERSION=2.7.0
ARG UV_VERSION=0.13.7
# Bumping UV_VERSION or OSV_SCANNER_VERSION: update the sha256 and asset ids in the RUN below.

RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 python3-venv ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# uv and osv-scanner: release binaries, sha256-pinned. GitHub's release download URL
# can fail on its own (2026-11-09: 504 for the uv asset, every try, while the API's
# asset endpoint served the same bytes), so each download retries and then falls back
# to the API endpoint by asset id. The sha256 check decides either way.
RUN set -eu; \
    arch="${TARGETARCH:-$(echo "${BUILD_ARCH:-}" | sed 's/^aarch64$/arm64/')}"; \
    case "${arch}" in \
      amd64) a=x86_64; \
        uv_sha=287491da03f2a785c70fa75b13e1f849918c2f2b5415fe84876b8214eeb792f9; uv_id=704009859; \
        osv_sha=160c6253e2922e9e0a6a9771c5c4c40a4b3c6090b34a3cdd5e80c96cc2e4218b; osv_id=632251666 ;; \
      arm64) a=aarch64; \
        uv_sha=2d3ec076a0c4c0e8250bb6418c44080828b544f1a3be0b6e46adf9fb6923de45; uv_id=704009487; \
        osv_sha=4061ef4c021ed3c47f203b818f337e351336cc5cd67c0274fc36bd1dfc728dd7; osv_id=632251568 ;; \
      *) echo "unsupported architecture '${arch}' (TARGETARCH/BUILD_ARCH)"; exit 1 ;; \
    esac; \
    get() { \
      out="$1" url="$2" api="$3" sha="$4"; \
      curl -fsSL --retry 3 --retry-all-errors --retry-delay 3 -o "${out}" "${url}" \
        || { echo "download failed, trying the GitHub API asset endpoint"; \
             curl -fsSL --retry 3 --retry-all-errors --retry-delay 3 \
               -H "Accept: application/octet-stream" -o "${out}" "${api}"; }; \
      echo "${sha}  ${out}" | sha256sum -c -; \
    }; \
    get /tmp/uv.tgz \
      "https://github.com/astral-sh/uv/releases/download/${UV_VERSION}/uv-${a}-unknown-linux-musl.tar.gz" \
      "https://api.github.com/repos/astral-sh/uv/releases/assets/${uv_id}" "${uv_sha}"; \
    tar -xzf /tmp/uv.tgz -C /usr/local/bin --strip-components=1; \
    rm /tmp/uv.tgz; \
    get /usr/local/bin/osv-scanner \
      "https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}/osv-scanner_linux_${arch}" \
      "https://api.github.com/repos/google/osv-scanner/releases/assets/${osv_id}" "${osv_sha}"; \
    chmod +x /usr/local/bin/osv-scanner

# Semgrep and GuardDog, each in its own venv, wheels only.
ENV UV_TOOL_DIR=/opt/tools \
    UV_TOOL_BIN_DIR=/usr/local/bin \
    UV_PYTHON_DOWNLOADS=never \
    UV_NO_CACHE=1 \
    SEMGREP_SEND_METRICS=off \
    SEMGREP_ENABLE_VERSION_CHECK=0
RUN uv tool install --python /usr/bin/python3 --no-build "semgrep==${SEMGREP_VERSION}" \
    && uv tool install --python /usr/bin/python3 --no-build "guarddog==${GUARDDOG_VERSION}"

# Trim what never runs. GuardDog: boto3 and friends serve only guarddog/utils/s3.py,
# which imports them lazily for S3 uploads; local scans never load them (Diagnostics
# runs a GuardDog scan in the image).
RUN set -eu; \
    gd="$(echo /opt/tools/guarddog/lib/python3*/site-packages)"; \
    rm -rf "${gd}"/boto3 "${gd}"/boto3-* "${gd}"/botocore "${gd}"/botocore-* \
           "${gd}"/s3transfer "${gd}"/s3transfer-* "${gd}"/jmespath "${gd}"/jmespath-*; \
    rm -f /usr/local/bin/uvx
# The scanner, with its locked runtime dependencies.
COPY scanner /src
RUN uv venv --python /usr/bin/python3 /opt/sniff-test \
    && uv export --frozen --no-dev --no-emit-project --project /src -o /tmp/req.txt \
    && uv pip install --python /opt/sniff-test --no-build --require-hashes -r /tmp/req.txt \
    && uv pip install --python /opt/sniff-test --no-deps /src \
    && ln -s /opt/sniff-test/bin/sniff-test /usr/local/bin/sniff-test \
    && rm -rf /src /tmp/req.txt

# --- the shipped image: base + Python + the trimmed tools ---------------------------
FROM ghcr.io/home-assistant/base-debian:trixie
ARG BUILD_VERSION=0.3.0
ARG BUILD_ARCH
RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 ca-certificates \
    && rm -rf /var/lib/apt/lists/*
ENV UV_PYTHON_DOWNLOADS=never \
    UV_NO_CACHE=1 \
    SEMGREP_SEND_METRICS=off \
    SEMGREP_ENABLE_VERSION_CHECK=0
COPY --from=build /opt/tools /opt/tools
COPY --from=build /opt/sniff-test /opt/sniff-test
COPY --from=build /usr/local/bin/ /usr/local/bin/
# Precompile the venvs: 3,200 modules had no .pyc, so every run tried to write them next
# to the code (strace, 2026-11-11). Under the AppArmor profile /opt is read-only, and
# those writes would be denied (silently to Python, loudly in the audit log).
RUN python3 -m compileall -q -j 0 /opt/tools /opt/sniff-test

COPY rootfs /

LABEL \
    io.hass.version="${BUILD_VERSION}" \
    io.hass.arch="${BUILD_ARCH}" \
    io.hass.type="app" \
    org.opencontainers.image.title="Barkley" \
    org.opencontainers.image.description="Static security scanner for HA Marketplace integrations and cards" \
    org.opencontainers.image.licenses="MIT"
