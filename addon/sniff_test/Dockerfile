# Barkley app image. The build context is the *staged* add-on folder, which also
# carries the scanner's source in scanner/ (the Supervisor only sees this folder):
#   uv run python scripts/stage_addon.py && docker build dist/addon/sniff_test
#
# Debian, not Alpine: every tool here is installed from wheels only (nothing is compiled
# in the image), and Semgrep ships manylinux wheels, so it runs on Debian trixie's
# Python 3.13. (0.15) GuardDog was removed: on 600 real apps 22 of its 23 heuristic hits
# were wrong; Barkley's own package checks come later. (0.14.0) Barkley itself runs on the Python
# Home Assistant runs (BARKLEY_PYTHON, HA's .python-version), so its parse-only checks
# read every syntax HA's Python accepts (3.14's t-strings don't parse on 3.13). The
# scanner resolves *scanned* dependencies for HA's musl platforms with uv regardless of
# the image's own libc.
#
# Two stages (M8, image slimming): tools are installed and trimmed in `build`, and only
# the results are copied into a fresh base, so build-only packages (binutils) and
# anything deleted never ship. Measured on amd64 before trimming (with GuardDog, removed
# in 0.15): 695 MB unpacked, of which semgrep-core 255 MB.
# Do NOT strip semgrep-core: its sections are laid out unusually (".dynstr not in
# segment"), and every binutils mode, even --strip-debug, leaves it failing with
# "symbol lookup error: undefined symbol: , version" (tried 2026-11-10).
FROM ghcr.io/home-assistant/base-debian:trixie AS build

# TARGETARCH comes from BuildKit (amd64/arm64); the Supervisor passes BUILD_ARCH
# (amd64/aarch64). Either is enough.
ARG TARGETARCH
ARG BUILD_ARCH

ARG SEMGREP_VERSION=1.185.0
ARG OSV_SCANNER_VERSION=2.7.1
ARG UV_VERSION=0.13.7
# Barkley's own interpreter: CPython from python-build-standalone, installed by uv, which
# checks it against the SHA-256 it ships for that build. Keep it at HA's .python-version
# (tests/test_publish.py fails when it's older; data/ha_domains.txt records HA's).
ARG BARKLEY_PYTHON=3.14.10
# Bumping UV_VERSION or OSV_SCANNER_VERSION: update the sha256 and asset ids in the RUN below.
# osv-scanner 2.7.1 (2026-11-13): 2.7.0 was built with Go 1.27.0 and x/net 0.61, which
# carry five high CVEs with fixes (one in crypto/x509's chain checks, and osv-scanner's
# one job on the network is a TLS call to osv.dev). 2.7.1 is built with Go 1.27.3.

# The base image's shell is bash; a pipe's left side failing must fail the RUN.
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 python3-venv ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# uv and osv-scanner: release binaries, sha256-pinned. GitHub's release download URL
# can fail on its own (2026-11-09: 504 for the uv asset, every try, while the API's
# asset endpoint served the same bytes), so each download retries and then falls back
# to the API endpoint by asset id. The sha256 check decides either way.
RUN set -eu; \
    arch="${TARGETARCH:-${BUILD_ARCH:-}}"; \
    if [ "${arch}" = aarch64 ]; then arch=arm64; fi; \
    case "${arch}" in \
      amd64) a=x86_64; \
        uv_sha=287491da03f2a785c70fa75b13e1f849918c2f2b5415fe84876b8214eeb792f9; uv_id=704009859; \
        osv_sha=fb7dab19a8bd9bbe5c3189f09d4b7ee1820c9553a23bac202648a56efd2f6ee8; osv_id=726165286 ;; \
      arm64) a=aarch64; \
        uv_sha=2d3ec076a0c4c0e8250bb6418c44080828b544f1a3be0b6e46adf9fb6923de45; uv_id=704009487; \
        osv_sha=983d22fbad9724514e3fcc6acc83b5fa64c5ffa6b0d9f510028f22c1b223ff81; osv_id=726165576 ;; \
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

# Semgrep in its own venv, wheels only.
ENV UV_TOOL_DIR=/opt/tools \
    UV_TOOL_BIN_DIR=/usr/local/bin \
    UV_PYTHON_DOWNLOADS=never \
    UV_NO_CACHE=1 \
    SEMGREP_SEND_METRICS=off \
    SEMGREP_ENABLE_VERSION_CHECK=0
RUN uv tool install --python /usr/bin/python3 --no-build "semgrep==${SEMGREP_VERSION}" \
    && rm -f /usr/local/bin/uvx
# Barkley's Python (see BARKLEY_PYTHON), with the parts nothing here runs left out.
ENV UV_PYTHON_INSTALL_DIR=/opt/python
RUN set -eu; \
    UV_PYTHON_DOWNLOADS=manual uv python install --no-bin "cpython-${BARKLEY_PYTHON}"; \
    home="$(echo /opt/python/cpython-${BARKLEY_PYTHON}-linux-*)"; \
    py="$(echo "${home}"/lib/python3*)"; \
    rm -rf "${py}"/test "${py}"/idlelib "${py}"/tkinter "${py}"/turtledemo "${py}"/ensurepip \
           "${py}"/lib-dynload/_tkinter*.so "${py}"/site-packages/pip* \
           "${home}"/lib/tcl* "${home}"/lib/tk* "${home}"/lib/libtcl* "${home}"/lib/libtk* \
           "${home}"/lib/itcl* "${home}"/lib/thread* "${home}"/share "${home}"/include \
           /opt/python/.temp /opt/python/.lock; \
    ln -s /opt/python/cpython-${BARKLEY_PYTHON}-linux-*/bin/python3 /opt/python/barkley-python
# The scanner, with its locked runtime dependencies.
COPY scanner /src
RUN uv venv --python /opt/python/barkley-python /opt/sniff-test \
    && uv export --frozen --no-dev --no-emit-project --project /src -o /tmp/req.txt \
    && uv pip install --python /opt/sniff-test --no-build --require-hashes -r /tmp/req.txt \
    && uv pip install --python /opt/sniff-test --no-deps /src \
    && ln -s /opt/sniff-test/bin/sniff-test /usr/local/bin/sniff-test \
    && rm -rf /src /tmp/req.txt

# --- the shipped image: base + Python + the trimmed tools ---------------------------
FROM ghcr.io/home-assistant/base-debian:trixie
ARG BUILD_ARCH
# `upgrade`: the base image is rebuilt less often than Debian ships security fixes
# (2026-11-13: zlib1g had two high CVEs fixed in trixie-security that the base lacked).
# tempio is the base image's template tool (a Go binary, 6 MB). Nothing here calls it
# (no script in the base's s6 or bashio files does either), and the copy in the base
# is built with Go 1.26.5 and x/crypto 0.31: 24 high CVEs for a file nobody runs.
RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends python3 ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && rm -f /usr/bin/tempio
ENV UV_PYTHON_DOWNLOADS=never \
    UV_NO_CACHE=1 \
    SEMGREP_SEND_METRICS=off \
    SEMGREP_ENABLE_VERSION_CHECK=0
COPY --from=build /opt/tools /opt/tools
COPY --from=build /opt/python /opt/python
COPY --from=build /opt/sniff-test /opt/sniff-test
COPY --from=build /usr/local/bin/ /usr/local/bin/
# Precompile the venvs: 3,200 modules had no .pyc, so every run tried to write them next
# to the code (strace, 2026-11-11). Under the AppArmor profile /opt is read-only, and
# those writes would be denied (silently to Python, loudly in the audit log).
# Each venv with its own interpreter (the .pyc name carries the Python version).
RUN python3 -m compileall -q -j 0 /opt/tools \
    && /opt/python/barkley-python -m compileall -q -j 0 /opt/python /opt/sniff-test

COPY rootfs /

# Declared here, where only the label uses it: every RUN after an ARG takes it as an input,
# so a new version number made Docker rebuild every tool layer on each Update.
ARG BUILD_VERSION=0.3.0
LABEL \
    io.hass.version="${BUILD_VERSION}" \
    io.hass.arch="${BUILD_ARCH}" \
    io.hass.type="app" \
    org.opencontainers.image.title="Barkley" \
    org.opencontainers.image.description="Static security scanner for HA Marketplace integrations and cards" \
    org.opencontainers.image.licenses="MIT"
