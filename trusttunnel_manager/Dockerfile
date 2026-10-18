# trusttunnel_endpoint is the pinned upstream release binary (Apache-2.0), verified by sha256.
FROM python:3.13.5-slim@sha256:4c2cf9917bd1cbacc5e9b07320025bdb7cdf2df7b0ceaccb55e9dd7e30987419 AS endpoint
ARG TARGETARCH
ARG TT_VERSION=v1.1.0
ARG TT_SHA256_X86_64=91c2ea3db7416a01b5258a4c047ec22890490bc55e1b194206031aa75144f0e7
ARG TT_SHA256_AARCH64=c2aee17a1ced349283cba4775202e2baba053b8ea835d4cc23dc67d16c6b9686
RUN set -eu; \
    case "${TARGETARCH:-amd64}" in \
      amd64) arch=x86_64; sha="${TT_SHA256_X86_64}" ;; \
      arm64) arch=aarch64; sha="${TT_SHA256_AARCH64}" ;; \
      *) echo "unsupported architecture ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    asset="trusttunnel-${TT_VERSION}-linux-${arch}"; \
    python -c "import sys, urllib.request; urllib.request.urlretrieve(sys.argv[1], '/tmp/tt.tar.gz')" \
      "https://github.com/TrustTunnel/TrustTunnel/releases/download/${TT_VERSION}/${asset}.tar.gz"; \
    echo "${sha}  /tmp/tt.tar.gz" | sha256sum --check --strict -; \
    mkdir /out; \
    tar -xzf /tmp/tt.tar.gz -C /out --strip-components=1 "${asset}/trusttunnel_endpoint"; \
    chmod 0755 /out/trusttunnel_endpoint

FROM python:3.13.5-slim@sha256:4c2cf9917bd1cbacc5e9b07320025bdb7cdf2df7b0ceaccb55e9dd7e30987419
ARG TT_VERSION=v1.1.0
COPY --from=endpoint /out/trusttunnel_endpoint /usr/local/bin/trusttunnel_endpoint
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 TT_VERSION=${TT_VERSION}
WORKDIR /app
COPY trusttunnel_manager /app/trusttunnel_manager
# Root inside the container so it can read the 0600 Let's Encrypt key; compose drops every
# capability. The endpoint listens on loopback only, so no privileged port is needed.
ENTRYPOINT ["python", "-m", "trusttunnel_manager"]
