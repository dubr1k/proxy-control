# trusttunnel_endpoint is the pinned upstream release binary (Apache-2.0), verified by sha256.
# `ADD --checksum` refuses any other bytes; one stage per architecture, picked by TARGETARCH.
ARG TT_VERSION=v1.1.0
ARG TT_SHA256_X86_64=91c2ea3db7416a01b5258a4c047ec22890490bc55e1b194206031aa75144f0e7
ARG TT_SHA256_AARCH64=c2aee17a1ced349283cba4775202e2baba053b8ea835d4cc23dc67d16c6b9686

FROM rust:1.99-slim-bookworm@sha256:86234e857a413004348b471d11a4ebe1aa92d2eae2b6b143cac68fd1ac3c48be AS endpoint-amd64
ARG TT_VERSION
ARG TT_SHA256_X86_64
ADD --checksum=sha256:${TT_SHA256_X86_64} \
    https://github.com/TrustTunnel/TrustTunnel/releases/download/${TT_VERSION}/trusttunnel-${TT_VERSION}-linux-x86_64.tar.gz \
    /tmp/tt.tar.gz
RUN mkdir /out && tar -xzf /tmp/tt.tar.gz -C /out --strip-components=1 --wildcards '*/trusttunnel_endpoint'

FROM rust:1.99-slim-bookworm@sha256:86234e857a413004348b471d11a4ebe1aa92d2eae2b6b143cac68fd1ac3c48be AS endpoint-arm64
ARG TT_VERSION
ARG TT_SHA256_AARCH64
ADD --checksum=sha256:${TT_SHA256_AARCH64} \
    https://github.com/TrustTunnel/TrustTunnel/releases/download/${TT_VERSION}/trusttunnel-${TT_VERSION}-linux-aarch64.tar.gz \
    /tmp/tt.tar.gz
RUN mkdir /out && tar -xzf /tmp/tt.tar.gz -C /out --strip-components=1 --wildcards '*/trusttunnel_endpoint'

FROM endpoint-${TARGETARCH:-amd64} AS endpoint
RUN chmod 0755 /out/trusttunnel_endpoint

# The manager: built from the locked dependency set, nothing fetched beyond Cargo.lock.
FROM rust:1.99-slim-bookworm@sha256:86234e857a413004348b471d11a4ebe1aa92d2eae2b6b143cac68fd1ac3c48be AS build
WORKDIR /src
COPY pc_common /src/pc_common
COPY trusttunnel_manager /src/trusttunnel_manager
RUN cd /src/trusttunnel_manager \
    && cargo build --release --locked \
    && install -D -m 0755 target/release/trusttunnel-manager /out/trusttunnel-manager

FROM debian:bookworm-slim@sha256:7ff6ba31527b9e336162fa061746c366c4b2032f4d2cff2078bea43f78efe3f8
ARG TT_VERSION
COPY --from=endpoint /out/trusttunnel_endpoint /usr/local/bin/trusttunnel_endpoint
COPY --from=build /out/trusttunnel-manager /usr/local/bin/trusttunnel-manager
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
ENV TT_VERSION=${TT_VERSION}
# Root inside the container so it can read the 0600 Let's Encrypt key; compose drops every
# capability. The endpoint listens on loopback only, so no privileged port is needed.
ENTRYPOINT ["/usr/local/bin/trusttunnel-manager"]
