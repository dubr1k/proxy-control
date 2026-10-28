# amneziawg-go is built from the pinned upstream commit (tag v3.1.20260828) and verified. The
# version-agent may rebuild with another tag (3.2): both values come as build args then.
FROM golang:1.25.12@sha256:dbeddb5e728ea4b5ba7920574413e311025ffa42d196793857e4d160e8dfe60d AS awg-go
ARG AWG_GO_COMMIT=b5928efb6ca19f0153958460c3d141f04abc5c2e
RUN git clone https://github.com/amnezia-vpn/amneziawg-go /src \
 && cd /src \
 && git checkout "${AWG_GO_COMMIT}" \
 && test "$(git rev-parse HEAD)" = "${AWG_GO_COMMIT}" \
 && CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/amneziawg-go .

# The manager: built from the locked dependency set, nothing fetched beyond Cargo.lock.
FROM rust:1.99-slim-bookworm@sha256:86234e857a413004348b471d11a4ebe1aa92d2eae2b6b143cac68fd1ac3c48be AS build
WORKDIR /src
ENV CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0
COPY pc_common /src/pc_common
COPY awg_manager /src/awg_manager
RUN cd /src/awg_manager \
    && cargo build --release --locked \
    && install -D -m 0755 target/release/awg-manager /out/awg-manager

FROM debian:bookworm-slim@sha256:7ff6ba31527b9e336162fa061746c366c4b2032f4d2cff2078bea43f78efe3f8
# The manager runs `ip` (addresses, links, the egress rules and table, the router's TUN device) and
# `nft` (the forward/NAT table), as before.
RUN apt-get update \
 && apt-get install -y --no-install-recommends iproute2 nftables \
 && rm -rf /var/lib/apt/lists/*
COPY --from=awg-go /out/amneziawg-go /usr/local/bin/amneziawg-go
COPY --from=build /out/awg-manager /usr/local/bin/awg-manager
# The trust store of the WARP registration (one HTTPS call at Cloudflare's client API).
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
ARG AWG_GO_VERSION=3.1.20260828
ARG AWG_GO_COMMIT=b5928efb6ca19f0153958460c3d141f04abc5c2e
# The version the agent reads back from the running container (`docker inspect`).
ENV AWG_GO_VERSION=${AWG_GO_VERSION} AWG_GO_COMMIT=${AWG_GO_COMMIT}
# Runs as root inside the container: TUN/netlink/nft need NET_ADMIN (the only added caps are
# NET_ADMIN and NET_RAW, everything else is dropped by compose).
ENTRYPOINT ["/usr/local/bin/awg-manager"]
