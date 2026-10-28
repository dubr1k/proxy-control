# The MTProxy ingress bridge (3.0): a static Go binary, stdlib only, from this tree. The toolchain
# is the one pinned for amneziawg-go (awg_manager/Dockerfile).
FROM golang:1.25.12@sha256:dbeddb5e728ea4b5ba7920574413e311025ffa42d196793857e4d160e8dfe60d AS bridge
WORKDIR /src
COPY xray_router_manager/mtproxy-bridge/ ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/mtproxy-bridge .

# The manager (4.0, Rust): built from the locked dependency set, nothing fetched beyond Cargo.lock.
FROM rust:1.99-slim-bookworm@sha256:86234e857a413004348b471d11a4ebe1aa92d2eae2b6b143cac68fd1ac3c48be AS build
WORKDIR /src
ENV CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0
COPY pc_common /src/pc_common
COPY xray_router_manager /src/xray_router_manager
RUN cd /src/xray_router_manager \
    && cargo build --release --locked \
    && install -D -m 0755 target/release/xray-router-manager /out/xray-router-manager

# The pinned Xray binary and its geodata are not in the image: they come from the host directory
# the installer filled from the release archive (`/opt/xray`, read-only), checked by digest.
FROM debian:bookworm-slim@sha256:7ff6ba31527b9e336162fa061746c366c4b2032f4d2cff2078bea43f78efe3f8
RUN groupadd --system --gid 10006 xray-router \
 && useradd --system --uid 10006 --gid xray-router --no-create-home xray-router
COPY --from=bridge /out/mtproxy-bridge /usr/local/bin/mtproxy-bridge
COPY --from=build /out/xray-router-manager /usr/local/bin/xray-router-manager
# The geodata downloads, the WARP registration and the exit probe verify TLS against this bundle.
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
USER 10006:10006
ENTRYPOINT ["/usr/local/bin/xray-router-manager"]
