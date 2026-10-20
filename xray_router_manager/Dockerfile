# The MTProxy ingress bridge (3.0): a static Go binary, stdlib only, from this tree. The toolchain
# is the one pinned for amneziawg-go (awg_manager/Dockerfile).
FROM golang:1.25.12@sha256:dbeddb5e728ea4b5ba7920574413e311025ffa42d196793857e4d160e8dfe60d AS bridge
WORKDIR /src
COPY xray_router_manager/mtproxy-bridge/ ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/mtproxy-bridge .

FROM python:3.13.5-slim@sha256:4c2cf9917bd1cbacc5e9b07320025bdb7cdf2df7b0ceaccb55e9dd7e30987419
# The base image ships no bytecode and the container's root is read-only, so every Python start
# (the health check every 20 s) would compile the standard library again. First step after FROM,
# so every Proxy Control image shares this layer.
RUN python -m compileall -q -j0 /usr/local/lib/python3.13
RUN groupadd --system --gid 10006 xray-router \
 && useradd --system --uid 10006 --gid xray-router --no-create-home xray-router
COPY --from=bridge /out/mtproxy-bridge /usr/local/bin/mtproxy-bridge
WORKDIR /app
COPY xray_router_manager /app/xray_router_manager
RUN python -m compileall -q /app
USER 10006:10006
ENTRYPOINT ["python", "-m", "xray_router_manager"]
