# amneziawg-go is built from the pinned upstream commit (tag v3.1.20260828) and verified.
FROM golang:1.25.12@sha256:dbeddb5e728ea4b5ba7920574413e311025ffa42d196793857e4d160e8dfe60d AS awg-go
ARG AWG_GO_COMMIT=b5928efb6ca19f0153958460c3d141f04abc5c2e
RUN git clone https://github.com/amnezia-vpn/amneziawg-go /src \
 && cd /src \
 && git checkout "${AWG_GO_COMMIT}" \
 && test "$(git rev-parse HEAD)" = "${AWG_GO_COMMIT}" \
 && CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/amneziawg-go .

FROM python:3.13.5-slim@sha256:4c2cf9917bd1cbacc5e9b07320025bdb7cdf2df7b0ceaccb55e9dd7e30987419
# The base image ships no bytecode and the container's root is read-only, so every Python start
# (health checks, `docker exec`) would compile the standard library again. First step after
# FROM, so every Proxy Control image shares this layer.
RUN python -m compileall -q -j0 /usr/local/lib/python3.13
RUN apt-get update \
 && apt-get install -y --no-install-recommends iproute2 nftables \
 && rm -rf /var/lib/apt/lists/*
COPY --from=awg-go /out/amneziawg-go /usr/local/bin/amneziawg-go
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY awg_manager /app/awg_manager
RUN python -m compileall -q /app
# Runs as root inside the container: TUN/netlink/nft need NET_ADMIN (the only added caps are
# NET_ADMIN and NET_RAW, everything else is dropped by compose).
ENTRYPOINT ["python", "-m", "awg_manager"]
