# The manager: built from the locked dependency set (SQLite and the TLS probe are compiled in),
# nothing fetched beyond Cargo.lock.
FROM rust:1.99-slim-bookworm@sha256:86234e857a413004348b471d11a4ebe1aa92d2eae2b6b143cac68fd1ac3c48be AS build
WORKDIR /src
COPY pc_common /src/pc_common
COPY naive_manager /src/naive_manager
RUN cd /src/naive_manager \
    && cargo build --release --locked \
    && install -D -m 0755 target/release/naive-manager /out/naive-manager

FROM debian:bookworm-slim@sha256:7ff6ba31527b9e336162fa061746c366c4b2032f4d2cff2078bea43f78efe3f8
COPY --from=build /out/naive-manager /usr/local/bin/naive-manager
ENV NAIVE_CADDYFILE=/data/Caddyfile NAIVE_STATE_FILE=/data/users.json \
    NAIVE_BACKUP_DIR=/data/backups NAIVE_MANAGER_SOCKET=/run/naive-manager/manager.sock \
    NAIVE_MANAGER_TOKEN_FILE=/run/secrets/naive-manager-token
# compose runs it as 10002:101 on a read-only root with every capability dropped; Caddy's
# admin API and the private listener are on the host's loopback (network_mode: host).
ENTRYPOINT ["/usr/local/bin/naive-manager"]
