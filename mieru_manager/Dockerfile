# The manager: built from the locked dependency set, nothing fetched beyond Cargo.lock. mita
# itself is not in the image: compose binds the host's pinned, statically linked /usr/bin/mita
# read-only, and the manager refuses it unless its sha256 is MIERU_MITA_SHA256.
FROM rust:1.99-slim-bookworm@sha256:86234e857a413004348b471d11a4ebe1aa92d2eae2b6b143cac68fd1ac3c48be AS build
WORKDIR /src
ENV CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0
COPY pc_common /src/pc_common
COPY mieru_manager /src/mieru_manager
RUN cd /src/mieru_manager \
    && cargo build --release --locked \
    && install -D -m 0755 target/release/mieru-manager /out/mieru-manager

FROM debian:bookworm-slim@sha256:7ff6ba31527b9e336162fa061746c366c4b2032f4d2cff2078bea43f78efe3f8
RUN groupadd --system --gid 10005 mieru-manager \
 && useradd --system --uid 10005 --gid mieru-manager --no-create-home mieru-manager
COPY --from=build /out/mieru-manager /usr/local/bin/mieru-manager
USER 10005:10005
ENTRYPOINT ["/usr/local/bin/mieru-manager"]
