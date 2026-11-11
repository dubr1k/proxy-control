# Older version agents do not sync pc_common. Fail closed on incomplete generations.
FROM rust:1.99-slim-bookworm@sha256:86234e857a413004348b471d11a4ebe1aa92d2eae2b6b143cac68fd1ac3c48be AS generation
COPY VERSION /src/VERSION
COPY pc_common/RELEASE /src/pc_common/RELEASE
RUN cmp -s /src/VERSION /src/pc_common/RELEASE \
    || { echo 'panel source generation is incomplete; use install-release.sh --update' >&2; exit 1; }

FROM rust:1.99-slim-bookworm@sha256:86234e857a413004348b471d11a4ebe1aa92d2eae2b6b143cac68fd1ac3c48be AS build
WORKDIR /src
ENV CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0
COPY pc_common /src/pc_common
COPY panel /src/panel
# Verified release archives contain the static binary built twice by release/build.py.
# A source checkout still builds normally; no persistent target cache can supply stale code.
RUN if [ -f /src/panel/bin/linux-amd64/panel ]; then \
      test -x /src/panel/bin/linux-amd64/panel \
      && install -D -m 0755 /src/panel/bin/linux-amd64/panel /out/panel; \
    else \
      cd /src/panel \
      && cargo build --release --locked -p panel-web \
      && install -D -m 0755 target/release/panel /out/panel; \
    fi

FROM debian:bookworm-slim@sha256:7ff6ba31527b9e336162fa061746c366c4b2032f4d2cff2078bea43f78efe3f8
RUN groupadd --system --gid 101 panel \
    && useradd --system --uid 10001 --gid panel --no-create-home panel \
    && install -d -o panel -g panel /data
WORKDIR /app
COPY --from=build /out/panel /usr/local/bin/panel
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=generation /src/VERSION /app/VERSION
COPY panel/static /app/panel/static
COPY --chmod=0755 panel/entrypoint.sh /app/panel/entrypoint.sh
EXPOSE 8787
ENTRYPOINT ["/app/panel/entrypoint.sh"]
