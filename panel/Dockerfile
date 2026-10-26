FROM rust:1.99-slim-bookworm@sha256:86234e857a413004348b471d11a4ebe1aa92d2eae2b6b143cac68fd1ac3c48be AS build
WORKDIR /src
COPY VERSION /src/VERSION
COPY pc_common /src/pc_common
# A 3.x version-agent does not sync pc_common. Refuse its incomplete/stale generation before
# compiling, so the old agent restores its previous image and files instead of restarting into 4.x.
RUN cmp -s /src/VERSION /src/pc_common/RELEASE \
    || { echo 'panel source generation is incomplete; use install-release.sh --update' >&2; exit 1; }
COPY panel /src/panel
RUN cd /src/panel \
    && cargo build --release --locked -p panel-web \
    && install -D -m 0755 target/release/panel /out/panel

FROM debian:bookworm-slim@sha256:7ff6ba31527b9e336162fa061746c366c4b2032f4d2cff2078bea43f78efe3f8
RUN groupadd --system --gid 101 panel \
    && useradd --system --uid 10001 --gid panel --no-create-home panel \
    && install -d -o panel -g panel /data
WORKDIR /app
COPY --from=build /out/panel /usr/local/bin/panel
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY VERSION /app/VERSION
COPY panel/static /app/panel/static
COPY --chmod=0755 panel/entrypoint.sh /app/panel/entrypoint.sh
EXPOSE 8787
ENTRYPOINT ["/app/panel/entrypoint.sh"]
