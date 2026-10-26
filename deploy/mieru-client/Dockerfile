# Isolated harness for the pinned official Mieru client.
#
# The client binary is not downloaded here: the adapter extracts it from the
# pinned upstream package, verifies its digest, and places it in the build
# context, so this image is reproducible from artifacts the installer has
# already proven.
FROM rust:1.99-alpine@sha256:b1d5dd5a22a09404d3e798c0cf051b689077360374eb505fa5bb93c479693d87 AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

FROM debian:bookworm-slim@sha256:7ff6ba31527b9e336162fa061746c366c4b2032f4d2cff2078bea43f78efe3f8

COPY mieru /usr/local/bin/mieru
COPY --from=build /src/target/release/mieru-probe /usr/local/bin/mieru-probe
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
RUN chmod 0755 /usr/local/bin/mieru

ENV MIERU_CONFIG_JSON_FILE=/tmp/mieru-client.json \
    MIERU_PROBE_CONFIG=/etc/mieru/client.json \
    MIERU_PROBE_SOCKS=127.0.0.1:1080 \
    MIERU_PROBE_URL=http://cp.cloudflare.com/generate_204 \
    MIERU_PROBE_STATUS=204

ENTRYPOINT ["/usr/local/bin/mieru-probe"]
