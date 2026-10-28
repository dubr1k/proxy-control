# The MCP server: built from the locked dependency set, nothing fetched beyond Cargo.lock.
FROM rust:1.99-slim-bookworm@sha256:86234e857a413004348b471d11a4ebe1aa92d2eae2b6b143cac68fd1ac3c48be AS build
WORKDIR /src
ENV CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0
COPY pc_common /src/pc_common
COPY mcp_server /src/mcp_server
RUN cd /src/mcp_server \
    && cargo build --release --locked \
    && install -D -m 0755 target/release/mcp-server /out/mcp-server

FROM debian:bookworm-slim@sha256:7ff6ba31527b9e336162fa061746c366c4b2032f4d2cff2078bea43f78efe3f8
COPY --from=build /out/mcp-server /usr/local/bin/mcp-server
# CA bundle for an https MCP_PANEL_URL (the panel is plain http inside the Compose network).
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
USER 10007:10007
EXPOSE 8793
HEALTHCHECK --interval=20s --timeout=3s --retries=3 --start-period=15s CMD ["/usr/local/bin/mcp-server", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/mcp-server"]
