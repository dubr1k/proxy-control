# Isolated harness for the pinned official Mieru client.
#
# The client binary is not downloaded here: the adapter extracts it from the
# pinned upstream package, verifies its digest, and places it in the build
# context, so this image is reproducible from artifacts the installer has
# already proven.
FROM python:3.13.5-slim@sha256:4c2cf9917bd1cbacc5e9b07320025bdb7cdf2df7b0ceaccb55e9dd7e30987419

COPY mieru /usr/local/bin/mieru
COPY probe.py /usr/local/bin/mieru-probe
RUN chmod 0755 /usr/local/bin/mieru /usr/local/bin/mieru-probe

ENV MIERU_CONFIG_JSON_FILE=/tmp/mieru-client.json \
    MIERU_PROBE_CONFIG=/etc/mieru/client.json \
    MIERU_PROBE_SOCKS=127.0.0.1:1080 \
    MIERU_PROBE_URL=http://cp.cloudflare.com/generate_204 \
    MIERU_PROBE_STATUS=204

ENTRYPOINT ["python", "/usr/local/bin/mieru-probe"]
