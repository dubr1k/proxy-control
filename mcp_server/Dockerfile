FROM python:3.13.5-slim@sha256:4c2cf9917bd1cbacc5e9b07320025bdb7cdf2df7b0ceaccb55e9dd7e30987419

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app
COPY mcp_server/requirements.txt /tmp/requirements.txt
RUN pip install -r /tmp/requirements.txt \
 && groupadd --system --gid 10007 mcp \
 && useradd --system --uid 10007 --gid mcp --no-create-home mcp
COPY mcp_server /app/mcp_server
USER 10007:10007
EXPOSE 8793
HEALTHCHECK --interval=20s --timeout=3s --retries=3 --start-period=15s CMD ["python", "-m", "mcp_server.healthcheck"]
ENTRYPOINT ["python", "-m", "mcp_server"]
