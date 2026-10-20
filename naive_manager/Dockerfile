FROM python:3.13.5-slim@sha256:4c2cf9917bd1cbacc5e9b07320025bdb7cdf2df7b0ceaccb55e9dd7e30987419
# The base image ships no bytecode and the container's root is read-only, so every Python start
# (health checks, `docker exec`) would compile the standard library again. First step after
# FROM, so every Proxy Control image shares this layer.
RUN python -m compileall -q -j0 /usr/local/lib/python3.13
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    NAIVE_CADDYFILE=/data/Caddyfile NAIVE_STATE_FILE=/data/users.json \
    NAIVE_BACKUP_DIR=/data/backups NAIVE_MANAGER_SOCKET=/run/naive-manager/manager.sock \
    NAIVE_MANAGER_TOKEN_FILE=/run/secrets/naive-manager-token
WORKDIR /app
COPY naive_manager /app/naive_manager
RUN python -m compileall -q /app
ENTRYPOINT ["python", "-m", "naive_manager.server"]
