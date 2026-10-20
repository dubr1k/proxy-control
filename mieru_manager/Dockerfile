FROM python:3.13.5-slim@sha256:4c2cf9917bd1cbacc5e9b07320025bdb7cdf2df7b0ceaccb55e9dd7e30987419
# The base image ships no bytecode and the container's root is read-only, so every Python start
# (health checks, `docker exec`) would compile the standard library again. First step after
# FROM, so every Proxy Control image shares this layer.
RUN python -m compileall -q -j0 /usr/local/lib/python3.13
RUN groupadd --system --gid 10005 mieru-manager \
 && useradd --system --uid 10005 --gid mieru-manager --no-create-home mieru-manager
WORKDIR /app
COPY mieru_manager /app/mieru_manager
RUN python -m compileall -q /app
USER 10005:10005
ENTRYPOINT ["python", "-m", "mieru_manager"]
