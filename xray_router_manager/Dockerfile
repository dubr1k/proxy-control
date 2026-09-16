FROM python:3.13.5-slim@sha256:4c2cf9917bd1cbacc5e9b07320025bdb7cdf2df7b0ceaccb55e9dd7e30987419
RUN groupadd --system --gid 10006 xray-router \
 && useradd --system --uid 10006 --gid xray-router --no-create-home xray-router
WORKDIR /app
COPY xray_router_manager /app/xray_router_manager
USER 10006:10006
ENTRYPOINT ["python", "-m", "xray_router_manager"]
