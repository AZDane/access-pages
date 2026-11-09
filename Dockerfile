FROM python:3.16.0a1-alpine@sha256:57d59f9badcd47eabb3ed920d3bd5ae02f44664fc224ae57f1687980227741d2

WORKDIR /app

COPY server.py .
COPY actions.py .
COPY admin.py .
COPY access.py .
COPY upstream_cleanup.py .
COPY guest_resources.py .
COPY internal.py .
COPY config.py .
COPY themes.py .
COPY ha.py .
COPY guest_diagnostics.py .
COPY guest_request.py .
COPY ha_broker.py .
COPY pages.py .
COPY layerv.py .
COPY layerv_broker.py .
COPY policy.py .
COPY policy_store.py .
COPY audit.py .
COPY activity.py .
COPY rate_limit.py .
COPY email_delivery.py .
COPY verification.py .
COPY static ./static

RUN apk upgrade --no-cache \
    && addgroup -S gateway \
    && adduser -S -G gateway gateway \
    && mkdir -p /data/pages \
    && chown -R gateway:gateway /data

USER gateway

EXPOSE 8080

CMD ["python", "server.py"]
