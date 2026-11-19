FROM python:3.15.2-alpine@sha256:0f9552bb28711333da16915ec146f5e6bb44a7fdac9ced15dc17c2e0206346dd

COPY security/runtime_backports.py /opt/build/backports.py
COPY packaging/minimal/patches/ /usr/share/access-pages/backports/
COPY packaging/standalone/ /usr/share/access-pages/backports/
RUN python /opt/build/backports.py --base sha256:0f9552bb28711333da16915ec146f5e6bb44a7fdac9ced15dc17c2e0206346dd \
    && rm /opt/build/backports.py

WORKDIR /app

COPY server.py .
COPY schedules.py schedule_routes.py invitations.py ./
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
    && apk add --no-cache tzdata \
    && addgroup -S gateway \
    && adduser -S -G gateway gateway \
    && mkdir -p /data/pages \
    && chown -R gateway:gateway /data

USER gateway

EXPOSE 8080

CMD ["python", "server.py"]
