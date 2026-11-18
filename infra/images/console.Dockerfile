# syntax=docker/dockerfile:1

ARG NODE_IMAGE=node:24-bookworm-slim
ARG NGINX_IMAGE=nginx:1.27-alpine

FROM ${NODE_IMAGE} AS builder
WORKDIR /build

COPY package.json package-lock.json tsconfig.base.json .node-version ./
COPY packages/domain/package.json packages/domain/package.json
COPY packages/contracts/package.json packages/contracts/package.json
COPY packages/event-schema/package.json packages/event-schema/package.json
COPY packages/egress/package.json packages/egress/package.json
COPY packages/signing/package.json packages/signing/package.json
COPY packages/broker/package.json packages/broker/package.json
COPY packages/runtime/package.json packages/runtime/package.json
COPY packages/auth/package.json packages/auth/package.json
COPY packages/application/package.json packages/application/package.json
COPY packages/postgres/package.json packages/postgres/package.json
COPY packages/producer-sdk/package.json packages/producer-sdk/package.json
COPY packages/receiver-sdk/package.json packages/receiver-sdk/package.json
COPY apps/api/package.json apps/api/package.json
COPY apps/relay/package.json apps/relay/package.json
COPY apps/fanout/package.json apps/fanout/package.json
COPY apps/sender/package.json apps/sender/package.json
COPY apps/coordinator/package.json apps/coordinator/package.json
COPY apps/admin/package.json apps/admin/package.json
COPY apps/console/package.json apps/console/package.json
COPY examples/receiver/package.json examples/receiver/package.json
COPY examples/provider-ingress/package.json examples/provider-ingress/package.json
COPY examples/producer/package.json examples/producer/package.json

RUN npm ci --ignore-scripts

COPY tools/ tools/
COPY packages/domain/ packages/domain/
COPY packages/contracts/ packages/contracts/
COPY packages/producer-sdk/ packages/producer-sdk/
COPY apps/console/ apps/console/

RUN node tools/build-workspaces.mjs \
      --workspace @relayquill/domain \
      --workspace @relayquill/contracts \
      --workspace @relayquill/producer-sdk \
      --workspace @relayquill/console

FROM ${NGINX_IMAGE} AS runtime

ENV RELAYQUILL_API_UPSTREAM=http://relayquill-api:8005

COPY --from=builder --chown=0:101 /build/apps/console/dist /usr/share/nginx/html
COPY --chown=0:101 infra/images/nginx/nginx.conf /etc/nginx/nginx.conf
COPY --chown=0:101 infra/images/nginx/security-headers.conf /etc/nginx/snippets/security-headers.conf
COPY --chown=0:101 infra/images/nginx/default.conf.template /etc/nginx/templates/default.conf.template
COPY --chown=0:101 infra/images/console-entrypoint.sh /usr/local/bin/console-entrypoint

RUN tr -d '\r' < /usr/local/bin/console-entrypoint > /usr/local/bin/console-entrypoint.clean && \
    mv /usr/local/bin/console-entrypoint.clean /usr/local/bin/console-entrypoint && \
    chmod 0755 /usr/local/bin/console-entrypoint && \
    chmod -R a+rX,go-w /usr/share/nginx/html /etc/nginx

USER 101:101

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/console-entrypoint"]
