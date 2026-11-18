# syntax=docker/dockerfile:1

ARG NODE_IMAGE=node:24-bookworm-slim

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
COPY packages/ packages/
COPY apps/ apps/
COPY examples/ examples/
COPY migrations/ migrations/
COPY config/schema/ config/schema/

RUN npm run build && \
    npm prune --omit=dev --ignore-scripts && \
    mkdir -p /staging/config /staging/migrations && \
    cp package.json package-lock.json /staging/ && \
    cp -a node_modules /staging/node_modules && \
    for dir in packages/* apps/api apps/relay apps/fanout apps/sender apps/coordinator apps/admin examples/receiver examples/provider-ingress; do \
      if [ -f "${dir}/package.json" ]; then \
        mkdir -p "/staging/${dir}"; \
        cp "${dir}/package.json" "/staging/${dir}/"; \
        if [ -d "${dir}/dist" ]; then cp -a "${dir}/dist" "/staging/${dir}/dist"; fi; \
        if [ -d "${dir}/migrations" ]; then cp -a "${dir}/migrations" "/staging/${dir}/migrations"; fi; \
      fi; \
    done && \
    cp -a migrations/. /staging/migrations/ && \
    cp -a config/schema /staging/config/schema

FROM ${NODE_IMAGE} AS runtime

ENV NODE_ENV=production \
    HOME=/tmp

RUN groupadd -g 10001 -r relayquill && \
    useradd -u 10001 -g 10001 -r -d /tmp -s /sbin/nologin relayquill

WORKDIR /app

COPY --from=builder --chown=0:10001 /staging /app
COPY --chown=0:10001 infra/images/application-entrypoint.sh /usr/local/bin/relayquill-entrypoint

RUN tr -d '\r' < /usr/local/bin/relayquill-entrypoint > /usr/local/bin/relayquill-entrypoint.clean && \
    mv /usr/local/bin/relayquill-entrypoint.clean /usr/local/bin/relayquill-entrypoint && \
    chmod 0755 /usr/local/bin/relayquill-entrypoint && \
    chmod -R a+rX,go-w /app

USER 10001:10001

ENTRYPOINT ["/usr/local/bin/relayquill-entrypoint"]
CMD ["api", "--config", "/etc/relayquill/role-config.json"]
