# syntax=docker/dockerfile:1

ARG GO_IMAGE=golang:1.27.1-bookworm

FROM ${GO_IMAGE} AS builder
WORKDIR /src

COPY tools/broker-launcher/go.mod tools/broker-launcher/go.sum ./
RUN go mod download

COPY tools/broker-launcher/ ./

ARG TARGETOS=linux
ARG TARGETARCH=amd64

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
      go build -trimpath -ldflags="-s -w" -o /out/relayquill-broker ./cmd/relayquill-broker && \
    mkdir -p /staging/data/jetstream /staging/etc/relayquill/broker /staging/etc/relayquill/certs

FROM gcr.io/distroless/static-debian12:nonroot AS runtime

COPY --from=builder --chown=0:65532 /out/relayquill-broker /usr/local/bin/relayquill-broker
COPY --from=builder --chown=65532:65532 /staging/data/jetstream /data/jetstream
COPY --from=builder --chown=0:65532 /staging/etc/relayquill /etc/relayquill

USER 65532:65532

EXPOSE 4222 6222 8222

ENTRYPOINT ["/usr/local/bin/relayquill-broker"]
CMD ["--topology", "/etc/relayquill/broker/public-topology.json"]
