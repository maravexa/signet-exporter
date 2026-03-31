# syntax=docker/dockerfile:1
# Multi-stage build for signet-exporter.
# Stage 1 builds the binary; stage 2 produces a minimal nonroot image.

# ── Build stage ──────────────────────────────────────────────────────────────
FROM golang:1.22-bookworm AS builder

WORKDIR /src

# Cache module downloads separately from source to improve layer reuse.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown

RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags "-s -w \
      -X github.com/maravexa/signet-exporter/internal/version.Version=${VERSION} \
      -X github.com/maravexa/signet-exporter/internal/version.Commit=${COMMIT} \
      -X github.com/maravexa/signet-exporter/internal/version.Date=${DATE}" \
    -o /signet-exporter \
    ./cmd/signet-exporter

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM gcr.io/distroless/static-debian12:nonroot

# OCI image annotations (https://github.com/opencontainers/image-spec)
LABEL org.opencontainers.image.title="signet-exporter" \
      org.opencontainers.image.description="Prometheus exporter for network inventory observability" \
      org.opencontainers.image.source="https://github.com/maravexa/signet-exporter" \
      org.opencontainers.image.licenses="Apache-2.0"

COPY --from=builder /signet-exporter /signet-exporter

# Default metrics port.
EXPOSE 9420

ENTRYPOINT ["/signet-exporter"]
