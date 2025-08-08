# --- Builder stage (Debian bookworm) ---
FROM golang:1.22.5-bookworm AS builder

# Install build dependencies including libolm
RUN apt-get update -y \
    && apt-get install -y --no-install-recommends git ca-certificates build-essential libolm-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download

COPY . .
# Build with CGO to link against libolm
RUN CGO_ENABLED=1 go build -o emaildawg ./cmd/emaildawg

# --- Runtime dependencies stage (Debian bookworm-slim) ---
FROM debian:bookworm-slim AS runtime-deps
RUN apt-get update -y \
    && apt-get install -y --no-install-recommends ca-certificates libolm3 tzdata \
    && rm -rf /var/lib/apt/lists/*

# --- Final minimal runtime (Distroless) ---
# Distroless base matching Debian 12
FROM gcr.io/distroless/cc-debian12:nonroot

# Copy the compiled binary
COPY --from=builder /build/emaildawg /usr/bin/emaildawg
# Copy only required shared libraries and data from runtime-deps
COPY --from=runtime-deps /usr/lib/x86_64-linux-gnu/libolm.so.3 /usr/lib/x86_64-linux-gnu/libolm.so.3
COPY --from=runtime-deps /usr/lib/x86_64-linux-gnu/libolm.so /usr/lib/x86_64-linux-gnu/libolm.so
COPY --from=runtime-deps /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=runtime-deps /usr/share/zoneinfo /usr/share/zoneinfo

WORKDIR /opt/emaildawg
# Expose a writable volume for data (mount a host volume here)
VOLUME ["/opt/emaildawg/data"]

EXPOSE 29319
ENTRYPOINT ["/usr/bin/emaildawg"]
