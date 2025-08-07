FROM golang:1.22-alpine AS builder

# Install build dependencies including libolm
RUN apk add --no-cache git ca-certificates build-base olm-dev

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download

COPY . .
# Enable CGO and build with libolm support
RUN CGO_ENABLED=1 CGO_CFLAGS="-I/usr/include" CGO_LDFLAGS="-L/usr/lib" go build -o mautrix-emaildawg ./cmd/mautrix-emaildawg

FROM alpine:latest

# Install runtime dependencies
RUN apk --no-cache add ca-certificates olm tzdata
WORKDIR /opt/mautrix-emaildawg

# Create data directory
RUN mkdir -p /opt/mautrix-emaildawg/data

COPY --from=builder /build/mautrix-emaildawg /usr/bin/

USER 1337

EXPOSE 29319

CMD ["/usr/bin/mautrix-emaildawg"]
