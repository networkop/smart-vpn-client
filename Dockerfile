FROM --platform=${BUILDPLATFORM} golang:1.26 AS builder

WORKDIR /src

ARG LDFLAGS

COPY go.mod .
COPY go.sum .

RUN go mod download

COPY . .

ENV CGO_ENABLED=0
ARG TARGETOS
ARG TARGETARCH

# Install 'file' so we can inspect the built binary in CI logs for debugging
RUN apt-get update && apt-get install -y --no-install-recommends file && rm -rf /var/lib/apt/lists/*

# Build for the target platform. Using TARGETOS/TARGETARCH supplied by buildx.
RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -ldflags "${LDFLAGS}" -o smart-vpn-client main.go

# Debugging: print the Go env and binary file information so CI logs reveal
# whether the binary was built for the expected architecture.
RUN echo "GOOS=${TARGETOS} TARGETARCH=${TARGETARCH}" && \
	GOOS=${TARGETOS} GOARCH=${TARGETARCH} go env GOOS GOARCH && \
	file ./smart-vpn-client || true

FROM alpine:3.21

RUN apk upgrade --no-cache && \
    apk add --no-cache iptables iptables-legacy ca-certificates

WORKDIR /
COPY --from=builder /src/smart-vpn-client .

ENTRYPOINT ["/smart-vpn-client"]