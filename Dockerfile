FROM --platform=${BUILDPLATFORM} golang:1.15.6-buster as builder

WORKDIR /src
ENV CGO_ENABLED=0

COPY go.mod .
COPY go.sum .

RUN go mod download

COPY . .

ARG TARGETOS
ARG TARGETARCH


RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -a -o smart-vpn-client .

FROM gcr.io/distroless/static:nonroot
WORKDIR /
COPY --from=builder /src/smart-vpn-client .
USER nonroot:nonroot

ENTRYPOINT ["/smart-vpn-client"]