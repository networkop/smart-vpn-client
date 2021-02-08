FROM --platform=${BUILDPLATFORM} golang:1.15.6-buster as builder

WORKDIR /src

ARG LDFLAGS

COPY go.mod .
COPY go.sum .

RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GO111MODULE=on go build -ldflags "${LDFLAGS}" -o smart-vpn-client main.go

FROM alpine:latest

RUN apk add --no-cache iptables

WORKDIR /
COPY --from=builder /src/smart-vpn-client .

ENTRYPOINT ["/smart-vpn-client"]