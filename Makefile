SOURCES := $(shell find . -name '*.go')
COMMIT := $(shell git describe --dirty --always)
LDFLAGS := "-s -w -X main.GitCommit=$(COMMIT)"
DOCKER_IMAGE ?= networkop/smart-vpn-client

default: smart-vpn-client

smart-vpn-client: $(SOURCES) test
	CGO_ENABLED=0 go build -o smart-vpn-client -ldflags $(LDFLAGS) main.go
 
arm64: $(SOURCES) test
	CGO_ENABLED=0 GOARCH=arm64 -o smart-vpn-client -ldflags $(LDFLAGS) main.go

docker: Dockerfile test
	docker buildx build --push \
	--platform linux/amd64,linux/arm64 \
	--build-arg LDFLAGS=$(LDFLAGS) \
	-t $(DOCKER_IMAGE):$(COMMIT) \
	-t $(DOCKER_IMAGE):latest .

test:
	sudo go test -race ./...  -v

lint:
	golangci-lint run