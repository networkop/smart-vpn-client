SOURCES := $(shell find . -name '*.go')
DOCKER_IMAGE ?= networkop/smart-vpn-client

default: smart-vpn-client

smart-vpn-client: $(SOURCES)
	CGO_ENABLED=0 go build -o smart-vpn-client -ldflags "-X main.version=$(VERSION) -extldflags -static" .

nas: $(SOURCES)
	CGO_ENABLED=0 GOARCH=arm64 -o smart-vpn-client -ldflags "-X main.version=$(VERSION) -extldflags -static" .

docker: Dockerfile
	docker buildx build --push --platform linux/amd64,linux/arm64 -t $(DOCKER_IMAGE)  .

test:
	go test -race ./...  -v