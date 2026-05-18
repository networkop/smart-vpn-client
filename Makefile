SOURCES := $(shell find . -name '*.go')
COMMIT := $(shell git describe --dirty --always)
LDFLAGS := "-s -w -X main.GitCommit=$(COMMIT)"
DOCKER_IMAGE ?= networkop/smart-vpn-client
GO := $(shell which go)

default: smart-vpn-client

smart-vpn-client: $(SOURCES) test
	CGO_ENABLED=0 go build -o smart-vpn-client -ldflags $(LDFLAGS) main.go
 
arm64: $(SOURCES) test
	CGO_ENABLED=0 GOARCH=arm64 go build -o smart-vpn-client -ldflags $(LDFLAGS) main.go

docker: Dockerfile test
	# Ensure a buildx builder exists and bootstrap QEMU for cross-builds
	@docker buildx create --use --name multi-builder --driver docker-container >/dev/null 2>&1 || true
	@docker buildx inspect --bootstrap >/dev/null

	# Build and push multi-arch images to the registry configured in DOCKER_IMAGE
	docker buildx build --push \
	  --platform linux/amd64,linux/arm64 \
	  --build-arg LDFLAGS=$(LDFLAGS) \
	  -t $(DOCKER_IMAGE):$(COMMIT) \
	  -t $(DOCKER_IMAGE):latest .

test:
	sudo $(GO) test -race ./...  -v

lint:
	golangci-lint run


# Update go module dependencies to latest compatible versions
update-deps:
	@echo "Updating Go modules..."
	@go get -u ./...
	@go mod tidy
	@echo "Done. Run 'git status' to see changes."


# Release using goreleaser inside docker so 'make release' works locally and in CI
release:
	@echo "Running goreleaser via Docker"
	@docker run --rm -e GITHUB_TOKEN=$(GITHUB_TOKEN) -v $(shell pwd):/src -w /src goreleaser/goreleaser:latest release --rm-dist

