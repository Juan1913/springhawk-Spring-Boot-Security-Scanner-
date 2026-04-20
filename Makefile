VERSION ?= 1.0.0
BUILD_DATE := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS := -ldflags "-s -w -X github.com/springhawk/springhawk/cmd.Version=$(VERSION) -X github.com/springhawk/springhawk/cmd.BuildDate=$(BUILD_DATE)"

.PHONY: build clean test lint install

build:
	CGO_ENABLED=0 go build $(LDFLAGS) -trimpath -o dist/springhawk .
	@echo "Built: dist/springhawk"

build-all:
	@mkdir -p dist
	CGO_ENABLED=0 GOOS=linux   GOARCH=amd64  go build $(LDFLAGS) -trimpath -o dist/springhawk-linux-amd64 .
	CGO_ENABLED=0 GOOS=linux   GOARCH=arm64  go build $(LDFLAGS) -trimpath -o dist/springhawk-linux-arm64 .
	CGO_ENABLED=0 GOOS=darwin  GOARCH=amd64  go build $(LDFLAGS) -trimpath -o dist/springhawk-darwin-amd64 .
	CGO_ENABLED=0 GOOS=darwin  GOARCH=arm64  go build $(LDFLAGS) -trimpath -o dist/springhawk-darwin-arm64 .
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64  go build $(LDFLAGS) -trimpath -o dist/springhawk-windows-amd64.exe .
	@echo "All platform builds complete in dist/"

install: build
	cp dist/springhawk /usr/local/bin/springhawk
	@echo "Installed to /usr/local/bin/springhawk"

test:
	go test -race -cover ./...

lint:
	golangci-lint run ./...

clean:
	rm -rf dist/

deps:
	go mod tidy
	go mod verify
