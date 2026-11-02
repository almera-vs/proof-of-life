VERSION ?= 0.1.0
LDFLAGS := -s -w -X github.com/almera-vs/proof-of-life/internal/obs.Version=$(VERSION)

.PHONY: build test lint integration fault image

build:
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o bin/pol ./cmd/pol

test:
	go test ./...

lint:
	golangci-lint run

integration:
	go test -tags integration -timeout 60m -v ./test/integration/...

fault:
	go test -tags integration -timeout 90m -v ./test/fault/...

image:
	docker build -t pol:$(VERSION) --build-arg VERSION=$(VERSION) .
