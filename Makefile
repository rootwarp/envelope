# Pins match .github/workflows/ci.yml (FR-29). Do not float tool tags.
.PHONY: build test race lint vuln vet ci fmt clean run tidy

APP_NAME := envelope
BUILD_DIR := bin

STATICCHECK := honnef.co/go/tools/cmd/staticcheck@v0.8.1
GOVULNCHECK := golang.org/x/vuln/cmd/govulncheck@v1.8.0

# go install writes to GOBIN (or GOPATH/bin). Prepend it so the CI binary names resolve locally.
GOBIN := $(shell go env GOBIN)
ifeq ($(GOBIN),)
GOBIN := $(shell go env GOPATH)/bin
endif
export PATH := $(GOBIN):$(PATH)

build:
	go build -o $(BUILD_DIR)/$(APP_NAME) ./cmd/$(APP_NAME)

run:
	go run ./cmd/$(APP_NAME)

test:
	go test ./...

race:
	go test -race ./...

vet:
	go vet ./...

lint:
	go install $(STATICCHECK)
	staticcheck ./...

vuln:
	go install $(GOVULNCHECK)
	govulncheck ./...

ci: test race vet lint vuln
	scripts/check-discipline.sh

fmt:
	gofmt -w .

tidy:
	go mod tidy

clean:
	rm -rf $(BUILD_DIR)
