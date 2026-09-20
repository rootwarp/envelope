# Pins match .github/workflows/ci.yml (FR-29). Do not float tool tags.
.PHONY: build test race lint vuln vet ci fmt clean run tidy sigstress

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
	go test -count=1 ./...

race:
	go test -count=1 -race ./...

# Never run the suite with -tags envelope_signaltest: every in-process restore
# and every plugin PIN prompt would park until go test's own timeout.
# -run SIG covers the exec'd signal tests and excludes the WaitTimer sleep.
sigstress:
	go test -count=20 -race -run 'SIG' ./cmd/envelope

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
