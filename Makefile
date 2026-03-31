BINARY     := signet-exporter
CMD        := ./cmd/signet-exporter
DIST       := dist

# Build-time version injection via ldflags.
VERSION    := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT     := $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
DATE       := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS    := -X github.com/maravexa/signet-exporter/internal/version.Version=$(VERSION) \
              -X github.com/maravexa/signet-exporter/internal/version.Commit=$(COMMIT) \
              -X github.com/maravexa/signet-exporter/internal/version.Date=$(DATE)

.PHONY: all build build-fips test lint validate-config run clean

all: build

## build: compile the standard binary
build:
	@mkdir -p $(DIST)
	go build -trimpath -ldflags "$(LDFLAGS)" -o $(DIST)/$(BINARY) $(CMD)

## build-fips: compile with FIPS 140-2 compliant BoringCrypto
build-fips:
	@mkdir -p $(DIST)
	GOEXPERIMENT=boringcrypto go build -trimpath -ldflags "$(LDFLAGS)" \
		-o $(DIST)/$(BINARY)-fips $(CMD)

## test: run the full test suite
test:
	go test -race -count=1 ./...

## lint: run golangci-lint
lint:
	golangci-lint run ./...

## validate-config: validate the example configuration file
validate-config: build
	$(DIST)/$(BINARY) --validate --config=configs/signet.example.yaml

## run: build and run with the minimal example config
run: build
	$(DIST)/$(BINARY) --config=configs/signet.minimal.yaml

## clean: remove build artifacts
clean:
	rm -rf $(DIST)
