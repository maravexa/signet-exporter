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

.PHONY: all build build-fips test lint validate-config run clean setcap install install-data install-all vet check

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

## setcap: build and set CAP_NET_RAW on the local development binary (requires sudo)
setcap: build
	sudo setcap cap_net_raw+ep $(DIST)/$(BINARY)

## install: install binary to /usr/local/bin/ with capabilities set (requires sudo)
install: build
	sudo install -m 755 $(DIST)/$(BINARY) /usr/local/bin/signet-exporter
	sudo setcap cap_net_raw+ep /usr/local/bin/signet-exporter

## install-data: install OUI database and update script to system paths (requires sudo)
install-data:
	sudo install -d -m 755 /usr/share/signet
	sudo install -m 644 data/oui.txt /usr/share/signet/oui.txt
	sudo install -d -m 755 /usr/lib/signet
	sudo install -m 755 scripts/update-oui.sh /usr/lib/signet/update-oui.sh

## install-all: full system install — binary + data + capabilities (requires sudo)
install-all: install install-data

## vet: run go vet
vet:
	go vet ./...

## check: run vet + lint + test
check: vet lint test

## clean: remove build artifacts
clean:
	rm -rf $(DIST)
