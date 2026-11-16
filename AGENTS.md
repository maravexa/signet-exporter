# Signet Exporter contributor guide

Repository-wide instructions for contributors and automated agents. `go.mod` declares Go 1.26.0 (the checked-in CI/FIPS workflows select 1.26.9); use its current requirement when building.

## Project Overview

`signet-exporter` is a Prometheus exporter for network inventory observability.
It performs ARP sweeps, ICMP probing, DNS consistency checks, TCP port probing,
MAC OUI vendor enrichment, and rogue device detection. Designed for compliance-heavy
and air-gapped environments.

- **Module:** `github.com/maravexa/signet-exporter`
- **Binary output:** `dist/signet-exporter`
- **Config location:** `/etc/signet/signet.yaml`

## Repository Structure

```
cmd/signet-exporter/   — main entry point
internal/
  audit/              — structured JSON and CEF audit logging
  collector/          — Prometheus collector
  config/             — YAML config loading and validation
  oui/                — IEEE OUI database parser and lookup
  scanner/            — ARP, ICMP, DNS, port, allowlist scanners
  server/             — HTTP server for /metrics
  state/              — bbolt/memory state, source ownership and TTL
  remotewrite/        — optional queue/converter/sender for push delivery
  tlsutil/            — TLS policy and atomic certificate rotation
  fips/               — BoringCrypto detection (not certification)
  version/            — build version injection
pkg/netutil/          — shared network utilities
api/v6stub/           — IPv6 stub (placeholder)
configs/              — example and minimal YAML configs
data/oui.txt          — IEEE OUI database stub (for tests)
deploy/               — systemd unit and sysusers file
scripts/              — maintenance scripts
```

## Key Design Decisions

### Root Refusal

The normal startup path refuses UID 0 before loading configuration. Use Linux capabilities or
`AmbientCapabilities` in systemd instead.

### State Backends

- `memory`: default, ephemeral, no persistence across restarts
- `bolt`: bbolt-backed, persists state to disk (Phase 4)

### OUI Lookup

- Loaded once at startup from the path in `oui_database` config key.
- An empty configured path returns an empty database. An unreadable non-empty path returns an error from `internal/oui.LoadDatabase`; inspect the caller for error handling rather than treating a missing file as error-free.
- Parse format: `XX-XX-XX   (hex)    Vendor Name` lines only.

### Makefile Conventions

- `make build` is always unprivileged — safe for CI.
- Anything requiring `sudo` is in a separate target (`setcap`, `install`, `install-data`).
- `make check` runs the full validation suite: vet + lint + test.

---

## Current runtime contracts

Remote write is disabled by default and can coexist with the scrape endpoint.
`internal/remotewrite/` owns bounded queue/drop policy, encoding, credentials,
retry and reload behavior. Enabling it sends inventory metrics to the configured
receiver; credential-bearing authentication requires HTTPS. Keep secrets in the
supported credential files and preserve their permission checks.

`internal/state/ownership.go` merges observations by source, preserving fields
owned by other scanners. Keep observation timestamps, host TTL and persistence
semantics consistent across memory and bbolt; missing or expired observations are
not affirmative evidence that every scanner found a host absent.

SIGHUP validates a candidate generation before activation, rejects immutable
setting changes that require restart, and retains the old generation on failure.
Certificate rotation at existing paths is separate from changing TLS settings.
Preserve this transaction across scanner, allowlist and remote-write changes.

Do not infer TLS 1.3-only or mandatory mTLS from README summaries: inspect
`internal/server/server.go`, configuration validation and `internal/tlsutil/`
for the selected minimum/version and client-auth policy. Empty certificate
configuration serves plaintext with a warning. `make build-fips` enables
BoringCrypto with CGO; `internal/fips` reports actual backend availability.
That flag and the packaging suffix do not establish FIPS certification.

## Packaging & Deployment

### Linux Capabilities

- The binary requires `CAP_NET_RAW` for ARP scanning via raw sockets.
- `make build` does NOT set capabilities — CI and development builds stay unprivileged.
- `make setcap` builds and sets `CAP_NET_RAW` (requires sudo). Use for local testing.
- `make install` installs to `/usr/local/bin/` with capabilities set.
- The systemd unit uses `AmbientCapabilities=CAP_NET_RAW`.
- The `.deb`/`.rpm`/`.pkg.tar.zst` packages use `scripts/postinstall.sh` to set capabilities after install/upgrade.

### OUI Database

- IEEE OUI database lives at `/usr/share/signet/oui.txt` (FHS: vendor-supplied reference data).
- The repo ships a stub in `data/oui.txt` for testing. Do not infer the size or freshness of an externally downloaded database from this stub.
- `scripts/update-oui.sh` downloads and validates a fresh copy from IEEE.
- The update script installs to `/usr/lib/signet/update-oui.sh` (FHS: package-shipped helper scripts).
- The exporter loads the OUI database once at startup. Restart required after updates.
- Empty `oui_database` configuration allows no enrichment; missing/unreadable files at a non-empty path are loader errors. Preserve that distinction.

### FHS File Locations

| Path | Contents | Managed by |
|---|---|---|
| `/etc/signet/signet.yaml` | Operator configuration | Operator |
| `/usr/bin/signet-exporter` | Binary (`.deb` installs here) | Package |
| `/usr/local/bin/signet-exporter` | Binary (`make install` installs here) | Operator |
| `/usr/share/signet/oui.txt` | IEEE OUI database snapshot | Package / update script |
| `/usr/share/signet/oui.txt.updated` | Last update timestamp | Update script |
| `/usr/lib/signet/update-oui.sh` | OUI update helper script | Package |
| `/var/lib/signet/state.db` | bbolt persistent state (Phase 4) | Exporter runtime |

### Distribution Packages

- GoReleaser builds `.deb`, `.rpm`, and `.pkg.tar.zst` (Arch) packages via nFPM.
- Package config is in `.goreleaser.yaml` under the `nfpms` section.
- `scripts/postinstall.sh` runs after install/upgrade: sets CAP_NET_RAW, creates signet user, creates data directories.
- `scripts/preremove.sh` runs before removal: stops and disables the systemd service.
- Both scripts must be POSIX sh (not bash) and idempotent.
- `/etc/signet/signet.yaml` is marked as a config file — package managers won't overwrite operator edits on upgrade.
- The `.deb` dependency is `libcap2-bin` (provides setcap). The `.rpm` and Arch dependency is `libcap`.
- `deploy/signet-exporter.sysusers` is a systemd-sysusers definition — declarative user creation as a backup to the postinstall script.
- Packages are built only from the `standard` build (not FIPS). FIPS ships as a separate tarball.

### Package File Manifest

| Source | Package Destination | Notes |
|---|---|---|
| binary | `/usr/bin/signet-exporter` | goreleaser builds section |
| `configs/signet.example.yaml` | `/etc/signet/signet.yaml` | conffile, preserved on upgrade |
| `deploy/signet-exporter.service` | `/usr/lib/systemd/system/signet-exporter.service` | systemd unit |
| `deploy/signet-exporter.sysusers` | `/usr/lib/sysusers.d/signet-exporter.conf` | declarative user creation |
| `data/oui.txt` | `/usr/share/signet/oui.txt` | OUI database stub |
| `scripts/update-oui.sh` | `/usr/lib/signet/update-oui.sh` | OUI update helper |

---

## Development Workflow

```bash
# Build
make build

# Run tests
make test

# Full check (vet + lint + test)
make check

# Build and set CAP_NET_RAW for local ARP testing (requires sudo)
make setcap

# Validate example config
make validate-config
```

## Testing Notes

- `internal/scanner/arp_stub.go` and `icmp_stub.go` use `//go:build !linux`: they are platform fallbacks, not test-only stubs on Linux.
- `internal/integration_test.go` exercises scheduler/collector integration using mock scanners; it does not prove real ARP/ICMP reachability.
- OUI tests in `internal/oui/oui_test.go` create temporary oui.txt fixtures and cover empty/missing files.
- Run with `-race` flag (enabled in `make test`) — the scanner is heavily concurrent.

Run commands from the repository root. `make test` runs `go test -race -count=1 ./...`; focus affected packages first. `make validate-config` builds and validates the example as a non-root user. Live scans, setcap, installation, service changes and OUI downloads are separate operational actions, not routine documentation checks. See `.github/workflows/` for CI and `.goreleaser.yaml` for package contents; this guide does not attest to live deployment or compliance certification.
