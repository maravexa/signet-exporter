# Claude Code Context — signet-exporter

This file provides context for Claude Code sessions working on this repository.

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
  audit/              — structured JSON audit logging
  collector/          — Prometheus collector
  config/             — YAML config loading and validation
  oui/                — IEEE OUI database parser and lookup
  scanner/            — ARP, ICMP, DNS, port, allowlist scanners
  server/             — HTTP server for /metrics
  state/              — bbolt and memory state backends
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

The binary exits immediately if launched as UID 0. Use Linux capabilities or
`AmbientCapabilities` in systemd instead.

### State Backends

- `memory`: default, ephemeral, no persistence across restarts
- `bolt`: bbolt-backed, persists state to disk (Phase 4)

### OUI Lookup

- Loaded once at startup from the path in `oui_database` config key.
- Empty/missing path → degraded mode: `vendor` label is blank, no error.
- Parse format: `XX-XX-XX   (hex)    Vendor Name` lines only.

### Makefile Conventions

- `make build` is always unprivileged — safe for CI.
- Anything requiring `sudo` is in a separate target (`setcap`, `install`, `install-data`).
- `make check` runs the full validation suite: vet + lint + test.

---

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
- The repo ships a stub in `data/oui.txt` for testing. The full database is ~500KB.
- `scripts/update-oui.sh` downloads and validates a fresh copy from IEEE.
- The update script installs to `/usr/lib/signet/update-oui.sh` (FHS: package-shipped helper scripts).
- The exporter loads the OUI database once at startup. Restart required after updates.
- Empty or missing `oui_database` config → degraded mode, no vendor enrichment, no error.

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

- Tests use build tags to stub out raw socket operations (ARP, ICMP).
  See `internal/scanner/arp_stub.go` and `internal/scanner/icmp_stub.go`.
- `internal/integration_test.go` exercises the full scan pipeline.
- OUI tests in `internal/oui/oui_test.go` use the stub `data/oui.txt`.
- Run with `-race` flag (enabled in `make test`) — the scanner is heavily concurrent.
