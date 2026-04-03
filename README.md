# signet-exporter

**Prometheus exporter for network inventory observability** — designed for compliance-heavy and air-gapped environments.

---

## Security Posture

| Control | Implementation |
|---------|---------------|
| Transport security | mTLS with TLS 1.3 minimum; `client_ca_file` enforces mutual authentication |
| FIPS 140-2 | Alternate build target with `GOEXPERIMENT=boringcrypto` |
| Least privilege | Runs as dedicated `signet` system user; only `CAP_NET_RAW` granted |
| Supply chain | Signed releases via cosign (Sigstore); CycloneDX SBOM attached to every release |
| Audit logging | Structured JSON audit records for all binding changes and rogue device detections |
| Root refusal | Process exits immediately if launched as UID 0 |
| Bind safety | Default listen address is `127.0.0.1`; binding to `0.0.0.0` is rejected at validation |

---

## Features

- **ARP sweep** — discovers live hosts and MAC addresses on configured subnets
- **ICMP probing** — liveness check complementing ARP results
- **Duplicate IP detection** — alerts when multiple MACs respond to the same IP
- **MAC-IP binding tracking** — detects and records changes in MAC-to-IP mappings
- **DNS forward/reverse consistency** — flags mismatches between A and PTR records
- **TCP port probing** — lightweight connect scan on configurable per-subnet port lists
- **MAC OUI vendor enrichment** — resolves IEEE OUI prefix to vendor name
- **Rogue device detection** — compares observed MACs against per-subnet allowlists
- **Persistent state** — optional bbolt backend survives restarts; memory backend for ephemeral use
- **FIPS build variant** — BoringCrypto TLS for FIPS 140-2 environments

---

## Installation

### Debian / Ubuntu (apt)

    sudo dpkg -i signet-exporter_<version>_linux_amd64.deb

Or from a hosted apt repository (if configured):

    sudo apt install signet-exporter

### RHEL / Fedora / SUSE (yum / dnf / zypper)

    sudo rpm -i signet-exporter_<version>_linux_amd64.rpm

Or:

    sudo dnf install signet-exporter_<version>_linux_amd64.rpm

### Arch Linux (pacman)

    sudo pacman -U signet-exporter_<version>_linux_amd64.pkg.tar.zst

### From Source

    git clone https://github.com/maravexa/signet-exporter.git
    cd signet-exporter
    make install-all

### Post-Install

All packages automatically:
- Create a `signet` system user
- Set `CAP_NET_RAW` on the binary
- Install a default config at `/etc/signet/signet.yaml`
- Install the systemd unit

Enable and start the service:

    sudo systemctl enable --now signet-exporter

Edit `/etc/signet/signet.yaml` to add your subnets before starting.

---

## Quickstart

### Build

```bash
# Standard binary
make build

# FIPS variant (requires Go toolchain with BoringCrypto support)
make build-fips
```

### Configure

Copy and edit the example configuration:

```bash
cp configs/signet.example.yaml /etc/signet/signet.yaml
$EDITOR /etc/signet/signet.yaml
```

Validate before running:

```bash
./dist/signet-exporter --validate --config=/etc/signet/signet.yaml
```

### Run

```bash
./dist/signet-exporter --config=/etc/signet/signet.yaml
```

---

## Configuration Reference

See [`configs/signet.example.yaml`](configs/signet.example.yaml) for a fully annotated example.

Key fields:

| Field | Default | Description |
|-------|---------|-------------|
| `listen_address` | `127.0.0.1:9420` | Address for the `/metrics` endpoint |
| `tls.cert_file` | `""` | Server TLS certificate (leave empty for plaintext) |
| `tls.client_ca_file` | `""` | CA for mTLS client verification |
| `tls.min_version` | `"1.3"` | Minimum TLS version (`"1.2"` or `"1.3"`) |
| `subnets[].cidr` | required | Subnet to scan in CIDR notation |
| `subnets[].scan_interval` | required | Scan frequency (Go duration, e.g. `60s`) |
| `subnets[].ports` | `[]` | TCP ports to probe |
| `subnets[].mac_allowlist_file` | `""` | Path to MAC allowlist for rogue device detection |
| `state.backend` | `"memory"` | State backend: `"memory"` or `"bolt"` |
| `oui_database` | `/usr/share/signet/oui.txt` | Path to IEEE OUI database |

---

## Metrics Reference

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `signet_host_up` | Gauge | `ip, mac, vendor, subnet` | 1 if host responded in last scan |
| `signet_scan_duration_seconds` | Gauge | `subnet, scanner` | Duration of most recent scan |
| `signet_last_scan_timestamp` | Gauge | `subnet` | Unix timestamp of last completed scan |
| `signet_duplicate_ip_detected` | Gauge | `ip, subnet` | 1 if duplicate IP observed |
| `signet_dns_forward_reverse_mismatch` | Gauge | `ip, hostname, subnet` | 1 if DNS inconsistency detected |
| `signet_mac_ip_binding_changes_total` | Counter | `ip, subnet` | Total MAC-IP binding changes |
| `signet_subnet_addresses_used` | Gauge | `subnet` | Active addresses in subnet |
| `signet_subnet_addresses_total` | Gauge | `subnet` | Total usable addresses in subnet |
| `signet_unauthorized_device_detected` | Gauge | `ip, mac, vendor, subnet` | 1 if device not in allowlist |
| `signet_port_open` | Gauge | `ip, port, subnet` | 1 if TCP port was open in last scan |
| `signet_scan_errors_total` | Counter | `subnet, scanner` | Total scan errors |
| `signet_exporter_build_info` | Gauge | `version, commit, goversion` | Build metadata |

---

## Linux Capabilities

Signet requires `CAP_NET_RAW` for ARP scanning. The binary refuses to run as root —
use Linux capabilities instead.

**Development builds:**

    make setcap

This builds the binary and sets the capability. Requires `sudo`.

**Manual installation:**

    make install

Installs to `/usr/local/bin/` with capabilities set.

**Debian packages:**

The `.deb` package sets capabilities automatically via `postinst`.

**systemd:**

The included systemd unit uses `AmbientCapabilities=CAP_NET_RAW` — no manual
capability setting needed when running as a service.

---

## OUI Vendor Database

Signet resolves MAC address prefixes to manufacturer names using the IEEE OUI database.
This populates the `vendor` label on `signet_host_up` metrics.

### Configuration

Set the path in `signet.yaml`:

    oui_database: "/usr/share/signet/oui.txt"

Leave empty or omit to run without vendor enrichment (the `vendor` label will be blank).

### Data Sources

**Debian package:** Ships with a snapshot of the IEEE database. No action needed after install.

**Manual install:** Download the database:

    sudo /usr/lib/signet/update-oui.sh

Or manually:

    sudo mkdir -p /usr/share/signet
    sudo curl -o /usr/share/signet/oui.txt https://standards-oui.ieee.org/oui/oui.txt

**Air-gapped environments:** Copy `oui.txt` from a connected machine to
`/usr/share/signet/oui.txt` on the target host. The file is available from
https://standards-oui.ieee.org/oui/oui.txt (~500KB).

### Keeping the Database Current

The IEEE updates the OUI database periodically. To refresh:

    sudo /usr/lib/signet/update-oui.sh

The script downloads, validates, and installs the new database. Restart signet to
pick up the changes:

    sudo systemctl restart signet-exporter

The last update timestamp is recorded in `/usr/share/signet/oui.txt.updated`.

For automated updates, add a cron entry or systemd timer:

    # Weekly OUI update (cron example)
    0 3 * * 0 /usr/lib/signet/update-oui.sh >> /var/log/signet-oui-update.log 2>&1

---

## Makefile Targets

| Target | Sudo | Description |
|---|---|---|
| `make build` | No | Build the binary to `dist/` |
| `make build-fips` | No | Build the FIPS 140-2 variant |
| `make test` | No | Run tests with race detector |
| `make vet` | No | Run `go vet` |
| `make lint` | No | Run `golangci-lint` |
| `make check` | No | Run vet + lint + test |
| `make validate-config` | No | Validate the example config file |
| `make run` | No | Build and run with minimal config |
| `make setcap` | Yes | Build and set `CAP_NET_RAW` on the binary |
| `make install` | Yes | Install binary to `/usr/local/bin/` with capabilities |
| `make install-data` | Yes | Install OUI database and update script to system paths |
| `make install-all` | Yes | Full install: binary + data + capabilities |
| `make clean` | No | Remove build artifacts |

---

## Deployment

### systemd

```bash
# Install binary
install -m 755 dist/signet-exporter /usr/local/bin/

# Create service user
systemd-sysusers deploy/signet.sysusers

# Install and enable service
install -m 644 deploy/signet-exporter.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now signet-exporter
```

### Docker

```bash
docker build -t signet-exporter .
docker run --rm --cap-add NET_RAW \
  -v /etc/signet:/etc/signet:ro \
  -p 127.0.0.1:9420:9420 \
  signet-exporter --config=/etc/signet/signet.yaml
```

### Kubernetes

Kubernetes deployment manifests are planned for a future release. The exporter requires a pod with `CAP_NET_RAW` and `hostNetwork: true` (or a dedicated network namespace covering the subnets to scan).

---

## License

Apache License 2.0 — see [LICENSE](LICENSE).

---

## Prometheus Scrape Config

```yaml
- job_name: "signet"
    scrape_interval: 30s
    scrape_timeout: 10s
    static_configs:
      - targets: ["127.0.0.1:9420"]
```
