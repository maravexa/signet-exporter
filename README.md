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

---

## mTLS

Signet supports mutual TLS (mTLS) so that only authenticated Prometheus scrapers can reach `/metrics`. This satisfies SC-8 (Transmission Confidentiality and Integrity) in NIST 800-53 / FedRAMP environments.

### Dev quickstart — generate a cert chain

```bash
signet-exporter --generate-certs /etc/signet/tls
```

This creates a self-signed CA, a server cert (SAN: `localhost`, `127.0.0.1`, `::1`), and a client cert — all ECDSA P-256:

```
/etc/signet/tls/
  ca.pem            ca-key.pem
  server.pem        server-key.pem
  client.pem        client-key.pem
```

### Enable mTLS in signet.yaml

```yaml
tls:
  cert_file: "/etc/signet/tls/server.pem"
  key_file:  "/etc/signet/tls/server-key.pem"
  client_ca_file:     "/etc/signet/tls/ca.pem"
  client_auth_policy: "require_and_verify"   # default when client_ca_file is set
```

`client_auth_policy` values:

| Value | Behaviour |
|---|---|
| `require_and_verify` | Client cert is mandatory and must be CA-signed *(default)* |
| `verify_if_given` | Verify if presented, but don't require one |
| `no_client_cert` | Don't request a client cert |

### Configure Prometheus to present the client cert

```yaml
scrape_configs:
  - job_name: "signet"
    scheme: https
    scrape_interval: 30s
    scrape_timeout: 10s
    tls_config:
      ca_file:   "/etc/signet/tls/ca.pem"
      cert_file: "/etc/signet/tls/client.pem"
      key_file:  "/etc/signet/tls/client-key.pem"
    static_configs:
      - targets: ["127.0.0.1:9420"]
```

### Certificate rotation (zero downtime)

Send `SIGHUP` to reload the server cert and key from disk without restarting:

```bash
# systemd
systemctl reload signet-exporter

# manual
kill -HUP $(pidof signet-exporter)
```

If the new files are invalid, the old certificate remains active and an error is logged. No connections are dropped.

---

## Grafana Dashboard

A pre-built Grafana dashboard is included in [`grafana/signet-overview.json`](grafana/signet-overview.json).

See [`grafana/README.md`](grafana/README.md) for import instructions (UI upload or provisioning) and full details.

The dashboard covers:

- **Host Inventory** — live host counts and MAC-IP binding table
- **Scan Performance** — ARP, ICMP, DNS, and port scan durations
- **Subnet Utilization** — address space usage per subnet
- **Security Alerts** — unauthorized devices, duplicate IPs, and DNS mismatches


---

## Audit Logging

signet-exporter emits structured audit records for security-relevant events (new hosts, MAC changes, unauthorized devices, scan errors, and TLS certificate reloads).

Records can be written in **JSON** (default, one object per line) or **CEF** (Common Event Format) for SIEM integration with Splunk, QRadar, ArcSight, and similar platforms.

```yaml
audit:
  enabled: true
  format: "json"    # or "cef"
  output: "file"
  path: "/var/log/signet/audit.log"
```

See [`docs/audit-logging.md`](docs/audit-logging.md) for the full event reference, log rotation guidance, and SIEM integration examples.

---

## Config Hot-Reload (SIGHUP)

Send `SIGHUP` to apply configuration changes without restarting or losing scan state:

```bash
# systemd
systemctl reload signet-exporter

# manual
kill -HUP $(pidof signet-exporter)
```

### What is reloadable

| Setting | Reloadable? |
|---------|-------------|
| `subnets` — CIDR list, scan intervals | Yes — SIGHUP |
| `subnets` — TCP ports per subnet | Yes — SIGHUP |
| `subnets` — MAC allowlist file paths | Yes — SIGHUP |
| `host_ttl` | Yes — SIGHUP |
| TLS certificate contents | Yes — SIGHUP (cert rotation) |
| `listen_address` | **No** — restart required |
| `tls.*` (paths, min_version) | **No** — restart required |
| `state.*` (backend, bolt path) | **No** — restart required |
| `dns.*`, `scanner.*`, `oui_database` | **No** — restart required |
| `audit.*` | **No** — restart required |

### What happens on reload

1. The config file is re-read from the same path used at startup.
2. The reloadable subset is validated. **If validation fails, the old config stays active** — the exporter continues running unchanged and logs the error.
3. If validation passes, changes are diffed and applied atomically:
   - New subnets begin scanning immediately.
   - Removed subnets exit after their current scan cycle completes.
   - Interval, port, and allowlist changes take effect on the next scan cycle.
4. TLS certificates are reloaded from disk (same paths as startup).
5. All changes are logged in the audit trail with a `config_reloaded` event containing a human-readable diff.

### Invalid config handling

If the reloaded config contains an invalid CIDR, out-of-range port, or a missing allowlist file, the reload is rejected entirely — no partial changes are applied. The error is logged at ERROR level and the exporter continues with the previous configuration.

---

## Cardinality and Scaling

### Port scan list guidance

Signet is a network inventory tool, not a vulnerability scanner. The port scan list (`ports` in `signet.yaml`) exists to detect service presence for inventory purposes — knowing that a device is running SSH or HTTP, not enumerating all open ports on every host. Every port in the scan list is a linear multiplier on `signet_port_open` series count: 100 hosts × 20 ports = up to 2,000 `signet_port_open` series. Keep the list to genuinely meaningful service indicators: SSH (22), HTTP/S (80, 443), common management interfaces (161 SNMP, 623 IPMI, 3389 RDP). A 500-port scan list on a /16 will generate millions of series and should be handled by a dedicated port scanner like nmap, not Signet.

### Network size guidance

| Network | Usable hosts | Live hosts (40% fill) | Estimated series (10 ports) | Notes |
|---|---|---|---|---|
| /24 | 254 | ~100 | ~600 | Trivially fine |
| /20 | 4,094 | ~1,600 | ~8K | Fine |
| /16 | 65,534 | ~26K | ~120K | Fine on standard Prometheus |
| /14 | 262,142 | ~105K | ~500K | Approaching limits; plan for federation |
| /12 | 1,048,574 | ~419K | ~2M | Single Prometheus not recommended |
| /10 and larger | — | — | — | Requires federation or Thanos/Cortex |

The `signet_active_series_estimate` metric in `/metrics` gives a real-time estimate based on actual host count and configured port list, which is more reliable than this table for a specific deployment.

### /14+ deployments

At /14 and larger, plan for Prometheus federation or a horizontally scalable TSDB (Thanos, Cortex, Mimir) from the start. Retrofitting remote storage after a TSDB is already straining is painful. The inflection point is not just series count but scrape cardinality — at /14+, a single Prometheus instance scraping Signet will have its query layer stressed by even simple aggregations. If a /14+ deployment is in scope, this should already be an infrastructure architecture discussion, not a surprise. Signet is designed to be a good federation citizen: all metrics carry `subnet` labels suitable for hierarchical aggregation.

### PromQL join examples for `signet_host_info`

`signet_host_up` carries only `ip` and `subnet` labels. Enrichment metadata (MAC, vendor, hostname) lives on `signet_host_info` (value always 1). Join them in PromQL when you need to filter or group by enrichment labels.

```promql
# Find all unauthorized devices, with vendor and MAC
signet_unauthorized_device_detected * on(ip, subnet) group_left(vendor, mac)
  signet_host_info

# Count live hosts by vendor
count by (vendor) (
  signet_host_up * on(ip, subnet) group_left(vendor) signet_host_info
)

# Alert on hosts with hostname matching a pattern that are down
signet_host_up == 0
  * on(ip, subnet) group_left(hostname)
  signet_host_info{hostname=~"prod-.*"}
```

### TTL tuning guidance

The default TTL of 3× the scan interval means a host must miss three consecutive scans before being pruned. For most environments this is appropriate — it tolerates transient scan failures (packet loss, host briefly unavailable) without generating false `HostExpired` audit events. In environments with very long scan intervals (>30 minutes), consider setting an explicit `host_ttl` in `signet.yaml` to avoid retaining stale data for hours. In environments where any host disappearance is immediately significant (air-gapped networks with a fixed inventory), tighten the TTL to 1× or 2× the scan interval and treat `HostExpired` audit events as actionable.

```yaml
# Explicit TTL: 15 minutes regardless of scan interval
host_ttl: 15m

# Disable TTL eviction entirely (hosts persist until restart)
host_ttl: 0
```
