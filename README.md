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
