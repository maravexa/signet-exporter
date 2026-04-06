# Signet Exporter — Project Knowledge Base

This file tracks release history, metric reference, and roadmap for the signet-exporter project.

---

## Release History

### v0.5.0 — Phase 5: Scalability & Observability
Host TTL staleness expiration on both state backends with HostExpired audit events. signet_host_up label reduction (ip, subnet only) with new signet_host_info info metric for enrichment labels. signet_active_series_estimate gauge for cardinality visibility. Cardinality and scaling section added to README covering port list guidance, network size table, /14+ federation guidance, and TTL tuning.

### v0.4.0 — Phase 4: Persistence & Production Hardening
bbolt persistent state backend, mTLS, FIPS build variant (GOEXPERIMENT=boringcrypto), config hot-reload via SIGHUP, CEF audit format for SIEM integration, GoReleaser packaging (.deb/.rpm/.pkg.tar.zst).

### v0.3.0 — Phase 3: Inventory Enrichment
TCP port probing (configurable per-subnet port lists), MAC OUI vendor enrichment (IEEE OUI database), rogue device detection via per-subnet MAC allowlists, structured JSON audit logging, integration test pipeline.

### v0.2.0 — Phase 2: Active Probing
ICMP probing, DNS forward/reverse consistency checks, duplicate IP detection, MAC-IP binding change tracking, Prometheus metrics collector with full label set.

### v0.1.0 — Phase 1: Foundation
ARP sweep scanner, MemoryStore state backend, Prometheus exporter skeleton, Linux capabilities (CAP_NET_RAW), root refusal, systemd unit file.

---

## Metric Reference

| Metric | Type | Labels | Description |
|---|---|---|---|
| `signet_host_up` | Gauge | `ip`, `subnet` | 1 if host responded in last scan, 0 if stale |
| `signet_host_info` | Gauge | `ip`, `mac`, `vendor`, `hostname`, `subnet` | Always 1. Enrichment metadata. Join with host_up. |
| `signet_active_series_estimate` | Gauge | — | Conservative estimate of active Prometheus series |
| `signet_scan_duration_seconds` | Gauge | `subnet`, `scanner` | Duration of most recent scan cycle |
| `signet_last_scan_timestamp` | Gauge | `subnet` | Unix timestamp of most recent completed scan |
| `signet_duplicate_ip_detected` | Gauge | `ip`, `macs`, `subnet` | 1 if multiple MACs claimed this IP |
| `signet_dns_forward_reverse_mismatch` | Gauge | `ip`, `hostname`, `subnet` | 1 if DNS forward/reverse inconsistent |
| `signet_mac_ip_binding_changes_total` | Counter | `ip`, `subnet` | Cumulative MAC changes for this IP |
| `signet_subnet_addresses_used` | Gauge | `subnet` | Hosts detected in subnet |
| `signet_subnet_addresses_total` | Gauge | `subnet` | Total usable addresses in subnet |
| `signet_unauthorized_device_detected` | Gauge | `ip`, `mac`, `vendor`, `subnet` | 1 if MAC not in allowlist |
| `signet_port_open` | Gauge | `ip`, `port`, `subnet` | 1 if TCP port responded |
| `signet_scan_errors_total` | Counter | `subnet`, `scanner` | Cumulative scan errors |
| `signet_exporter_build_info` | Gauge | `version`, `commit`, `goversion` | Always 1, carries build metadata |
| `signet_exporter_fips_enabled` | Gauge | — | 1 if compiled with BoringCrypto |

**Note:** `signet_host_up` carries only `ip` and `subnet` labels as of v0.5.0. The `mac`, `vendor`,
and `hostname` labels moved to `signet_host_info`. See CHANGELOG.md for migration instructions.

---

## v1.0.0 Checklist

- [x] `signet_host_up` / `signet_host_info` split shipped and migration documented
- [x] Host TTL eviction working on both state backends
- [x] Cardinality scaling docs in README
- [x] `signet_active_series_estimate` visible in `/metrics`
- [ ] SBOM generation (CycloneDX, attached to release artifacts)
- [ ] SECURITY.md (vulnerability disclosure policy)
- [ ] Grafana dashboard update for host_info join pattern
- [ ] Signed release artifacts (cosign / Sigstore)

---

## Roadmap

| Phase | Version | Status | Description |
|---|---|---|---|
| Phase 1 | v0.1.0 | ✓ SHIPPED | ARP sweep, MemoryStore, exporter skeleton |
| Phase 2 | v0.2.0 | ✓ SHIPPED | ICMP, DNS checks, duplicate IP, MAC tracking |
| Phase 3 | v0.3.0 | ✓ SHIPPED | Port probing, OUI enrichment, allowlists, audit logging |
| Phase 4 | v0.4.0 | ✓ SHIPPED | bbolt, mTLS, FIPS, SIGHUP hot-reload, packaging |
| Phase 5 | v0.5.0 | ✓ SHIPPED | TTL eviction, host_info split, series estimate, scaling docs |
| Phase 6 | v0.6.0 | planned | IPv6 support, SNMPv2c probing stub |
| v1.0.0 | v1.0.0 | planned | SBOM, SECURITY.md, signed releases, Grafana dashboard |
