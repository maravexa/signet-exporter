# Changelog

All notable changes to signet-exporter are documented in this file.

---

## [0.5.0] - UNRELEASED

### Breaking Changes

#### signet_host_up label reduction

The `mac`, `vendor`, and `hostname` labels have been removed from `signet_host_up`.
These labels move to the new `signet_host_info` metric (value always 1).

Dashboards and alert rules filtering `signet_host_up` by hostname, vendor, or MAC
must be migrated to use a PromQL join:

**Before:**

    signet_host_up{hostname="srv01"}

**After:**

    signet_host_up * on(ip, subnet) group_left(hostname) signet_host_info{hostname="srv01"}

This change eliminates label churn caused by hostname and vendor changes in
environments with DHCP or frequent inventory updates, and reduces series count
at /16+ scale.

### New Features

- **Host TTL eviction** — hosts not seen within `host_ttl` (default: 3× scan interval) are
  automatically pruned from state. Works on both memory and bolt backends. Pruned hosts
  emit `host_expired` audit events. Set `host_ttl: 0` to disable. Hot-reloadable via SIGHUP.

- **`signet_host_info` metric** — new info metric carrying enrichment labels (`mac`, `vendor`,
  `hostname`, `subnet`, `ip`) with a constant value of 1. Always emitted for every known
  host regardless of liveness. Join with `signet_host_up` in PromQL for enriched queries.

- **`signet_active_series_estimate` metric** — gauge estimating total active Prometheus series
  based on current host count and configured port list. Useful for capacity planning.
  Conservative: uses port list length as worst-case (actual series lower if not all ports open).

- **Cardinality and scaling documentation** — new README section covering port list guidance,
  network size table (/24 through /10+), /14+ federation recommendations, PromQL join
  examples for `signet_host_info`, and TTL tuning guidance.

---

## [0.4.0]

Phase 4: bbolt persistent state backend, mTLS, FIPS build variant, config hot-reload via SIGHUP,
CEF audit format, and GoReleaser packaging (.deb/.rpm/.pkg.tar.zst).

---

## [0.3.0]

Phase 3: TCP port probing, MAC OUI vendor enrichment, rogue device detection via MAC allowlists,
structured JSON audit logging, and integration test pipeline.

---

## [0.2.0]

Phase 2: ICMP probing, DNS forward/reverse consistency checks, duplicate IP detection,
MAC-IP binding change tracking, and Prometheus metrics collector.

---

## [0.1.0]

Phase 1: ARP sweep, MemoryStore state backend, Prometheus exporter skeleton,
Linux capabilities (CAP_NET_RAW), root refusal, and systemd unit.
