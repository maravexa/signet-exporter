# Push-Mode Operations

## 1. When to use which

If you are running Alloy, scrape Signet with Alloy. Use Signet's native remote write only when running Alloy alongside is operationally undesirable — typically air-gapped deployments, single-binary compliance constraints, or environments where qualifying a second binary is non-trivial.

**Alloy** is the right choice when Alloy is already running in your environment. If you already have Alloy deployed, adding Signet as a scrape target is a single stanza — no new binary, no new TLS footprint, and no new authentication path to manage. Alloy is also the right choice when you need metric relabeling before ingestion, fan-out to multiple backends simultaneously, or service discovery mechanisms (Kubernetes pod discovery, Consul catalog, DNS-SD) to pick up Signet instances dynamically. These are capabilities Alloy provides natively and that Signet's native remote write deliberately does not duplicate.

**Native remote write** is the right choice when adding Alloy is operationally undesirable. The main cases: air-gapped environments where qualifying a second binary for deployment requires its own change process, compliance reviews that prefer a smaller dependency surface in the metrics path (the reviewer can audit the single Signet binary rather than two), single-binary deployment constraints (systemd-managed FHS-compliant deployments without container orchestration, edge devices, field-deployed sensors), and homelab or development environments where adding Alloy is more operational weight than the deployment justifies.

**Running both simultaneously** is supported but discouraged. If `cfg.RemoteWrite.Enabled: true` and an Alloy instance is also scraping Signet and forwarding to the same receiver, the receiver will ingest two identical streams and produce duplicate samples. Mimir, Cortex, and Thanos receive will accept both streams without complaint. The resulting duplicate series will silently inflate query results for any metric using `sum()`, `count()`, or `rate()`. If you need both for a migration period, route the two streams to different tenants or different receivers until you cut over.

---

## 2. Cardinality at the receiver

Push mode amplifies the cost of cardinality decisions. In scrape mode, a high-cardinality metric creates load on the Prometheus TSDB but the series are bounded by what Prometheus can ingest in a given scrape. In push mode, every label combination becomes a series at the receiver, and those series persist until the receiver's retention sweeps them. A single Signet scrape that emits 5,000 series produces 5,000 receiver-side series; if hostname churn (DHCP reassignment) creates new label combinations at every scrape interval, those stale series accumulate at the receiver long after the host has gone — until retention expires them.

**The Phase 5 cardinality work is the foundation that makes push mode safe at scale.** The `signet_host_up` / `signet_host_info` split moved high-churn labels (`hostname`, `vendor`, `mac`) off the hot-path health metric and onto a separate info metric. The `signet_active_series_estimate` gauge provides a real-time pre-ingestion cardinality estimate based on actual host count and configured port list. These two design decisions mean operators have the tools they need to understand and control receiver-side series volume before it becomes a problem.

**DHCP hostname churn is the primary receiver-side risk.** In environments where hosts acquire hostnames via DHCP, each new hostname value creates a new `signet_host_info` series at the receiver. The old series becomes stale and is not cleaned up until retention expires it. The v0.5.0 info-split addressed this specifically: by moving `hostname` to `signet_host_info`, operators can scrape the enrichment metric less frequently or drop it entirely at the receiver. The `cardinality-conscious.alloy` example demonstrates both patterns. The same patterns apply when using native remote write — at the Signet config level rather than the Alloy relabel level.

**Concrete example.** A /22 subnet (1,024 usable addresses) with a 20-port scan list produces up to 20,480 active `signet_port_open` series at maximum fill. With 1% per-scrape hostname churn (roughly 10 DHCP reassignments per 60-second scrape interval), the `signet_host_info` metric generates approximately 10 new series per scrape cycle. Over a 30-day retention window at 60-second scrape intervals (43,200 scrape cycles), the cumulative receiver-side stale series from hostname churn alone can exceed 50,000 before the retention sweep catches up. Operators with 30-day retention and active DHCP should plan ingestion limits and series cardinality budgets around this dynamic. The most effective mitigation is dropping `signet_host_info` at the receiver and accepting enrichment-label queries will require a join against a separate source.

**Measuring receiver-side cardinality.** After enabling push mode, verify receiver-side series volume with these queries:

```promql
# Series count per metric name
count({__name__=~"signet_.+"}) by (__name__)

# Unique hostname count (proxy for DHCP churn risk)
count(count by (hostname) (signet_host_info))
```

For receiver-specific cardinality tooling: Mimir exposes a `cardinality_analysis` API at `/api/v1/cardinality/label_names` and `/api/v1/cardinality/label_values`; Prometheus exposes raw label enumeration at `/api/v1/labels` and `/api/v1/label/{label_name}/values`. Both can be used to identify which label dimensions are growing fastest.

**`signet_active_series_estimate`** is the authoritative pre-receiver-side cardinality predictor. Query it from Signet's `/metrics` endpoint to understand what the exporter is about to push before the receiver sees it. It accounts for actual observed host count and the configured port list, making it more accurate than static calculations.

---

## 3. External labels

Signet does not inject any external labels by default. The default `external_labels` map is empty.

This is intentional. Any auto-injection would create surprises during compliance review: reviewers expect every label on every series to trace back to explicit operator configuration. An implicit `instance` or `job` label injected by the exporter would be a label that appears in the receiver but has no corresponding operator-authored config stanza. For compliance environments that require a full label provenance chain, this creates audit questions that are difficult to answer. The no-magic policy means every label in the receiver was explicitly placed there by the operator.

**Conventional labels operators usually want:**

| Label | Typical value | Purpose |
|---|---|---|
| `cluster` | `prod-eu-west-1` | Identifies the deployment in multi-cluster Mimir or Cortex |
| `environment` | `production`, `staging`, `homelab` | Separates environments in multi-tenant receivers |
| `instance` | `signet-01.dc1.example.com` | Distinguishes Signet instances when running multiple per cluster |
| `region` | `eu-west-1` | Required by multi-region observability backends for routing |

Configure external labels in `signet.yaml`:

```yaml
remote_write:
  enabled: true
  endpoint: "https://mimir.internal.example.com/api/v1/push"
  external_labels:
    cluster: "prod-eu-west-1"
    environment: "production"
    instance: "signet-01.dc1.example.com"
```

**Anti-patterns to avoid:**

- **Per-scrape variable labels** (timestamps, request IDs, UUIDs): every distinct value creates a new series at the receiver. These are not external labels in any meaningful sense — they are cardinality bombs. Do not use them.
- **Labels duplicating existing metric labels** (`subnet`, `ip`, `mac`, `hostname`): the remote write converter will return a `LabelCollisionError` for the offending metric family and drop it. The collision is logged with the metric name, the colliding label key, and both values. Remove the duplicate from `external_labels` or rename it.
- **Labels reserved by the receiver** (`__name__`, `__address__`, `__metrics_path__`, and any label beginning with `__`): these are Prometheus internal labels. The wire protocol rejects them.

---

## 4. FIPS compliance for the remote write path

Operators in regulated environments need to verify that enabling remote write does not break their FIPS posture. The answer is that it does not, and the reasoning is verifiable.

**Snappy compression is not a cryptographic primitive.** The remote write protocol uses Snappy to compress the protobuf payload before transmission. Snappy provides data compression only — it has no security properties, makes no confidentiality guarantees, and is not subject to FIPS 140-2 or FIPS 140-3 cryptographic algorithm requirements. Its presence in the remote write path is FIPS-irrelevant. Compliance reviewers should treat it the same as gzip or zstd: a transport encoding, not a cryptographic operation.

**TLS for the remote write client uses Go's stdlib `crypto/tls`.** The remote write client opens an HTTPS connection to the configured endpoint using the same TLS stack as Signet's `/metrics` listener. When Signet is built with `GOEXPERIMENT=boringcrypto`, the stdlib's cryptographic operations — key generation, cipher suite negotiation, certificate chain validation, RNG sourcing — all go through the BoringCrypto FIPS module. The remote write client inherits this automatically because it uses the same stdlib; there is no separate crypto path to audit.

**`signet_exporter_fips_enabled` is the authoritative runtime indicator.** This metric (introduced in v0.4.0) reports `1` when the binary was built with BoringCrypto active. A value of `1` means all cryptographic operations in the binary — including the remote write TLS client — are going through the FIPS-validated module. Query it from `/metrics`:

```
signet_exporter_fips_enabled 1
```

**Verifying end-to-end FIPS coverage:**

1. Build with `GOEXPERIMENT=boringcrypto`: `make build-fips`
2. Confirm `signet_exporter_fips_enabled == 1` in `/metrics`
3. Enable remote write and configure an mTLS endpoint
4. Capture a TLS handshake with `tcpdump -i any -w /tmp/rw-handshake.pcap host <receiver-ip> and port <receiver-port>`
5. Decode in Wireshark and verify the negotiated cipher suite is in the FIPS-approved set (AES-128-GCM-SHA256, AES-256-GCM-SHA384, or equivalent approved suites). Alternatively, check the receiver's TLS handshake logs if the receiver records them.

**mTLS auth is the recommended choice in FIPS environments.** Bearer tokens stored at rest in files (`auth.bearer_token_file`) are outside the scope of FIPS validation — they are pre-shared secrets managed by operator procedure, not cryptographic keys. mTLS client certificates are issued by the same PKI infrastructure as Signet's server certs, meaning their lifecycle (issuance, rotation, revocation) follows the same process as the rest of Signet's TLS posture and sits within the FIPS-validated crypto path. For compliance reviews where the auditor asks "how are authentication credentials protected?", mTLS has a cleaner answer than bearer tokens.

---

## 5. mTLS configuration for remote write

**Reusing existing Signet certificates.** The `auth.client_cert_file` and `auth.client_key_file` configuration fields can point at the same certificates used by Signet's TLS listener — operators with a single internal CA and per-instance cert typically point both at the same files. This works when the receiver's CA bundle includes the same issuer that signed Signet's server cert. Configuration:

```yaml
remote_write:
  enabled: true
  endpoint: "https://mimir.internal.example.com/api/v1/push"
  auth:
    type: mtls
    client_cert_file: "/etc/signet/tls/server.pem"
    client_key_file:  "/etc/signet/tls/server-key.pem"
    ca_cert_file:     "/etc/signet/tls/ca.pem"
```

**Separate trust domains.** When Signet's TLS listener uses one internal CA and the remote write endpoint uses a different CA (for example, the receiver is operated by a separate team with its own PKI), use distinct paths under `/etc/signet/tls/remote-write/`. The convention:

```
/etc/signet/tls/
  server.pem          server-key.pem   ca.pem     # listener certs
  remote-write/
    client.pem        client-key.pem   ca.pem     # remote write client certs
```

This makes the two trust domains visually distinct in the filesystem and simplifies cert rotation — rotating the listener certs does not accidentally affect the remote write client and vice versa.

**Cert rotation.** Sending `SIGHUP` to Signet (`systemctl reload signet-exporter`) causes the remote write client to re-read the cert, key, and CA files from disk. In-flight requests complete using the old TLS configuration. New connections after the reload use the new certificates. This matches Phase 4's listener cert rotation behavior and uses the same operator workflow — `systemctl reload` is the single command for both.

**System root CA pool vs. explicit pinning.** The default behavior when `auth.ca_cert_file` is configured is explicit pinning: only the configured CA is trusted for the remote write endpoint. To use the system root CA pool instead (appropriate for Grafana Cloud, commercial SaaS receivers, or any receiver whose TLS cert chains to a public CA), use `auth.type: bearer` or `auth.type: basic` without a `ca_cert_file` — the stdlib defaults to the system root pool when no CA file is configured. Do not set `auth.ca_cert_file` to a system bundle path; let the stdlib handle it.

---

## 6. Scaling considerations

**Symptoms of approaching receiver limits.** Watch for these signals before the receiver starts rejecting samples:

- `signet_remote_write_queue_size` persistently growing rather than draining between scrape cycles
- `signet_remote_write_failures_total{reason="5xx"}` incrementing — the receiver is throttling or returning 503
- `signet_remote_write_send_duration_seconds` p99 trending upward over hours, indicating the receiver is slow to acknowledge

**Horizontal scaling.** Deploy multiple Signet instances, each scanning a disjoint set of subnets via per-instance config. Use `external_labels.instance` to distinguish the streams at the receiver. Each instance sends independently to the same remote write endpoint; the receiver merges the streams. This scales linearly and is the primary scale-out path for Signet.

**When to add Alloy in front.** If a single Signet instance must fan out to multiple backends simultaneously — for example, a primary Mimir for operational alerting and a secondary cold-storage receiver for compliance archival — Alloy is the right tool. Signet's native remote write is single-endpoint by design; multi-endpoint fan-out is deferred to v0.7.0. Alloy's `prometheus.remote_write` component supports multiple endpoints natively and handles the fan-out, retries, and queue management per-backend.

**Federation pattern for very large deployments.** Deployments covering /14 or larger subnet aggregates should follow the standard Prometheus federation or Thanos/Cortex receive patterns. At that scale, the infrastructure architecture conversation should already be happening. Signet's role at /14+ is to be a well-behaved remote-write source within the existing pattern: all metrics carry `subnet` labels suitable for hierarchical aggregation, and `signet_active_series_estimate` gives each instance's contribution to the total series budget.
