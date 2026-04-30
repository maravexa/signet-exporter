# Alloy Integration Examples

If you are running Alloy, scrape Signet with Alloy. Use Signet's native remote write only when running Alloy alongside is operationally undesirable — typically air-gapped deployments, single-binary compliance constraints, or environments where qualifying a second binary is non-trivial.

## When to use which

- Already running Alloy? Use these examples.
- No existing Alloy deployment, want minimal infrastructure? Native remote write.
- Air-gapped or single-binary preferred? Native remote write.
- Need metric relabeling, multi-backend fan-out, service discovery, or OTLP? Alloy.
- Compliance review prefers a smaller dependency surface in the metrics path? Native remote write.

## The examples

**`basic-scrape.alloy`** is the minimal working configuration: one Alloy instance scrapes one Signet instance over mTLS and forwards to a generic Prometheus-compatible remote_write endpoint. Before deploying, replace the `prometheus.example.com` URL with your real receiver and verify that the `/etc/alloy/tls/` paths point at certificates whose issuer matches Signet's `tls.client_ca_file`.

**`grafana-cloud.alloy`** targets Grafana Cloud Prometheus. Before deploying, replace `prometheus-prod-XX-prod-REGION-X.grafana.net` with the push URL from the Grafana Cloud portal, set `username` to your numeric instance ID, write your Grafana Cloud token to `/etc/alloy/grafana-cloud-token` (mode 0600, owned by the Alloy process user), and edit the `external_labels` block to match your environment.

**`mimir-self-hosted.alloy`** targets a self-hosted Mimir cluster with mTLS and tenant scoping. Before deploying, replace `mimir.internal.example.com` with your Mimir gateway URL, populate `/etc/alloy/tls/mimir/` with certificates issued by your Mimir CA, set `X-Scope-OrgID` to your tenant ID (or remove the `headers` block entirely on single-tenant clusters), and edit the `external_labels` block.

**`cardinality-conscious.alloy`** is the canonical reference for large deployments. It demonstrates two reduction patterns wired into a single working pipeline: dropping `signet_port_open` to eliminate O(hosts × ports) series, and staggering scrape frequency so the high-cardinality `signet_host_info` enrichment metric is sampled at 5-minute intervals while health and utilization metrics stay at 60 seconds. Before deploying, replace the placeholder `prometheus.example.com` URL, populate `/etc/alloy/tls/` and `/etc/alloy/tls/backend/`, and confirm the keep regex in `prometheus.relabel "keep_fast_metrics"` matches the metrics your dashboards and alerts query.

## mTLS to Signet

Alloy authenticates to Signet by presenting a client certificate to Signet's TLS listener. The chain has three requirements:

- The CA that signed Alloy's client cert must match the CA configured at Signet's `tls.client_ca_file`.
- The CA that signed Signet's server cert must be present in Alloy's scrape `tls_config.ca_file`.
- Operators typically reuse the same internal CA for both ends — the dev cert chain produced by `signet-exporter --generate-certs` is sufficient for this and is the recommended starting point.

See the [TLS section of the main Signet README](../../README.md#mtls) for cert generation, rotation, and the `client_auth_policy` settings.

## Cardinality reduction patterns

The two patterns demonstrated in `cardinality-conscious.alloy`:

- **Drop `signet_port_open` entirely.** Eliminates O(hosts × ports) series. At 1024 hosts × 20 ports, this removes 20,480 series. At a /16 with a 10-port scan list, it removes on the order of 250,000 series. Use when port-presence is not part of your inventory model.
- **Stagger scrape frequency by metric.** `signet_host_info` carries the high-churn `hostname` and `vendor` labels. Sampling it every 5 minutes instead of every 60 seconds halves (or better) ingestion volume for that metric without changing series-volume-at-rest. Use when your dashboards and alerts join `signet_host_info` for enrichment but tolerate a 5-minute-old enrichment view.

See the [Cardinality and Scaling section of the main Signet README](../../README.md#cardinality-and-scaling) for the full guidance, network-size table, and the `signet_active_series_estimate` metric for measuring real deployments.

## Troubleshooting

- **Alloy can't connect to Signet.** Check cert paths, the cert chain, and that Signet's `tls.client_ca_file` was signed by the same issuer as Alloy's client cert.
- **Scrape times out.** Signet's `/metrics` is fast (cached state), so a timeout indicates network or auth handshake failure rather than slow rendering. Check `signet_scan_duration_seconds` to rule out a slow scan blocking the scrape.
- **Series rejected at receiver.** This is almost always a label cardinality limit at the receiver. Apply the patterns from `cardinality-conscious.alloy`.
- **External labels missing.** Signet does not inject any external labels — they must be set in `prometheus.remote_write` per the no-magic policy. Add an `external_labels` block to the relevant remote_write component.
- **Why are some metrics missing?** Using `cardinality-conscious.alloy`? Verify that the `metric_relabel_configs` keep regex matches the metric name you expect to see.

## References

- [Alloy upstream documentation](https://grafana.com/docs/alloy/latest/)
- [Signet main README](../../README.md)
- [Signet cardinality and scaling guidance](../../README.md#cardinality-and-scaling)
- [Signet native remote write configuration](../../configs/signet.example.yaml)

## Validating the examples

The four `.alloy` files in this directory are formatted for Alloy syntax (formerly River). To validate before deploying:

```sh
# Format check (exits non-zero if reformatting would change anything)
alloy fmt --test examples/alloy/*.alloy

# Per-file syntax/semantic validation
for f in examples/alloy/*.alloy; do
    alloy validate "$f" || exit 1
done
```

If `alloy` is not installed locally, the configurations can be validated by deploying them to a test Alloy instance — Alloy refuses to start with an invalid config and writes the parse error to stderr.
