# Grafana Dashboard — Signet Exporter

Pre-built Grafana dashboard for Signet Exporter metrics.

## Prerequisites

- A Prometheus datasource configured in Grafana and actively scraping Signet's `/metrics` endpoint.
- Signet Exporter v0.3.1 or later.

## Import Instructions

### Method 1 — Grafana UI

1. In Grafana, navigate to **Dashboards → Import**.
2. Click **Upload JSON file** and select `grafana/signet-overview.json`, or paste the file contents into the JSON field.
3. Select your Prometheus datasource when prompted.
4. Click **Import**.

### Method 2 — Provisioning

1. Copy `signet-overview.json` to Grafana's dashboard provisioning directory (e.g. `/etc/grafana/provisioning/dashboards/`).
2. Create (or update) a YAML provider config in `/etc/grafana/provisioning/dashboards/` pointing at the directory:

```yaml
apiVersion: 1
providers:
  - name: signet
    type: file
    options:
      path: /etc/grafana/provisioning/dashboards
```

3. Restart Grafana (or trigger a provisioning reload). The dashboard will appear automatically.

## Dashboard Variables

The dashboard expects the following template variables:

| Variable | Description | Default |
|---|---|---|
| `job` | Prometheus job name for the Signet scrape target | `signet-exporter` |
| `subnet` | Populated from `signet_subnet_addresses_total` labels | *(all)* |

Adjust the `job` variable to match the `job_name` you configured in your Prometheus scrape config.

## Panels Overview

| Section | Description |
|---|---|
| **Host Inventory** | Live host count per subnet, MAC-IP binding table, last-seen timestamps |
| **Scan Performance** | ARP, ICMP, DNS, and port scan durations; scan cycle latency |
| **Subnet Utilization** | Address space usage per subnet (used vs. total) |
| **Security Alerts** | Unauthorized device detections, duplicate IP alerts, MAC churn rate |
| **DNS Health** | DNS consistency check failures and mismatch counts per host |

## Customization Notes

Alert thresholds for the **Security Alerts** panels (unauthorized devices, duplicate IPs) are set to conservative defaults. Tune the thresholds to match your environment's normal baseline before enabling Grafana alerts based on these panels.

<!-- TODO: Add dashboard screenshot -->
