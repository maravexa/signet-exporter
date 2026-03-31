#!/usr/bin/env bash
# generate-sbom.sh — generate a CycloneDX SBOM using syft
# Prerequisites: syft must be installed (https://github.com/anchore/syft)
#
# Usage: ./scripts/generate-sbom.sh [output-dir]

set -euo pipefail

OUTPUT_DIR="${1:-dist}"
BINARY="${OUTPUT_DIR}/signet-exporter"
SBOM_FILE="${OUTPUT_DIR}/signet-exporter.sbom.json"

if ! command -v syft &>/dev/null; then
    echo "ERROR: syft is not installed. Install from https://github.com/anchore/syft" >&2
    exit 1
fi

if [[ ! -f "${BINARY}" ]]; then
    echo "ERROR: binary not found at ${BINARY}. Run 'make build' first." >&2
    exit 1
fi

echo "Generating SBOM for ${BINARY}..."
syft "${BINARY}" -o cyclonedx-json="${SBOM_FILE}"
echo "SBOM written to ${SBOM_FILE}"
