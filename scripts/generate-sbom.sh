#!/usr/bin/env bash
# generate-sbom.sh — generate a CycloneDX SBOM using syft
# Prerequisites: syft must be installed (https://github.com/anchore/syft)
#
# Usage: ./scripts/generate-sbom.sh [output-dir]

set -euo pipefail

OUTPUT_DIR="${1:-dist}"
BINARY_NAME="signet-exporter"

if ! command -v syft &>/dev/null; then
    echo "ERROR: syft is not installed. Install from https://github.com/anchore/syft" >&2
    exit 1
fi

# Collect binaries: first check the flat path produced by `make build`,
# then fall back to GoReleaser's per-platform subdirectories.
mapfile -t BINARIES < <(
    find "${OUTPUT_DIR}" -maxdepth 2 -type f -name "${BINARY_NAME}" 2>/dev/null | sort
)

if [[ ${#BINARIES[@]} -eq 0 ]]; then
    echo "ERROR: no '${BINARY_NAME}' binary found under ${OUTPUT_DIR}. Run 'make build' or 'goreleaser build' first." >&2
    exit 1
fi

for BINARY in "${BINARIES[@]}"; do
    # Derive a unique SBOM filename from the binary's parent directory name.
    PARENT="$(basename "$(dirname "${BINARY}")")"
    if [[ "${PARENT}" == "${OUTPUT_DIR}" || "${PARENT}" == "$(basename "${OUTPUT_DIR}")" ]]; then
        SBOM_FILE="${OUTPUT_DIR}/${BINARY_NAME}.sbom.json"
    else
        SBOM_FILE="${OUTPUT_DIR}/${PARENT}.sbom.json"
    fi

    echo "Generating SBOM for ${BINARY}..."
    syft "${BINARY}" -o cyclonedx-json="${SBOM_FILE}"
    echo "SBOM written to ${SBOM_FILE}"
done
