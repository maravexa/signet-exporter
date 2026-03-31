#!/usr/bin/env bash
# verify-release.sh — verify a signet-exporter release artifact with cosign
# Prerequisites: cosign must be installed (https://github.com/sigstore/cosign)
#
# Usage: ./scripts/verify-release.sh <artifact> <signature> <cert>

set -euo pipefail

ARTIFACT="${1:-}"
SIGNATURE="${2:-}"
CERT="${3:-}"

if [[ -z "${ARTIFACT}" || -z "${SIGNATURE}" || -z "${CERT}" ]]; then
    echo "Usage: $0 <artifact> <signature> <cert>" >&2
    echo "  artifact  — path to the binary or archive to verify" >&2
    echo "  signature — path to the .sig file produced by cosign" >&2
    echo "  cert      — path to the signing certificate (.pem)" >&2
    exit 1
fi

if ! command -v cosign &>/dev/null; then
    echo "ERROR: cosign is not installed. Install from https://github.com/sigstore/cosign" >&2
    exit 1
fi

echo "Verifying ${ARTIFACT}..."
cosign verify-blob \
    --signature "${SIGNATURE}" \
    --certificate "${CERT}" \
    --certificate-identity-regexp "https://github.com/maravexa/signet-exporter" \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
    "${ARTIFACT}"

echo "Verification successful."
