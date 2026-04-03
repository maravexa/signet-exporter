#!/usr/bin/env bash
#
# update-oui.sh — Download and install the IEEE OUI database for signet-exporter
#
# Usage:
#   sudo /usr/lib/signet/update-oui.sh
#
# This script downloads a fresh copy of the IEEE OUI (Organizationally Unique
# Identifier) database from https://standards-oui.ieee.org/oui/oui.txt, validates
# it, and installs it to /usr/share/signet/oui.txt.
#
# For air-gapped systems, manually copy an oui.txt file to /usr/share/signet/oui.txt.
# The IEEE OUI database (~500KB) is available from:
#   https://standards-oui.ieee.org/oui/oui.txt
#
# After installation, restart signet-exporter to pick up the new database:
#   systemctl restart signet-exporter
#

set -euo pipefail

OUI_URL="https://standards-oui.ieee.org/oui/oui.txt"
INSTALL_DIR="/usr/share/signet"
INSTALL_PATH="${INSTALL_DIR}/oui.txt"
TIMESTAMP_PATH="${INSTALL_DIR}/oui.txt.updated"
OWNER="signet:signet"

MIN_SIZE_BYTES=102400   # 100KB
MIN_HEX_LINES=1000

TMPFILE=""
trap 'rm -f "${TMPFILE}"' EXIT

# --- Preflight checks ---

if ! command -v curl &>/dev/null; then
    echo "ERROR: curl is not installed. Install it with:" >&2
    echo "  apt install curl" >&2
    exit 1
fi

if [[ ! -w "${INSTALL_DIR}" ]] && [[ "${EUID}" -ne 0 ]]; then
    echo "ERROR: This script must be run as root (or with write access to ${INSTALL_DIR})." >&2
    echo "  sudo ${0}" >&2
    exit 1
fi

# Ensure the install directory exists
install -d -m 755 "${INSTALL_DIR}"

# --- Download ---

TMPFILE="$(mktemp /tmp/oui.txt.XXXXXX)"
echo "Downloading OUI database from ${OUI_URL} ..."

if ! curl --fail --silent --show-error --location \
        --connect-timeout 30 --max-time 120 \
        -o "${TMPFILE}" "${OUI_URL}"; then
    echo "ERROR: Download failed." >&2
    exit 1
fi

# --- Validate ---

ACTUAL_SIZE=$(stat -c '%s' "${TMPFILE}" 2>/dev/null || stat -f '%z' "${TMPFILE}")
if [[ "${ACTUAL_SIZE}" -lt "${MIN_SIZE_BYTES}" ]]; then
    echo "ERROR: Downloaded file is too small (${ACTUAL_SIZE} bytes, expected at least ${MIN_SIZE_BYTES})." >&2
    echo "  The download may have been truncated or returned an error page." >&2
    exit 1
fi

HEX_LINE_COUNT=$(grep -c '(hex)' "${TMPFILE}" || true)
if [[ "${HEX_LINE_COUNT}" -lt "${MIN_HEX_LINES}" ]]; then
    echo "ERROR: Downloaded file contains only ${HEX_LINE_COUNT} OUI entries (expected at least ${MIN_HEX_LINES})." >&2
    echo "  The file may be malformed or not a valid OUI database." >&2
    exit 1
fi

# --- Install ---

mv "${TMPFILE}" "${INSTALL_PATH}"
TMPFILE=""  # Already moved; clear trap target

TIMESTAMP="$(date -Iseconds)"
echo "${TIMESTAMP}" > "${TIMESTAMP_PATH}"

chown "${OWNER}" "${INSTALL_PATH}" "${TIMESTAMP_PATH}" 2>/dev/null || true
chmod 0644 "${INSTALL_PATH}" "${TIMESTAMP_PATH}"

# --- Summary ---

FILE_SIZE_KB=$(( ACTUAL_SIZE / 1024 ))

echo ""
echo "OUI database updated successfully."
echo "  Entries:   ${HEX_LINE_COUNT} OUI entries"
echo "  File size: ${FILE_SIZE_KB} KB"
echo "  Timestamp: ${TIMESTAMP}"
echo "  Installed: ${INSTALL_PATH}"
echo ""
echo "The signet-exporter loads the OUI database at startup."
echo "Restart the service to pick up the new data: systemctl restart signet-exporter"
