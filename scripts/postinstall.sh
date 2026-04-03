#!/bin/sh
# shellcheck shell=sh
set -e

# Set CAP_NET_RAW on the binary for raw socket access (ARP scanning).
# This runs on every install/upgrade since capabilities don't survive binary replacement.
setcap cap_net_raw+ep /usr/bin/signet-exporter

# Create the signet system user if it doesn't exist.
# --system: no home directory, no login shell, low UID range.
# The systemd unit runs the exporter as this user.
if ! getent passwd signet >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin signet
fi

# Ensure data directories exist with correct ownership.
install -d -m 750 -o signet -g signet /var/lib/signet
install -d -m 755 /usr/share/signet

# Set ownership on the OUI database if it exists.
if [ -f /usr/share/signet/oui.txt ]; then
    chown signet:signet /usr/share/signet/oui.txt
fi
