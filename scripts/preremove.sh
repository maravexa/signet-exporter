#!/bin/sh
# shellcheck shell=sh
set -e

# Stop and disable the service if systemd is available and the unit is loaded.
if command -v systemctl >/dev/null 2>&1; then
    if systemctl is-active --quiet signet-exporter 2>/dev/null; then
        systemctl stop signet-exporter
    fi
    if systemctl is-enabled --quiet signet-exporter 2>/dev/null; then
        systemctl disable signet-exporter
    fi
fi
