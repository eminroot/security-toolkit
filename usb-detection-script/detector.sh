#!/bin/bash
# Unauthorized USB Detection Script
# Monitors for USB device connections

AUTHORIZED_FILE="${1:-./authorized_usb.txt}"
LOG_FILE="${2:-/tmp/usb_connections.log}"

echo "[*] USB Detection Script"
echo "[*] Logging to $LOG_FILE"
echo ""

# Create udev rule or use existing monitoring
# This script checks current USB devices

echo "=== Currently connected USB devices ==="
lsusb 2>/dev/null

echo ""
echo "=== USB block devices ==="
lsblk -o NAME,SIZE,TYPE,MOUNTPOINT 2>/dev/null | grep -E "disk|part"

echo ""
echo "=== Dmesg USB events (recent) ==="
dmesg 2>/dev/null | grep -i usb | tail -20

# For real-time: use udevadm monitor or inotify
# udevadm monitor --environment --udev -s block

echo "$(date): USB check - $(lsusb 2>/dev/null | wc -l) devices" >> "$LOG_FILE"
