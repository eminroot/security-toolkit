# Open Port Watcher with Alerts

Monitors listening ports for changes and alerts when new ports open or close. Useful for detecting unauthorized services.

## Usage

```bash
chmod +x watcher.sh
./watcher.sh [alert_script]
```

Uses `ss` or `netstat`. Run in background for continuous monitoring.
