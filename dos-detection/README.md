# Basic DoS Detection via Connection Count

Monitors established connections per IP and alerts when an IP exceeds the threshold (potential DoS).

## Usage

```bash
chmod +x detector.sh
./detector.sh [threshold] [check_interval_seconds]
```

Default: 100 connections, check every 10s.
