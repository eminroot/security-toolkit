# Simple SIEM-style Log Aggregator

Aggregates logs from multiple sources, applies pattern detection, and produces a security events report.

## Usage

```bash
chmod +x aggregator.sh
./aggregator.sh [log_dir] [output_file]
```

Run via cron for periodic aggregation.
