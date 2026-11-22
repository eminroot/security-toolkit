# Failed Login Counter with IP Blocking

Counts failed SSH/login attempts per IP address and optionally blocks repeat offenders using iptables.

## Usage

```bash
sudo ./counter.sh [log_file] [threshold] [block_duration]
```

Run as root for iptables blocking. Default threshold: 5 failures.
