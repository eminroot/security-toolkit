# SSH Brute-Force Attempt Detector

Monitors system auth logs for repeated failed SSH login attempts and alerts on potential brute-force attacks.

## Usage

```bash
chmod +x detector.sh
./detector.sh [log_file] [threshold] [interval]
```

- `log_file`: Path to auth log (default: /var/log/auth.log)
- `threshold`: Failed attempts before alert (default: 5)
- `interval`: Check interval in seconds (default: 60)

## Requirements

- Linux with auth.log
- Bash
