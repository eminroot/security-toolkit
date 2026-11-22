# Simple Honeypot (Fake Login)

A minimal honeypot that listens on a port, presents a fake SSH banner, and logs connection attempts for analysis.

## Usage

```bash
chmod +x honeypot.sh
sudo ./honeypot.sh [port] [log_file]
```

Default port: 2222. Requires root for ports < 1024.
