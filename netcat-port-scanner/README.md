# Port Scanner using Netcat

Simple port scanner using netcat (nc) to detect open ports on a target host.

## Usage

```bash
chmod +x scanner.sh
./scanner.sh [target] [ports] [timeout]
```

Examples:
- `./scanner.sh 192.168.1.1` - Scan 1-1000
- `./scanner.sh 10.0.0.1 20-80` - Scan ports 20-80
- `./scanner.sh localhost 22,80,443` - Scan specific ports
