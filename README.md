# Security Toolkit

Sixty small blue-team and pentest utilities in Python and Bash that I wrote while studying information security. Each folder is self-contained with its own README and usage. Run them only on systems you own or are authorised to test.

## Network

| Tool | What it does |
|---|---|
| [`active-connection-monitor`](active-connection-monitor/) | Real-time monitor of active network connections, listening ports, and top connecting IPs. |
| [`banner-grabbing-tool`](banner-grabbing-tool/) | Retrieves service banners from common ports (SSH, HTTP, FTP, etc.) for service fingerprinting. |
| [`local-network-scanner`](local-network-scanner/) | Discovers active devices on the local network via ping sweep and ARP. |
| [`multi-threaded-port-scanner`](multi-threaded-port-scanner/) | Fast port scanner using Python threading for concurrent connection attempts. |
| [`netcat-port-scanner`](netcat-port-scanner/) | Simple port scanner using netcat (nc) to detect open ports on a target host. |
| [`nmap-report-generator`](nmap-report-generator/) | Runs Nmap scans (ping, port scan, version detection) and generates timestamped reports. |
| [`open-port-watcher`](open-port-watcher/) | Monitors listening ports for changes and alerts when new ports open or close. Useful for detecting unauthorized services. |
| [`packet-sniffer`](packet-sniffer/) | Captures and displays network packets (TCP, UDP, ICMP) using Scapy. Requires root/admin. |
| [`network-traffic-anomaly-detector`](network-traffic-anomaly-detector/) | Detects anomalies (e.g., high connection counts from single IP) using packet capture. Run as root. |
| [`wifi-deauth-detector`](wifi-deauth-detector/) | Detects 802.11 deauthentication frames (potential WiFi attack). Requires monitor mode. Run as root. |
| [`dos-detection`](dos-detection/) | Monitors established connections per IP and alerts when an IP exceeds the threshold (potential DoS). |
| [`firewall-rule-generator`](firewall-rule-generator/) | Generates iptables firewall rules based on security best practices. Review before applying! |
| [`ip-blacklist-checker`](ip-blacklist-checker/) | Checks an IP address against known threat intelligence blacklists (e.g., ipsum). |
| [`ip-geolocation-tracker`](ip-geolocation-tracker/) | Looks up IP address to geolocation (country, city, ISP) using ip-api.com. |
| [`mini-ids`](mini-ids/) | Pattern-based IDS using Scapy. Detects suspicious payloads (path traversal, SQLi, XSS, etc.). Run as root. |
| [`simple-honeypot`](simple-honeypot/) | A minimal honeypot that listens on a port, presents a fake SSH banner, and logs connection attempts for analysis. |
| [`subdomain-enumerator`](subdomain-enumerator/) | Enumerates subdomains using DNS resolution with a common wordlist. |

## Linux host hardening

| Tool | What it does |
|---|---|
| [`cron-security-auditor`](cron-security-auditor/) | Audits system and user crontab entries for suspicious patterns and security misconfigurations. |
| [`file-integrity-checker`](file-integrity-checker/) | Creates baseline hashes of files and verifies integrity to detect modifications. |
| [`hidden-file-detector`](hidden-file-detector/) | Finds hidden files and directories that could indicate hidden malware or attacker artifacts. |
| [`kernel-vulnerability-checker`](kernel-vulnerability-checker/) | Reports kernel version for manual CVE cross-reference. Use with CVE databases for vulnerability assessment. |
| [`linux-security-audit`](linux-security-audit/) | Comprehensive security audit: users, ports, services, SUID, permissions, updates, SSH, firewall. |
| [`service-security-scanner`](service-security-scanner/) | Scans critical security services (SSH, firewall, fail2ban) and identifies risky running services. |
| [`ssh-hardening-checker`](ssh-hardening-checker/) | Audits sshd_config against security best practices and hardening recommendations. |
| [`suid-enumerator`](suid-enumerator/) | Finds files with the SUID bit set that could be exploited for privilege escalation. |
| [`suspicious-cron-finder`](suspicious-cron-finder/) | Finds cron jobs containing suspicious patterns like remote code execution, temp file usage, or privilege escalation. |
| [`suspicious-process-monitor`](suspicious-process-monitor/) | Monitors running processes for patterns associated with reverse shells, backdoors, and malicious code execution. |
| [`suspicious-user-finder`](suspicious-user-finder/) | Identifies potentially compromised accounts: UID 0 duplicates, no-password accounts, recent logins. |
| [`weak-permission-finder`](weak-permission-finder/) | Finds files and directories with insecure permissions: world-readable keys, world-writable files, 777 dirs. |
| [`world-writable-finder`](world-writable-finder/) | Finds files and directories with world-writable permissions (security risk). |
| [`usb-detection-script`](usb-detection-script/) | Monitors and logs USB device connections. Extend with udev rules for real-time alerts. |
| [`reverse-shell-detector`](reverse-shell-detector/) | Detects processes and network connections indicative of reverse shells or backdoors. |

## Logs, detection and threat intel

| Tool | What it does |
|---|---|
| [`failed-login-counter`](failed-login-counter/) | Counts failed SSH/login attempts per IP address and optionally blocks repeat offenders using iptables. |
| [`log-analyzer`](log-analyzer/) | Analyzes log files for security-relevant patterns (failed logins, errors, attacks). |
| [`log-anomaly-scanner`](log-anomaly-scanner/) | Scans log directories for suspicious patterns including authentication failures, permission issues, and kernel errors. |
| [`log-tampering-detector`](log-tampering-detector/) | Detects potential log tampering by analyzing file stats and timestamp sequences. |
| [`simple-siem-aggregator`](simple-siem-aggregator/) | Aggregates logs from multiple sources, applies pattern detection, and produces a security events report. |
| [`ssh-brute-force-detector`](ssh-brute-force-detector/) | Monitors system auth logs for repeated failed SSH login attempts and alerts on potential brute-force attacks. |
| [`file-hash-malware-scanner`](file-hash-malware-scanner/) | Scans files by SHA256 hash against a malware hash database. Add threat intel hashes to hash-db file. |
| [`phishing-email-detector`](phishing-email-detector/) | Heuristic-based detector for phishing email content. Analyzes text for suspicious patterns. |
| [`threat-intelligence-ioc-checker`](threat-intelligence-ioc-checker/) | Checks IPs/hashes against threat intelligence feeds (e.g., ipsum). |
| [`url-reputation-analyzer`](url-reputation-analyzer/) | Checks URLs/domains against the StevenBlack hosts blocklist for malicious reputation. |
| [`darkweb-leak-monitor`](darkweb-leak-monitor/) | python monitor.py. |
| [`username-osint-checker`](username-osint-checker/) | Checks if a username exists on GitHub, Twitter, Instagram, Reddit (availability enumeration). |

## Web and application security

| Tool | What it does |
|---|---|
| [`http-header-security-checker`](http-header-security-checker/) | Checks websites for presence of security headers (HSTS, CSP, X-Frame-Options, etc.). |
| [`jwt-analyzer`](jwt-analyzer/) | Decodes JWT header and payload, checks for alg:none vulnerability. |
| [`sql-injection-tester`](sql-injection-tester/) | pip install -r requirements.txt. |
| [`xss-payload-tester`](xss-payload-tester/) | Tests URL parameters for reflected XSS. **LAB USE ONLY** - authorized testing only. |
| [`web-vulnerability-scanner`](web-vulnerability-scanner/) | Quick scan for missing security headers and robots.txt disclosure. |
| [`session-hijacking-demo`](session-hijacking-demo/) | Educational tool explaining session hijacking concepts and mitigations. No actual attack code. |
| [`bruteforce-login-simulator`](bruteforce-login-simulator/) | pip install -r requirements.txt. |

## Cryptography and passwords

| Tool | What it does |
|---|---|
| [`digital-signature-verifier`](digital-signature-verifier/) | Verifies file integrity using RSA public key and SHA256 signature. |
| [`encrypted-file-vault`](encrypted-file-vault/) | Encrypt and decrypt files using AES with password-derived keys (PBKDF2). |
| [`hash-cracker`](hash-cracker/) | Cracks MD5, SHA1, SHA256 hashes using a wordlist. Educational/authorized use only. |
| [`password-entropy-calculator`](password-entropy-calculator/) | Calculates password entropy (bits) and strength based on character set diversity and length. |
| [`password-strength-checker`](password-strength-checker/) | Command-line password strength checker evaluating length, character variety, and common patterns. |
| [`secure-chat-app`](secure-chat-app/) | Simple peer-to-peer chat with AES encryption. Share key out-of-band. |
| [`steganography-tool`](steganography-tool/) | LSB steganography - hide and extract text in PNG images. |

## Lab simulations (defensive training only)

| Tool | What it does |
|---|---|
| [`keylogger-lab`](keylogger-lab/) | pip install -r requirements.txt. |
| [`ransomware-simulator`](ransomware-simulator/) | python simulator.py [test_dir] # Simulate only. |

## Use

```bash
git clone https://github.com/eminroot/security-toolkit
cd security-toolkit/<tool>
# Python tools
pip install -r requirements.txt && python <script>.py --help
# Bash tools
chmod +x *.sh && ./<script>.sh
```

## License

MIT
