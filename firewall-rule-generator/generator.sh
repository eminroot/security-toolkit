#!/bin/bash
# Firewall Rule Auto-Generator
# Generates iptables rules based on common security best practices

OUTPUT="${1:-./firewall_rules.sh}"
INTERFACE="${2:-eth0}"

cat > "$OUTPUT" << 'RULES'
#!/bin/bash
# Auto-generated firewall rules - REVIEW BEFORE APPLYING

# Flush existing rules
iptables -F
iptables -X

# Default policies
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Allow loopback
iptables -A INPUT -i lo -j ACCEPT

# Allow established connections
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow SSH (limit to prevent brute force)
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --set --name SSH
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 60 --hitcount 4 --name SSH -j DROP
iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# Allow HTTP/HTTPS
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# Drop invalid packets
iptables -A INPUT -m state --state INVALID -j DROP

# Log dropped packets
iptables -A INPUT -j LOG --log-prefix "FW-DROP: " --log-level 4
RULES

echo "[+] Generated $OUTPUT"
echo "[!] Edit INTERFACE variable and review before: iptables-restore or source $OUTPUT"
