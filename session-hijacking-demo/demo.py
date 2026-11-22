#!/usr/bin/env python3
"""Session Hijacking Demo Tool - EDUCATIONAL. Demonstrates cookie/session concepts."""

# EDUCATIONAL: Shows how session cookies work - NOT for malicious use

def show_demo():
    print("""
=== Session Hijacking Demo (Educational) ===

1. Session cookies (e.g., session_id, PHPSESSID) identify logged-in users.
2. If an attacker obtains the cookie (XSS, MITM, sniffing), they can impersonate the user.
3. Mitigations:
   - HttpOnly cookies (no JS access)
   - Secure flag (HTTPS only)
   - SameSite=Strict
   - Short session timeout
   - Regenerate ID on login

This tool does NOT perform actual hijacking.
""")

if __name__ == '__main__':
    show_demo()
