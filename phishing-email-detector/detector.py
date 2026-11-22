#!/usr/bin/env python3
"""
Phishing Email Detector
Heuristic-based analysis with header inspection, link extraction,
domain reputation checks, and weighted scoring.
"""

import re
import sys
from dataclasses import dataclass, field
from email import policy
from email.parser import BytesParser
from pathlib import Path
from urllib.parse import urlparse
from typing import List, Tuple, Optional


@dataclass
class PhishingResult:
    score: int
    max_score: int
    verdict: str
    findings: List[Tuple[str, int, str]] = field(default_factory=list)
    suspicious_links: List[str] = field(default_factory=list)
    header_issues: List[str] = field(default_factory=list)


# (pattern, weight, description)
CONTENT_RULES = [
    (r"\burgent\b|\bimmediately\b|\basap\b", 2, "Urgency language"),
    (r"action required|verify (your )?account|suspend", 3, "Account action"),
    (r"click (here|below|now)", 2, "Click bait"),
    (r"confirm (your )?(identity|password|account)", 3, "Credential request"),
    (r"bit\.ly|tinyurl|goo\.gl|t\.co", 2, "URL shortener"),
    (r"\$\d{2,}|wire transfer|western union|moneygram", 3, "Financial pressure"),
    (r"dear (customer|user|member|valued)", 1, "Impersonal greeting"),
    (r"free (money|gift|prize|winner)", 3, "Too good to be true"),
    (r"your account (has been|will be) (locked|suspended)", 3, "Account lock threat"),
    (r"microsoft|apple|paypal|bank|irs|fedex", 1, "Brand impersonation"),
    (r"limited time|expires (today|soon)", 2, "Time pressure"),
    (r"congratulations|you (have )?won", 2, "Prize scam"),
    (r"reply (to )?this email", 1, "Reply request"),
    (r"<\s*script|javascript:", 4, "Malicious script"),
    (r"password.*expir|credential.*verif", 3, "Credential phishing"),
]

# Suspicious TLDs
SUSPICIOUS_TLDS = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".work"}


def extract_links(text: str) -> List[str]:
    """Extract URLs from text."""
    url_pattern = r"https?://[^\s<>\"'\\)]+"
    return re.findall(url_pattern, text)


def check_link(link: str) -> Tuple[bool, str]:
    """Check if link is suspicious."""
    try:
        parsed = urlparse(link)
        domain = parsed.netloc.lower()
        if any(tld in domain for tld in SUSPICIOUS_TLDS):
            return True, "Suspicious TLD"
        if re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", domain):
            return True, "IP address in URL"
        if len(parsed.path) > 100:
            return True, "Very long path"
        return False, ""
    except Exception:
        return True, "Parse error"


def analyze_headers(headers: dict) -> List[str]:
    """Analyze email headers for spoofing indicators."""
    issues = []
    if "From" in headers:
        from_val = str(headers.get("From", ""))
        if "=" in from_val and "?" in from_val:
            issues.append("Encoded From header (possible spoofing)")
    if "Reply-To" in headers and "From" in headers:
        from_dom = re.search(r"@([\w.-]+)", str(headers.get("From", "")))
        reply_dom = re.search(r"@([\w.-]+)", str(headers.get("Reply-To", "")))
        if from_dom and reply_dom and from_dom.group(1) != reply_dom.group(1):
            issues.append("Reply-To domain differs from From")
    return issues


def score_content(text: str) -> Tuple[int, List[Tuple[str, int, str]]]:
    """Score email content."""
    text_lower = text.lower()
    total = 0
    findings = []
    for pattern, weight, desc in CONTENT_RULES:
        if re.search(pattern, text_lower):
            total += weight
            findings.append((desc, weight, pattern))
    return total, findings


def analyze_email(
    text: str,
    headers: Optional[dict] = None,
) -> PhishingResult:
    """Full phishing analysis."""
    score, findings = score_content(text)
    links = extract_links(text)
    suspicious_links = []
    for link in links:
        sus, reason = check_link(link)
        if sus:
            suspicious_links.append(f"{link[:60]}... ({reason})")
            score += 2

    header_issues = []
    if headers:
        header_issues = analyze_headers(headers)
        score += len(header_issues)

    max_score = sum(r[1] for r in CONTENT_RULES) + 20
    normalized = min(100, int(score * 100 / max(1, max_score)))

    if normalized >= 60 or len(suspicious_links) >= 2:
        verdict = "LIKELY PHISHING"
    elif normalized >= 40:
        verdict = "SUSPICIOUS"
    else:
        verdict = "POSSIBLY SAFE"

    return PhishingResult(
        score=normalized,
        max_score=100,
        verdict=verdict,
        findings=[(d, w, p) for d, w, p in findings],
        suspicious_links=suspicious_links,
        header_issues=header_issues,
    )


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Phishing email detector")
    parser.add_argument("file", nargs="?", help="Email file (or stdin)")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    if args.file:
        path = Path(args.file)
        if not path.exists():
            print(f"Error: File not found: {path}")
            sys.exit(1)
        raw = path.read_bytes()
        try:
            msg = BytesParser(policy=policy.default).parsebytes(raw)
            body = msg.get_body(preferencelist=("plain", "html"))
            text = body.get_content() if body else str(msg)
            headers = dict(msg.headers)
        except Exception:
            text = path.read_text(errors="replace")
            headers = None
    else:
        text = sys.stdin.read()
        headers = None

    result = analyze_email(text, headers)

    print("=" * 55)
    print("PHISHING EMAIL ANALYSIS")
    print("=" * 55)
    print(f"Score:   {result.score}/100")
    print(f"Verdict: {result.verdict}")
    print()
    if result.findings:
        print("Findings:")
        for desc, weight, _ in result.findings:
            print(f"  - [{weight}] {desc}")
    if result.suspicious_links:
        print("\nSuspicious links:")
        for link in result.suspicious_links[:5]:
            print(f"  - {link}")
    if result.header_issues:
        print("\nHeader issues:")
        for issue in result.header_issues:
            print(f"  - {issue}")
    print("=" * 55)


if __name__ == "__main__":
    main()
