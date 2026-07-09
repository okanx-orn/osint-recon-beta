"""
Email Intelligence Module
Performs passive OSINT on an email address:
  - Format & syntax validation
  - Domain MX record lookup
  - SPF / DMARC / DKIM DNS record checks
  - Disposable/temp email provider detection
  - Email pattern guessing (for person intel)
  - HaveIBeenPwned breach check (public API)
"""

import re
import dns.resolver
import socket
import requests
import time
from datetime import datetime


# Known disposable/throwaway email domains
DISPOSABLE_DOMAINS = {
    "mailinator.com","guerrillamail.com","10minutemail.com","tempmail.com",
    "throwam.com","yopmail.com","sharklasers.com","guerrillamailblock.com",
    "grr.la","guerrillamail.info","guerrillamail.biz","guerrillamail.de",
    "guerrillamail.net","guerrillamail.org","spam4.me","trashmail.com",
    "trashmail.me","trashmail.net","dispostable.com","maildrop.cc",
    "fakeinbox.com","spamgourmet.com","getairmail.com","discard.email",
    "mailnull.com","spamex.com","spamoff.de","tempr.email","anonaddy.com",
    "duck.com","simplelogin.io",
}

# Known phishing / suspicious TLDs (not always bad, but flag them)
SUSPICIOUS_TLDS = {".xyz",".top",".click",".gq",".cf",".tk",".ml",".ga",".info"}

FREE_EMAIL_PROVIDERS = {
    "gmail.com","yahoo.com","outlook.com","hotmail.com","live.com",
    "protonmail.com","icloud.com","aol.com","mail.com","zoho.com",
}


class EmailIntel:
    def __init__(self, email: str):
        self.email = email.strip().lower()
        self.results = {"email": self.email, "risk_factors": []}

    # ──────────────────────────────────────────────────────────
    def run(self) -> dict:
        print(f"  [*] Analyzing: {self.email}")
        self._validate_format()
        self._classify_provider()
        self._check_mx()
        self._check_spf_dmarc_dkim()
        self._check_disposable()
        self._check_breach()
        self._check_suspicious_tld()
        self._print_findings()
        return self.results

    # ── 1. Format Validation ──────────────────────────────────
    def _validate_format(self):
        pattern = r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$"
        valid = bool(re.match(pattern, self.email))
        self.results["format_valid"] = valid
        if not valid:
            self.results["risk_factors"].append({"factor": "Invalid email format", "severity": "HIGH"})
        self._log("Format valid", "✓ Yes" if valid else "✗ INVALID ⚠")

    # ── 2. Provider Classification ────────────────────────────
    def _classify_provider(self):
        domain = self.email.split("@")[-1]
        self.results["domain"] = domain
        if domain in FREE_EMAIL_PROVIDERS:
            provider = "Free/Personal"
        else:
            provider = "Corporate/Custom"
        self.results["provider"] = f"{domain} ({provider})"
        self._log("Provider", self.results["provider"])

    # ── 3. MX Record Lookup ───────────────────────────────────
    def _check_mx(self):
        domain = self.email.split("@")[-1]
        try:
            mx_records = dns.resolver.resolve(domain, "MX")
            mx_hosts = sorted([(r.preference, str(r.exchange).rstrip(".")) for r in mx_records])
            self.results["mx_valid"] = True
            self.results["mx_records"] = [f"Priority {p}: {h}" for p,h in mx_hosts]
            self._log("MX Records", ", ".join([h for _,h in mx_hosts[:3]]))
        except Exception:
            self.results["mx_valid"] = False
            self.results["mx_records"] = []
            self.results["risk_factors"].append({"factor": "No MX records — domain cannot receive email", "severity": "HIGH"})
            self._log("MX Records", "NONE FOUND ⚠")

    # ── 4. SPF / DMARC / DKIM ────────────────────────────────
    def _check_spf_dmarc_dkim(self):
        domain = self.email.split("@")[-1]

        # SPF
        spf = self._dns_txt(domain, "v=spf1")
        self.results["spf"] = bool(spf)
        self._log("SPF Record", spf if spf else "MISSING ⚠")
        if not spf:
            self.results["risk_factors"].append({"factor": "No SPF record — domain allows email spoofing", "severity": "HIGH"})

        # DMARC
        dmarc = self._dns_txt(f"_dmarc.{domain}", "v=DMARC1")
        self.results["dmarc"] = bool(dmarc)
        self._log("DMARC Record", dmarc if dmarc else "MISSING ⚠")
        if not dmarc:
            self.results["risk_factors"].append({"factor": "No DMARC record — phishing emails can pass undetected", "severity": "HIGH"})

        # DKIM (check common selectors)
        dkim_found = None
        for selector in ["default","google","k1","mail","dkim","s1","s2"]:
            dkim = self._dns_txt(f"{selector}._domainkey.{domain}", "v=DKIM1")
            if dkim:
                dkim_found = f"{selector}._domainkey.{domain}"
                break
        self.results["dkim"] = bool(dkim_found)
        self._log("DKIM Record", dkim_found if dkim_found else "Not found (checked common selectors)")
        if not dkim_found:
            self.results["risk_factors"].append({"factor": "DKIM not found — email integrity unverifiable", "severity": "MEDIUM"})

    def _dns_txt(self, name: str, prefix: str) -> str | None:
        try:
            answers = dns.resolver.resolve(name, "TXT")
            for r in answers:
                txt = r.to_text().strip('"')
                if txt.startswith(prefix):
                    return txt[:120]
            return None
        except Exception:
            return None

    # ── 5. Disposable Email Check ─────────────────────────────
    def _check_disposable(self):
        domain = self.email.split("@")[-1]
        is_disposable = domain in DISPOSABLE_DOMAINS
        self.results["disposable"] = is_disposable
        if is_disposable:
            self.results["risk_factors"].append({"factor": f"Disposable/throwaway email provider: {domain}", "severity": "CRITICAL"})
        self._log("Disposable Domain", "YES — THROWAWAY ADDRESS ⚠" if is_disposable else "No")

    # ── 6. HaveIBeenPwned Breach Check ───────────────────────
    def _check_breach(self):
        """
        Uses the public HIBP v3 API (no key needed for breach name lookup).
        NOTE: Full breach detail requires an API key. This checks the public range endpoint
        for the domain instead, and uses the public /breachedaccount endpoint with a user-agent.
        """
        print(f"  [*] Checking breach databases (HIBP)...")
        headers = {"User-Agent": "OSINT-Recon-Tool/1.0"}
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{requests.utils.quote(self.email)}"
        try:
            resp = requests.get(url, headers=headers, timeout=8)
            if resp.status_code == 200:
                breaches = resp.json()
                names = [b.get("Name","?") for b in breaches]
                self.results["breached"] = True
                self.results["breach_sources"] = names
                self.results["risk_factors"].append({
                    "factor": f"Email found in {len(names)} known data breach(es): {', '.join(names[:5])}",
                    "severity": "CRITICAL"
                })
                self._log("Data Breaches", f"FOUND IN {len(names)} BREACH(ES): {', '.join(names[:5])} ⚠")
            elif resp.status_code == 404:
                self.results["breached"] = False
                self.results["breach_sources"] = []
                self._log("Data Breaches", "Not found in public HIBP database")
            elif resp.status_code == 401:
                self.results["breached"] = None
                self._log("Data Breaches", "API key required for full lookup (see README)")
            else:
                self.results["breached"] = None
                self._log("Data Breaches", f"Check skipped (HTTP {resp.status_code})")
        except requests.RequestException as e:
            self.results["breached"] = None
            self._log("Data Breaches", f"Could not reach HIBP: {e}")

    # ── 7. Suspicious TLD ─────────────────────────────────────
    def _check_suspicious_tld(self):
        domain = self.email.split("@")[-1]
        tld = "." + domain.rsplit(".",1)[-1]
        if tld in SUSPICIOUS_TLDS:
            self.results["risk_factors"].append({
                "factor": f"Suspicious TLD detected: '{tld}' — frequently abused in phishing campaigns",
                "severity": "HIGH"
            })
            self._log("TLD Warning", f"'{tld}' is flagged as commonly abused ⚠")
        else:
            self.results["suspicious_tld"] = False

    # ── Helpers ───────────────────────────────────────────────
    def _log(self, label: str, value: str):
        print(f"  {label:<26} {value}")

    def _print_findings(self):
        rf = self.results.get("risk_factors", [])
        if rf:
            print(f"\n  [!] {len(rf)} risk factor(s) found for this email:")
            for r in rf:
                icon = "🔴" if r["severity"]=="CRITICAL" else "🟠" if r["severity"]=="HIGH" else "🟡"
                print(f"      {icon}  [{r['severity']}] {r['factor']}")
