
# OSINT-Recon

**A passive OSINT & threat-intelligence framework for SOC analysts and phishing triage.**

CLI + Desktop GUI + Windows .exe build pipeline.

![Version](https://img.shields.io/badge/version-2.0-blue)
![License](https://img.shields.io/badge/license-MIT-green)

---

## Why this exists

SOC analysts triage dozens of suspicious emails a day. Before escalating or blocking, you need fast answers:

- Is this domain new?
- Does it have SPF/DMARC?
- Has this email leaked in a breach?
- Is the sending IP blacklisted?

**OSINT-Recon** automates that first triage pass using **only passive**, publicly available data — no active exploitation, no credential brute-forcing, no scraping behind logins.

---

## Features

| Module              | What it checks |
|---------------------|----------------|
| **Email Intelligence** | Format validation, provider classification, MX records, SPF/DMARC/DKIM presence, disposable domain detection, HaveIBeenPwned breach lookup, suspicious TLD flagging |
| **Domain Intelligence** | WHOIS (registrar, age, expiry), DNS records, IP geolocation & hosting/proxy detection, passive subdomain enumeration, common-port probing, DNSBL blacklist checks, TLS/SSL validity |
| **Person Intelligence** | Corporate email-pattern generation, public social-profile discovery, public-records search link generation |
| **Risk Scoring Engine** | Weighted severity scoring (0-100), CRITICAL/HIGH/MEDIUM/LOW breakdown, mapped attack vectors, remediation recommendations |
| **Scan History** | Every scan is stored locally in SQLite — reload, compare, or re-export any past report |

---

## Installation

### Windows (Recommended)

Download the latest `.exe` from [Releases](https://github.com/okanx-om/osint-recon-beta/releases)

Or build yourself:

```bash
python build_exe.py
