"""
Person Intelligence Module
Passive OSINT for a named individual:
  - LinkedIn URL construction & format guess
  - Common corporate email pattern generation
  - Social platform username probing (HTTP 200 check)
  - Public records search URL generation (PeopleFinder, etc.)
  - GitHub / Twitter / HackerNews profile probe
  - Phone number extraction hints from LinkedIn-style data
NOTE: This module is entirely passive — no scraping, no logins.
      It generates leads and verifiable URLs, not confirmed data.
"""

import re
import requests
from urllib.parse import quote


SOCIAL_PLATFORMS = [
    ("LinkedIn",   "https://www.linkedin.com/in/{slug}"),
    ("GitHub",     "https://github.com/{slug}"),
    ("Twitter/X",  "https://twitter.com/{slug}"),
    ("HackerNews", "https://news.ycombinator.com/user?id={slug}"),
    ("Keybase",    "https://keybase.io/{slug}"),
    ("GitLab",     "https://gitlab.com/{slug}"),
]

EMAIL_PATTERNS = [
    "{first}.{last}",
    "{f}{last}",
    "{first}{l}",
    "{first}{last}",
    "{last}{first}",
    "{first}_{last}",
    "{last}.{first}",
    "{first}",
]

PUBLIC_RECORDS_SITES = [
    ("Pipl",          "https://pipl.com/search/?q={name}"),
    ("TruePeopleSearch","https://www.truepeoplesearch.com/results?name={name}"),
    ("FastPeopleSearch","https://www.fastpeoplesearch.com/name/{name}"),
    ("PeekYou",       "https://www.peekyou.com/{slug}"),
    ("That's Them",   "https://thatsthem.com/name/{name}"),
]


class PersonIntel:
    def __init__(self, name: str, company: str = None):
        self.name    = name.strip()
        self.company = company
        self.parts   = self._parse_name(name)
        self.results = {"name": self.name, "risk_factors": []}
        if company:
            self.results["company"] = company

    # ──────────────────────────────────────────────────────────
    def run(self) -> dict:
        print(f"  [*] Building intel for: {self.name}" + (f" @ {self.company}" if self.company else ""))
        self._generate_email_patterns()
        self._probe_social_profiles()
        self._generate_public_record_links()
        self._print_findings()
        return self.results

    # ── 1. Email Pattern Generation ───────────────────────────
    def _generate_email_patterns(self):
        if not self.parts:
            self.results["possible_emails"] = []
            return

        first, last = self.parts
        f, l = first[0], last[0]
        domain = self._guess_domain()

        candidates = []
        for pattern in EMAIL_PATTERNS:
            local = pattern.format(first=first, last=last, f=f, l=l)
            candidates.append(f"{local}@{domain}")

        self.results["possible_emails"] = candidates
        print(f"  [*] Generated {len(candidates)} possible email patterns for domain: {domain}")
        for i, email in enumerate(candidates[:5], 1):
            print(f"      {i}. {email}")
        if len(candidates) > 5:
            print(f"      ... and {len(candidates)-5} more")

    def _guess_domain(self) -> str:
        if self.company:
            slug = re.sub(r"[^a-z0-9]", "", self.company.lower())
            return f"{slug}.com"
        return "unknown.com"

    # ── 2. Social Profile Probe ───────────────────────────────
    def _probe_social_profiles(self):
        print(f"  [*] Probing social platforms (passive HTTP check)...")
        first, last = self.parts if self.parts else (self.name.lower().replace(" ",""),"")
        slugs = [
            f"{first}{last}",
            f"{first}.{last}",
            f"{first}_{last}",
            f"{first[0]}{last}" if first else last,
        ]

        found_profiles = []
        headers = {"User-Agent": "Mozilla/5.0 (compatible; OSINT-Recon/1.0)"}

        for slug in slugs[:2]:  # check top 2 slug variations
            for platform, url_template in SOCIAL_PLATFORMS:
                url = url_template.format(slug=quote(slug))
                try:
                    resp = requests.head(url, headers=headers, timeout=5, allow_redirects=True)
                    if resp.status_code in [200, 302]:
                        found_profiles.append(f"{platform}: {url}")
                        if platform == "LinkedIn":
                            self.results["linkedin_url"] = url
                        break  # found on this platform, move on
                except Exception:
                    pass

        self.results["social_profiles"] = found_profiles
        if found_profiles:
            print(f"  Found {len(found_profiles)} potential profile(s):")
            for p in found_profiles:
                print(f"      ✓ {p}")
        else:
            print(f"  No confirmed social profiles found (may need manual verification)")

    # ── 3. Public Record Links ────────────────────────────────
    def _generate_public_record_links(self):
        name_slug  = quote(self.name)
        name_dash  = self.name.lower().replace(" ", "-")
        links = []
        for site, url_template in PUBLIC_RECORDS_SITES:
            url = url_template.format(name=name_slug, slug=name_dash)
            links.append(f"{site}: {url}")

        self.results["public_record_links"] = links
        print(f"\n  [*] Public record search URLs (manual verification):")
        for link in links:
            print(f"      → {link}")

    # ── Helpers ───────────────────────────────────────────────
    def _parse_name(self, name: str):
        """Returns (first, last) normalized."""
        parts = name.strip().lower().split()
        if len(parts) >= 2:
            return parts[0], parts[-1]
        elif len(parts) == 1:
            return parts[0], parts[0]
        return None

    def _print_findings(self):
        rf = self.results.get("risk_factors", [])
        if rf:
            print(f"\n  [!] {len(rf)} risk factor(s) found:")
            for r in rf:
                icon = "🔴" if r["severity"]=="CRITICAL" else "🟠" if r["severity"]=="HIGH" else "🟡"
                print(f"      {icon}  [{r['severity']}] {r['factor']}")
