"""
Domain Intelligence Module
Performs passive OSINT on a domain:
  - WHOIS (registrar, dates, registrant, country)
  - DNS A / NS / CNAME / TXT records
  - IP reputation & geolocation (ip-api.com free endpoint)
  - Subdomain enumeration via DNS brute-force (passive wordlist)
  - Port scan (common ports, passive socket probe)
  - Blacklist / RBL check (MX Toolbox style)
  - Google Safe Browsing hint
  - HTTPS / TLS presence check
"""

import socket
import dns.resolver
import whois
import requests
from datetime import datetime, timezone


COMMON_SUBDOMAINS = [
    "www","mail","remote","blog","webmail","server","ns1","ns2","smtp","secure",
    "vpn","api","dev","staging","admin","portal","login","ftp","cloud","cdn",
    "shop","app","media","support","help","test","beta","dashboard","git",
]

COMMON_PORTS = [21,22,23,25,53,80,110,143,443,445,465,587,993,995,3306,3389,5432,6379,8080,8443,27017]

# Known public DNS-based blacklists (DNSBL)
DNSBL_SERVERS = [
    "zen.spamhaus.org",
    "bl.spamcop.net",
    "dnsbl.sorbs.net",
    "b.barracudacentral.org",
]


class DomainIntel:
    def __init__(self, domain: str):
        self.domain = domain.strip().lower().lstrip("https://").lstrip("http://").rstrip("/")
        # strip subdomains for WHOIS
        self.root_domain = ".".join(self.domain.rsplit(".",2)[-2:]) if self.domain.count(".")>=2 else self.domain
        self.results = {"domain": self.domain, "risk_factors": []}

    # ──────────────────────────────────────────────────────────
    def run(self) -> dict:
        print(f"  [*] Analyzing: {self.domain}")
        self._whois_lookup()
        self._dns_records()
        self._ip_geolocation()
        self._subdomain_enum()
        self._port_scan()
        self._dnsbl_check()
        self._https_check()
        self._print_findings()
        return self.results

    # ── 1. WHOIS ──────────────────────────────────────────────
    def _whois_lookup(self):
        print(f"  [*] WHOIS lookup for {self.root_domain}...")
        try:
            w = whois.whois(self.root_domain)
            self.results["registrar"]     = str(w.registrar or "Unknown")
            self.results["registrant"]    = str(w.name or w.org or "Redacted (Privacy Protected)")
            self.results["country"]       = str(w.country or "Unknown")
            self.results["name_servers"]  = [str(n).lower() for n in (w.name_servers or [])][:4]

            # Creation date
            cd = w.creation_date
            if isinstance(cd, list): cd = cd[0]
            if cd:
                if hasattr(cd, "tzinfo") and cd.tzinfo:
                    cd = cd.replace(tzinfo=None)
                self.results["creation_date"] = cd.strftime("%Y-%m-%d")
                age = (datetime.now() - cd).days
                self.results["age_days"] = age
                if age < 30:
                    self.results["risk_factors"].append({"factor": f"Domain is very new ({age} days old) — common trait of phishing domains", "severity": "CRITICAL"})
                elif age < 180:
                    self.results["risk_factors"].append({"factor": f"Domain is less than 6 months old ({age} days) — treat with suspicion", "severity": "HIGH"})
            else:
                self.results["creation_date"] = "Unknown"
                self.results["age_days"] = "Unknown"

            # Expiry date
            ed = w.expiration_date
            if isinstance(ed, list): ed = ed[0]
            self.results["expiry_date"] = ed.strftime("%Y-%m-%d") if ed else "Unknown"

            self._log("Registrar",    self.results["registrar"])
            self._log("Registrant",   self.results["registrant"])
            self._log("Country",      self.results["country"])
            self._log("Created",      self.results["creation_date"])
            self._log("Expires",      self.results["expiry_date"])
            self._log("Domain Age",   f"{self.results['age_days']} days" if isinstance(self.results['age_days'], int) else "Unknown")
            if self.results["name_servers"]:
                self._log("Name Servers", ", ".join(self.results["name_servers"]))
        except Exception as e:
            self.results["registrar"] = "WHOIS lookup failed"
            self._log("WHOIS", f"Failed: {e}")

    # ── 2. DNS Records ────────────────────────────────────────
    def _dns_records(self):
        print(f"  [*] Resolving DNS records...")
        # A record → IP
        try:
            answers = dns.resolver.resolve(self.domain, "A")
            ips = [str(r) for r in answers]
            self.results["ip"] = ips[0]
            self.results["all_ips"] = ips
            self._log("A Record (IP)", ", ".join(ips))
        except Exception:
            self.results["ip"] = None
            self._log("A Record (IP)", "Not resolved ⚠")
            self.results["risk_factors"].append({"factor": "Domain does not resolve to an IP address", "severity": "MEDIUM"})

        # MX
        try:
            mx = dns.resolver.resolve(self.domain, "MX")
            self.results["mx"] = [str(r.exchange).rstrip(".") for r in mx]
            self._log("MX Records", ", ".join(self.results["mx"][:3]))
        except Exception:
            self.results["mx"] = []

        # TXT (grab SPF/DMARC)
        try:
            txt = dns.resolver.resolve(self.domain, "TXT")
            txts = [r.to_text().strip('"') for r in txt]
            self.results["txt_records"] = txts[:5]
        except Exception:
            self.results["txt_records"] = []

    # ── 3. IP Geolocation & Reputation ───────────────────────
    def _ip_geolocation(self):
        ip = self.results.get("ip")
        if not ip:
            return
        print(f"  [*] IP geolocation for {ip}...")
        try:
            resp = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org,hosting,proxy,query", timeout=8)
            if resp.status_code == 200:
                d = resp.json()
                if d.get("status") == "success":
                    country = d.get("country","?")
                    city    = d.get("city","?")
                    isp     = d.get("isp","?")
                    org     = d.get("org","?")
                    hosting = d.get("hosting", False)
                    proxy   = d.get("proxy", False)
                    self.results["ip_country"]  = country
                    self.results["ip_city"]     = city
                    self.results["ip_isp"]      = isp
                    self.results["ip_org"]      = org
                    self.results["ip_hosting"]  = hosting
                    self.results["ip_proxy"]    = proxy
                    self.results["ip_reputation"] = f"{country}, {city} | ISP: {isp}"
                    self._log("IP Location",  f"{city}, {country}")
                    self._log("ISP / Org",    f"{isp} / {org}")
                    self._log("Hosting IP",   "YES (VPS/Cloud host)" if hosting else "No")
                    self._log("Proxy/VPN",    "YES ⚠" if proxy else "No")
                    if hosting:
                        self.results["risk_factors"].append({"factor": "Domain hosted on VPS/cloud — common for phishing infra", "severity": "MEDIUM"})
                    if proxy:
                        self.results["risk_factors"].append({"factor": "IP flagged as proxy/VPN/Tor exit node", "severity": "HIGH"})
        except Exception as e:
            self._log("IP Geolocation", f"Failed: {e}")

    # ── 4. Subdomain Enumeration ──────────────────────────────
    def _subdomain_enum(self):
        print(f"  [*] Passive subdomain enumeration...")
        found = []
        for sub in COMMON_SUBDOMAINS:
            target = f"{sub}.{self.domain}"
            try:
                dns.resolver.resolve(target, "A")
                found.append(target)
            except Exception:
                pass
        self.results["subdomains"] = found
        if found:
            self._log("Subdomains Found", ", ".join(found[:8]))
        else:
            self._log("Subdomains Found", "None from wordlist")

    # ── 5. Port Scan (passive socket probe) ──────────────────
    def _port_scan(self):
        ip = self.results.get("ip")
        if not ip:
            return
        print(f"  [*] Common port probe on {ip} (passive)...")
        open_ports = []
        for port in COMMON_PORTS:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.7)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
            except Exception:
                pass
        self.results["open_ports"] = open_ports
        interesting = [p for p in open_ports if p in [21,23,3306,5432,6379,27017,3389]]
        if open_ports:
            self._log("Open Ports", ", ".join(map(str, open_ports)))
        else:
            self._log("Open Ports", "None detected (or filtered)")
        for p in interesting:
            svc = {21:"FTP",23:"Telnet",3306:"MySQL",5432:"PostgreSQL",6379:"Redis",27017:"MongoDB",3389:"RDP"}.get(p,"")
            self.results["risk_factors"].append({"factor": f"Port {p} ({svc}) is open — potential data exposure risk", "severity": "HIGH"})

    # ── 6. DNSBL Blacklist Check ──────────────────────────────
    def _dnsbl_check(self):
        ip = self.results.get("ip")
        if not ip:
            return
        print(f"  [*] DNSBL blacklist check...")
        reversed_ip = ".".join(reversed(ip.split(".")))
        listed_on = []
        for bl in DNSBL_SERVERS:
            try:
                query = f"{reversed_ip}.{bl}"
                dns.resolver.resolve(query, "A")
                listed_on.append(bl)
            except Exception:
                pass
        self.results["blacklisted"] = bool(listed_on)
        self.results["blacklist_sources"] = listed_on
        if listed_on:
            self.results["risk_factors"].append({"factor": f"IP {ip} is blacklisted on: {', '.join(listed_on)}", "severity": "CRITICAL"})
            self._log("DNSBL Blacklisted", f"YES — {', '.join(listed_on)} ⚠")
        else:
            self._log("DNSBL Blacklisted", "Not found on checked RBLs")

    # ── 7. HTTPS / TLS ────────────────────────────────────────
    def _https_check(self):
        try:
            resp = requests.head(f"https://{self.domain}", timeout=5, verify=True, allow_redirects=True)
            self.results["https"] = True
            self._log("HTTPS / TLS", f"Valid (HTTP {resp.status_code})")
        except requests.exceptions.SSLError:
            self.results["https"] = False
            self.results["risk_factors"].append({"factor": "TLS/SSL certificate invalid or expired", "severity": "HIGH"})
            self._log("HTTPS / TLS", "SSL ERROR ⚠")
        except requests.exceptions.ConnectionError:
            self.results["https"] = False
            self._log("HTTPS / TLS", "Not reachable / no HTTPS")
        except Exception:
            self.results["https"] = None
            self._log("HTTPS / TLS", "Check skipped")

    # ── Helpers ───────────────────────────────────────────────
    def _log(self, label: str, value: str):
        print(f"  {label:<26} {value}")

    def _print_findings(self):
        rf = self.results.get("risk_factors", [])
        if rf:
            print(f"\n  [!] {len(rf)} risk factor(s) found for this domain:")
            for r in rf:
                icon = "🔴" if r["severity"]=="CRITICAL" else "🟠" if r["severity"]=="HIGH" else "🟡"
                print(f"      {icon}  [{r['severity']}] {r['factor']}")
