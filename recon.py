#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════╗
║           OSINT RECON TOOL - Red Team Assistant           ║
║           For Educational & Authorized Use Only           ║
╚═══════════════════════════════════════════════════════════╝
"""

import argparse
import sys
import os
from datetime import datetime
from modules.email_intel import EmailIntel
from modules.domain_intel import DomainIntel
from modules.person_intel import PersonIntel
from utils.banner import print_banner
from utils.report import ReportGenerator
from utils.risk import RiskScorer

def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description="OSINT Recon Tool - Passive intelligence gathering for security assessments",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python recon.py --email attacker@example.com
  python recon.py --domain example.com
  python recon.py --person "John Doe" --company "Acme Corp"
  python recon.py --email suspicious@phish.net --domain phish.net --full
        """
    )

    parser.add_argument("--email",    metavar="EMAIL",   help="Target email address to investigate")
    parser.add_argument("--domain",   metavar="DOMAIN",  help="Target domain to investigate")
    parser.add_argument("--person",   metavar="NAME",    help="Target person name (use quotes)")
    parser.add_argument("--company",  metavar="COMPANY", help="Target company name (use with --person)")
    parser.add_argument("--full",     action="store_true", help="Run all available modules")
    parser.add_argument("--output",   metavar="FILE",    help="Save report to file (e.g. report.txt or report.json)")
    parser.add_argument("--format",   choices=["txt","json"], default="txt", help="Report format (default: txt)")

    args = parser.parse_args()

    if not any([args.email, args.domain, args.person]):
        parser.print_help()
        sys.exit(1)

    print(f"\n[*] Scan started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"[*] Target parameters received. Beginning passive recon...\n")

    findings = {}
    risk_factors = []

    # ── Email Intelligence ──────────────────────────────────
    if args.email or args.full:
        target_email = args.email
        if target_email:
            print("─" * 60)
            print(f"[MODULE] Email Intelligence → {target_email}")
            print("─" * 60)
            email_intel = EmailIntel(target_email)
            email_results = email_intel.run()
            findings["email_intel"] = email_results
            risk_factors.extend(email_results.get("risk_factors", []))

    # ── Domain Intelligence ─────────────────────────────────
    if args.domain or args.full:
        target_domain = args.domain
        if not target_domain and args.email:
            target_domain = args.email.split("@")[-1]
            print(f"\n[*] Extracting domain from email: {target_domain}")
        if target_domain:
            print("\n" + "─" * 60)
            print(f"[MODULE] Domain Intelligence → {target_domain}")
            print("─" * 60)
            domain_intel = DomainIntel(target_domain)
            domain_results = domain_intel.run()
            findings["domain_intel"] = domain_results
            risk_factors.extend(domain_results.get("risk_factors", []))

    # ── Person Intelligence ─────────────────────────────────
    if args.person:
        print("\n" + "─" * 60)
        print(f"[MODULE] Person Intelligence → {args.person}")
        print("─" * 60)
        person_intel = PersonIntel(args.person, company=args.company)
        person_results = person_intel.run()
        findings["person_intel"] = person_results
        risk_factors.extend(person_results.get("risk_factors", []))

    # ── Risk Scoring ────────────────────────────────────────
    print("\n" + "═" * 60)
    print("[RISK ASSESSMENT]")
    print("═" * 60)
    scorer = RiskScorer(risk_factors)
    risk_report = scorer.score()
    findings["risk_assessment"] = risk_report
    scorer.print_summary()

    # ── Final Summary ───────────────────────────────────────
    print("\n" + "═" * 60)
    print("[INTELLIGENCE SUMMARY]")
    print("═" * 60)
    _print_summary(findings)

    # ── Report Output ───────────────────────────────────────
    generator = ReportGenerator(findings, args)
    if args.output:
        generator.save(args.output, args.format)
        print(f"\n[✓] Report saved → {args.output}")
    else:
        print("\n[i] Tip: Use --output report.txt to save full report")

    print(f"\n[*] Scan completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")


def _print_summary(findings):
    """Print a clean final summary table."""
    lines = []

    email = findings.get("email_intel", {})
    if email:
        lines.append(f"  {'Email':<22} {email.get('email','N/A')}")
        lines.append(f"  {'Provider':<22} {email.get('provider','Unknown')}")
        lines.append(f"  {'Disposable':<22} {'YES ⚠' if email.get('disposable') else 'No'}")
        lines.append(f"  {'Breached':<22} {'YES ⚠' if email.get('breached') else 'No / Unknown'}")
        if email.get("breach_sources"):
            lines.append(f"  {'Breach Sources':<22} {', '.join(email['breach_sources'])}")
        lines.append(f"  {'MX Valid':<22} {'Yes' if email.get('mx_valid') else 'No ⚠'}")
        lines.append(f"  {'Format Valid':<22} {'Yes' if email.get('format_valid') else 'No ⚠'}")
        lines.append(f"  {'SPF Record':<22} {'Yes' if email.get('spf') else 'Missing ⚠'}")
        lines.append(f"  {'DMARC Record':<22} {'Yes' if email.get('dmarc') else 'Missing ⚠'}")
        lines.append(f"  {'DKIM Record':<22} {'Yes' if email.get('dkim') else 'Missing ⚠'}")

    domain = findings.get("domain_intel", {})
    if domain:
        lines.append("")
        lines.append(f"  {'Domain':<22} {domain.get('domain','N/A')}")
        lines.append(f"  {'Registrar':<22} {domain.get('registrar','Unknown')}")
        lines.append(f"  {'Created':<22} {domain.get('creation_date','Unknown')}")
        lines.append(f"  {'Expires':<22} {domain.get('expiry_date','Unknown')}")
        lines.append(f"  {'Age (days)':<22} {domain.get('age_days','Unknown')}")
        lines.append(f"  {'Registrant':<22} {domain.get('registrant','Redacted/Privacy')}")
        lines.append(f"  {'Country':<22} {domain.get('country','Unknown')}")
        lines.append(f"  {'IP Address':<22} {domain.get('ip','Unknown')}")
        lines.append(f"  {'IP Reputation':<22} {domain.get('ip_reputation','Unknown')}")
        lines.append(f"  {'Blacklisted':<22} {'YES ⚠' if domain.get('blacklisted') else 'No'}")
        lines.append(f"  {'HTTPS/TLS':<22} {'Yes' if domain.get('https') else 'No ⚠'}")
        if domain.get("subdomains"):
            lines.append(f"  {'Subdomains Found':<22} {', '.join(domain['subdomains'][:5])}")
        if domain.get("open_ports"):
            lines.append(f"  {'Open Ports':<22} {', '.join(map(str, domain['open_ports']))}")
        lines.append(f"  {'Google Indexed':<22} {'Yes' if domain.get('google_indexed') else 'No / Unknown'}")

    person = findings.get("person_intel", {})
    if person:
        lines.append("")
        lines.append(f"  {'Person':<22} {person.get('name','N/A')}")
        if person.get("company"):
            lines.append(f"  {'Company':<22} {person['company']}")
        if person.get("linkedin_url"):
            lines.append(f"  {'LinkedIn':<22} {person['linkedin_url']}")
        if person.get("social_profiles"):
            lines.append(f"  {'Social Profiles':<22} {', '.join(person['social_profiles'])}")
        if person.get("possible_emails"):
            lines.append(f"  {'Possible Emails':<22} {', '.join(person['possible_emails'])}")
        if person.get("phone_numbers"):
            lines.append(f"  {'Phone Numbers':<22} {', '.join(person['phone_numbers'])}")

    risk = findings.get("risk_assessment", {})
    if risk:
        lines.append("")
        score = risk.get("score", 0)
        label = risk.get("label", "Unknown")
        bar = _risk_bar(score)
        lines.append(f"  {'Risk Score':<22} {score}/100  {bar}  [{label}]")

    for line in lines:
        print(line)


def _risk_bar(score):
    filled = int(score / 10)
    return "█" * filled + "░" * (10 - filled)


if __name__ == "__main__":
    main()
