import argparse
import csv
import html
import json
import os
import sys
from collections import Counter
from datetime import date, datetime
from string import Template

from tabulate import tabulate

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SAMPLE_FILE = os.path.join(BASE_DIR, "scripts", "sample_users.json")
TEMPLATE_FILE = os.path.join(BASE_DIR, "templates", "report_template.html")

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
SEVERITY_WEIGHT = {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 3, "LOW": 1}
ADMIN_POLICIES = {"AdministratorAccess", "*:*", "OwnerRole", "roles/owner"}


# ------------------------------------------------------------- loading
def parse_date(value):
    return datetime.strptime(value, "%Y-%m-%d").date() if value else None


def load_users(path):
    """Accepts a JSON list of users, or an object with a 'users' list."""
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, list):
        return data, None
    if "users" not in data:
        raise ValueError("JSON must be a list of users or contain a 'users' list")
    return data["users"], data.get("as_of")


# -------------------------------------------------------------- checks
def finding(user, rule, severity, message, recommendation):
    return {
        "user": user["username"],
        "rule": rule,
        "severity": severity,
        "message": message,
        "recommendation": recommendation,
    }


def audit_user(user, today, inactive_days, key_age_days):
    name = user["username"]
    kind = user.get("type", "human")
    mfa = user.get("mfa_enabled", False)
    policies = user.get("policies", [])
    keys = user.get("access_keys", [])
    active_keys = [k for k in keys if k.get("active", True)]
    is_admin = any(p in ADMIN_POLICIES for p in policies)
    results = []

    # Root account rules
    if kind == "root" or name.lower() == "root":
        if not mfa:
            results.append(finding(user, "MFA-001", "CRITICAL",
                                   "Root account has no MFA.", "Enable hardware or virtual MFA on the root account."))
        if active_keys:
            results.append(finding(user, "ROOT-001", "CRITICAL",
                                   f"Root account has {len(active_keys)} active access key(s).",
                                   "Delete root access keys and use IAM users or roles instead."))
        return results

    # MFA for human users
    if kind == "human" and not mfa:
        severity = "CRITICAL" if is_admin else "HIGH"
        results.append(finding(user, "MFA-001", severity,
                               "Console user has no MFA enabled.", "Enforce MFA for this user."))

    # Privileges
    if is_admin:
        results.append(finding(user, "ADMIN-001", "HIGH",
                               "User has full administrator privileges.",
                               "Apply least privilege and grant only the permissions needed."))
    else:
        broad = [p for p in policies if p.endswith("FullAccess")]
        if broad:
            results.append(finding(user, "POLICY-001", "MEDIUM",
                                   f"Broad permissions attached: {', '.join(broad)}.",
                                   "Replace full-access policies with narrower custom policies."))

    # Inactive human users
    if kind == "human":
        last_login = parse_date(user.get("last_login"))
        created = parse_date(user.get("created"))
        if last_login is None:
            if created is None or (today - created).days > inactive_days:
                results.append(finding(user, "INACTIVE-001", "MEDIUM",
                                       "User has never logged in.", "Remove the account if it is not needed."))
        elif (today - last_login).days > inactive_days:
            results.append(finding(user, "INACTIVE-001", "MEDIUM",
                                   f"No login for {(today - last_login).days} days.",
                                   "Disable or delete inactive accounts."))

    # Access keys
    for key in active_keys:
        created = parse_date(key.get("created"))
        last_used = parse_date(key.get("last_used"))
        if created and (today - created).days > key_age_days:
            results.append(finding(user, "KEY-AGE-001", "MEDIUM",
                                   f"Access key {key['id']} is {(today - created).days} days old.",
                                   f"Rotate access keys at least every {key_age_days} days."))
        if last_used is None:
            if created is None or (today - created).days > 30:
                results.append(finding(user, "KEY-UNUSED-001", "MEDIUM",
                                       f"Access key {key['id']} has never been used.",
                                       "Delete access keys that are not used."))
        elif (today - last_used).days > inactive_days:
            results.append(finding(user, "KEY-UNUSED-001", "MEDIUM",
                                   f"Access key {key['id']} unused for {(today - last_used).days} days.",
                                   "Delete access keys that are not used."))
    if len(active_keys) > 1:
        results.append(finding(user, "KEY-MULTI-001", "LOW",
                               f"User has {len(active_keys)} active access keys.",
                               "Keep only one active key per user."))
    return results


def audit_all(users, today, inactive_days, key_age_days):
    findings = []
    for user in users:
        findings.extend(audit_user(user, today, inactive_days, key_age_days))
    order = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    return sorted(findings, key=lambda f: (order[f["severity"]], f["user"], f["rule"]))


def risk_level(score):
    if score >= 10:
        return "CRITICAL"
    if score >= 5:
        return "HIGH"
    if score >= 3:
        return "MEDIUM"
    if score >= 1:
        return "LOW"
    return "CLEAN"


def user_risks(users, findings):
    scores, counts = Counter(), Counter()
    for f in findings:
        scores[f["user"]] += SEVERITY_WEIGHT[f["severity"]]
        counts[f["user"]] += 1
    rows = [
        {
            "user": u["username"],
            "type": u.get("type", "human"),
            "findings": counts[u["username"]],
            "score": scores[u["username"]],
            "level": risk_level(scores[u["username"]]),
        }
        for u in users
    ]
    return sorted(rows, key=lambda r: (-r["score"], r["user"]))


# ------------------------------------------------------------- output
def print_summary(users, findings, risks, as_of):
    counts = Counter(f["severity"] for f in findings)
    flagged = sum(1 for r in risks if r["findings"] > 0)

    print(f"\nCloud Access Audit  (audit date: {as_of})")
    print("=" * 50)
    print(f"Users audited       : {len(users)}")
    print(f"Users with findings : {flagged}")
    print(f"Total findings      : {len(findings)}")
    for severity in SEVERITY_ORDER:
        print(f"  {severity:<9}: {counts[severity]}")

    top = [[r["user"], r["findings"], r["score"], r["level"]] for r in risks if r["score"] > 0][:5]
    if top:
        print("\nTop risky users")
        print(tabulate(top, headers=["User", "Findings", "Score", "Level"], tablefmt="grid"))


def build_html(users, findings, risks, as_of, inactive_days, key_age_days):
    esc = html.escape
    counts = Counter(f["severity"] for f in findings)

    user_rows = "\n".join(
        f'<tr><td>{esc(r["user"])}</td><td>{esc(r["type"])}</td><td>{r["findings"]}</td>'
        f'<td>{r["score"]}</td><td><span class="tag {r["level"]}">{r["level"]}</span></td></tr>'
        for r in risks
    )
    finding_rows = "\n".join(
        f'<tr><td><span class="tag {f["severity"]}">{f["severity"]}</span></td><td>{esc(f["user"])}</td>'
        f'<td>{f["rule"]}</td><td>{esc(f["message"])}</td><td>{esc(f["recommendation"])}</td></tr>'
        for f in findings
    ) or '<tr><td colspan="5">No findings. All users passed the checks.</td></tr>'

    with open(TEMPLATE_FILE, "r", encoding="utf-8") as f:
        template = Template(f.read())

    return template.substitute(
        title="Cloud Access Audit Report",
        generated=datetime.now().strftime("%d %b %Y, %H:%M"),
        as_of=as_of.strftime("%d %b %Y"),
        inactive_days=inactive_days,
        key_age_days=key_age_days,
        users_audited=len(users),
        users_flagged=sum(1 for r in risks if r["findings"] > 0),
        total_findings=len(findings),
        critical=counts["CRITICAL"], high=counts["HIGH"],
        medium=counts["MEDIUM"], low=counts["LOW"],
        user_rows=user_rows,
        finding_rows=finding_rows,
    )


def save_reports(output_dir, html_text, findings):
    os.makedirs(output_dir, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    html_path = os.path.join(output_dir, f"audit_report_{stamp}.html")
    csv_path = os.path.join(output_dir, f"audit_findings_{stamp}.csv")

    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html_text)
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["severity", "user", "rule", "message", "recommendation"])
        writer.writeheader()
        writer.writerows(findings)
    return html_path, csv_path


# --------------------------------------------------------------- main
def parse_args():
    p = argparse.ArgumentParser(description="Audit cloud user access and generate a security report.")
    p.add_argument("--input", help="JSON file with users (see scripts/sample_users.json)")
    p.add_argument("--demo", action="store_true", help="use the built-in sample data")
    p.add_argument("--inactive-days", type=int, default=90, help="days before a user/key is inactive (default 90)")
    p.add_argument("--key-age-days", type=int, default=90, help="maximum access key age in days (default 90)")
    p.add_argument("--as-of", help="audit date YYYY-MM-DD (default: today)")
    p.add_argument("--output-dir", default=os.path.join(BASE_DIR, "reports"), help="folder for reports")
    p.add_argument("--fail-on-critical", action="store_true", help="exit with code 1 if critical findings exist")
    return p.parse_args()


def main():
    args = parse_args()

    if args.input:
        path = args.input
    elif args.demo:
        path = SAMPLE_FILE
    else:
        sys.exit("Give --input <file.json> or use --demo")

    try:
        users, file_as_of = load_users(path)
        as_of = parse_date(args.as_of or file_as_of) or date.today()
    except (OSError, ValueError, KeyError) as e:
        sys.exit(f"Could not read input: {e}")

    findings = audit_all(users, as_of, args.inactive_days, args.key_age_days)
    risks = user_risks(users, findings)

    print_summary(users, findings, risks, as_of)
    html_text = build_html(users, findings, risks, as_of, args.inactive_days, args.key_age_days)
    html_path, csv_path = save_reports(args.output_dir, html_text, findings)
    print(f"\nHTML report : {html_path}")
    print(f"CSV findings: {csv_path}")

    if args.fail_on_critical and any(f["severity"] == "CRITICAL" for f in findings):
        sys.exit(1)


if __name__ == "__main__":
    main()
