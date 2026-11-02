# Cloud Access Audit Tool

A Python tool that audits cloud user accounts and access keys and generates a security report. It finds risky settings such as users without MFA, administrator access, inactive accounts, old access keys and unused keys, then ranks users by risk and produces an **HTML report** and a **CSV file** of findings.

It works offline with exported user data (JSON), so no cloud credentials are needed to try it. An export script is included to pull real users from **AWS IAM**.

## Features
- Detects 9 types of access risks (see the rules table)
- Risk score and risk level for every user
- Colour-coded HTML report generated from an editable template
- CSV export of all findings with recommendations
- Configurable thresholds for inactivity and key age
- Demo mode with sample data
- Script to export live AWS IAM users
- `--fail-on-critical` option for use in automated pipelines

## Tech Stack
- Python 3
- tabulate (console tables)
- boto3 (AWS export, optional)
- HTML, CSV, JSON

## Project Structure
```
cloud-access-audit-tool/
├── scripts/
│   ├── sample_users.json      # demo data
│   ├── aws_export.py          # export users from AWS IAM
│   ├── run_audit.bat          # run the demo (Windows)
│   └── run_audit.sh           # run the demo (Linux / Mac)
├── templates/
│   └── report_template.html   # HTML report layout
├── audit_report.py            # main program
├── requirements.txt
└── README.md
```

## How to Run

1. Clone the repository
```bash
git clone https://github.com/leninanto5/cloud-access-audit-tool.git
cd cloud-access-audit-tool
```

2. Install dependencies
```bash
pip install -r requirements.txt
```

3. Run the demo
```bash
python audit_report.py --demo
```

4. Open the generated HTML report from the `reports/` folder in your browser

## Audit Your Own Data
```bash
python audit_report.py --input my_users.json
```

To export real users from AWS IAM (needs AWS credentials with read-only IAM access):
```bash
python scripts/aws_export.py --output my_users.json
python audit_report.py --input my_users.json
```

## Arguments
| Argument | Description | Default |
|---|---|---|
| `--input` | JSON file with users | none |
| `--demo` | Use `scripts/sample_users.json` | off |
| `--inactive-days` | Days without login/use before flagged | 90 |
| `--key-age-days` | Maximum access key age in days | 90 |
| `--as-of` | Audit date (YYYY-MM-DD) | today |
| `--output-dir` | Folder for the reports | `reports/` |
| `--fail-on-critical` | Exit with code 1 if critical findings exist | off |

## Audit Rules
| Rule | Severity | What it checks |
|---|---|---|
| MFA-001 | High / Critical | User without MFA (Critical for admins and root) |
| ROOT-001 | Critical | Root account has active access keys |
| ADMIN-001 | High | User has full administrator privileges |
| POLICY-001 | Medium | Broad `*FullAccess` policies attached |
| INACTIVE-001 | Medium | No login for more than the inactive days, or never logged in |
| KEY-AGE-001 | Medium | Active access key older than the maximum age |
| KEY-UNUSED-001 | Medium | Access key never used or unused for too long |
| KEY-MULTI-001 | Low | More than one active access key |

## Risk Score
Critical = 10 points, High = 5, Medium = 3, Low = 1. A user's risk level comes from the total score.

## Input Format
```json
{
  "users": [
    {
      "username": "alice",
      "type": "human",
      "mfa_enabled": false,
      "created": "2025-01-10",
      "last_login": "2026-10-30",
      "access_keys": [
        {"id": "AKIA...", "created": "2025-02-01", "last_used": "2026-10-29", "active": true}
      ],
      "policies": ["AdministratorAccess"]
    }
  ]
}
```
`type` can be `human`, `service` or `root`.

## Author
**Leninanto**
GitHub: [leninanto5](https://github.com/leninanto5)
