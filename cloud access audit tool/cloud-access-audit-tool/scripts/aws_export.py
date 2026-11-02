"""Exports IAM users from a real AWS account into the JSON format used by audit_report.py.

Requirements:
  - pip install boto3
  - AWS credentials configured (aws configure) with read-only IAM permissions
    (iam:ListUsers, iam:ListMfaDevices, iam:ListAccessKeys, iam:GetAccessKeyLastUsed,
     iam:ListAttachedUserPolicies, iam:ListUserPolicies, iam:ListGroupsForUser,
     iam:ListAttachedGroupPolicies, iam:GetLoginProfile)

Usage:
    python scripts/aws_export.py --output my_users.json
    python audit_report.py --input my_users.json
"""
import argparse
import json


def fmt(dt):
    return dt.strftime("%Y-%m-%d") if dt else None


def has_console_access(iam, name):
    """A user with a console password is treated as a human user."""
    try:
        iam.get_login_profile(UserName=name)
        return True
    except Exception as e:
        code = getattr(e, "response", {}).get("Error", {}).get("Code", "")
        if code == "NoSuchEntity" or "NoSuchEntity" in str(e):
            return False
        raise


def export_users(iam):
    users = []
    for page in iam.get_paginator("list_users").paginate():
        for u in page["Users"]:
            name = u["UserName"]

            mfa = iam.list_mfa_devices(UserName=name)["MFADevices"]

            keys = []
            for k in iam.list_access_keys(UserName=name)["AccessKeyMetadata"]:
                used = iam.get_access_key_last_used(AccessKeyId=k["AccessKeyId"])["AccessKeyLastUsed"]
                keys.append({
                    "id": k["AccessKeyId"],
                    "created": fmt(k["CreateDate"]),
                    "last_used": fmt(used.get("LastUsedDate")),
                    "active": k["Status"] == "Active",
                })

            policies = [p["PolicyName"] for p in iam.list_attached_user_policies(UserName=name)["AttachedPolicies"]]
            policies += iam.list_user_policies(UserName=name)["PolicyNames"]
            for g in iam.list_groups_for_user(UserName=name)["Groups"]:
                attached = iam.list_attached_group_policies(GroupName=g["GroupName"])["AttachedPolicies"]
                policies += [p["PolicyName"] for p in attached]

            users.append({
                "username": name,
                "type": "human" if has_console_access(iam, name) else "service",
                "mfa_enabled": len(mfa) > 0,
                "created": fmt(u.get("CreateDate")),
                "last_login": fmt(u.get("PasswordLastUsed")),
                "access_keys": keys,
                "policies": sorted(set(policies)),
            })
    return users


def main():
    parser = argparse.ArgumentParser(description="Export AWS IAM users for auditing.")
    parser.add_argument("--output", default="my_users.json", help="output JSON file")
    args = parser.parse_args()

    import boto3
    users = export_users(boto3.client("iam"))
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump({"users": users}, f, indent=2)
    print(f"Exported {len(users)} users to {args.output}")


if __name__ == "__main__":
    main()
