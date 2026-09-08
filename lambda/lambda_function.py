"""AWS Lambda: inventory all IAM access keys across the AWS Organization -> S3 CSV.

Runs in the management account. Discovers accounts via Organizations, assumes a
read role in each member account, lists every IAM user's access keys, and writes
a single consolidated CSV to S3.

Observability:
  * Every account outcome is logged as "[OK] ..." or "[ERR] ..." (INFO/ERROR).
  * At the end, a single "RUN SUMMARY" line is logged. If any account could not
    be reached, it is logged at ERROR level tagged "ADMIN ACTION REQUIRED" so it
    is easy to find/alarm on, and (if ALERT_TOPIC_ARN is set) an SNS notification
    is published so an administrator is actively notified.
  * The returned payload includes "status": "OK" | "ATTENTION_REQUIRED".

Environment variables:
  BUCKET           (required)  destination S3 bucket
  PREFIX           (optional)  key prefix, default "access-key-reports"
  CANDIDATE_ROLES  (optional)  comma-separated role names to try (in order) when
                               assuming into a member account. Default:
                               "OrgAccessKeyAuditRole,OrganizationAccountAccessRole,AWSControlTowerExecution"
  ALERT_TOPIC_ARN  (optional)  SNS topic ARN to notify when errors occur.
"""
import csv
import datetime as dt
import io
import logging
import os

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

RETRY_CFG = Config(retries={"max_attempts": 10, "mode": "adaptive"})
_DEFAULT_ROLES = "OrgAccessKeyAuditRole,OrganizationAccountAccessRole,AWSControlTowerExecution"
CANDIDATE_ROLES = [r.strip() for r in os.environ.get("CANDIDATE_ROLES", _DEFAULT_ROLES).split(",") if r.strip()]
FIELDS = ["account_id", "account_name", "user", "access_key_id",
          "status", "create_date", "age_days", "last_used"]

# Show only the first/last few characters of an access key id (e.g. keep 4 at
# each end, mask the middle). Controlled by MASK_HEAD / MASK_TAIL env vars
# (defaults 4/4); set both to 0 to disable masking.
_MASK_HEAD = int(os.environ.get("MASK_HEAD", "4"))
_MASK_TAIL = int(os.environ.get("MASK_TAIL", "4"))


def _mask(kid):
    if not kid or (_MASK_HEAD == 0 and _MASK_TAIL == 0):
        return kid
    if len(kid) <= _MASK_HEAD + _MASK_TAIL:
        return kid
    return kid[:_MASK_HEAD] + "*" * (len(kid) - _MASK_HEAD - _MASK_TAIL) + kid[-_MASK_TAIL:]


def _collect_keys(iam, now):
    rows = []
    for page in iam.get_paginator("list_users").paginate():
        for u in page["Users"]:
            name = u["UserName"]
            for k in iam.list_access_keys(UserName=name)["AccessKeyMetadata"]:
                kid = k["AccessKeyId"]
                last_used = "N/A"
                try:
                    lu = iam.get_access_key_last_used(AccessKeyId=kid)["AccessKeyLastUsed"]
                    if "LastUsedDate" in lu:
                        last_used = lu["LastUsedDate"].isoformat()
                except ClientError:
                    pass
                rows.append({
                    "user": name,
                    "access_key_id": _mask(kid),
                    "status": k["Status"],
                    "create_date": k["CreateDate"].isoformat(),
                    "age_days": (now - k["CreateDate"]).days,
                    "last_used": last_used,
                })
    return rows


def _member_iam(sts, session, account_id):
    last_err = None
    for role in CANDIDATE_ROLES:
        arn = f"arn:aws:iam::{account_id}:role/{role}"
        try:
            c = sts.assume_role(RoleArn=arn, RoleSessionName="AccessKeyAudit")["Credentials"]
            return session.client("iam",
                                  aws_access_key_id=c["AccessKeyId"],
                                  aws_secret_access_key=c["SecretAccessKey"],
                                  aws_session_token=c["SessionToken"],
                                  config=RETRY_CFG), role
        except ClientError as e:
            last_err = e
    raise last_err


def _notify(errors, summary):
    """Publish an SNS alert when there are errors, if a topic is configured."""
    topic = os.environ.get("ALERT_TOPIC_ARN")
    if not topic or not errors:
        return
    lines = [f"  - {e['account_id']} ({e['account_name']}): {e['error']}" for e in errors]
    msg = (
        "Org-wide IAM access-key inventory needs administrator attention.\n\n"
        f"{summary}\n\n"
        f"{len(errors)} account(s) could NOT be inventoried "
        "(no assumable audit role, SCP denial, or suspended account):\n"
        + "\n".join(lines)
        + "\n\nFix: ensure one of the CANDIDATE_ROLES exists and is assumable in "
          "each account above (deploy the OrgAccessKeyAuditRole StackSet), then re-run."
    )
    try:
        boto3.client("sns").publish(
            TopicArn=topic,
            Subject="[ACTION REQUIRED] Access-key inventory errors",
            Message=msg,
        )
        logger.info("Published error alert to SNS topic %s", topic)
    except ClientError as e:
        logger.error("Failed to publish SNS alert: %s", e)


def handler(event, context):
    bucket = os.environ["BUCKET"]
    prefix = os.environ.get("PREFIX", "access-key-reports").strip("/")
    now = dt.datetime.now(dt.timezone.utc)

    session = boto3.Session()
    mgmt_id = session.client("sts").get_caller_identity()["Account"]
    orgs = session.client("organizations", config=RETRY_CFG)
    sts = session.client("sts", config=RETRY_CFG)

    accounts = []
    for page in orgs.get_paginator("list_accounts").paginate():
        accounts.extend([a for a in page["Accounts"] if a["Status"] == "ACTIVE"])

    all_rows, errors = [], []
    for a in accounts:
        aid, aname = a["Id"], a["Name"]
        try:
            if aid == mgmt_id:
                iam, via = session.client("iam", config=RETRY_CFG), "direct"
            else:
                iam, via = _member_iam(sts, session, aid)
            rows = _collect_keys(iam, now)
            for r in rows:
                r["account_id"], r["account_name"] = aid, aname
            all_rows.extend(rows)
            logger.info("[OK]  %s %s keys=%d via %s", aid, aname, len(rows), via)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            errors.append({"account_id": aid, "account_name": aname, "error": code})
            logger.error("[ERR] %s %s could not be inventoried: %s", aid, aname, code)

    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=FIELDS)
    w.writeheader()
    for r in sorted(all_rows, key=lambda x: (x["account_id"], x["create_date"])):
        w.writerow({k: r[k] for k in FIELDS})

    key = f"{prefix}/{now:%Y/%m/%d}/org-access-keys-{now:%Y%m%dT%H%M%SZ}.csv"
    boto3.client("s3").put_object(
        Bucket=bucket, Key=key,
        Body=buf.getvalue().encode("utf-8"),
        ContentType="text/csv",
        ServerSideEncryption="AES256",
    )

    status = "ATTENTION_REQUIRED" if errors else "OK"
    summary = (
        f"RUN SUMMARY: status={status} accounts_scanned={len(accounts)} "
        f"keys_found={len(all_rows)} errors={len(errors)} "
        f"report=s3://{bucket}/{key}"
    )
    if errors:
        # ERROR level + explicit marker makes this trivial to search and alarm on.
        logger.error("ADMIN ACTION REQUIRED -- %s", summary)
        _notify(errors, summary)
    else:
        logger.info(summary)

    return {
        "status": status,
        "accounts_scanned": len(accounts),
        "keys_found": len(all_rows),
        "errors": errors,
        "s3_location": f"s3://{bucket}/{key}",
    }
