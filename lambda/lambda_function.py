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

Metrics & history:
  * After each run, aggregate counts (total/active/inactive/stale/never-used
    keys, accounts scanned, accounts with errors) are published to CloudWatch as
    custom metrics under METRIC_NAMESPACE, so you get a time series of your
    org's key posture and can build alarms/dashboards on it.
  * The run also diffs against the previous run's state (a small JSON kept in S3)
    to detect keys ADDED, REMOVED, ACTIVATED, and DEACTIVATED since last time.
    Those change counts are emitted as metrics too, and a per-run changelog is
    written to S3 (PREFIX/history/...). This turns isolated snapshots into a
    tracked history of what changed and when.

Environment variables:
  BUCKET           (required)  destination S3 bucket
  PREFIX           (optional)  key prefix, default "access-key-reports"
  CANDIDATE_ROLES  (optional)  comma-separated role names to try (in order) when
                               assuming into a member account. Default:
                               "OrgAccessKeyAuditRole,OrganizationAccountAccessRole,AWSControlTowerExecution"
  ALERT_TOPIC_ARN  (optional)  SNS topic ARN to notify when errors occur.
  METRIC_NAMESPACE (optional)  CloudWatch namespace for custom metrics.
                               Default "OrgAccessKeyInventory".
  STALE_AGE_DAYS   (optional)  Age (days) at/above which a key counts as "stale"
                               and needs rotation. Default 90.
  PUBLISH_METRICS  (optional)  "true"/"false" to enable/disable CloudWatch metric
                               publishing. Default "true".
"""
import csv
import datetime as dt
import hashlib
import io
import json
import logging
import os

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

RETRY_CFG = Config(retries={"max_attempts": 10, "mode": "adaptive"})
_DEFAULT_ROLES = "OrgAccessKeyAuditRole,OrganizationAccountAccessRole,AWSControlTowerExecution"
CANDIDATE_ROLES = [r.strip() for r in os.environ.get("CANDIDATE_ROLES", _DEFAULT_ROLES).split(",") if r.strip()]
FIELDS = ["account_id", "account_name", "user", "access_key_id",
          "status", "create_date", "age_days", "last_used"]

METRIC_NAMESPACE = os.environ.get("METRIC_NAMESPACE", "OrgAccessKeyInventory")
STALE_AGE_DAYS = int(os.environ.get("STALE_AGE_DAYS", "90"))
PUBLISH_METRICS = os.environ.get("PUBLISH_METRICS", "true").lower() != "false"
# Where the "last run" state used for change detection lives (relative to PREFIX).
STATE_SUFFIX = "state/keys-state.json"

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
                except (ClientError, BotoCoreError):
                    pass
                rows.append({
                    "user": name,
                    "access_key_id": _mask(kid),
                    # Kept only in-memory for change detection; never written to
                    # the CSV (not in FIELDS) nor to the S3 state file (hashed).
                    "raw_key_id": kid,
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


def _summarize(rows, accounts_scanned, error_count):
    """Aggregate the raw rows into the counts we track over time."""
    total = len(rows)
    active = sum(1 for r in rows if r["status"] == "Active")
    never_used = sum(1 for r in rows if r["last_used"] == "N/A")
    stale = sum(1 for r in rows if r["age_days"] >= STALE_AGE_DAYS)
    stale_active = sum(1 for r in rows
                       if r["age_days"] >= STALE_AGE_DAYS and r["status"] == "Active")
    return {
        "KeysTotal": total,
        "KeysActive": active,
        "KeysInactive": total - active,
        "KeysNeverUsed": never_used,
        "KeysStale": stale,
        "KeysStaleActive": stale_active,
        "AccountsScanned": accounts_scanned,
        "AccountsWithErrors": error_count,
    }


def _state_id(account_id, raw_key_id):
    """Stable, non-reversible identifier for a key (no raw id is persisted)."""
    return hashlib.sha256(f"{account_id}:{raw_key_id}".encode("utf-8")).hexdigest()


def _build_state(rows):
    """Map of hashed-key-id -> lightweight descriptor, for run-to-run diffing."""
    state = {}
    for r in rows:
        state[_state_id(r["account_id"], r["raw_key_id"])] = {
            "account_id": r["account_id"],
            "account_name": r["account_name"],
            "user": r["user"],
            "access_key_id": r["access_key_id"],  # already masked
            "status": r["status"],
            "create_date": r["create_date"],
        }
    return state


def _load_state(s3, bucket, key):
    """Load the previous run's state, or {} if this is the first run."""
    try:
        obj = s3.get_object(Bucket=bucket, Key=key)
        return json.loads(obj["Body"].read().decode("utf-8"))
    except ClientError as e:
        if e.response["Error"]["Code"] in ("NoSuchKey", "NoSuchBucket", "404"):
            return {}
        logger.warning("Could not load previous state (%s); treating as first run",
                       e.response["Error"]["Code"])
        return {}
    except (ValueError, KeyError):
        logger.warning("Previous state was unreadable; treating as first run")
        return {}


def _diff_states(prev, curr):
    """Compute added / removed / status-changed keys between two runs."""
    added = [curr[k] for k in curr if k not in prev]
    removed = [prev[k] for k in prev if k not in curr]
    activated, deactivated = [], []
    for k in curr:
        if k in prev and prev[k].get("status") != curr[k].get("status"):
            entry = {**curr[k], "old_status": prev[k].get("status")}
            if curr[k].get("status") == "Active":
                activated.append(entry)
            else:
                deactivated.append(entry)
    return {
        "added": added,
        "removed": removed,
        "activated": activated,
        "deactivated": deactivated,
    }


def _publish_metrics(counts, changes, first_run):
    """Publish aggregate + change counts to CloudWatch as custom metrics."""
    if not PUBLISH_METRICS:
        return
    ts = dt.datetime.now(dt.timezone.utc)
    metrics = dict(counts)
    # On the very first run there's no baseline, so change counts are omitted
    # rather than reported as a misleading "everything is new".
    if not first_run:
        metrics["KeysAdded"] = len(changes["added"])
        metrics["KeysRemoved"] = len(changes["removed"])
        metrics["KeysActivated"] = len(changes["activated"])
        metrics["KeysDeactivated"] = len(changes["deactivated"])

    data = [{"MetricName": name, "Timestamp": ts, "Value": float(val),
             "Unit": "Count"} for name, val in metrics.items()]
    try:
        cw = boto3.client("cloudwatch", config=RETRY_CFG)
        # PutMetricData accepts up to 1000 datums per call.
        for i in range(0, len(data), 1000):
            cw.put_metric_data(Namespace=METRIC_NAMESPACE, MetricData=data[i:i + 1000])
        logger.info("Published %d metric(s) to CloudWatch namespace %s",
                    len(data), METRIC_NAMESPACE)
    except ClientError as e:
        logger.error("Failed to publish CloudWatch metrics: %s", e)


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
        except (ClientError, BotoCoreError) as e:
            # ClientError has a structured code; BotoCoreError (timeouts,
            # connection failures) does not, so fall back to its class name.
            if isinstance(e, ClientError):
                code = e.response["Error"]["Code"]
            else:
                code = type(e).__name__
            errors.append({"account_id": aid, "account_name": aname, "error": code})
            logger.error("[ERR] %s %s could not be inventoried: %s", aid, aname, code)

    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=FIELDS)
    w.writeheader()
    for r in sorted(all_rows, key=lambda x: (x["account_id"], x["create_date"])):
        w.writerow({k: r[k] for k in FIELDS})

    s3 = boto3.client("s3", config=RETRY_CFG)
    key = f"{prefix}/{now:%Y/%m/%d}/org-access-keys-{now:%Y%m%dT%H%M%SZ}.csv"
    s3.put_object(
        Bucket=bucket, Key=key,
        Body=buf.getvalue().encode("utf-8"),
        ContentType="text/csv",
        ServerSideEncryption="AES256",
    )

    # ---- History: diff against the previous run and record what changed ------
    state_key = f"{prefix}/{STATE_SUFFIX}"
    prev_state = _load_state(s3, bucket, state_key)
    first_run = not prev_state
    curr_state = _build_state(all_rows)

    # Accounts that could not be inventoried this run have NO rows, so a naive
    # diff would report all their keys as "removed" (and re-added when the
    # account recovers) and would persist an incomplete baseline. Instead, carry
    # forward the previous state for those accounts and exclude them from the
    # diff, so transient failures don't produce phantom history churn.
    errored_ids = {e["account_id"] for e in errors}
    if errored_ids:
        carried = 0
        for sid, entry in prev_state.items():
            if entry.get("account_id") in errored_ids and sid not in curr_state:
                curr_state[sid] = entry
                carried += 1
        if carried:
            logger.info("Carried forward %d key(s) from %d un-inventoried account(s): %s",
                        carried, len(errored_ids), ", ".join(sorted(errored_ids)))

    changes = _diff_states(prev_state, curr_state)
    change_counts = {k: len(v) for k, v in changes.items()}

    # Persist the new state so the next run has a baseline to diff against.
    try:
        s3.put_object(
            Bucket=bucket, Key=state_key,
            Body=json.dumps(curr_state).encode("utf-8"),
            ContentType="application/json",
            ServerSideEncryption="AES256",
        )
    except ClientError as e:
        logger.error("Failed to persist run state to s3://%s/%s: %s", bucket, state_key, e)

    # Write a per-run changelog (skip the first run, which has no baseline).
    history_location = None
    if not first_run and any(change_counts.values()):
        history_key = f"{prefix}/history/{now:%Y/%m/%d}/changes-{now:%Y%m%dT%H%M%SZ}.json"
        changelog = {
            "run_time": now.isoformat(),
            "report": f"s3://{bucket}/{key}",
            "counts": change_counts,
            "changes": changes,
        }
        try:
            s3.put_object(
                Bucket=bucket, Key=history_key,
                Body=json.dumps(changelog, indent=2).encode("utf-8"),
                ContentType="application/json",
                ServerSideEncryption="AES256",
            )
            history_location = f"s3://{bucket}/{history_key}"
            logger.info("CHANGES since last run: %s -> %s", change_counts, history_location)
        except ClientError as e:
            logger.error("Failed to write changelog to s3://%s/%s: %s", bucket, history_key, e)
    elif first_run:
        logger.info("First run: %d keys recorded as the history baseline.", len(all_rows))

    # ---- Metrics: publish the run's posture + changes to CloudWatch ----------
    counts = _summarize(all_rows, len(accounts), len(errors))
    _publish_metrics(counts, changes, first_run)

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
        "metrics": counts,
        # On the first run there's no baseline, so report zeros here to match the
        # metrics (which omit change counts) rather than "everything is new".
        "changes": {"first_run": first_run,
                    **({k: 0 for k in change_counts} if first_run else change_counts)},
        "history_location": history_location,
    }
