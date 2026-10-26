"""AWS Lambda: inventory all IAM access keys (and long-term Amazon Bedrock API
keys) across the AWS Organization -> S3 CSV.

Runs in the management account. Discovers accounts via Organizations, assumes a
read role in each member account, lists every IAM user's access keys, and writes
a consolidated CSV per run to S3.

S3 layout (one folder per run; every file of a run shares one run id, e.g.
"20260908T063802Z", which is also the first column of both CSVs):
  PREFIX/runs/YYYY/MM/DD/<run-id>/manifest.json            written LAST
  PREFIX/runs/YYYY/MM/DD/<run-id>/access-keys.csv
  PREFIX/runs/YYYY/MM/DD/<run-id>/bedrock-api-keys.csv     (Bedrock enabled)
  PREFIX/runs/YYYY/MM/DD/<run-id>/changes-access-keys.json (only if changed)
  PREFIX/runs/YYYY/MM/DD/<run-id>/changes-bedrock-api-keys.json
  PREFIX/latest/{manifest.json, access-keys.csv, bedrock-api-keys.csv}
  PREFIX/state/{access-keys.json, bedrock-api-keys.json}   change detection
  * The run manifest lists every file of the run; a file that failed to write
    is recorded as null plus an error, never as a success.
  * latest/ is refreshed after the run folder, with latest/manifest.json last.
    A latest/ CSV is only replaced by a byte-identical copy of this run's CSV;
    if that copy failed, the old object is left alone and latest/manifest.json
    says so (the old file names its own run in its run_id column).
  * Legacy state fallback: if PREFIX/state/ has no state yet, the previous
    layout's state (LEGACY_PREFIX/state/keys-state.json and
    LEGACY_PREFIX/bedrock-api-keys/state/keys-state.json) is read once to seed
    change detection. Legacy objects are never modified, moved, or deleted.

Bedrock API keys:
  * Long-term Amazon Bedrock API keys are IAM service-specific credentials
    (ServiceName "bedrock.amazonaws.com") attached to IAM users. When
    INCLUDE_BEDROCK_KEYS is on (default), they are listed with
    iam:ListServiceSpecificCredentials in the same accounts, using the same
    IAM client, and written to a SEPARATE CSV (bedrock-api-keys.csv) in the
    same run folder. Metadata only: credentials are never created or reset,
    and the credential alias is never stored. Credential ids are masked like
    access key ids.
  * Short-term Bedrock API keys are presigned tokens derived from the caller's
    session. They are never stored in IAM, so they CANNOT be inventoried here.
  * A Bedrock-only failure in an account (e.g. the member audit role predates
    iam:ListServiceSpecificCredentials, or an SCP denies it) never drops that
    account's access-key rows and never fails the run: it is logged as
    "[WARN] ...", listed in the payload's bedrock.errors[], and flags the run
    as ATTENTION_REQUIRED.

Observability:
  * Every account outcome is logged as "[OK] ..." or "[ERR] ..." (INFO/ERROR).
  * At the end, a single "RUN SUMMARY" line is logged. If any account could not
    be reached (or its Bedrock API keys could not be listed, or a report/state
    file could not be written to S3), it is logged at
    ERROR level tagged "ADMIN ACTION REQUIRED" so it is easy to find/alarm on,
    and (if ALERT_TOPIC_ARN is set) an SNS notification is published so an
    administrator is actively notified.
  * The returned payload includes "status": "OK" | "ATTENTION_REQUIRED".

Metrics & history:
  * After each run, aggregate counts (total/active/inactive/stale/never-used
    keys, accounts scanned, accounts with errors) are published to CloudWatch as
    custom metrics under METRIC_NAMESPACE, so you get a time series of your
    org's key posture and can build alarms/dashboards on it.
  * The run also diffs against the previous run's state (a small JSON kept in S3)
    to detect keys ADDED, REMOVED, ACTIVATED, and DEACTIVATED since last time.
    Those change counts are emitted as metrics too, and a per-run changelog is
    written to the run folder (changes-*.json). This turns isolated snapshots
    into a tracked history of what changed and when.
  * The state also records every account ever listed successfully for that
    credential type. Keys in an account listed for the first time (newly
    invited, or recovered from a failure) are "baselined", not "added".
  * Bedrock API keys get their own state/changelog and BedrockKeys* metrics.

Environment variables:
  BUCKET           (required)  destination S3 bucket
  PREFIX           (optional)  key prefix, default "credential-inventory"
  LEGACY_PREFIX    (optional)  prefix of the previous S3 layout, read (never
                               written) only to seed change detection when
                               PREFIX/state/ is empty. Default
                               "access-key-reports"; empty disables it.
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
  INCLUDE_BEDROCK_KEYS     (optional)  "true"/"false" to enable/disable the
                               long-term Bedrock API key inventory. Default "true".
  BEDROCK_EXPIRY_WARN_DAYS (optional)  An active Bedrock API key expiring within
                               this many days counts as "expiring soon".
                               Default 30.
"""
import csv
import datetime as dt
import hashlib
import io
import json
import logging
import os
from collections import Counter

import boto3
import botocore
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

RETRY_CFG = Config(retries={"max_attempts": 10, "mode": "adaptive"})
_DEFAULT_ROLES = "OrgAccessKeyAuditRole,OrganizationAccountAccessRole,AWSControlTowerExecution"
CANDIDATE_ROLES = [r.strip() for r in os.environ.get("CANDIDATE_ROLES", _DEFAULT_ROLES).split(",") if r.strip()]
FIELDS = ["run_id", "account_id", "account_name", "user", "access_key_id",
          "status", "create_date", "age_days", "last_used"]
# last_used values other than an ISO timestamp. "Unknown" is the shared
# "couldn't determine" value used in both CSVs.
LAST_USED_NEVER = "Never"
LAST_USED_UNKNOWN = "Unknown"

METRIC_NAMESPACE = os.environ.get("METRIC_NAMESPACE", "OrgAccessKeyInventory")
STALE_AGE_DAYS = int(os.environ.get("STALE_AGE_DAYS", "90"))
PUBLISH_METRICS = os.environ.get("PUBLISH_METRICS", "true").lower() != "false"
# Descriptor fields persisted (per hashed key id) in the access-key state file.
_KEY_STATE_FIELDS = ["account_id", "account_name", "user", "access_key_id",
                     "status", "create_date"]

# Long-term Amazon Bedrock API keys are IAM service-specific credentials for
# this service. They get their own CSV, state, and changelog next to the
# access-key ones (see _layout).
BEDROCK_SERVICE_NAME = "bedrock.amazonaws.com"
INCLUDE_BEDROCK_KEYS = os.environ.get("INCLUDE_BEDROCK_KEYS", "true").lower() != "false"
BEDROCK_EXPIRY_WARN_DAYS = int(os.environ.get("BEDROCK_EXPIRY_WARN_DAYS", "30"))
BEDROCK_FIELDS = ["run_id", "account_id", "account_name", "user", "credential_id",
                  "service_name", "status", "create_date", "age_days", "expiration_date",
                  "days_to_expiry", "never_expires", "user_active_access_keys"]
_BEDROCK_STATE_FIELDS = ["account_id", "account_name", "user", "credential_id",
                         "service_name", "status", "create_date", "expiration_date"]

# S3 layout (see the module docstring). File names are relative to the run
# folder (or latest/); state files are relative to PREFIX.
DEFAULT_PREFIX = "credential-inventory"
# Root of the previous layout. Only its state files are ever read, to seed
# change detection once; nothing under it is written, moved, or deleted.
DEFAULT_LEGACY_PREFIX = "access-key-reports"
ACCESS_CSV_FILE = "access-keys.csv"
BEDROCK_CSV_FILE = "bedrock-api-keys.csv"
ACCESS_CHANGES_FILE = "changes-access-keys.json"
BEDROCK_CHANGES_FILE = "changes-bedrock-api-keys.json"
MANIFEST_FILE = "manifest.json"
ACCESS_STATE_FILE = "state/access-keys.json"
BEDROCK_STATE_FILE = "state/bedrock-api-keys.json"
LEGACY_ACCESS_STATE = "state/keys-state.json"
LEGACY_BEDROCK_STATE = "bedrock-api-keys/state/keys-state.json"
# v2 state = {"schema_version", "run_id", "updated_at", "covered_accounts", "keys"}.
# The legacy state is the bare {hashed-id: descriptor} map (no coverage info).
STATE_SCHEMA_VERSION = 2
MANIFEST_VERSION = 1

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


def _err_code(e):
    """Short error code for logs/payloads.

    ClientError has a structured code; BotoCoreError (timeouts, connection
    failures, parameter validation) does not, so fall back to its class name.
    """
    if isinstance(e, ClientError):
        return e.response["Error"]["Code"]
    return type(e).__name__


def _list_user_names(iam):
    names = []
    for page in iam.get_paginator("list_users").paginate():
        names.extend(u["UserName"] for u in page["Users"])
    return names


def _collect_keys(iam, now, user_names=None):
    if user_names is None:
        user_names = _list_user_names(iam)
    rows = []
    for name in user_names:
        for k in iam.list_access_keys(UserName=name)["AccessKeyMetadata"]:
            kid = k["AccessKeyId"]
            # "Never" only when IAM confirms there is no last-used date; a failed
            # lookup is "Unknown" so it isn't miscounted as a dormant key.
            try:
                lu = iam.get_access_key_last_used(AccessKeyId=kid)["AccessKeyLastUsed"]
                last_used = (lu["LastUsedDate"].isoformat() if "LastUsedDate" in lu
                             else LAST_USED_NEVER)
            except (ClientError, BotoCoreError) as e:
                last_used = LAST_USED_UNKNOWN
                logger.warning("Could not read last-used date for user %s key %s: %s",
                               name, _mask(kid), _err_code(e))
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


def _ssc_capabilities(iam):
    """What the bundled SDK's IAM model supports for service-specific credentials.

    Returns (supports_all_users, supports_expiration). botocore < 1.39.0 has no
    AllUsers/Marker inputs (passing AllUsers raises ParamValidationError) and
    silently drops ExpirationDate from responses, so detect both at runtime.
    """
    try:
        model = iam.meta.service_model
        op = model.operation_model("ListServiceSpecificCredentials")
        all_users = "AllUsers" in op.input_shape.members
        expiry = "ExpirationDate" in model.shape_for("ServiceSpecificCredentialMetadata").members
        return all_users, expiry
    except Exception:  # noqa: BLE001 -- any model surprise -> safest mode
        return False, False


def _list_service_credentials(iam, service_name, user_names, all_users):
    """List service-specific credential METADATA (never secrets) for an account.

    all_users=True: one AllUsers call per account, paging with Marker.
    all_users=False: one call per user (older SDKs). UserName is always passed,
    because omitting it targets the caller, and an assumed role has no user.
    """
    creds = []
    if all_users:
        kwargs = {"ServiceName": service_name, "AllUsers": True, "MaxItems": 1000}
        while True:
            resp = iam.list_service_specific_credentials(**kwargs)
            creds.extend(resp.get("ServiceSpecificCredentials", []))
            if not (resp.get("IsTruncated") and resp.get("Marker")):
                break
            kwargs["Marker"] = resp["Marker"]
        return creds
    for name in user_names:
        try:
            resp = iam.list_service_specific_credentials(UserName=name, ServiceName=service_name)
        except ClientError as e:
            if _err_code(e) == "NoSuchEntity":  # user deleted mid-run
                continue
            raise
        creds.extend(resp.get("ServiceSpecificCredentials", []))
    return creds


def _service_credential_row(cred, now, expiry_supported):
    """One report row for a service-specific credential.

    ServiceCredentialAlias (the public part of the bearer token) and
    ServiceUserName are deliberately NOT copied.
    """
    cid = cred["ServiceSpecificCredentialId"]
    exp = cred.get("ExpirationDate") if expiry_supported else None
    if exp is not None:
        expiration_date, days_to_expiry, never_expires = exp.isoformat(), (exp - now).days, "false"
    elif expiry_supported:
        expiration_date, days_to_expiry, never_expires = "Never", "", "true"
    else:
        # The SDK model has no ExpirationDate, so we can't tell.
        expiration_date, days_to_expiry, never_expires = "Unknown", "", "Unknown"
    return {
        "user": cred["UserName"],
        "credential_id": _mask(cid),
        # In-memory only, for change detection (hashed in the state file).
        "raw_key_id": cid,
        "service_name": cred["ServiceName"],
        "status": cred["Status"],
        "create_date": cred["CreateDate"].isoformat(),
        "age_days": (now - cred["CreateDate"]).days,
        "expiration_date": expiration_date,
        "days_to_expiry": days_to_expiry,
        "never_expires": never_expires,
    }


def _collect_bedrock_keys(iam, now, user_names):
    """Long-term Bedrock API keys in one account -> (rows, listing_mode, expiry_supported)."""
    all_users, expiry_supported = _ssc_capabilities(iam)
    creds = _list_service_credentials(iam, BEDROCK_SERVICE_NAME, user_names, all_users)
    rows = [_service_credential_row(c, now, expiry_supported) for c in creds]
    return rows, ("all_users" if all_users else "per_user"), expiry_supported


def _annotate_bedrock_rows(b_rows, key_rows, account_id, account_name):
    """Add account info and the owning user's active access-key count (no extra API call)."""
    active_keys = Counter(r["user"] for r in key_rows if r["status"] == "Active")
    for r in b_rows:
        r["account_id"], r["account_name"] = account_id, account_name
        r["user_active_access_keys"] = active_keys.get(r["user"], 0)
    return b_rows


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


def _notify(errors, summary, bedrock_errors=(), write_errors=()):
    """Publish an SNS alert when there are errors, if a topic is configured."""
    topic = os.environ.get("ALERT_TOPIC_ARN")
    if not topic or not (errors or bedrock_errors or write_errors):
        return
    parts = ["Org-wide IAM access-key inventory needs administrator attention.", summary]
    if errors:
        lines = [f"  - {e['account_id']} ({e['account_name']}): {e['error']}" for e in errors]
        parts.append(
            f"{len(errors)} account(s) could NOT be inventoried "
            "(no assumable audit role, SCP denial, or suspended account):\n"
            + "\n".join(lines)
            + "\n\nFix: ensure one of the CANDIDATE_ROLES exists and is assumable in "
              "each account above (deploy the OrgAccessKeyAuditRole StackSet), then re-run."
        )
    if bedrock_errors:
        lines = [f"  - {e['account_id']} ({e['account_name']}): {e['error']}" for e in bedrock_errors]
        parts.append(
            f"{len(bedrock_errors)} account(s) were inventoried for access keys, but their "
            "Bedrock API keys could NOT be listed (usually the OrgAccessKeyAuditRole "
            "StackSet lacks iam:ListServiceSpecificCredentials, or an SCP denies it):\n"
            + "\n".join(lines)
            + "\n\nFix: re-run ./deploy-audit-role-stackset.sh, wait for SUCCEEDED, then re-run."
        )
    if write_errors:
        lines = [f"  - {w['s3_uri']}: {w['error']}" for w in write_errors]
        parts.append(
            f"{len(write_errors)} report/state file(s) could NOT be written to S3:\n"
            + "\n".join(lines)
            + "\n\nFix: check the function role's s3:PutObject permission and any bucket "
              "policy, then re-run."
        )
    msg = "\n\n".join(parts)
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
    never_used = sum(1 for r in rows if r["last_used"] == LAST_USED_NEVER)
    last_used_unknown = sum(1 for r in rows if r["last_used"] == LAST_USED_UNKNOWN)
    stale = sum(1 for r in rows if r["age_days"] >= STALE_AGE_DAYS)
    stale_active = sum(1 for r in rows
                       if r["age_days"] >= STALE_AGE_DAYS and r["status"] == "Active")
    return {
        "KeysTotal": total,
        "KeysActive": active,
        "KeysInactive": total - active,
        "KeysNeverUsed": never_used,
        "KeysLastUsedUnknown": last_used_unknown,
        "KeysStale": stale,
        "KeysStaleActive": stale_active,
        "AccountsScanned": accounts_scanned,
        "AccountsWithErrors": error_count,
    }


def _summarize_bedrock(rows, error_count, expiry_supported):
    """Aggregate Bedrock API key rows. Total = Active + Inactive + Expired.

    A key is Expired if IAM says so or its expiration date has passed (expired
    takes precedence over Active/Inactive). Expiry-based counts are omitted when
    the SDK can't report expiration dates, rather than published as zeros.
    """
    def _expired(r):
        d = r["days_to_expiry"]
        return r["status"] == "Expired" or (isinstance(d, int) and d < 0)

    live = [r for r in rows if not _expired(r)]
    active = [r for r in live if r["status"] == "Active"]
    metrics = {
        "BedrockKeysTotal": len(rows),
        "BedrockKeysActive": len(active),
        "BedrockKeysInactive": len(live) - len(active),
        "BedrockKeysExpired": len(rows) - len(live),
        "BedrockKeysStale": sum(1 for r in rows if r["age_days"] >= STALE_AGE_DAYS),
        "BedrockKeysStaleActive": sum(1 for r in active if r["age_days"] >= STALE_AGE_DAYS),
        "BedrockAccountsWithErrors": error_count,
    }
    if expiry_supported:
        metrics["BedrockKeysNoExpiry"] = sum(1 for r in rows if r["never_expires"] == "true")
        metrics["BedrockKeysNoExpiryActive"] = sum(1 for r in active if r["never_expires"] == "true")
        metrics["BedrockKeysExpiringSoon"] = sum(
            1 for r in active
            if isinstance(r["days_to_expiry"], int)
            and 0 <= r["days_to_expiry"] <= BEDROCK_EXPIRY_WARN_DAYS)
    return metrics


def _utcnow():
    """Current UTC time (a seam so tests can pin the run id)."""
    return dt.datetime.now(dt.timezone.utc)


def _layout(prefix, legacy_prefix, now):
    """Every S3 key one run reads or writes, derived from a single run id.

    Pure, so the handler and the tests share one source of truth. Legacy keys
    are None when legacy_prefix is empty (fallback disabled).
    """
    run_id = f"{now:%Y%m%dT%H%M%SZ}"
    run_prefix = f"{prefix}/runs/{now:%Y/%m/%d}/{run_id}"
    latest_prefix = f"{prefix}/latest"
    return {
        "run_id": run_id,
        "run_prefix": run_prefix,
        "latest_prefix": latest_prefix,
        "manifest": f"{run_prefix}/{MANIFEST_FILE}",
        "access_csv": f"{run_prefix}/{ACCESS_CSV_FILE}",
        "bedrock_csv": f"{run_prefix}/{BEDROCK_CSV_FILE}",
        "access_changes": f"{run_prefix}/{ACCESS_CHANGES_FILE}",
        "bedrock_changes": f"{run_prefix}/{BEDROCK_CHANGES_FILE}",
        "latest_manifest": f"{latest_prefix}/{MANIFEST_FILE}",
        "latest_access_csv": f"{latest_prefix}/{ACCESS_CSV_FILE}",
        "latest_bedrock_csv": f"{latest_prefix}/{BEDROCK_CSV_FILE}",
        "access_state": f"{prefix}/{ACCESS_STATE_FILE}",
        "bedrock_state": f"{prefix}/{BEDROCK_STATE_FILE}",
        "legacy_access_state": f"{legacy_prefix}/{LEGACY_ACCESS_STATE}" if legacy_prefix else None,
        "legacy_bedrock_state": f"{legacy_prefix}/{LEGACY_BEDROCK_STATE}" if legacy_prefix else None,
    }


def _put_object(s3, bucket, key, body, content_type, writes, label="", metadata=None):
    """Write one S3 object and record the outcome in `writes`.

    Never raises for S3 errors: the manifest is built from `writes`, so a file
    that failed to write is reported as null + error instead of aborting the
    run (and losing the state, manifest, metrics and alert with it).
    Returns the s3:// URI, or None on failure.
    """
    uri = f"s3://{bucket}/{key}"
    kwargs = {"Bucket": bucket, "Key": key, "Body": body, "ContentType": content_type,
              "ServerSideEncryption": "AES256"}
    if metadata:
        kwargs["Metadata"] = metadata
    try:
        s3.put_object(**kwargs)
    except (ClientError, BotoCoreError) as e:
        logger.error("%sFailed to write s3://%s/%s: %s", label, bucket, key, e)
        writes.append({"key": key, "s3_uri": uri, "error": _err_code(e)})
        return None
    writes.append({"key": key, "s3_uri": uri, "error": None})
    return uri


def _state_id(account_id, raw_key_id):
    """Stable, non-reversible identifier for a key (no raw id is persisted)."""
    return hashlib.sha256(f"{account_id}:{raw_key_id}".encode("utf-8")).hexdigest()


def _build_state(rows, fields=_KEY_STATE_FIELDS):
    """Map of hashed-key-id -> lightweight descriptor, for run-to-run diffing.

    Only `fields` are persisted (key ids in them are already masked).
    """
    state = {}
    for r in rows:
        state[_state_id(r["account_id"], r["raw_key_id"])] = {f: r[f] for f in fields}
    return state


def _load_state(s3, bucket, key, label="", quiet=False):
    """Load a stored state document, or None if there is none.

    An existing but empty state ({}) is a valid baseline (zero keys last run),
    so it is returned as-is and is NOT treated as missing. Any read error
    counts as missing: without s3:ListBucket a missing object comes back as
    AccessDenied, so quiet=True (the legacy fallback) logs that at INFO.
    """
    try:
        obj = s3.get_object(Bucket=bucket, Key=key)
        doc = json.loads(obj["Body"].read().decode("utf-8"))
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ("NoSuchKey", "NoSuchBucket", "404"):
            return None
        logger.log(logging.INFO if quiet else logging.WARNING,
                   "%sCould not load state s3://%s/%s (%s); treating it as missing",
                   label, bucket, key, code)
        return None
    except (ValueError, KeyError):
        doc = None
    if not isinstance(doc, dict):
        logger.warning("%sState s3://%s/%s was unreadable; treating it as missing",
                       label, bucket, key)
        return None
    return doc


def _parse_state(doc):
    """State document -> (keys, covered_accounts, coverage_inferred).

    v2 documents carry their coverage. The legacy format is the bare
    {hashed-id: descriptor} map (64-hex keys, so it can't clash with the v2
    field names); its coverage is inferred from the accounts owning entries.
    Owners of stored keys always count as covered.
    """
    def _owners(keys):
        return {e.get("account_id") for e in keys.values() if isinstance(e, dict)} - {None}

    if doc is None:
        return {}, set(), False
    if "schema_version" in doc and isinstance(doc.get("keys"), dict):
        keys = doc["keys"]
        return keys, {a for a in doc.get("covered_accounts") or [] if a} | _owners(keys), False
    return doc, _owners(doc), True


def _state_doc(keys, covered, run_id, now):
    """The v2 state document persisted after each run."""
    return {
        "schema_version": STATE_SCHEMA_VERSION,
        "run_id": run_id,
        "updated_at": now.isoformat(),
        "covered_accounts": sorted(covered),
        "keys": keys,
    }


def _carry_forward(prev, curr, errored_ids, label=""):
    """Keep the previous entries of accounts that could not be read this run.

    Such accounts have NO rows, so a naive diff would report all their keys as
    "removed" (and re-added when the account recovers) and would persist an
    incomplete baseline. Returns the number of entries carried forward.
    """
    if not errored_ids or not prev:
        return 0
    carried = 0
    for sid, entry in prev.items():
        if entry.get("account_id") in errored_ids and sid not in curr:
            curr[sid] = entry
            carried += 1
    if carried:
        logger.info("%sCarried forward %d key(s) from %d un-inventoried account(s): %s",
                    label, carried, len(errored_ids), ", ".join(sorted(errored_ids)))
    return carried


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


def _track_history(s3, bucket, writes, *, state_key, legacy_state_key, changes_key, rows,
                   errored_ids, listed_accounts, now, run_id, report_uri, state_fields,
                   label=""):
    """Diff this run against the stored state, persist the new state, and write
    a changelog when something changed (never on the first run).

    listed_accounts ({account_id: name}) are the accounts whose keys of this
    type were listed successfully this run. Keys in an account that has never
    been listed before are "baselined" (reported separately), not "added": the
    keys already existed, they were just never seen.

    The previous state is read from state_key; if there is none yet, from
    legacy_state_key (read-only, so the upgrade isn't a first run). The new
    state is only ever written to state_key.
    """
    previous_state = None
    doc = _load_state(s3, bucket, state_key, label)
    if doc is not None:
        previous_state = f"s3://{bucket}/{state_key}"
    elif legacy_state_key:
        doc = _load_state(s3, bucket, legacy_state_key, label, quiet=True)
        if doc is not None:
            previous_state = f"s3://{bucket}/{legacy_state_key}"
            logger.info("%sNo state at s3://%s/%s yet; seeding the baseline from legacy "
                        "state s3://%s/%s (left unchanged)",
                        label, bucket, state_key, bucket, legacy_state_key)
    first_run = doc is None
    prev_keys, prev_covered, inferred = _parse_state(doc)
    curr_state = _build_state(rows, state_fields)
    _carry_forward(prev_keys, curr_state, errored_ids, label)

    changes = _diff_states(prev_keys, curr_state)

    # Baseline accounts listed for the first time (on a first run: all of them).
    new_accounts = set(listed_accounts) - prev_covered
    changes["added"] = [e for e in changes["added"] if e.get("account_id") not in new_accounts]
    per_account = Counter(e.get("account_id") for e in curr_state.values())
    baselined = [{"account_id": a, "account_name": listed_accounts[a],
                  "keys": per_account.get(a, 0)} for a in sorted(new_accounts)]
    baselined_keys = sum(b["keys"] for b in baselined)
    if baselined and not first_run:
        logger.info("%sBaselined %d key(s) from %d newly covered account(s): %s", label,
                    baselined_keys, len(baselined), ", ".join(b["account_id"] for b in baselined))
    if inferred:
        with_keys = [b["account_id"] for b in baselined if b["keys"]]
        if with_keys:
            # The legacy state can't tell "listed with zero keys" from "never
            # listed", so these keys can't be classified as new: say so loudly.
            logger.warning(
                "%sLegacy state has no coverage info: %d key(s) in %d account(s) with no "
                "legacy entries were recorded as baseline, not as added: %s. Review their "
                "create_date in %s if a key may have been created since the last legacy run.",
                label, baselined_keys, len(with_keys), ", ".join(with_keys),
                report_uri or "the run CSV")
        else:
            logger.info("%sLegacy state has no coverage info; coverage inferred from the %d "
                        "account(s) owning legacy entries.", label, len(prev_covered))
    change_counts = {k: len(v) for k, v in changes.items()}

    # Persist the new state so the next run has a baseline to diff against.
    # Coverage only grows: an account that fails later keeps its coverage.
    covered = prev_covered | set(listed_accounts)
    state_location = _put_object(
        s3, bucket, state_key,
        json.dumps(_state_doc(curr_state, covered, run_id, now)).encode("utf-8"),
        "application/json", writes, label)

    # Write a per-run changelog (skip the first run, which has no baseline).
    # Newly covered zero-key accounts alone don't warrant one.
    history_location = None
    if not first_run and (any(change_counts.values()) or baselined_keys):
        changelog = {
            "run_id": run_id,
            "run_time": now.isoformat(),
            "report": report_uri,
            "counts": change_counts,
            "changes": changes,
            "baselined_accounts": baselined,
        }
        history_location = _put_object(
            s3, bucket, changes_key, json.dumps(changelog, indent=2).encode("utf-8"),
            "application/json", writes, label)
        if history_location:
            logger.info("%sCHANGES since last run: %s -> %s", label, change_counts, history_location)
    elif first_run:
        logger.info("%sFirst run: %d keys recorded as the history baseline.", label, len(rows))

    return {
        "first_run": first_run,
        "changes": changes,
        "change_counts": change_counts,
        "history_location": history_location,
        "baselined_accounts": baselined,
        "previous_state": previous_state,
        "state_location": state_location,
    }


def _changes_block(hist):
    """The payload/manifest "changes" block for one credential type.

    On the first run there's no baseline, so report zeros here to match the
    metrics (which omit change counts) rather than "everything is new".
    """
    first = hist["first_run"]
    return {"first_run": first,
            **({k: 0 for k in hist["change_counts"]} if first else hist["change_counts"]),
            "baselined_accounts": hist["baselined_accounts"]}


def _change_metrics(changes, metric_prefix):
    """Change counts as metrics, e.g. KeysAdded or BedrockKeysAdded."""
    return {
        f"{metric_prefix}Added": len(changes["added"]),
        f"{metric_prefix}Removed": len(changes["removed"]),
        f"{metric_prefix}Activated": len(changes["activated"]),
        f"{metric_prefix}Deactivated": len(changes["deactivated"]),
    }


def _publish_metrics(metrics):
    """Publish the given name -> count map to CloudWatch as custom metrics."""
    if not PUBLISH_METRICS:
        return
    ts = dt.datetime.now(dt.timezone.utc)
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


def _csv_bytes(rows, fields, run_id):
    """CSV with run_id filled in on every row, so a downloaded file (e.g. from
    latest/) always says which run produced it."""
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=fields)
    w.writeheader()
    for r in sorted(rows, key=lambda x: (x["account_id"], x["create_date"])):
        w.writerow({k: (run_id if k == "run_id" else r[k]) for k in fields})
    return buf.getvalue().encode("utf-8")


def _manifest(bucket, prefix, keys, now, status, accounts_scanned, errors,
              access_block, bedrock_block, writes):
    """The run manifest: what this run wrote (or failed to write) and found.

    files/state_files are derived from the recorded writes, so a failed write
    is listed as null with a matching write_errors entry, never as a success.
    """
    run_dir = keys["run_prefix"] + "/"
    state_dir = f"{prefix}/state/"
    files, state_files = {}, {}
    for w in writes:
        uri = None if w["error"] else w["s3_uri"]
        if w["key"].startswith(run_dir):
            files[w["key"][len(run_dir):]] = uri
        elif w["key"].startswith(state_dir):
            state_files[w["key"][len(prefix) + 1:]] = uri
    return {
        "manifest_version": MANIFEST_VERSION,
        "run_id": keys["run_id"],
        "run_time": now.isoformat(),
        "status": status,
        "bucket": bucket,
        "prefix": prefix,
        "run_prefix": f"s3://{bucket}/{run_dir}",
        "manifest": f"s3://{bucket}/{keys['manifest']}",
        "files": files,
        "state_files": state_files,
        "write_errors": [{"s3_uri": w["s3_uri"], "error": w["error"]} for w in writes if w["error"]],
        "accounts_scanned": accounts_scanned,
        "errors": errors,
        "access_keys": access_block,
        "bedrock": bedrock_block,
        "sdk": {"boto3": boto3.__version__, "botocore": botocore.__version__},
    }


def _update_latest(s3, bucket, keys, run_id, bodies, files, writes, include_bedrock):
    """Refresh latest/<csv> from this run; returns the latest manifest's "files".

    Every latest/ object is a byte-identical copy of a run-folder file, so a
    CSV is only replaced if this run's copy was written. Otherwise the existing
    object (from an earlier run, identified by its run_id column and
    x-amz-meta-run-id) is left as-is rather than deleted or blanked: a
    header-only placeholder would look like "zero keys".
    """
    latest = {}
    for name, latest_key, enabled in (
            (ACCESS_CSV_FILE, keys["latest_access_csv"], True),
            (BEDROCK_CSV_FILE, keys["latest_bedrock_csv"], include_bedrock)):
        uri = f"s3://{bucket}/{latest_key}"
        note = (f"Not replaced by this run: any existing object at {uri} is from an earlier "
                "run; its run_id column and x-amz-meta-run-id metadata identify which run.")
        source = files.get(name)
        if not enabled:
            latest[name] = {"status": "disabled", "s3_uri": uri, "note": note}
        elif source is None:
            latest[name] = {"status": "not_updated", "s3_uri": uri,
                            "reason": "the run copy could not be written", "note": note}
        elif _put_object(s3, bucket, latest_key, bodies[name], "text/csv", writes,
                         metadata={"run-id": run_id}):
            latest[name] = {"status": "updated", "s3_uri": uri, "source": source}
        else:
            latest[name] = {"status": "failed", "s3_uri": uri, "source": source,
                            "error": writes[-1]["error"], "note": note}
    return latest


def handler(event, context):
    bucket = os.environ["BUCKET"]
    prefix = os.environ.get("PREFIX", DEFAULT_PREFIX).strip("/")
    legacy_prefix = os.environ.get("LEGACY_PREFIX", DEFAULT_LEGACY_PREFIX).strip("/")
    now = _utcnow()
    keys = _layout(prefix, legacy_prefix, now)
    run_id = keys["run_id"]
    logger.info("SDK boto3=%s botocore=%s", boto3.__version__, botocore.__version__)

    session = boto3.Session()
    mgmt_id = session.client("sts").get_caller_identity()["Account"]
    orgs = session.client("organizations", config=RETRY_CFG)
    sts = session.client("sts", config=RETRY_CFG)

    accounts = []
    for page in orgs.get_paginator("list_accounts").paginate():
        accounts.extend([a for a in page["Accounts"] if a["Status"] == "ACTIVE"])

    all_rows, errors = [], []
    bedrock_rows, bedrock_errors = [], []
    listing_mode = expiry_supported = None
    for a in accounts:
        aid, aname = a["Id"], a["Name"]
        try:
            if aid == mgmt_id:
                iam, via = session.client("iam", config=RETRY_CFG), "direct"
            else:
                iam, via = _member_iam(sts, session, aid)
            user_names = _list_user_names(iam)
            rows = _collect_keys(iam, now, user_names)
            for r in rows:
                r["account_id"], r["account_name"] = aid, aname
            all_rows.extend(rows)
        except (ClientError, BotoCoreError) as e:
            code = _err_code(e)
            errors.append({"account_id": aid, "account_name": aname, "error": code})
            logger.error("[ERR] %s %s could not be inventoried: %s", aid, aname, code)
            continue

        bedrock_note = ""
        if INCLUDE_BEDROCK_KEYS:
            # A Bedrock-only failure (member role without
            # iam:ListServiceSpecificCredentials, an SCP denial, an SDK
            # parameter error, ...) must never drop this account's access-key
            # rows or fail the run.
            b_err = None
            try:
                b_rows, mode, exp_ok = _collect_bedrock_keys(iam, now, user_names)
                _annotate_bedrock_rows(b_rows, rows, aid, aname)
            except (ClientError, BotoCoreError) as e:
                b_err = _err_code(e)
            except Exception as e:  # noqa: BLE001 -- degrade per account, never fail the run
                b_err = type(e).__name__
                logger.exception("Unexpected error listing Bedrock API keys in %s", aid)
            if b_err:
                bedrock_errors.append({"account_id": aid, "account_name": aname, "error": b_err})
                logger.warning("[WARN] %s %s Bedrock API keys could not be listed: %s",
                               aid, aname, b_err)
                bedrock_note = " bedrock_keys=ERR"
            else:
                bedrock_rows.extend(b_rows)
                bedrock_note = f" bedrock_keys={len(b_rows)}"
                if listing_mode is None:
                    listing_mode, expiry_supported = mode, exp_ok
                    if not exp_ok:
                        logger.warning(
                            "botocore %s cannot report Bedrock API key expiration dates "
                            "(listing_mode=%s): expiration fields are reported as Unknown and "
                            "expiry metrics are skipped. Vendor boto3/botocore >= 1.39.0 into "
                            "the Lambda package to fix.", botocore.__version__, mode)
        logger.info("[OK]  %s %s keys=%d%s via %s", aid, aname, len(rows), bedrock_note, via)

    s3 = boto3.client("s3", config=RETRY_CFG)
    # Every S3 write is recorded here; the manifest is derived from it.
    writes = []

    # ---- Run folder: CSVs first ----------------------------------------------
    bodies = {ACCESS_CSV_FILE: _csv_bytes(all_rows, FIELDS, run_id)}
    access_location = _put_object(s3, bucket, keys["access_csv"], bodies[ACCESS_CSV_FILE],
                                  "text/csv", writes)
    bedrock_location = None
    if INCLUDE_BEDROCK_KEYS:
        bodies[BEDROCK_CSV_FILE] = _csv_bytes(bedrock_rows, BEDROCK_FIELDS, run_id)
        bedrock_location = _put_object(s3, bucket, keys["bedrock_csv"], bodies[BEDROCK_CSV_FILE],
                                       "text/csv", writes, label="[bedrock] ")

    # ---- History: diff against the previous run and record what changed ------
    # Accounts that could not be inventoried this run keep their previous state
    # (see _carry_forward), so transient failures don't produce phantom churn.
    # Only accounts actually listed this run extend each type's coverage.
    error_ids = {e["account_id"] for e in errors}
    bedrock_error_ids = error_ids | {e["account_id"] for e in bedrock_errors}
    listed = {a["Id"]: a["Name"] for a in accounts if a["Id"] not in error_ids}
    hist = _track_history(
        s3, bucket, writes, state_key=keys["access_state"],
        legacy_state_key=keys["legacy_access_state"], changes_key=keys["access_changes"],
        rows=all_rows, errored_ids=error_ids, listed_accounts=listed, now=now,
        run_id=run_id, report_uri=access_location, state_fields=_KEY_STATE_FIELDS)
    if INCLUDE_BEDROCK_KEYS:
        b_hist = _track_history(
            s3, bucket, writes, state_key=keys["bedrock_state"],
            legacy_state_key=keys["legacy_bedrock_state"], changes_key=keys["bedrock_changes"],
            rows=bedrock_rows, errored_ids=bedrock_error_ids,
            listed_accounts={k: v for k, v in listed.items() if k not in bedrock_error_ids},
            now=now, run_id=run_id, report_uri=bedrock_location,
            state_fields=_BEDROCK_STATE_FIELDS, label="[bedrock] ")

    # ---- Metrics: publish the run's posture + changes to CloudWatch ----------
    counts = _summarize(all_rows, len(accounts), len(errors))
    metrics = dict(counts)
    # On the very first run there's no baseline, so change counts are omitted
    # rather than reported as a misleading "everything is new".
    if not hist["first_run"]:
        metrics.update(_change_metrics(hist["changes"], "Keys"))
    if INCLUDE_BEDROCK_KEYS:
        b_counts = _summarize_bedrock(bedrock_rows, len(bedrock_errors), expiry_supported)
        metrics.update(b_counts)
        if not b_hist["first_run"]:
            metrics.update(_change_metrics(b_hist["changes"], "BedrockKeys"))
    _publish_metrics(metrics)

    # ---- Run manifest: written after every run/state file it describes -------
    access_block = {"keys_found": len(all_rows), "metrics": counts,
                    "changes": _changes_block(hist), "previous_state": hist["previous_state"]}
    if INCLUDE_BEDROCK_KEYS:
        bedrock_block = {
            "enabled": True,
            "service_name": BEDROCK_SERVICE_NAME,
            "keys_found": len(bedrock_rows),
            "errors": bedrock_errors,
            "metrics": b_counts,
            "changes": _changes_block(b_hist),
            "previous_state": b_hist["previous_state"],
            "listing_mode": listing_mode,
            "expiry_supported": expiry_supported,
            "botocore_version": botocore.__version__,
        }
    else:
        bedrock_block = {"enabled": False}
    status = ("ATTENTION_REQUIRED" if errors or bedrock_errors or any(w["error"] for w in writes)
              else "OK")
    manifest = _manifest(bucket, prefix, keys, now, status, len(accounts), errors,
                         access_block, bedrock_block, writes)
    manifest_location = _put_object(s3, bucket, keys["manifest"],
                                    json.dumps(manifest, indent=2).encode("utf-8"),
                                    "application/json", writes)

    # ---- latest/: copies of this run's CSVs, latest/manifest.json LAST -------
    latest_files = _update_latest(s3, bucket, keys, run_id, bodies, manifest["files"], writes,
                                  INCLUDE_BEDROCK_KEYS)
    latest_doc = {**manifest, "latest": {"run_manifest": manifest_location, "files": latest_files}}
    _put_object(s3, bucket, keys["latest_manifest"],
                json.dumps(latest_doc, indent=2).encode("utf-8"),
                "application/json", writes, metadata={"run-id": run_id})

    # Final status also covers the manifest and latest/ writes.
    write_errors = [{"s3_uri": w["s3_uri"], "error": w["error"]} for w in writes if w["error"]]
    status = "ATTENTION_REQUIRED" if errors or bedrock_errors or write_errors else "OK"
    summary = (
        f"RUN SUMMARY: status={status} accounts_scanned={len(accounts)} "
        f"keys_found={len(all_rows)} errors={len(errors)} "
        f"report={access_location or 'none'}"
    )
    if INCLUDE_BEDROCK_KEYS:
        summary += (f" bedrock_keys_found={len(bedrock_rows)} "
                    f"bedrock_errors={len(bedrock_errors)} "
                    f"bedrock_report={bedrock_location or 'none'}")
    summary += (f" run_id={run_id} manifest={manifest_location or 'none'} "
                f"write_errors={len(write_errors)}")
    if errors or bedrock_errors or write_errors:
        # ERROR level + explicit marker makes this trivial to search and alarm on.
        logger.error("ADMIN ACTION REQUIRED -- %s", summary)
        _notify(errors, summary, bedrock_errors, write_errors)
    else:
        logger.info(summary)

    if INCLUDE_BEDROCK_KEYS:
        bedrock = {
            "enabled": True,
            "service_name": BEDROCK_SERVICE_NAME,
            "keys_found": len(bedrock_rows),
            "errors": bedrock_errors,
            "s3_location": bedrock_location,
            "metrics": b_counts,
            "changes": bedrock_block["changes"],
            "history_location": b_hist["history_location"],
            "listing_mode": listing_mode,
            "expiry_supported": expiry_supported,
            "botocore_version": botocore.__version__,
        }
    else:
        bedrock = {"enabled": False}

    # Same shape as the "bedrock" block (and the manifest's "access_keys").
    access_keys = {
        "keys_found": len(all_rows),
        "errors": errors,
        # The run folder's access-keys.csv (None if it could not be written).
        "s3_location": access_location,
        "metrics": counts,
        "changes": access_block["changes"],
        "history_location": hist["history_location"],
    }

    return {
        "status": status,
        "accounts_scanned": len(accounts),
        # Top-level access-key fields are kept for backward compatibility; they
        # carry the same values as access_keys.*.
        "keys_found": len(all_rows),
        "errors": errors,
        "s3_location": access_location,
        "metrics": counts,
        "changes": access_block["changes"],
        "history_location": hist["history_location"],
        "access_keys": access_keys,
        "bedrock": bedrock,
        "run_id": run_id,
        "manifest_location": manifest_location,
        "latest_prefix": f"s3://{bucket}/{keys['latest_prefix']}/",
        "write_errors": write_errors,
    }
