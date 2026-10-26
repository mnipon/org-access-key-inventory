"""Unit tests for the org inventory Lambda: Bedrock API keys and the
run-centric S3 layout (run folders, manifests, latest/, state, legacy fallback).

No AWS calls and no network: every client is a botocore Stubber or a mock, and
any real HTTP send fails the test. Run from the repo root:

    PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
"""
import sys

# Never leave bytecode behind: ./lambda is zipped as-is by `cloudformation package`.
sys.dont_write_bytecode = True

import csv  # noqa: E402
import hashlib  # noqa: E402
import io  # noqa: E402
import json  # noqa: E402
import logging  # noqa: E402
import os  # noqa: E402
import pathlib  # noqa: E402
import re  # noqa: E402
import unittest  # noqa: E402
from datetime import datetime, timedelta, timezone  # noqa: E402
from unittest import mock  # noqa: E402

# Deterministic, credential-free environment BEFORE importing the module (it
# reads env vars at import time).
os.environ.update({
    "BUCKET": "test-bucket",
    "PREFIX": "credential-inventory",
    "AWS_DEFAULT_REGION": "us-east-1",
    "AWS_ACCESS_KEY_ID": "testing",
    "AWS_SECRET_ACCESS_KEY": "testing",
    "AWS_EC2_METADATA_DISABLED": "true",
    "AWS_CONFIG_FILE": os.devnull,
    "AWS_SHARED_CREDENTIALS_FILE": os.devnull,
})
for _var in ("AWS_PROFILE", "AWS_SESSION_TOKEN", "ALERT_TOPIC_ARN", "CANDIDATE_ROLES",
             "METRIC_NAMESPACE", "STALE_AGE_DAYS", "PUBLISH_METRICS", "MASK_HEAD",
             "MASK_TAIL", "INCLUDE_BEDROCK_KEYS", "BEDROCK_EXPIRY_WARN_DAYS",
             "LEGACY_PREFIX"):
    os.environ.pop(_var, None)

import botocore  # noqa: E402
import botocore.session  # noqa: E402
from botocore.exceptions import (ClientError, EndpointConnectionError,  # noqa: E402
                                 ParamValidationError)
from botocore.stub import Stubber  # noqa: E402

REPO = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "lambda"))  # "lambda" is a keyword: import the module directly
import lambda_function as lf  # noqa: E402

_IAM_MODEL = botocore.session.Session().get_service_model("iam")
HAS_ALL_USERS = "AllUsers" in _IAM_MODEL.operation_model(
    "ListServiceSpecificCredentials").input_shape.members
HAS_EXPIRATION = "ExpirationDate" in _IAM_MODEL.shape_for(
    "ServiceSpecificCredentialMetadata").members

NOW = datetime(2026, 10, 26, tzinfo=timezone.utc)
SVC = "bedrock.amazonaws.com"
MGMT, MEMBER = "111111111111", "222222222222"

# Pinned run times (via lf._utcnow) for exact-key assertions.
RUN_NOW = datetime(2026, 9, 8, 6, 38, 2, 123456, tzinfo=timezone.utc)
RUN_ID = "20260908T063802Z"
RUN_PREFIX = "credential-inventory/runs/2026/09/08/20260908T063802Z"
RUN2_NOW = RUN_NOW + timedelta(hours=1)
RUN2_ID = "20260908T073802Z"
RUN2_PREFIX = "credential-inventory/runs/2026/09/08/20260908T073802Z"
LATEST = "credential-inventory/latest"
URI = "s3://test-bucket/"

LEGACY_TOP_KEYS = {"status", "accounts_scanned", "keys_found", "errors", "s3_location",
                   "metrics", "changes", "history_location"}
PAYLOAD_TOP_KEYS = LEGACY_TOP_KEYS | {"access_keys", "bedrock", "run_id", "manifest_location",
                                      "latest_prefix", "write_errors"}
LEGACY_METRICS = {"KeysTotal", "KeysActive", "KeysInactive", "KeysNeverUsed", "KeysStale",
                  "KeysStaleActive", "AccountsScanned", "AccountsWithErrors"}
ACCESS_KEY_METRICS = LEGACY_METRICS | {"KeysLastUsedUnknown"}
BEDROCK_BLOCK_KEYS = {"enabled", "service_name", "keys_found", "errors", "s3_location",
                      "metrics", "changes", "history_location", "listing_mode",
                      "expiry_supported", "botocore_version"}
MANIFEST_TOP_KEYS = {"manifest_version", "run_id", "run_time", "status", "bucket", "prefix",
                     "run_prefix", "manifest", "files", "state_files", "write_errors",
                     "accounts_scanned", "errors", "access_keys", "bedrock", "sdk"}
ACCESS_CSV_RE = r"^credential-inventory/runs/\d{4}/\d{2}/\d{2}/\d{8}T\d{6}Z/access-keys\.csv$"
BEDROCK_CSV_RE = (r"^credential-inventory/runs/\d{4}/\d{2}/\d{2}/\d{8}T\d{6}Z/"
                  r"bedrock-api-keys\.csv$")
ACCESS_STATE_KEY = "credential-inventory/state/access-keys.json"
BEDROCK_STATE_KEY = "credential-inventory/state/bedrock-api-keys.json"
LEGACY_ACCESS_STATE_KEY = "access-key-reports/state/keys-state.json"
LEGACY_BEDROCK_STATE_KEY = "access-key-reports/bedrock-api-keys/state/keys-state.json"
ALERT_ENV = {"ALERT_TOPIC_ARN": "arn:aws:sns:us-east-1:111111111111:alerts"}


def _client_error(code, op="ListServiceSpecificCredentials"):
    return ClientError({"Error": {"Code": code, "Message": code}}, op)


class NoNetworkTestCase(unittest.TestCase):
    """Fails the test if anything tries a real HTTP send."""

    def setUp(self):
        p = mock.patch("botocore.httpsession.URLLib3Session.send",
                       side_effect=AssertionError("network call attempted"))
        p.start()
        self.addCleanup(p.stop)


def _stub_iam():
    client = botocore.session.Session().create_client(
        "iam", region_name="us-east-1",
        aws_access_key_id="testing", aws_secret_access_key="testing")
    return client, Stubber(client)


def _model_cred(user, cid, status="Active", created=NOW - timedelta(days=5), expires=None):
    """Credential metadata that validates against the INSTALLED IAM model."""
    c = {"UserName": user, "Status": status, "ServiceUserName": f"{user}-at-{MGMT}",
         "CreateDate": created, "ServiceSpecificCredentialId": cid, "ServiceName": SVC}
    if HAS_EXPIRATION:
        c["ServiceCredentialAlias"] = f"alias{cid}"
        if expires is not None:
            c["ExpirationDate"] = expires
    return c


def _cred(user, cid, status="Active", created=NOW - timedelta(days=5), expires=None,
          alias=None):
    """Plain credential metadata (newest API shape) for pure-function tests."""
    c = {"UserName": user, "Status": status, "ServiceUserName": "",
         "ServiceCredentialAlias": alias or f"alias-public-token-{cid[-4:]}",
         "CreateDate": created, "ServiceSpecificCredentialId": cid, "ServiceName": SVC}
    if expires is not None:
        c["ExpirationDate"] = expires
    return c


# ---------------------------------------------------------------------------
# Handler fixture
# ---------------------------------------------------------------------------
class FakeS3:
    """Minimal S3.

    get_object serves stored objects and raises `missing_code` otherwise
    (AccessDenied mirrors a role without s3:ListBucket). put_object raises
    AccessDenied for keys matching any `fail_puts` regex. Every attempt is
    recorded in `attempts`; only successful puts land in `puts`/`objects`.
    """

    def __init__(self, objects=None, fail_puts=(), missing_code="NoSuchKey"):
        self.objects = {k: (v if isinstance(v, bytes) else json.dumps(v).encode())
                        for k, v in (objects or {}).items()}
        self.fail_puts = list(fail_puts)
        self.missing_code = missing_code
        self.puts, self.attempts, self.gets = [], [], []

    def get_object(self, Bucket, Key):
        self.gets.append(Key)
        if Key in self.objects:
            return {"Body": io.BytesIO(self.objects[Key])}
        raise ClientError({"Error": {"Code": self.missing_code, "Message": "x"}}, "GetObject")

    def put_object(self, **kw):
        self.attempts.append(kw)
        if any(re.search(p, kw["Key"]) for p in self.fail_puts):
            raise ClientError({"Error": {"Code": "AccessDenied", "Message": "x"}}, "PutObject")
        self.puts.append(kw)
        self.objects[kw["Key"]] = kw["Body"]
        return {}

    def body(self, pattern):
        keys = [p["Key"] for p in self.puts if re.search(pattern, p["Key"])]
        assert len(keys) == 1, f"expected exactly one put matching {pattern}: {keys}"
        return keys[0], self.objects[keys[0]].decode("utf-8")

    def json(self, key):
        return json.loads(self.objects[key])

    def put_keys(self):
        return [p["Key"] for p in self.puts]


def _fake_iam(users, access_keys, bedrock_creds=(), bedrock_error=None):
    iam = mock.MagicMock()
    iam.get_paginator.return_value.paginate.return_value = [
        {"Users": [{"UserName": u} for u in users]}]
    iam.list_access_keys.side_effect = (
        lambda UserName: {"AccessKeyMetadata": access_keys.get(UserName, [])})
    iam.get_access_key_last_used.return_value = {"AccessKeyLastUsed": {}}

    def _ssc(**kw):
        if bedrock_error is not None:
            raise bedrock_error
        creds = [c for c in bedrock_creds
                 if "UserName" not in kw or c["UserName"] == kw["UserName"]]
        return {"ServiceSpecificCredentials": creds, "IsTruncated": False}

    iam.list_service_specific_credentials.side_effect = _ssc
    return iam


def _access_key(kid, status="Active", age_days=10):
    return {"AccessKeyId": kid, "Status": status,
            "CreateDate": datetime.now(timezone.utc) - timedelta(days=age_days)}


RAW_ACCESS_KEYS = ["AKIAMGMTEXAMPLE00001", "AKIAMEMBEREXAMPLE002"]
# Distinct last 4 chars so masked ids are distinguishable in assertions.
RAW_BEDROCK_IDS = ["ACCAMGMTEXAMPLE00A001", "ACCAMGMTEXAMPLE00B002", "ACCAMEMBEREXAMPLEC003"]


def _default_iams(member_bedrock_error=None):
    now = datetime.now(timezone.utc)
    mgmt = _fake_iam(
        users=["admin", "BedrockAPIKey-abcd"],
        access_keys={"admin": [_access_key(RAW_ACCESS_KEYS[0], age_days=100)]},
        bedrock_creds=[
            _cred("BedrockAPIKey-abcd", RAW_BEDROCK_IDS[0], created=now - timedelta(days=5)),
            _cred("admin", RAW_BEDROCK_IDS[1], created=now - timedelta(days=3),
                  expires=now + timedelta(days=20, hours=1)),
        ])
    member = _fake_iam(
        users=["dev"],
        access_keys={"dev": [_access_key(RAW_ACCESS_KEYS[1], age_days=10)]},
        bedrock_creds=[
            _cred("dev", RAW_BEDROCK_IDS[2], status="Inactive", created=now - timedelta(days=1),
                  expires=now + timedelta(days=45, hours=1)),
        ],
        bedrock_error=member_bedrock_error)
    return mgmt, member


def _run_handler(s3=None, mgmt_iam=None, member_iam=None, caps=(True, True),
                 member_assume_error=None, env=None, now=None):
    """Invoke lf.handler with every AWS client faked.

    caps=None leaves _ssc_capabilities unpatched (a MagicMock IAM client then
    looks like an SDK without AllUsers/ExpirationDate). now pins the run time
    (and so the run id); give each run on a shared FakeS3 a distinct now.
    """
    if mgmt_iam is None or member_iam is None:
        d_mgmt, d_member = _default_iams()
        mgmt_iam = mgmt_iam or d_mgmt
        member_iam = member_iam or d_member
    s3 = s3 if s3 is not None else FakeS3()
    cw, sns = mock.MagicMock(), mock.MagicMock()
    sts, orgs = mock.MagicMock(), mock.MagicMock()
    sts.get_caller_identity.return_value = {"Account": MGMT}
    orgs.get_paginator.return_value.paginate.return_value = [{"Accounts": [
        {"Id": MGMT, "Name": "mgmt", "Status": "ACTIVE"},
        {"Id": MEMBER, "Name": "member", "Status": "ACTIVE"},
        {"Id": "333333333333", "Name": "closed", "Status": "SUSPENDED"},
    ]}]
    session = mock.MagicMock()
    session.client.side_effect = (
        lambda name, **kw: {"sts": sts, "organizations": orgs, "iam": mgmt_iam}[name])

    def _member(_sts, _session, aid):
        assert aid == MEMBER
        if member_assume_error is not None:
            raise member_assume_error
        return member_iam, "OrgAccessKeyAuditRole"

    patches = [
        mock.patch.object(lf.boto3, "Session", return_value=session),
        mock.patch.object(lf.boto3, "client", side_effect=(
            lambda name, **kw: {"s3": s3, "cloudwatch": cw, "sns": sns}[name])),
        mock.patch.object(lf, "_member_iam", side_effect=_member),
        mock.patch.dict(os.environ, env or {}),
    ]
    if caps is not None:
        patches.append(mock.patch.object(lf, "_ssc_capabilities", return_value=caps))
    if now is not None:
        patches.append(mock.patch.object(lf, "_utcnow", return_value=now))
    for p in patches:
        p.start()
    try:
        result = lf.handler({}, None)
    finally:
        for p in reversed(patches):
            p.stop()
    return result, s3, cw, sns


def _metric_names(cw):
    names = set()
    for call in cw.put_metric_data.call_args_list:
        names |= {d["MetricName"] for d in call.kwargs["MetricData"]}
    return names


def _metric_values(cw):
    values = {}
    for call in cw.put_metric_data.call_args_list:
        values.update({d["MetricName"]: d["Value"] for d in call.kwargs["MetricData"]})
    return values


def _v2_state(keys, covered):
    """A stored v2 state document (as an earlier run would have written it)."""
    return lf._state_doc(keys, set(covered), "20260101T000000Z", NOW)


def _fixture_state_keys():
    """The {hashed-id: descriptor} maps a run over the default fixtures stores
    (access, bedrock), for seeding legacy or v2 states that match them."""
    logging.disable(logging.CRITICAL)
    try:
        _, s3, _, _ = _run_handler(now=RUN_NOW)
    finally:
        logging.disable(logging.NOTSET)
    return s3.json(ACCESS_STATE_KEY)["keys"], s3.json(BEDROCK_STATE_KEY)["keys"]


def _only(keys, account_id):
    return {k: v for k, v in keys.items() if v["account_id"] == account_id}


def _changes(first_run=False, added=0, removed=0, activated=0, deactivated=0, baselined=()):
    return {"first_run": first_run, "added": added, "removed": removed,
            "activated": activated, "deactivated": deactivated,
            "baselined_accounts": list(baselined)}


def _baselined(account_id, keys):
    return {"account_id": account_id,
            "account_name": {MGMT: "mgmt", MEMBER: "member"}[account_id], "keys": keys}


class HandlerTestCase(NoNetworkTestCase):
    def _assert_no_secrets(self, s3):
        for p in s3.puts:
            body = p["Body"].decode("utf-8")
            for raw in RAW_ACCESS_KEYS + RAW_BEDROCK_IDS:
                self.assertNotIn(raw, body, p["Key"])
            self.assertNotIn("alias-public-token", body, p["Key"])


# ---------------------------------------------------------------------------
# Access-key outputs (the new layout; run_id first is an intended breaking change)
# ---------------------------------------------------------------------------
class AccessKeyCharacterizationTests(NoNetworkTestCase):
    def test_access_key_outputs(self):
        with self.assertLogs(level="INFO"):
            result, s3, _, _ = _run_handler(caps=None)
        key, body = s3.body(ACCESS_CSV_RE)
        # Intended breaking change of the run-centric layout: run_id is first.
        self.assertEqual(body.splitlines()[0],
                         "run_id,account_id,account_name,user,access_key_id,status,"
                         "create_date,age_days,last_used")
        self.assertEqual(len(body.splitlines()), 3)  # header + 2 keys (suspended skipped)
        for line in body.splitlines()[1:]:
            self.assertTrue(line.startswith(result["run_id"] + ","), line)
        self.assertIn(ACCESS_STATE_KEY, s3.put_keys())
        self.assertEqual(set(result), PAYLOAD_TOP_KEYS)
        self.assertEqual(set(result["metrics"]), ACCESS_KEY_METRICS)
        self.assertEqual(result["s3_location"], f"s3://test-bucket/{key}")
        self.assertEqual(result["keys_found"], 2)
        self.assertEqual(result["errors"], [])
        for raw in RAW_ACCESS_KEYS:
            self.assertNotIn(raw, body)
            self.assertIn(lf._mask(raw), body)


# ---------------------------------------------------------------------------
# Shared history helpers (decision g: an empty stored state is a baseline)
# ---------------------------------------------------------------------------
class HistoryHelperTests(NoNetworkTestCase):
    def test_load_state_missing_is_none(self):
        self.assertIsNone(lf._load_state(FakeS3(), "b", "k"))

    def test_load_state_access_denied_is_none(self):
        s3 = mock.MagicMock()
        s3.get_object.side_effect = _client_error("AccessDenied", "GetObject")
        with self.assertLogs(level="WARNING"):
            self.assertIsNone(lf._load_state(s3, "b", "k"))

    def test_load_state_quiet_access_denied_logs_info(self):
        with self.assertLogs(level="INFO") as logs:
            self.assertIsNone(lf._load_state(FakeS3(missing_code="AccessDenied"), "b", "k",
                                             quiet=True))
        self.assertEqual([r.levelno for r in logs.records], [logging.INFO])
        self.assertIn("treating it as missing", logs.output[0])

    def test_load_state_empty_dict_is_baseline(self):
        self.assertEqual(lf._load_state(FakeS3({"k": {}}), "b", "k"), {})

    def test_load_state_invalid_json_is_none(self):
        with self.assertLogs(level="WARNING"):
            self.assertIsNone(lf._load_state(FakeS3({"k": b"{not json"}), "b", "k"))

    def test_empty_previous_state_reports_added(self):
        s3 = FakeS3({ACCESS_STATE_KEY: _v2_state({}, [MGMT])})
        row = {"account_id": MGMT, "account_name": "mgmt", "user": "u",
               "access_key_id": "AKIA****0001", "raw_key_id": "AKIAEXAMPLE000000001",
               "status": "Active", "create_date": NOW.isoformat()}
        changes_key = f"{RUN_PREFIX}/changes-access-keys.json"
        writes = []
        with self.assertLogs(level="INFO"):
            hist = lf._track_history(
                s3, "test-bucket", writes, state_key=ACCESS_STATE_KEY,
                legacy_state_key=None, changes_key=changes_key, rows=[row],
                errored_ids=set(), listed_accounts={MGMT: "mgmt"}, now=RUN_NOW,
                run_id=RUN_ID, report_uri="s3://test-bucket/r.csv",
                state_fields=lf._KEY_STATE_FIELDS)
        self.assertFalse(hist["first_run"])
        self.assertEqual(hist["change_counts"]["added"], 1)
        self.assertEqual(hist["baselined_accounts"], [])
        self.assertEqual(hist["history_location"], URI + changes_key)
        self.assertEqual(hist["previous_state"], URI + ACCESS_STATE_KEY)
        self.assertEqual(hist["state_location"], URI + ACCESS_STATE_KEY)
        self.assertEqual([w["key"] for w in writes], [ACCESS_STATE_KEY, changes_key])

    def test_carry_forward_for_errored_account(self):
        sid = lf._state_id(MEMBER, "AKIAEXAMPLE000000002")
        prev = {sid: {"account_id": MEMBER, "status": "Active"}}
        s3 = FakeS3({ACCESS_STATE_KEY: _v2_state(prev, [MEMBER])})
        with self.assertLogs(level="INFO") as logs:
            hist = lf._track_history(
                s3, "test-bucket", [], state_key=ACCESS_STATE_KEY, legacy_state_key=None,
                changes_key=f"{RUN_PREFIX}/changes-access-keys.json", rows=[],
                errored_ids={MEMBER}, listed_accounts={}, now=RUN_NOW, run_id=RUN_ID,
                report_uri="s3://r", state_fields=lf._KEY_STATE_FIELDS)
        self.assertEqual(hist["change_counts"]["removed"], 0)
        self.assertIsNone(hist["history_location"])
        self.assertIn(sid, s3.json(ACCESS_STATE_KEY)["keys"])
        self.assertTrue(any("Carried forward 1 key(s)" in m for m in logs.output))


# ---------------------------------------------------------------------------
# Pure S3-layout helpers
# ---------------------------------------------------------------------------
class LayoutHelperTests(NoNetworkTestCase):
    def test_layout_keys_exact(self):
        self.assertEqual(lf._layout("credential-inventory", "access-key-reports", RUN_NOW), {
            "run_id": "20260908T063802Z",
            "run_prefix": "credential-inventory/runs/2026/09/08/20260908T063802Z",
            "latest_prefix": "credential-inventory/latest",
            "manifest": "credential-inventory/runs/2026/09/08/20260908T063802Z/manifest.json",
            "access_csv": "credential-inventory/runs/2026/09/08/20260908T063802Z/access-keys.csv",
            "bedrock_csv":
                "credential-inventory/runs/2026/09/08/20260908T063802Z/bedrock-api-keys.csv",
            "access_changes":
                "credential-inventory/runs/2026/09/08/20260908T063802Z/changes-access-keys.json",
            "bedrock_changes": "credential-inventory/runs/2026/09/08/20260908T063802Z/"
                               "changes-bedrock-api-keys.json",
            "latest_manifest": "credential-inventory/latest/manifest.json",
            "latest_access_csv": "credential-inventory/latest/access-keys.csv",
            "latest_bedrock_csv": "credential-inventory/latest/bedrock-api-keys.csv",
            "access_state": "credential-inventory/state/access-keys.json",
            "bedrock_state": "credential-inventory/state/bedrock-api-keys.json",
            "legacy_access_state": "access-key-reports/state/keys-state.json",
            "legacy_bedrock_state": "access-key-reports/bedrock-api-keys/state/keys-state.json",
        })

    def test_layout_custom_and_empty_legacy_prefix(self):
        k = lf._layout("credential-inventory", "old-root", RUN_NOW)
        self.assertEqual((k["legacy_access_state"], k["legacy_bedrock_state"]),
                         ("old-root/state/keys-state.json",
                          "old-root/bedrock-api-keys/state/keys-state.json"))
        k = lf._layout("credential-inventory", "", RUN_NOW)
        self.assertEqual((k["legacy_access_state"], k["legacy_bedrock_state"]), (None, None))

    def test_put_object_success_and_failure(self):
        s3 = FakeS3(fail_puts=[r"bad\.csv$"])
        writes = []
        uri = lf._put_object(s3, "test-bucket", "p/good.csv", b"x", "text/csv", writes,
                             metadata={"run-id": RUN_ID})
        self.assertEqual(uri, "s3://test-bucket/p/good.csv")
        self.assertEqual(s3.puts, [{"Bucket": "test-bucket", "Key": "p/good.csv", "Body": b"x",
                                    "ContentType": "text/csv",
                                    "ServerSideEncryption": "AES256",
                                    "Metadata": {"run-id": RUN_ID}}])
        with self.assertLogs(level="ERROR") as logs:
            self.assertIsNone(lf._put_object(s3, "test-bucket", "p/bad.csv", b"y",
                                             "application/json", writes, label="[x] "))
        self.assertNotIn("Metadata", s3.attempts[1])
        self.assertNotIn("p/bad.csv", s3.objects)
        self.assertIn("[x] Failed to write s3://test-bucket/p/bad.csv", logs.output[0])
        # Transport errors (no ClientError code) are recorded by class name.
        broken = mock.MagicMock()
        broken.put_object.side_effect = EndpointConnectionError(endpoint_url="https://x")
        with self.assertLogs(level="ERROR"):
            self.assertIsNone(lf._put_object(broken, "test-bucket", "p/net.csv", b"z",
                                             "text/csv", writes))
        self.assertEqual(writes, [
            {"key": "p/good.csv", "s3_uri": "s3://test-bucket/p/good.csv", "error": None},
            {"key": "p/bad.csv", "s3_uri": "s3://test-bucket/p/bad.csv", "error": "AccessDenied"},
            {"key": "p/net.csv", "s3_uri": "s3://test-bucket/p/net.csv",
             "error": "EndpointConnectionError"},
        ])

    def test_parse_state_variants(self):
        e1 = {"account_id": MGMT, "status": "Active"}
        e2 = {"account_id": MEMBER, "status": "Active"}
        self.assertEqual(lf._parse_state(None), ({}, set(), False))
        v2 = _v2_state({"a" * 64: e1}, [MEMBER, "333333333333"])
        self.assertEqual(lf._parse_state(v2),
                         ({"a" * 64: e1}, {MGMT, MEMBER, "333333333333"}, False))
        flat = {"a" * 64: e1, "b" * 64: e2, "c" * 64: {"status": "Active"}, "d" * 64: "junk"}
        self.assertEqual(lf._parse_state(flat), (flat, {MGMT, MEMBER}, True))
        self.assertEqual(lf._parse_state({}), ({}, set(), True))
        no_coverage = {"schema_version": 2, "keys": {"a" * 64: e1}}
        self.assertEqual(lf._parse_state(no_coverage), ({"a" * 64: e1}, {MGMT}, False))

    def test_state_doc_shape(self):
        doc = lf._state_doc({"k": {}}, {MEMBER, MGMT}, RUN_ID, RUN_NOW)
        self.assertEqual(doc, {"schema_version": 2, "run_id": RUN_ID,
                               "updated_at": RUN_NOW.isoformat(),
                               "covered_accounts": [MGMT, MEMBER], "keys": {"k": {}}})
        self.assertEqual(list(doc), ["schema_version", "run_id", "updated_at",
                                     "covered_accounts", "keys"])


# ---------------------------------------------------------------------------
# T1: SDK capability detection
# ---------------------------------------------------------------------------
class CapabilityTests(NoNetworkTestCase):
    def test_capabilities_match_installed_model(self):
        client, _ = _stub_iam()
        self.assertEqual(lf._ssc_capabilities(client), (HAS_ALL_USERS, HAS_EXPIRATION))

    def test_capabilities_model_error_is_safest_mode(self):
        iam = mock.MagicMock()
        iam.meta.service_model.operation_model.side_effect = RuntimeError("boom")
        self.assertEqual(lf._ssc_capabilities(iam), (False, False))


# ---------------------------------------------------------------------------
# T2: listing (Stubber validates requests/responses against the real model)
# ---------------------------------------------------------------------------
class ListingTests(NoNetworkTestCase):
    @unittest.skipUnless(HAS_ALL_USERS, "installed botocore has no AllUsers (needs >= 1.39.0)")
    def test_all_users_marker_pagination(self):
        client, stub = _stub_iam()
        base = {"ServiceName": SVC, "AllUsers": True, "MaxItems": 1000}
        stub.add_response("list_service_specific_credentials",
                          {"ServiceSpecificCredentials": [
                              _model_cred("a", "ACCAEXAMPLE0000000001"),
                              _model_cred("b", "ACCAEXAMPLE0000000002")],
                           "IsTruncated": True, "Marker": "m1"},
                          dict(base))
        stub.add_response("list_service_specific_credentials",
                          {"ServiceSpecificCredentials": [
                              _model_cred("c", "ACCAEXAMPLE0000000003")],
                           "IsTruncated": False},
                          {**base, "Marker": "m1"})
        with stub:
            creds = lf._list_service_credentials(client, SVC, ["ignored"], all_users=True)
            stub.assert_no_pending_responses()
        self.assertEqual([c["ServiceSpecificCredentialId"] for c in creds],
                         ["ACCAEXAMPLE0000000001", "ACCAEXAMPLE0000000002",
                          "ACCAEXAMPLE0000000003"])

    @unittest.skipUnless(HAS_ALL_USERS, "installed botocore has no AllUsers (needs >= 1.39.0)")
    def test_all_users_single_page(self):
        client, stub = _stub_iam()
        stub.add_response("list_service_specific_credentials",
                          {"ServiceSpecificCredentials": [
                              _model_cred("a", "ACCAEXAMPLE0000000001")],
                           "IsTruncated": False},
                          {"ServiceName": SVC, "AllUsers": True, "MaxItems": 1000})
        with stub:
            creds = lf._list_service_credentials(client, SVC, [], all_users=True)
            stub.assert_no_pending_responses()
        self.assertEqual(len(creds), 1)

    def test_per_user_fallback_skips_deleted_user(self):
        client, stub = _stub_iam()
        stub.add_response("list_service_specific_credentials",
                          {"ServiceSpecificCredentials": []},
                          {"UserName": "alice", "ServiceName": SVC})
        stub.add_response("list_service_specific_credentials",
                          {"ServiceSpecificCredentials": [
                              _model_cred("BedrockAPIKey-abcd", "ACCAEXAMPLE0000000001")]},
                          {"UserName": "BedrockAPIKey-abcd", "ServiceName": SVC})
        stub.add_client_error("list_service_specific_credentials",
                              service_error_code="NoSuchEntity", http_status_code=404,
                              expected_params={"UserName": "gone", "ServiceName": SVC})
        with stub:
            creds = lf._list_service_credentials(
                client, SVC, ["alice", "BedrockAPIKey-abcd", "gone"], all_users=False)
            stub.assert_no_pending_responses()
        self.assertEqual([c["UserName"] for c in creds], ["BedrockAPIKey-abcd"])

    def test_per_user_access_denied_propagates(self):
        client, stub = _stub_iam()
        stub.add_client_error("list_service_specific_credentials",
                              service_error_code="AccessDenied", http_status_code=403,
                              expected_params={"UserName": "alice", "ServiceName": SVC})
        with stub, self.assertRaises(ClientError) as cm:
            lf._list_service_credentials(client, SVC, ["alice"], all_users=False)
        self.assertEqual(cm.exception.response["Error"]["Code"], "AccessDenied")

    def test_collect_uses_mode_supported_by_installed_sdk(self):
        client, stub = _stub_iam()
        exp = NOW + timedelta(days=7)
        resp = {"ServiceSpecificCredentials": [
            _model_cred("alice", "ACCAEXAMPLE0000000001", expires=exp)]}
        if HAS_ALL_USERS:
            stub.add_response("list_service_specific_credentials", {**resp, "IsTruncated": False},
                              {"ServiceName": SVC, "AllUsers": True, "MaxItems": 1000})
        else:
            stub.add_response("list_service_specific_credentials", resp,
                              {"UserName": "alice", "ServiceName": SVC})
        with stub:
            rows, mode, exp_ok = lf._collect_bedrock_keys(client, NOW, ["alice"])
            stub.assert_no_pending_responses()
        self.assertEqual(mode, "all_users" if HAS_ALL_USERS else "per_user")
        self.assertEqual(exp_ok, HAS_EXPIRATION)
        self.assertEqual(len(rows), 1)
        if HAS_EXPIRATION:
            self.assertEqual((rows[0]["expiration_date"], rows[0]["days_to_expiry"]),
                             (exp.isoformat(), 7))
        else:
            self.assertEqual(rows[0]["expiration_date"], "Unknown")


# ---------------------------------------------------------------------------
# T3: row building
# ---------------------------------------------------------------------------
class RowTests(unittest.TestCase):
    def test_active_with_expiration(self):
        r = lf._service_credential_row(
            _cred("u", "ACCAEXAMPLE0000000001", expires=NOW + timedelta(days=10)), NOW, True)
        self.assertEqual(r["expiration_date"], (NOW + timedelta(days=10)).isoformat())
        self.assertEqual(r["days_to_expiry"], 10)
        self.assertEqual(r["never_expires"], "false")
        self.assertEqual(r["status"], "Active")
        self.assertEqual(r["service_name"], SVC)
        self.assertEqual(r["age_days"], 5)

    def test_inactive_without_expiration_never_expires(self):
        r = lf._service_credential_row(
            _cred("u", "ACCAEXAMPLE0000000001", status="Inactive"), NOW, True)
        self.assertEqual((r["expiration_date"], r["days_to_expiry"], r["never_expires"]),
                         ("Never", "", "true"))
        self.assertEqual(r["status"], "Inactive")

    def test_expiry_unsupported_is_unknown(self):
        r = lf._service_credential_row(
            _cred("u", "ACCAEXAMPLE0000000001", expires=NOW + timedelta(days=10)), NOW, False)
        self.assertEqual((r["expiration_date"], r["days_to_expiry"], r["never_expires"]),
                         ("Unknown", "", "Unknown"))

    def test_expired_has_negative_days(self):
        r = lf._service_credential_row(
            _cred("u", "ACCAEXAMPLE0000000001", status="Expired",
                  expires=NOW - timedelta(days=3)), NOW, True)
        self.assertEqual(r["status"], "Expired")
        self.assertEqual(r["days_to_expiry"], -3)

    def test_id_masked_and_alias_not_copied(self):
        raw = "ACCAEXAMPLE0000000001"
        c = _cred("u", raw, alias="alias-public-token-zzzz")
        c["ServiceUserName"] = "service-user-name-zzzz"
        r = lf._service_credential_row(c, NOW, True)
        self.assertEqual(r["credential_id"], "ACCA" + "*" * (len(raw) - 8) + "0001")
        self.assertEqual(r["raw_key_id"], raw)
        values = [str(v) for v in r.values()]
        self.assertNotIn("alias-public-token-zzzz", values)
        self.assertNotIn("service-user-name-zzzz", values)
        self.assertNotIn("ServiceCredentialAlias", r)


# ---------------------------------------------------------------------------
# T4: summarize
# ---------------------------------------------------------------------------
class SummarizeTests(unittest.TestCase):
    def _creds(self):
        d = timedelta
        return [
            _cred("a", "ACCAEXAMPLE0000000001", created=NOW - d(days=10), expires=NOW + d(days=5)),
            _cred("b", "ACCAEXAMPLE0000000002", created=NOW - d(days=20)),
            _cred("c", "ACCAEXAMPLE0000000003", created=NOW - d(days=120)),
            _cred("d", "ACCAEXAMPLE0000000004", status="Inactive", created=NOW - d(days=200)),
            _cred("e", "ACCAEXAMPLE0000000005", status="Expired", created=NOW - d(days=400),
                  expires=NOW - d(days=3)),
            _cred("f", "ACCAEXAMPLE0000000006", created=NOW - d(days=30), expires=NOW - d(days=1)),
            _cred("g", "ACCAEXAMPLE0000000007", created=NOW - d(days=5), expires=NOW + d(days=60)),
        ]

    def test_mixed_counts(self):
        rows = [lf._service_credential_row(c, NOW, True) for c in self._creds()]
        with mock.patch.object(lf, "STALE_AGE_DAYS", 90), \
                mock.patch.object(lf, "BEDROCK_EXPIRY_WARN_DAYS", 30):
            m = lf._summarize_bedrock(rows, 2, True)
        self.assertEqual(m, {
            "BedrockKeysTotal": 7,
            "BedrockKeysActive": 4,      # a, b, c, g
            "BedrockKeysInactive": 1,    # d
            "BedrockKeysExpired": 2,     # e (status), f (date passed)
            "BedrockKeysStale": 3,       # c, d, e
            "BedrockKeysStaleActive": 1,  # c
            "BedrockAccountsWithErrors": 2,
            "BedrockKeysNoExpiry": 3,    # b, c, d
            "BedrockKeysNoExpiryActive": 2,  # b, c
            "BedrockKeysExpiringSoon": 1,  # a
        })
        self.assertEqual(m["BedrockKeysTotal"], m["BedrockKeysActive"]
                         + m["BedrockKeysInactive"] + m["BedrockKeysExpired"])

    def test_expiry_unsupported_omits_expiry_metrics(self):
        rows = [lf._service_credential_row(c, NOW, False) for c in self._creds()]
        m = lf._summarize_bedrock(rows, 0, False)
        for name in ("BedrockKeysNoExpiry", "BedrockKeysNoExpiryActive",
                     "BedrockKeysExpiringSoon"):
            self.assertNotIn(name, m)
        self.assertEqual(m["BedrockKeysExpired"], 1)  # only the status-based one
        self.assertEqual(m["BedrockKeysTotal"], m["BedrockKeysActive"]
                         + m["BedrockKeysInactive"] + m["BedrockKeysExpired"])


class LastUsedTests(NoNetworkTestCase):
    """last_used is a timestamp, "Never" (IAM has no date) or "Unknown" (lookup
    failed); only "Never" counts toward KeysNeverUsed."""
    USED, NEVER, FAILED = "AKIAUSEDEXAMPLE0001A", "AKIANEVEREXAMPLE002B", "AKIAFAILEDEXAMPLE03C"

    def _iam(self):
        used_at = NOW - timedelta(days=2)

        def _last_used(AccessKeyId):
            if AccessKeyId == self.FAILED:
                raise _client_error("Throttling", "GetAccessKeyLastUsed")
            if AccessKeyId == self.USED:
                return {"AccessKeyLastUsed": {"LastUsedDate": used_at, "ServiceName": "s3"}}
            return {"AccessKeyLastUsed": {"ServiceName": "N/A", "Region": "N/A"}}

        iam = mock.MagicMock()
        iam.list_access_keys.return_value = {"AccessKeyMetadata": [
            _access_key(k) for k in (self.USED, self.NEVER, self.FAILED)]}
        iam.get_access_key_last_used.side_effect = _last_used
        return iam, used_at

    def test_values_and_warning(self):
        iam, used_at = self._iam()
        with self.assertLogs(level="WARNING") as logs:
            rows = lf._collect_keys(iam, NOW, user_names=["u"])
        by_id = {r["raw_key_id"]: r["last_used"] for r in rows}
        self.assertEqual(by_id, {self.USED: used_at.isoformat(),
                                 self.NEVER: "Never", self.FAILED: "Unknown"})
        text = "\n".join(logs.output)
        self.assertIn("Throttling", text)
        self.assertIn(lf._mask(self.FAILED), text)
        self.assertNotIn(self.FAILED, text)  # raw key id never logged

    def test_summary_counts(self):
        iam, _ = self._iam()
        with self.assertLogs(level="WARNING"):
            rows = lf._collect_keys(iam, NOW, user_names=["u"])
        m = lf._summarize(rows, 1, 0)
        self.assertEqual((m["KeysTotal"], m["KeysNeverUsed"], m["KeysLastUsedUnknown"]),
                         (3, 1, 1))


class PayloadShapeTests(HandlerTestCase):
    def test_access_keys_block_mirrors_top_level(self):
        result, s3, _, _ = _run_handler()
        a = result["access_keys"]
        self.assertEqual(set(a), {"keys_found", "errors", "s3_location", "metrics",
                                  "changes", "history_location"})
        for k in a:
            self.assertEqual(a[k], result[k], k)
        rows = list(csv.DictReader(io.StringIO(s3.body(ACCESS_CSV_RE)[1])))
        self.assertTrue(rows)
        self.assertEqual({r["last_used"] for r in rows}, {"Never"})


# ---------------------------------------------------------------------------
# T5: handler
# ---------------------------------------------------------------------------
class HandlerTests(HandlerTestCase):
    def test_bedrock_access_denied_keeps_access_key_rows(self):
        mgmt, member = _default_iams(member_bedrock_error=_client_error("AccessDenied"))
        member_sid = lf._state_id(MEMBER, RAW_BEDROCK_IDS[2])
        prev_bedrock = {member_sid: {"account_id": MEMBER, "account_name": "member",
                                     "user": "dev", "credential_id": "ACCA*",
                                     "service_name": SVC, "status": "Inactive",
                                     "create_date": "2026-01-01T00:00:00+00:00",
                                     "expiration_date": "Never"}}
        # Both accounts were covered before, so new mgmt keys count as added.
        s3 = FakeS3({BEDROCK_STATE_KEY: _v2_state(prev_bedrock, [MGMT, MEMBER])})
        with self.assertLogs(level="INFO") as logs:
            result, s3, _, sns = _run_handler(
                s3=s3, mgmt_iam=mgmt, member_iam=member, env=ALERT_ENV)

        self.assertEqual(result["status"], "ATTENTION_REQUIRED")
        self.assertEqual(result["errors"], [])
        self.assertEqual(result["bedrock"]["errors"],
                         [{"account_id": MEMBER, "account_name": "member", "error": "AccessDenied"}])
        self.assertEqual(result["keys_found"], 2)
        _, access_csv = s3.body(ACCESS_CSV_RE)
        self.assertIn(lf._mask(RAW_ACCESS_KEYS[1]), access_csv)
        _, bedrock_csv = s3.body(BEDROCK_CSV_RE)
        self.assertNotIn(lf._mask(RAW_BEDROCK_IDS[2]), bedrock_csv)
        self.assertEqual(result["bedrock"]["keys_found"], 2)
        self.assertEqual(result["bedrock"]["metrics"]["BedrockAccountsWithErrors"], 1)

        # Previous Bedrock state of the failing account is carried forward.
        self.assertIn(member_sid, s3.json(BEDROCK_STATE_KEY)["keys"])
        self.assertFalse(result["bedrock"]["changes"]["first_run"])
        self.assertEqual(result["bedrock"]["changes"]["removed"], 0)
        self.assertEqual(result["bedrock"]["changes"]["added"], 2)

        out = "\n".join(logs.output)
        self.assertIn(f"[WARN] {MEMBER} member Bedrock API keys could not be listed: AccessDenied",
                      out)
        self.assertIn(f"[OK]  {MEMBER} member keys=1 bedrock_keys=ERR via OrgAccessKeyAuditRole",
                      out)
        self.assertIn(f"[OK]  {MGMT} mgmt keys=1 bedrock_keys=2 via direct", out)
        self.assertIn("ADMIN ACTION REQUIRED", out)
        self.assertIn("bedrock_errors=1", out)

        sns.publish.assert_called_once()
        msg = sns.publish.call_args.kwargs["Message"]
        self.assertIn("Bedrock API keys could NOT be listed", msg)
        self.assertIn(f"{MEMBER} (member): AccessDenied", msg)
        self.assertIn("deploy-audit-role-stackset.sh", msg)
        self.assertNotIn("could NOT be inventoried", msg)
        self.assertNotIn("could NOT be written to S3", msg)

    def test_bedrock_param_validation_error_degrades(self):
        mgmt, member = _default_iams(member_bedrock_error=ParamValidationError(report="x"))
        with self.assertLogs(level="INFO"):
            result, _, _, _ = _run_handler(mgmt_iam=mgmt, member_iam=member)
        self.assertEqual(result["status"], "ATTENTION_REQUIRED")
        self.assertEqual(result["keys_found"], 2)
        self.assertEqual([e["error"] for e in result["bedrock"]["errors"]],
                         ["ParamValidationError"])

    def test_bedrock_unexpected_exception_degrades(self):
        mgmt, member = _default_iams(member_bedrock_error=KeyError("ServiceSpecificCredentialId"))
        with self.assertLogs(level="INFO"):
            result, _, _, _ = _run_handler(mgmt_iam=mgmt, member_iam=member)
        self.assertEqual(result["status"], "ATTENTION_REQUIRED")
        self.assertEqual(result["keys_found"], 2)
        self.assertEqual(result["errors"], [])
        self.assertEqual([e["error"] for e in result["bedrock"]["errors"]], ["KeyError"])

    def test_account_failure_carries_bedrock_state_and_keeps_alert_text(self):
        member_sid = lf._state_id(MEMBER, RAW_BEDROCK_IDS[2])
        s3 = FakeS3({
            BEDROCK_STATE_KEY: _v2_state({member_sid: {"account_id": MEMBER, "status": "Active"}},
                                         [MGMT, MEMBER]),
            ACCESS_STATE_KEY: _v2_state({}, [MGMT, MEMBER])})
        with self.assertLogs(level="INFO"):
            result, s3, _, sns = _run_handler(
                s3=s3, member_assume_error=_client_error("AccessDenied", "AssumeRole"),
                env=ALERT_ENV)
        self.assertEqual(result["errors"],
                         [{"account_id": MEMBER, "account_name": "member", "error": "AccessDenied"}])
        self.assertEqual(result["bedrock"]["errors"], [])  # account-level failure stays in errors[]
        self.assertEqual(result["bedrock"]["changes"]["removed"], 0)
        self.assertIn(member_sid, s3.json(BEDROCK_STATE_KEY)["keys"])
        msg = sns.publish.call_args.kwargs["Message"]
        self.assertTrue(msg.startswith(
            "Org-wide IAM access-key inventory needs administrator attention.\n\nRUN SUMMARY:"))
        self.assertIn("1 account(s) could NOT be inventoried "
                      "(no assumable audit role, SCP denial, or suspended account):\n"
                      f"  - {MEMBER} (member): AccessDenied\n\nFix: ensure one of the "
                      "CANDIDATE_ROLES exists", msg)
        self.assertNotIn("Bedrock API keys could NOT be listed", msg)

    def test_csv_and_json_outputs(self):
        with self.assertLogs(level="INFO") as logs:
            result, s3, _, sns = _run_handler()

        # Access-key CSV: run_id first (intended breaking change), rest unchanged.
        access_key, access_csv = s3.body(ACCESS_CSV_RE)
        self.assertEqual(access_csv.splitlines()[0],
                         "run_id,account_id,account_name,user,access_key_id,status,"
                         "create_date,age_days,last_used")

        # Separate Bedrock CSV.
        b_key, b_csv = s3.body(BEDROCK_CSV_RE)
        self.assertEqual(lf.BEDROCK_FIELDS[0], "run_id")
        self.assertEqual(b_csv.splitlines()[0], ",".join(lf.BEDROCK_FIELDS))
        rows = list(csv.DictReader(io.StringIO(b_csv)))
        self.assertEqual(len(rows), 3)
        self.assertEqual({r["run_id"] for r in rows}, {result["run_id"]})
        by_user = {r["user"]: r for r in rows}
        console = by_user["BedrockAPIKey-abcd"]
        self.assertEqual(console["account_id"], MGMT)
        self.assertEqual(console["credential_id"], lf._mask(RAW_BEDROCK_IDS[0]))
        self.assertEqual((console["expiration_date"], console["days_to_expiry"],
                          console["never_expires"], console["user_active_access_keys"]),
                         ("Never", "", "true", "0"))
        admin = by_user["admin"]
        self.assertEqual(int(admin["days_to_expiry"]), 20)
        self.assertEqual((admin["never_expires"], admin["user_active_access_keys"]), ("false", "1"))
        dev = by_user["dev"]
        self.assertEqual((dev["account_id"], dev["account_name"], dev["status"],
                          dev["service_name"], dev["user_active_access_keys"]),
                         (MEMBER, "member", "Inactive", SVC, "1"))
        self.assertEqual([r["account_id"] for r in rows], [MGMT, MGMT, MEMBER])  # sorted

        # Bedrock state: hashed ids, only the documented descriptor fields.
        state = s3.json(BEDROCK_STATE_KEY)["keys"]
        self.assertEqual(set(state), {hashlib.sha256(f"{a}:{c}".encode()).hexdigest()
                                      for a, c in ((MGMT, RAW_BEDROCK_IDS[0]),
                                                   (MGMT, RAW_BEDROCK_IDS[1]),
                                                   (MEMBER, RAW_BEDROCK_IDS[2]))})
        for entry in state.values():
            self.assertEqual(set(entry), set(lf._BEDROCK_STATE_FIELDS))
        self.assertIn(ACCESS_STATE_KEY, s3.objects)
        self.assertFalse(any("/changes-" in k for k in s3.put_keys()))  # first runs
        self._assert_no_secrets(s3)

        # JSON payload: legacy keys kept, plus the additive bedrock/run fields.
        json.dumps(result)
        self.assertEqual(set(result), PAYLOAD_TOP_KEYS)
        self.assertEqual(set(result["metrics"]), ACCESS_KEY_METRICS)
        self.assertEqual(result["s3_location"], f"s3://test-bucket/{access_key}")
        self.assertEqual(result["status"], "OK")
        self.assertEqual(result["write_errors"], [])
        b = result["bedrock"]
        self.assertEqual(set(b), BEDROCK_BLOCK_KEYS)
        self.assertEqual((b["enabled"], b["service_name"], b["keys_found"], b["errors"]),
                         (True, SVC, 3, []))
        self.assertEqual(b["s3_location"], f"s3://test-bucket/{b_key}")
        self.assertEqual(b["changes"], _changes(first_run=True, baselined=[
            _baselined(MGMT, 2), _baselined(MEMBER, 1)]))
        self.assertIsNone(b["history_location"])
        self.assertEqual((b["listing_mode"], b["expiry_supported"], b["botocore_version"]),
                         ("all_users", True, botocore.__version__))
        self.assertEqual(b["metrics"]["BedrockKeysTotal"], 3)
        self.assertEqual(b["metrics"]["BedrockKeysNoExpiryActive"], 1)
        sns.publish.assert_not_called()

        out = "\n".join(logs.output)
        self.assertIn("SDK boto3=", out)
        self.assertIn("bedrock_keys_found=3 bedrock_errors=0 bedrock_report=s3://test-bucket/", out)
        self.assertIn("[bedrock] First run: 3 keys recorded as the history baseline.", out)
        self.assertIn(f"run_id={result['run_id']} manifest={result['manifest_location']} "
                      "write_errors=0", out)

    def test_metrics_published(self):
        # Access-key baseline exists (both accounts covered); Bedrock's doesn't.
        s3 = FakeS3({ACCESS_STATE_KEY: _v2_state({}, [MGMT, MEMBER])})
        with self.assertLogs(level="INFO"):
            result, s3, cw, _ = _run_handler(s3=s3, now=RUN_NOW)
        cw.put_metric_data.assert_called_once()
        self.assertEqual(cw.put_metric_data.call_args.kwargs["Namespace"], "OrgAccessKeyInventory")
        names = _metric_names(cw)
        self.assertTrue(LEGACY_METRICS <= names)
        self.assertIn("KeysAdded", names)
        self.assertEqual(result["changes"]["added"], 2)  # empty baseline is not a first run
        for name in ("BedrockKeysTotal", "BedrockKeysActive", "BedrockKeysInactive",
                     "BedrockKeysExpired", "BedrockKeysNoExpiry", "BedrockKeysNoExpiryActive",
                     "BedrockKeysExpiringSoon", "BedrockKeysStale", "BedrockKeysStaleActive",
                     "BedrockAccountsWithErrors"):
            self.assertIn(name, names)
        self.assertNotIn("BedrockKeysAdded", names)

        # Second run: the Bedrock baseline now exists -> change metrics appear.
        with self.assertLogs(level="INFO"):
            result2, _, cw2, _ = _run_handler(s3=s3, now=RUN2_NOW)
        names2 = _metric_names(cw2)
        for name in ("BedrockKeysAdded", "BedrockKeysRemoved", "BedrockKeysActivated",
                     "BedrockKeysDeactivated"):
            self.assertIn(name, names2)
        self.assertFalse(result2["bedrock"]["changes"]["first_run"])

    def test_status_change_to_expired_is_deactivated(self):
        with self.assertLogs(level="INFO"):
            _, s3, _, _ = _run_handler(now=RUN_NOW)
        now = datetime.now(timezone.utc)
        mgmt, member = _default_iams()
        expired = _cred("dev", RAW_BEDROCK_IDS[2], status="Expired",
                        created=now - timedelta(days=1), expires=now - timedelta(hours=1))
        member.list_service_specific_credentials.side_effect = (
            lambda **kw: {"ServiceSpecificCredentials": [expired], "IsTruncated": False})
        with self.assertLogs(level="INFO"):
            result, s3, _, _ = _run_handler(s3=s3, mgmt_iam=mgmt, member_iam=member,
                                            now=RUN2_NOW)
        self.assertEqual(result["bedrock"]["changes"]["deactivated"], 1)
        self.assertEqual(result["bedrock"]["metrics"]["BedrockKeysExpired"], 1)
        _, changelog = s3.body(r"/changes-bedrock-api-keys\.json$")
        entry = json.loads(changelog)["changes"]["deactivated"][0]
        self.assertEqual((entry["status"], entry["old_status"]), ("Expired", "Inactive"))

    def test_expiry_unsupported_reports_unknown(self):
        with self.assertLogs(level="INFO") as logs:
            result, s3, cw, _ = _run_handler(caps=(False, False))
        b = result["bedrock"]
        self.assertEqual((b["listing_mode"], b["expiry_supported"]), ("per_user", False))
        rows = list(csv.DictReader(io.StringIO(s3.body(BEDROCK_CSV_RE)[1])))
        self.assertEqual(len(rows), 3)
        self.assertEqual({(r["expiration_date"], r["never_expires"]) for r in rows},
                         {("Unknown", "Unknown")})
        names = _metric_names(cw)
        self.assertIn("BedrockKeysTotal", names)
        for name in ("BedrockKeysNoExpiry", "BedrockKeysNoExpiryActive", "BedrockKeysExpiringSoon"):
            self.assertNotIn(name, names)
        self.assertTrue(any("Vendor boto3/botocore >= 1.39.0" in m for m in logs.output))

    def test_per_user_mode_passes_user_name(self):
        mgmt, member = _default_iams()
        with self.assertLogs(level="INFO"):
            _run_handler(mgmt_iam=mgmt, member_iam=member, caps=(False, False))
        calls = [c.kwargs for c in mgmt.list_service_specific_credentials.call_args_list]
        self.assertEqual(calls, [{"UserName": "admin", "ServiceName": SVC},
                                 {"UserName": "BedrockAPIKey-abcd", "ServiceName": SVC}])

    def test_bedrock_disabled(self):
        mgmt, member = _default_iams()
        with mock.patch.object(lf, "INCLUDE_BEDROCK_KEYS", False), \
                self.assertLogs(level="INFO") as logs:
            result, s3, cw, _ = _run_handler(mgmt_iam=mgmt, member_iam=member)
        mgmt.list_service_specific_credentials.assert_not_called()
        member.list_service_specific_credentials.assert_not_called()
        self.assertFalse(any("bedrock-api-keys" in k for k in s3.put_keys()))
        self.assertEqual(result["bedrock"], {"enabled": False})
        self.assertEqual(result["status"], "OK")
        self.assertFalse(any(n.startswith("Bedrock") for n in _metric_names(cw)))
        out = "\n".join(logs.output)
        self.assertIn(f"[OK]  {MGMT} mgmt keys=1 via direct", out)
        self.assertNotIn("bedrock_keys", out)


# ---------------------------------------------------------------------------
# Run-centric S3 layout
# ---------------------------------------------------------------------------
class RunLayoutTests(HandlerTestCase):
    def test_first_run_writes_exact_keys_in_order(self):
        with self.assertLogs(level="INFO"):
            result, s3, _, _ = _run_handler(now=RUN_NOW)
        put_keys = s3.put_keys()
        self.assertEqual(len(put_keys), len(set(put_keys)), put_keys)  # each written once
        self.assertEqual(set(put_keys), {
            f"{RUN_PREFIX}/access-keys.csv",
            f"{RUN_PREFIX}/bedrock-api-keys.csv",
            f"{RUN_PREFIX}/manifest.json",
            "credential-inventory/state/access-keys.json",
            "credential-inventory/state/bedrock-api-keys.json",
            "credential-inventory/latest/access-keys.csv",
            "credential-inventory/latest/bedrock-api-keys.csv",
            "credential-inventory/latest/manifest.json",
        })
        self.assertFalse(any("/changes-" in k for k in put_keys))
        self.assertFalse(any(k.startswith("access-key-reports/") for k in put_keys))

        # Ordering: run files + state, then the run manifest, then latest/ with
        # latest/manifest.json as the very last write.
        idx = {k: i for i, k in enumerate(put_keys)}
        manifest_i = idx[f"{RUN_PREFIX}/manifest.json"]
        for k, i in idx.items():
            if k.startswith(f"{LATEST}/"):
                self.assertGreater(i, manifest_i, k)
            elif k != f"{RUN_PREFIX}/manifest.json":
                self.assertLess(i, manifest_i, k)
        self.assertEqual(put_keys[-1], f"{LATEST}/manifest.json")

        for p in s3.puts:
            self.assertEqual(p["ServerSideEncryption"], "AES256", p["Key"])
            self.assertEqual(p["ContentType"],
                             "text/csv" if p["Key"].endswith(".csv") else "application/json")

        self.assertEqual(result["s3_location"], URI + RUN_PREFIX + "/access-keys.csv")
        self.assertEqual(result["bedrock"]["s3_location"],
                         URI + RUN_PREFIX + "/bedrock-api-keys.csv")
        self.assertEqual(result["manifest_location"], URI + RUN_PREFIX + "/manifest.json")
        self.assertEqual(result["latest_prefix"], "s3://test-bucket/credential-inventory/latest/")
        self.assertEqual(result["run_id"], RUN_ID)
        self.assertEqual(result["write_errors"], [])

    def test_second_run_writes_changelogs_in_run_folder(self):
        with self.assertLogs(level="INFO"):
            _, s3, _, _ = _run_handler(now=RUN_NOW)
        mgmt, member = _default_iams()
        member.list_access_keys.side_effect = lambda UserName: {"AccessKeyMetadata": [
            _access_key(RAW_ACCESS_KEYS[1]), _access_key("AKIAMEMBEREXAMPLE003")]}
        kept = _cred("BedrockAPIKey-abcd", RAW_BEDROCK_IDS[0])
        mgmt.list_service_specific_credentials.side_effect = (
            lambda **kw: {"ServiceSpecificCredentials": [kept], "IsTruncated": False})
        with self.assertLogs(level="INFO"):
            result, s3, _, _ = _run_handler(s3=s3, mgmt_iam=mgmt, member_iam=member,
                                            now=RUN2_NOW)
        access_changes = f"{RUN2_PREFIX}/changes-access-keys.json"
        bedrock_changes = f"{RUN2_PREFIX}/changes-bedrock-api-keys.json"
        self.assertIn(access_changes, s3.put_keys())
        self.assertIn(bedrock_changes, s3.put_keys())
        self.assertEqual(result["history_location"], URI + access_changes)
        self.assertEqual(result["bedrock"]["history_location"], URI + bedrock_changes)
        self.assertEqual(result["changes"], _changes(added=1))
        self.assertEqual(result["bedrock"]["changes"], _changes(removed=1))
        for key, csv_name in ((access_changes, "access-keys.csv"),
                              (bedrock_changes, "bedrock-api-keys.csv")):
            log = s3.json(key)
            self.assertEqual(log["run_id"], RUN2_ID)
            self.assertEqual(log["report"], f"{URI}{RUN2_PREFIX}/{csv_name}")
            self.assertEqual(log["baselined_accounts"], [])
        manifest = s3.json(f"{RUN2_PREFIX}/manifest.json")
        self.assertEqual(manifest["files"]["changes-access-keys.json"], URI + access_changes)
        self.assertEqual(manifest["files"]["changes-bedrock-api-keys.json"], URI + bedrock_changes)
        # Run 1's folder is untouched by run 2.
        self.assertFalse(any(p["Key"].startswith(RUN_PREFIX + "/") for p in s3.puts[8:]))

    def test_run_id_shared_across_files(self):
        with self.assertLogs(level="INFO"):
            result, s3, _, _ = _run_handler(now=RUN_NOW)
        self.assertEqual(result["run_id"], RUN_ID)
        for key in (f"{RUN_PREFIX}/access-keys.csv", f"{LATEST}/access-keys.csv",
                    f"{RUN_PREFIX}/bedrock-api-keys.csv", f"{LATEST}/bedrock-api-keys.csv"):
            rows = list(csv.reader(io.StringIO(s3.objects[key].decode("utf-8"))))
            self.assertEqual(rows[0][0], "run_id", key)
            self.assertGreater(len(rows), 1, key)
            self.assertEqual({r[0] for r in rows[1:]}, {RUN_ID}, key)
        for key in (f"{RUN_PREFIX}/manifest.json", f"{LATEST}/manifest.json",
                    ACCESS_STATE_KEY, BEDROCK_STATE_KEY):
            self.assertEqual(s3.json(key)["run_id"], RUN_ID, key)
        for key in s3.put_keys():
            if "/runs/" in key:
                self.assertIn(f"/{RUN_ID}/", key)
        latest_puts = [p for p in s3.puts if p["Key"].startswith(f"{LATEST}/")]
        self.assertEqual(len(latest_puts), 3)
        for p in latest_puts:
            self.assertEqual(p["Metadata"], {"run-id": RUN_ID}, p["Key"])

    def test_manifest_contents(self):
        with self.assertLogs(level="INFO"):
            result, s3, _, _ = _run_handler(now=RUN_NOW)
        m = s3.json(f"{RUN_PREFIX}/manifest.json")
        self.assertEqual(set(m), MANIFEST_TOP_KEYS)
        self.assertEqual((m["manifest_version"], m["run_id"], m["run_time"], m["status"],
                          m["bucket"], m["prefix"]),
                         (1, RUN_ID, RUN_NOW.isoformat(), "OK", "test-bucket",
                          "credential-inventory"))
        self.assertEqual(m["run_prefix"], f"{URI}{RUN_PREFIX}/")
        self.assertEqual(m["manifest"], result["manifest_location"])
        self.assertEqual(m["files"], {
            "access-keys.csv": f"{URI}{RUN_PREFIX}/access-keys.csv",
            "bedrock-api-keys.csv": f"{URI}{RUN_PREFIX}/bedrock-api-keys.csv"})
        self.assertEqual(m["state_files"], {
            "state/access-keys.json": URI + ACCESS_STATE_KEY,
            "state/bedrock-api-keys.json": URI + BEDROCK_STATE_KEY})
        self.assertEqual(m["write_errors"], [])
        self.assertEqual(m["accounts_scanned"], result["accounts_scanned"])
        self.assertEqual(m["errors"], result["errors"])

        a = m["access_keys"]
        self.assertEqual(set(a), {"keys_found", "metrics", "changes", "previous_state"})
        self.assertEqual(a["keys_found"], result["keys_found"])
        self.assertEqual(a["metrics"], result["metrics"])
        self.assertEqual(a["changes"], result["changes"])
        self.assertIsNone(a["previous_state"])

        b = m["bedrock"]
        self.assertEqual(set(b), {"enabled", "service_name", "keys_found", "errors", "metrics",
                                  "changes", "previous_state", "listing_mode",
                                  "expiry_supported", "botocore_version"})
        self.assertEqual((b["enabled"], b["service_name"], b["keys_found"]), (True, SVC, 3))
        self.assertEqual(b["errors"], result["bedrock"]["errors"])
        self.assertEqual(b["metrics"], result["bedrock"]["metrics"])
        self.assertEqual(b["changes"], result["bedrock"]["changes"])
        self.assertIsNone(b["previous_state"])
        self.assertEqual((b["listing_mode"], b["expiry_supported"], b["botocore_version"]),
                         ("all_users", True, botocore.__version__))
        self.assertEqual(m["sdk"], {"boto3": lf.boto3.__version__,
                                    "botocore": botocore.__version__})
        self._assert_no_secrets(s3)

    def test_latest_copies_match_run(self):
        with self.assertLogs(level="INFO"):
            result, s3, _, _ = _run_handler(now=RUN_NOW)
        for name in ("access-keys.csv", "bedrock-api-keys.csv"):
            self.assertEqual(s3.objects[f"{LATEST}/{name}"], s3.objects[f"{RUN_PREFIX}/{name}"])
        run_manifest = s3.json(f"{RUN_PREFIX}/manifest.json")
        latest_doc = s3.json(f"{LATEST}/manifest.json")
        self.assertEqual({k: v for k, v in latest_doc.items() if k != "latest"}, run_manifest)
        self.assertEqual(latest_doc["latest"], {
            "run_manifest": result["manifest_location"],
            "files": {
                name: {"status": "updated", "s3_uri": f"{URI}{LATEST}/{name}",
                       "source": f"{URI}{RUN_PREFIX}/{name}"}
                for name in ("access-keys.csv", "bedrock-api-keys.csv")}})


# ---------------------------------------------------------------------------
# S3 write failures: recorded, never presented as success, never abort the run
# ---------------------------------------------------------------------------
class WriteFailureTests(HandlerTestCase):
    def test_bedrock_csv_write_failure(self):
        old_latest = b"run_id,old\nOLD,1\n"
        s3 = FakeS3({BEDROCK_STATE_KEY: _v2_state({}, [MGMT, MEMBER]),
                     f"{LATEST}/bedrock-api-keys.csv": old_latest},
                    fail_puts=[r"/runs/.*/bedrock-api-keys\.csv$"])
        with self.assertLogs(level="INFO") as logs:
            result, s3, _, _ = _run_handler(s3=s3, now=RUN_NOW)
        failed_uri = f"{URI}{RUN_PREFIX}/bedrock-api-keys.csv"

        self.assertIsNone(result["bedrock"]["s3_location"])
        self.assertEqual(result["write_errors"], [{"s3_uri": failed_uri, "error": "AccessDenied"}])
        self.assertEqual(result["status"], "ATTENTION_REQUIRED")
        self.assertEqual(result["s3_location"], f"{URI}{RUN_PREFIX}/access-keys.csv")

        # History still works: changelog (report null) and the new state.
        changelog = s3.json(f"{RUN_PREFIX}/changes-bedrock-api-keys.json")
        self.assertIsNone(changelog["report"])
        self.assertEqual(changelog["counts"]["added"], 3)
        self.assertEqual(len(s3.json(BEDROCK_STATE_KEY)["keys"]), 3)

        manifest = s3.json(f"{RUN_PREFIX}/manifest.json")
        self.assertIsNone(manifest["files"]["bedrock-api-keys.csv"])
        self.assertEqual(manifest["write_errors"],
                         [{"s3_uri": failed_uri, "error": "AccessDenied"}])
        self.assertEqual(manifest["status"], "ATTENTION_REQUIRED")

        # latest/: the old Bedrock CSV is left alone (no attempt), and says so.
        self.assertNotIn(f"{LATEST}/bedrock-api-keys.csv", [p["Key"] for p in s3.attempts])
        self.assertEqual(s3.objects[f"{LATEST}/bedrock-api-keys.csv"], old_latest)
        latest = s3.json(f"{LATEST}/manifest.json")["latest"]["files"]
        entry = latest["bedrock-api-keys.csv"]
        self.assertEqual(entry["status"], "not_updated")
        self.assertEqual(entry["reason"], "the run copy could not be written")
        self.assertIn("earlier run", entry["note"])
        self.assertEqual(latest["access-keys.csv"]["status"], "updated")
        self.assertEqual(s3.objects[f"{LATEST}/access-keys.csv"],
                         s3.objects[f"{RUN_PREFIX}/access-keys.csv"])

        errors = [r.getMessage() for r in logs.records if r.levelno == logging.ERROR]
        self.assertTrue(any(f"{RUN_PREFIX}/bedrock-api-keys.csv" in m for m in errors), errors)

    def test_access_csv_write_failure_does_not_abort_run(self):
        s3 = FakeS3(fail_puts=[r"/runs/.*/access-keys\.csv$"])
        with self.assertLogs(level="INFO") as logs:
            result, s3, cw, sns = _run_handler(s3=s3, now=RUN_NOW, env=ALERT_ENV)
        failed_uri = f"{URI}{RUN_PREFIX}/access-keys.csv"
        self.assertIsNone(result["s3_location"])
        self.assertEqual(result["status"], "ATTENTION_REQUIRED")
        self.assertIn(ACCESS_STATE_KEY, s3.objects)
        self.assertIn(f"{RUN_PREFIX}/manifest.json", s3.objects)
        cw.put_metric_data.assert_called_once()
        self.assertNotIn(f"{LATEST}/access-keys.csv", [p["Key"] for p in s3.attempts])
        latest = s3.json(f"{LATEST}/manifest.json")["latest"]["files"]
        self.assertEqual(latest["access-keys.csv"]["status"], "not_updated")

        sns.publish.assert_called_once()
        msg = sns.publish.call_args.kwargs["Message"]
        self.assertIn("1 report/state file(s) could NOT be written to S3:\n"
                      f"  - {failed_uri}: AccessDenied", msg)
        self.assertIn("s3:PutObject", msg)
        out = "\n".join(logs.output)
        self.assertIn("ADMIN ACTION REQUIRED", out)
        self.assertIn("report=none", out)
        self.assertIn("write_errors=1", out)

    def test_latest_write_failure_is_reported(self):
        s3 = FakeS3(fail_puts=[r"/latest/access-keys\.csv$"])
        with self.assertLogs(level="INFO"):
            result, s3, _, _ = _run_handler(s3=s3, now=RUN_NOW)
        latest_uri = f"{URI}{LATEST}/access-keys.csv"
        entry = s3.json(f"{LATEST}/manifest.json")["latest"]["files"]["access-keys.csv"]
        self.assertEqual((entry["status"], entry["error"], entry["source"]),
                         ("failed", "AccessDenied", f"{URI}{RUN_PREFIX}/access-keys.csv"))
        self.assertIn("note", entry)
        manifest = s3.json(f"{RUN_PREFIX}/manifest.json")
        self.assertEqual((manifest["status"], manifest["write_errors"]), ("OK", []))
        self.assertEqual(result["write_errors"], [{"s3_uri": latest_uri, "error": "AccessDenied"}])
        self.assertEqual(result["status"], "ATTENTION_REQUIRED")
        self.assertEqual(s3.put_keys()[-1], f"{LATEST}/manifest.json")

    def test_manifest_write_failure(self):
        s3 = FakeS3(fail_puts=[r"/runs/.*/manifest\.json$"])
        with self.assertLogs(level="INFO"):
            result, s3, _, _ = _run_handler(s3=s3, now=RUN_NOW)
        self.assertIsNone(result["manifest_location"])
        latest_doc = s3.json(f"{LATEST}/manifest.json")
        self.assertIsNone(latest_doc["latest"]["run_manifest"])
        self.assertIn({"s3_uri": f"{URI}{RUN_PREFIX}/manifest.json", "error": "AccessDenied"},
                      result["write_errors"])
        self.assertEqual(result["status"], "ATTENTION_REQUIRED")

    def test_bedrock_disabled_layout(self):
        old_latest = b"run_id,old\nOLD,1\n"
        s3 = FakeS3({f"{LATEST}/bedrock-api-keys.csv": old_latest})
        with mock.patch.object(lf, "INCLUDE_BEDROCK_KEYS", False), \
                self.assertLogs(level="INFO"):
            result, s3, _, _ = _run_handler(s3=s3, now=RUN_NOW)
        self.assertFalse(any("bedrock-api-keys" in p["Key"] for p in s3.attempts))
        self.assertNotIn(BEDROCK_STATE_KEY, s3.gets)
        self.assertNotIn(LEGACY_BEDROCK_STATE_KEY, s3.gets)
        manifest = s3.json(f"{RUN_PREFIX}/manifest.json")
        self.assertEqual(manifest["bedrock"], {"enabled": False})
        self.assertEqual(set(manifest["files"]), {"access-keys.csv"})
        self.assertEqual(set(manifest["state_files"]), {"state/access-keys.json"})
        entry = s3.json(f"{LATEST}/manifest.json")["latest"]["files"]["bedrock-api-keys.csv"]
        self.assertEqual(entry["status"], "disabled")
        self.assertIn("note", entry)
        self.assertEqual(s3.objects[f"{LATEST}/bedrock-api-keys.csv"], old_latest)
        self.assertEqual(result["status"], "OK")
        self.assertEqual(result["bedrock"], {"enabled": False})


# ---------------------------------------------------------------------------
# Legacy state fallback (read-only, once). AccessDenied = missing (no ListBucket).
# ---------------------------------------------------------------------------
class LegacyStateTests(HandlerTestCase):
    def _legacy_s3(self):
        acc, bed = _fixture_state_keys()
        return FakeS3({LEGACY_ACCESS_STATE_KEY: acc, LEGACY_BEDROCK_STATE_KEY: bed},
                      missing_code="AccessDenied"), acc, bed

    def test_legacy_state_used_when_new_state_missing(self):
        s3, acc, bed = self._legacy_s3()
        before = {k: s3.objects[k] for k in (LEGACY_ACCESS_STATE_KEY, LEGACY_BEDROCK_STATE_KEY)}
        with self.assertLogs(level="INFO") as logs:
            result, s3, _, _ = _run_handler(s3=s3, now=RUN_NOW)
        self.assertEqual(result["changes"], _changes())
        self.assertEqual(result["bedrock"]["changes"], _changes())
        for key, keys in ((ACCESS_STATE_KEY, acc), (BEDROCK_STATE_KEY, bed)):
            doc = s3.json(key)
            self.assertEqual(doc["schema_version"], 2)
            self.assertEqual(doc["covered_accounts"], [MGMT, MEMBER])
            self.assertEqual(set(doc["keys"]), set(keys))
        self.assertFalse(any(p["Key"].startswith("access-key-reports/") for p in s3.attempts))
        for k, v in before.items():
            self.assertEqual(s3.objects[k], v)
        for new, legacy in ((ACCESS_STATE_KEY, LEGACY_ACCESS_STATE_KEY),
                            (BEDROCK_STATE_KEY, LEGACY_BEDROCK_STATE_KEY)):
            self.assertEqual([k for k in s3.gets if k in (new, legacy)], [new, legacy])
        manifest = s3.json(f"{RUN_PREFIX}/manifest.json")
        self.assertEqual(manifest["access_keys"]["previous_state"], URI + LEGACY_ACCESS_STATE_KEY)
        self.assertEqual(manifest["bedrock"]["previous_state"], URI + LEGACY_BEDROCK_STATE_KEY)
        self.assertTrue(any(r.levelno == logging.INFO
                            and "seeding the baseline from legacy state" in r.getMessage()
                            for r in logs.records))

    def test_legacy_read_only_once(self):
        s3, _, _ = self._legacy_s3()
        with self.assertLogs(level="INFO"):
            _, s3, _, _ = _run_handler(s3=s3, now=RUN_NOW)
        n = len(s3.gets)
        with self.assertLogs(level="INFO"):
            result, s3, _, _ = _run_handler(s3=s3, now=RUN2_NOW)
        self.assertFalse({LEGACY_ACCESS_STATE_KEY, LEGACY_BEDROCK_STATE_KEY} & set(s3.gets[n:]))
        manifest = s3.json(f"{RUN2_PREFIX}/manifest.json")
        self.assertEqual(manifest["access_keys"]["previous_state"], URI + ACCESS_STATE_KEY)
        self.assertEqual(manifest["bedrock"]["previous_state"], URI + BEDROCK_STATE_KEY)
        self.assertEqual(result["changes"], _changes())

    def test_new_state_preferred_over_legacy(self):
        acc, bed = _fixture_state_keys()
        bogus = {"f" * 64: {"account_id": MGMT, "status": "Active"}}
        s3 = FakeS3({ACCESS_STATE_KEY: _v2_state(acc, [MGMT, MEMBER]),
                     BEDROCK_STATE_KEY: _v2_state(bed, [MGMT, MEMBER]),
                     LEGACY_ACCESS_STATE_KEY: {**acc, **bogus},
                     LEGACY_BEDROCK_STATE_KEY: {**bed, **bogus}},
                    missing_code="AccessDenied")
        with self.assertLogs(level="INFO"):
            result, s3, _, _ = _run_handler(s3=s3, now=RUN_NOW)
        self.assertNotIn(LEGACY_ACCESS_STATE_KEY, s3.gets)
        self.assertNotIn(LEGACY_BEDROCK_STATE_KEY, s3.gets)
        self.assertEqual(result["changes"]["removed"], 0)
        self.assertEqual(result["bedrock"]["changes"]["removed"], 0)

    def test_custom_legacy_prefix(self):
        acc, bed = _fixture_state_keys()
        s3 = FakeS3({"old-root/state/keys-state.json": acc,
                     "old-root/bedrock-api-keys/state/keys-state.json": bed},
                    missing_code="AccessDenied")
        with self.assertLogs(level="INFO"):
            result, s3, _, _ = _run_handler(s3=s3, now=RUN_NOW, env={"LEGACY_PREFIX": "old-root"})
        self.assertFalse(result["changes"]["first_run"])
        self.assertFalse(result["bedrock"]["changes"]["first_run"])
        self.assertFalse(any(k.startswith("access-key-reports/") for k in s3.gets))
        manifest = s3.json(f"{RUN_PREFIX}/manifest.json")
        self.assertEqual(manifest["access_keys"]["previous_state"],
                         URI + "old-root/state/keys-state.json")

    def test_no_state_anywhere_is_first_run(self):
        s3 = FakeS3(missing_code="AccessDenied")
        with self.assertLogs(level="INFO") as logs:
            result, s3, _, _ = _run_handler(s3=s3, now=RUN_NOW)
        self.assertTrue(result["changes"]["first_run"])
        self.assertTrue(result["bedrock"]["changes"]["first_run"])
        self.assertIn(LEGACY_ACCESS_STATE_KEY, s3.gets)
        self.assertIn(LEGACY_BEDROCK_STATE_KEY, s3.gets)
        warnings = [r.getMessage() for r in logs.records if r.levelno == logging.WARNING]
        self.assertEqual(sum(ACCESS_STATE_KEY in w for w in warnings), 1, warnings)
        self.assertEqual(sum(BEDROCK_STATE_KEY in w for w in warnings), 1, warnings)
        self.assertFalse(any("access-key-reports/" in w for w in warnings), warnings)

    def test_legacy_coverage_edge_case(self):
        acc, _ = _fixture_state_keys()
        # The member had no legacy entries (e.g. it failed during the legacy runs).
        s3 = FakeS3({LEGACY_ACCESS_STATE_KEY: _only(acc, MGMT)}, missing_code="AccessDenied")
        mgmt, member = _default_iams()
        new_key = "AKIAMGMTEXAMPLE00009"
        mgmt.list_access_keys.side_effect = lambda UserName: {"AccessKeyMetadata": (
            [_access_key(RAW_ACCESS_KEYS[0], age_days=100), _access_key(new_key)]
            if UserName == "admin" else [])}
        with self.assertLogs(level="INFO") as logs:
            result, s3, cw, _ = _run_handler(s3=s3, mgmt_iam=mgmt, member_iam=member,
                                             now=RUN_NOW)
        self.assertEqual(result["changes"], _changes(added=1, baselined=[_baselined(MEMBER, 1)]))
        self.assertEqual(_metric_values(cw)["KeysAdded"], 1)
        warnings = [r.getMessage() for r in logs.records if r.levelno == logging.WARNING]
        self.assertTrue(any("Legacy state has no coverage info" in w and MEMBER in w
                            for w in warnings), warnings)
        changelog = s3.json(f"{RUN_PREFIX}/changes-access-keys.json")
        self.assertEqual(changelog["baselined_accounts"], [_baselined(MEMBER, 1)])
        self.assertEqual([e["access_key_id"] for e in changelog["changes"]["added"]],
                         [lf._mask(new_key)])
        self.assertEqual(s3.json(ACCESS_STATE_KEY)["covered_accounts"], [MGMT, MEMBER])

    def test_legacy_empty_flat_state(self):
        s3 = FakeS3({LEGACY_ACCESS_STATE_KEY: {}}, missing_code="AccessDenied")
        with self.assertLogs(level="INFO"):
            result, s3, _, _ = _run_handler(s3=s3, now=RUN_NOW)
        self.assertEqual(result["changes"], _changes(baselined=[
            _baselined(MGMT, 1), _baselined(MEMBER, 1)]))


# ---------------------------------------------------------------------------
# Per-type coverage: first-seen accounts are baselined, not "added"
# ---------------------------------------------------------------------------
class CoverageTests(HandlerTestCase):
    def test_first_seen_account_baselined_not_added(self):
        acc, _ = _fixture_state_keys()
        s3 = FakeS3({ACCESS_STATE_KEY: _v2_state(_only(acc, MGMT), [MGMT])})
        with self.assertLogs(level="INFO") as logs:
            result, s3, cw, _ = _run_handler(s3=s3, now=RUN_NOW)
        self.assertEqual(result["changes"], _changes(baselined=[_baselined(MEMBER, 1)]))
        self.assertEqual(_metric_values(cw)["KeysAdded"], 0)
        changelog = s3.json(f"{RUN_PREFIX}/changes-access-keys.json")
        self.assertEqual(changelog["baselined_accounts"], [_baselined(MEMBER, 1)])
        self.assertEqual(changelog["counts"],
                         {"added": 0, "removed": 0, "activated": 0, "deactivated": 0})
        self.assertEqual(result["history_location"], f"{URI}{RUN_PREFIX}/changes-access-keys.json")
        self.assertEqual(s3.json(ACCESS_STATE_KEY)["covered_accounts"], [MGMT, MEMBER])
        self.assertEqual([r.getMessage() for r in logs.records if r.levelno >= logging.WARNING],
                         [])
        self.assertTrue(any("Baselined 1 key(s) from 1 newly covered account(s)" in m
                            for m in logs.output))

    def test_failed_then_recovered_account_baselined(self):
        cases = {
            "bedrock_only": dict(
                member_iam=_default_iams(member_bedrock_error=_client_error("AccessDenied"))[1]),
            "whole_account": dict(
                member_assume_error=_client_error("AccessDenied", "AssumeRole")),
        }
        for name, failing in cases.items():
            with self.subTest(name):
                with self.assertLogs(level="INFO"):
                    _, s3, _, _ = _run_handler(now=RUN_NOW, **failing)
                    result, s3, cw, _ = _run_handler(s3=s3, now=RUN2_NOW)
                values = _metric_values(cw)
                self.assertEqual(result["bedrock"]["changes"],
                                 _changes(baselined=[_baselined(MEMBER, 1)]))
                self.assertEqual(values["BedrockKeysAdded"], 0)
                if name == "bedrock_only":
                    # Access keys were listed in run 1, so only Bedrock is baselined.
                    self.assertEqual(result["changes"], _changes())
                else:
                    self.assertEqual(result["changes"],
                                     _changes(baselined=[_baselined(MEMBER, 1)]))
                    self.assertEqual(values["KeysAdded"], 0)

        # Run 1's Bedrock state only covers the account that was listed.
        with self.assertLogs(level="INFO"):
            _, s3, _, _ = _run_handler(now=RUN_NOW, **cases["bedrock_only"])
        self.assertEqual(s3.json(BEDROCK_STATE_KEY)["covered_accounts"], [MGMT])
        self.assertEqual(s3.json(ACCESS_STATE_KEY)["covered_accounts"], [MGMT, MEMBER])

    def test_new_key_in_covered_account_is_added(self):
        acc, _ = _fixture_state_keys()
        # The member was covered before, with zero keys.
        s3 = FakeS3({ACCESS_STATE_KEY: _v2_state(_only(acc, MGMT), [MGMT, MEMBER])})
        with self.assertLogs(level="INFO"):
            result, s3, cw, _ = _run_handler(s3=s3, now=RUN_NOW)
        self.assertEqual(result["changes"], _changes(added=1))
        self.assertEqual(_metric_values(cw)["KeysAdded"], 1)

    def test_coverage_persists_through_failure(self):
        acc, _ = _fixture_state_keys()
        s3 = FakeS3({ACCESS_STATE_KEY: _v2_state(acc, [MGMT, MEMBER])})
        with self.assertLogs(level="INFO"):
            result, s3, _, _ = _run_handler(
                s3=s3, now=RUN_NOW, member_assume_error=_client_error("AccessDenied", "AssumeRole"))
        doc = s3.json(ACCESS_STATE_KEY)
        self.assertEqual(doc["covered_accounts"], [MGMT, MEMBER])
        self.assertEqual(set(doc["keys"]), set(acc))  # member's entries carried forward
        self.assertEqual(result["changes"]["removed"], 0)

    def test_zero_key_new_account_writes_no_changelog(self):
        acc, _ = _fixture_state_keys()
        s3 = FakeS3({ACCESS_STATE_KEY: _v2_state(_only(acc, MGMT), [MGMT])})
        mgmt, _ = _default_iams()
        member = _fake_iam(users=["dev"], access_keys={})
        with self.assertLogs(level="INFO"):
            result, s3, _, _ = _run_handler(s3=s3, mgmt_iam=mgmt, member_iam=member, now=RUN_NOW)
        self.assertEqual(result["changes"], _changes(baselined=[_baselined(MEMBER, 0)]))
        manifest = s3.json(f"{RUN_PREFIX}/manifest.json")
        self.assertEqual(manifest["access_keys"]["changes"]["baselined_accounts"],
                         [_baselined(MEMBER, 0)])
        self.assertNotIn(f"{RUN_PREFIX}/changes-access-keys.json", s3.put_keys())
        self.assertIsNone(result["history_location"])


if __name__ == "__main__":
    unittest.main()
