# Org-wide IAM Access Key Inventory

List **every IAM user access key in every account of your AWS Organization** —
with each key's **creation date**, age, and last-used — into a CSV in S3.
It also inventories **long-term Amazon Bedrock API keys** into a second CSV.

A Lambda runs in the management account, assumes a read-only role in each member
account, and writes the report. Optionally emails you on errors and runs on a
schedule.

> Need more detail (architecture, security notes, troubleshooting)? See
> [`README.detailed.md`](./README.detailed.md).

---

## What you get

- One consolidated CSV per run: `run_id, account_id, account_name, user, access_key_id, status, create_date, age_days, last_used` (`last_used` is a timestamp, `Never`, or `Unknown` if the lookup failed).
- Key IDs are **masked** (e.g. `AKIA************MPLE`); secret keys are never touched.
- Reports stored in a private, encrypted, versioned S3 bucket, **one folder per run** plus a `latest/` copy (layout below).
- **History tracking** — each run diffs against the previous one and records which keys were **added, removed, activated, or deactivated**, as a JSON changelog in the run folder.
- **CloudWatch metrics + dashboard** — key counts, staleness, and run-to-run changes are published as custom metrics (namespace `OrgAccessKeyInventory`) so you get a time series of your org's key posture and a ready-made dashboard.
- **Long-term Bedrock API keys** (IAM service-specific credentials for `bedrock.amazonaws.com`) in `bedrock-api-keys.csv`, next to `access-keys.csv` in each run folder: `run_id, account_id, account_name, user, credential_id, service_name, status, create_date, age_days, expiration_date, days_to_expiry, never_expires, user_active_access_keys`. Credential IDs are masked the same way; it has its own history and `BedrockKeys*` metrics. Turn it off with `IncludeBedrockKeys=false`.

```text
s3://<bucket>/credential-inventory/            (the stack's Prefix)
├── runs/YYYY/MM/DD/<run-id>/                   one folder per run, e.g. runs/2026/09/08/20260908T063802Z/
│   ├── manifest.json                           what the run wrote and found, and any errors (written last)
│   ├── access-keys.csv
│   ├── bedrock-api-keys.csv                    (omitted when IncludeBedrockKeys=false)
│   ├── changes-access-keys.json                (only when something changed)
│   └── changes-bedrock-api-keys.json           (only when something changed)
├── latest/                                     copy of the most recent run
│   ├── manifest.json
│   ├── access-keys.csv
│   └── bedrock-api-keys.csv
└── state/                                      change-detection baseline (used by the Lambda)
    ├── access-keys.json
    └── bedrock-api-keys.json
```

Every file of a run shares one run id (UTC, e.g. `20260908T063802Z`): it names
the run folder and is the first column of both CSVs, so a downloaded file always
tells you which run produced it.

> **Short-term Bedrock API keys can't be inventoried.** They're presigned
> tokens generated from the caller's own session (valid up to 12 hours, one
> Region), and IAM never stores them, so there is nothing to list. Detect their
> use with CloudTrail, and restrict them with the `bedrock:bearerTokenType`
> condition key — see [`README.detailed.md`](./README.detailed.md#short-term-bedrock-api-keys).

---

## Deploy (2 steps)

Run from your **Organizations management account** with AWS CLI v2 + Python 3.

```bash
PROFILE=<your-management-account-profile>
REGION=us-east-1

# one-time: allow StackSets to manage org accounts
aws cloudformation activate-organizations-access --profile "$PROFILE"

# 1) read-only audit role in every member account (auto-covers new accounts)
./deploy-audit-role-stackset.sh "$PROFILE" "$REGION"

# 2) the Lambda + S3 bucket (prompts for optional email alerts + schedule)
./deploy.sh "$PROFILE" "$REGION"
```

Always run step 1 before step 2: the member role must allow
`iam:ListServiceSpecificCredentials` before the Lambda lists Bedrock API keys.
The StackSet script waits until the StackSet operation has `SUCCEEDED`.

`deploy.sh` asks two optional questions:

- **Alert email** — blank = no alerting; an address = SNS alerts on errors (you must click the confirmation email AWS sends).
- **Schedule** — `N` = run on demand; or pick Daily / Weekly / Every 12h / Monthly / a specific day of month.

Reports go under `credential-inventory/` in the bucket. To use another root, set
`REPORT_PREFIX` (e.g. `REPORT_PREFIX=my-reports ./deploy.sh "$PROFILE" "$REGION"`).

---

## Upgrading an existing deployment

If you deployed before Bedrock API key support was added, **redeploy the
StackSet first**. Until you do, the member roles lack the new
`iam:ListServiceSpecificCredentials` permission. Access keys are still
inventoried, but each such account shows up in `bedrock.errors[]` and the run
reports `ATTENTION_REQUIRED`.

```bash
PROFILE=<mgmt-profile>; REGION=us-east-1; STACK=org-access-key-inventory

# 0) Note your current settings: deploy.sh always overrides AlertEmail/EnableSchedule/ScheduleExpression
aws cloudformation describe-stacks --stack-name "$STACK" --profile "$PROFILE" --region "$REGION" \
  --query "Stacks[0].Parameters[?ParameterKey=='AlertEmail'||ParameterKey=='EnableSchedule'||ParameterKey=='ScheduleExpression']" --output table

# 1) FIRST update the member audit role (adds iam:ListServiceSpecificCredentials); waits for SUCCEEDED
./deploy-audit-role-stackset.sh "$PROFILE" "$REGION"
aws cloudformation list-stack-instances --stack-set-name org-access-key-audit-role --profile "$PROFILE" --region "$REGION" \
  --query "Summaries[?Status!='CURRENT'].[Account,Status,StatusReason]" --output table   # expect no rows

# 2) THEN redeploy the main stack with the SAME email/schedule as step 0 (a blank email removes SNS alerting).
#    If you had no alert email, an empty 4th argument still prompts -- just press Enter.
./deploy.sh "$PROFILE" "$REGION" "$STACK" "<same-alert-email>" "<same-schedule-expression-or-none>"

# 3) Invoke and check: bedrock.errors=[], listing_mode=all_users, expiry_supported=true,
#    and bedrock.changes.first_run=true (this run is the Bedrock baseline)
aws lambda invoke --function-name "$STACK-inventory" --profile "$PROFILE" --region "$REGION" \
  --cli-binary-format raw-in-base64-out out.json && cat out.json
```

To opt out or roll back without touching other settings:
`aws cloudformation deploy --template-file packaged.yaml --stack-name "$STACK" --capabilities CAPABILITY_IAM --parameter-overrides IncludeBedrockKeys=false --profile "$PROFILE" --region "$REGION"`
(parameters you don't override keep their previous values).

### Upgrading to the run-centric S3 layout

Reports used to go under `access-key-reports/` (the CSVs by date, the Bedrock
files under `bedrock-api-keys/`, the changelogs under `history/`). They now go
under `credential-inventory/`, with one folder per run (see
[What you get](#what-you-get)). No StackSet change is needed for this.

- **Redeploy** with `./deploy.sh` as in step 2 above. It now always passes the
  stack's `Prefix` (default `credential-inventory`). To keep writing under the
  old root, run `REPORT_PREFIX=access-key-reports ./deploy.sh ...`. If your old
  stack used a custom `Prefix`, also set `LEGACY_REPORT_PREFIX=<old-prefix>`.
- **No re-baseline.** The first run after the upgrade reads the old state once,
  read-only (`access-key-reports/state/keys-state.json` and
  `access-key-reports/bedrock-api-keys/state/keys-state.json`), and from then on
  uses `credential-inventory/state/`. Check that `changes.first_run=false` and
  `bedrock.changes.first_run=false`, and that the run manifest's
  `access_keys.previous_state` / `bedrock.previous_state` point at
  `access-key-reports/...`. Accounts that have no entries in the old state are
  listed once under `baselined_accounts` instead of being counted as added (a
  WARNING is logged if they hold keys; check their `create_date` in the CSV).
- **Old reports stay where they are.** Nothing is deleted or moved (the
  function role has no `s3:DeleteObject`). To keep everything under one root,
  you can copy them yourself (`$BUCKET` is the stack's `BucketName` output, see
  [Run & download](#run--download)):
  ```bash
  aws s3 cp "s3://$BUCKET/access-key-reports/" "s3://$BUCKET/credential-inventory/legacy/access-key-reports/" \
    --recursive --profile "$PROFILE" --region "$REGION"
  ```
  This copies current versions only. The copies don't go into `runs/` and have
  no manifest.
- **Breaking changes:**
  - `run_id` is now the **first column** of both CSVs. Update any parser that
    reads columns by position.
  - `last_used` no longer uses `N/A`: it is `Never` (IAM has no record of use)
    or `Unknown` (lookup failed). `KeysNeverUsed` counts only `Never`; failed
    lookups go to the new `KeysLastUsedUnknown` metric. Bedrock
    `never_expires` uses `Unknown` (was `unknown`).
  - The stack output `BedrockReportPrefix` is replaced by `RunsPrefix`,
    `LatestPrefix` and `StatePrefix`.
  - `s3_location`, `bedrock.s3_location` and the `history_location` fields can
    be `null` when that write failed, and `ATTENTION_REQUIRED` now also covers
    S3 write failures (listed in `write_errors[]`).
- **Lifecycle rule:** noncurrent versions under `latest/` and `state/` expire
  after 30 days. `runs/` and current versions never expire. CloudFormation now
  owns the bucket's lifecycle rules, so it replaces any you added by hand.

---

## Run & download

```bash
FN=$(aws cloudformation describe-stacks --stack-name org-access-key-inventory \
  --profile "$PROFILE" --region "$REGION" \
  --query "Stacks[0].Outputs[?OutputKey=='FunctionName'].OutputValue" --output text)

# run it
aws lambda invoke --function-name "$FN" --profile "$PROFILE" --region "$REGION" \
  --cli-binary-format raw-in-base64-out out.json && cat out.json

BUCKET=$(aws cloudformation describe-stacks --stack-name org-access-key-inventory \
  --profile "$PROFILE" --region "$REGION" \
  --query "Stacks[0].Outputs[?OutputKey=='BucketName'].OutputValue" --output text)

# download the latest reports (copies of the most recent run)
aws s3 cp "s3://$BUCKET/credential-inventory/latest/access-keys.csv" ./access-keys.csv \
  --profile "$PROFILE" --region "$REGION"
aws s3 cp "s3://$BUCKET/credential-inventory/latest/bedrock-api-keys.csv" ./bedrock-api-keys.csv \
  --profile "$PROFILE" --region "$REGION"
# which run they came from, and whether every file was refreshed
aws s3 cp "s3://$BUCKET/credential-inventory/latest/manifest.json" - \
  --profile "$PROFILE" --region "$REGION"

# a specific run: list the run folders of a day, then read that run's manifest
aws s3 ls "s3://$BUCKET/credential-inventory/runs/2026/09/08/" --profile "$PROFILE" --region "$REGION"
aws s3 cp "s3://$BUCKET/credential-inventory/runs/2026/09/08/20260908T063802Z/manifest.json" - \
  --profile "$PROFILE" --region "$REGION"
```

A run's `manifest.json` lists the S3 URI of every file the run wrote (`files`),
or `null` plus an entry in `write_errors` for any file that failed. The invoke
result's `manifest_location` points straight at it. In `latest/manifest.json`,
`latest.files` says per CSV whether this run replaced it (`updated`); any other
status means the object there is from an earlier run (its `run_id` column says
which).

The invoke result shows `status` (`OK` or `ATTENTION_REQUIRED`), the run id,
counts, the S3 paths, a `metrics` block, a `changes` block, and a `bedrock`
block, for example:

```json
{
  "status": "OK",
  "run_id": "20260908T063802Z",
  "keys_found": 42,
  "s3_location": "s3://<bucket>/credential-inventory/runs/2026/09/08/20260908T063802Z/access-keys.csv",
  "manifest_location": "s3://<bucket>/credential-inventory/runs/2026/09/08/20260908T063802Z/manifest.json",
  "latest_prefix": "s3://<bucket>/credential-inventory/latest/",
  "write_errors": [],
  "metrics": {
    "KeysTotal": 42,
    "KeysActive": 30,
    "KeysStale": 7,
    "AccountsWithErrors": 0
  },
  "changes": {
    "first_run": false,
    "added": 1,
    "removed": 2,
    "activated": 0,
    "deactivated": 1,
    "baselined_accounts": []
  },
  "history_location": "s3://<bucket>/credential-inventory/runs/2026/09/08/20260908T063802Z/changes-access-keys.json",
  "bedrock": {
    "enabled": true,
    "keys_found": 3,
    "errors": [],
    "s3_location": "s3://<bucket>/credential-inventory/runs/2026/09/08/20260908T063802Z/bedrock-api-keys.csv",
    "metrics": { "BedrockKeysTotal": 3, "BedrockKeysActive": 2, "BedrockKeysNoExpiryActive": 1 },
    "changes": { "first_run": false, "added": 1, "removed": 0, "activated": 0, "deactivated": 0,
                 "baselined_accounts": [] },
    "history_location": "s3://<bucket>/credential-inventory/runs/2026/09/08/20260908T063802Z/changes-bedrock-api-keys.json",
    "listing_mode": "all_users",
    "expiry_supported": true
  }
}
```

(Abbreviated. See [`README.detailed.md`](./README.detailed.md#run-it) for every field.)

---

## Metrics & history

Every run publishes custom CloudWatch metrics (namespace `OrgAccessKeyInventory`)
and updates a dashboard named `<stack>-access-keys`:

| Metric                                                            | Meaning                                                                                  |
| ----------------------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| `KeysTotal` / `KeysActive` / `KeysInactive`                       | Total keys and their status split.                                                       |
| `KeysStale` / `KeysStaleActive`                                   | Keys at/above `StaleAgeDays` (default 90); the second counts only the still-active ones. |
| `KeysNeverUsed`                                                   | Keys IAM reports as never used (`last_used` = `Never`).                                  |
| `KeysLastUsedUnknown`                                             | Keys whose last-used lookup failed (`last_used` = `Unknown`); not counted as never used. |
| `AccountsScanned` / `AccountsWithErrors`                          | Coverage of the run.                                                                     |
| `KeysAdded` / `KeysRemoved` / `KeysActivated` / `KeysDeactivated` | Changes since the previous run (history). Keys in a newly covered account are baselined, not added. |
| `BedrockKeysTotal` / `BedrockKeysActive` / `BedrockKeysInactive` / `BedrockKeysExpired` | Long-term Bedrock API keys and their status split (expired keys are counted only as expired). |
| `BedrockKeysNoExpiry` / `BedrockKeysNoExpiryActive`               | Bedrock API keys that never expire; the second counts only the active ones.              |
| `BedrockKeysExpiringSoon`                                         | Active Bedrock API keys expiring within `BedrockExpiryWarnDays` (default 30).            |
| `BedrockKeysStale` / `BedrockKeysStaleActive`                     | Bedrock API keys at/above `StaleAgeDays`; the second counts only the active ones.        |
| `BedrockAccountsWithErrors`                                       | Accounts whose access keys were read but whose Bedrock API keys couldn't be listed.      |
| `BedrockKeysAdded` / `BedrockKeysRemoved` / `BedrockKeysActivated` / `BedrockKeysDeactivated` | Bedrock API key changes since the previous run.                        |

The dashboard has a full-width **Current counts** strip (KeysTotal, KeysActive,
KeysInactive, KeysNeverUsed, KeysLastUsedUnknown, KeysStale, AccountsScanned,
AccountsWithErrors) plus
time-series widgets for status, rotation risk, history, and run health, followed
by a **Bedrock API keys** section with the same kind of widgets. Open it
from the stack output:

```bash
aws cloudformation describe-stacks --stack-name org-access-key-inventory \
  --profile "$PROFILE" --region "$REGION" \
  --query "Stacks[0].Outputs[?OutputKey=='DashboardUrl'].OutputValue" --output text
```

> The single-value strip shows the latest datapoint **inside the selected time
> range**. Use a relative range (1h/3h/1d) ending at "now" and refresh after a
> run, or it may show an older value.

The **history changelog** for each run (what changed and in which account) is
written to the run folder: `runs/YYYY/MM/DD/<run-id>/changes-access-keys.json`
and `changes-bedrock-api-keys.json`. The first run only records a baseline (no
change metrics or changelog). Keys in an account that is listed for the first
time (a newly invited account, or one that failed until now) are also baselined:
they appear under `changes.baselined_accounts`, not in `KeysAdded` /
`BedrockKeysAdded`.

Set `PublishMetrics=false` at deploy time to skip metrics/dashboard; tune the
staleness threshold with `StaleAgeDays` and the Bedrock "expiring soon" window
with `BedrockExpiryWarnDays`.

---

## Teardown

Two parts to set up, two to tear down:

```bash
./destroy.sh "$PROFILE" "$REGION"                     # Lambda stack (bucket kept)
./destroy-audit-role-stackset.sh "$PROFILE" "$REGION" # audit role in all accounts
```

---

## Files

| File                                                               | Purpose                                                     |
| ------------------------------------------------------------------ | ----------------------------------------------------------- |
| `template.yaml`                                                    | Main stack: Lambda, role, S3, optional SNS/alarms/schedule. |
| `lambda/lambda_function.py`                                        | The inventory handler.                                      |
| `deploy.sh` / `destroy.sh`                                         | Deploy / remove the main stack.                             |
| `member-audit-role.yaml`                                           | Read-only role for member accounts.                         |
| `deploy-audit-role-stackset.sh` / `destroy-audit-role-stackset.sh` | Deploy / remove that role org-wide.                         |
| `tests/test_bedrock_keys.py`                                       | Offline unit tests (`python3 -m unittest discover -s tests -v`). |
| `README.detailed.md`                                               | Full documentation.                                         |
