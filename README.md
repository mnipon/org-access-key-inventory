# Org-wide IAM Access Key Inventory

List **every IAM user access key in every account of your AWS Organization**,
with each key's creation date, age, and last use, plus every **long-term Amazon
Bedrock API key**, into CSV reports in S3.

A Lambda in the management account assumes a read-only role in each member
account and writes the reports. It can run on a schedule and email you on errors.

> Architecture, security notes, and troubleshooting: see
> [`README.detailed.md`](./README.detailed.md).

---

## What you get

- **`access-keys.csv`**: `run_id, account_id, account_name, user, access_key_id, status, create_date, age_days, last_used` (`last_used` is a timestamp, `Never`, or `Unknown` if the lookup failed).
- **`bedrock-api-keys.csv`**: long-term Bedrock API keys with status, age, expiration date, days to expiry, and whether they never expire. Turn it off with `IncludeBedrockKeys=false`.
- Key IDs are **masked** (e.g. `AKIA************MPLE`); secret keys are never touched.
- Text cells starting with `=`, `+`, `-`, `@` (or tab/CR) get a leading `'`, so spreadsheets show them as text instead of running a formula.
- **History**: each run records which keys were added, removed, activated, or deactivated since the previous run.
- **CloudWatch metrics and a dashboard** for key counts, staleness, expiry, and changes over time.

Reports go to a private, encrypted, versioned S3 bucket:

```text
s3://<bucket>/credential-inventory/
├── runs/YYYY/MM/DD/<run-id>/   one folder per run: both CSVs, changelogs, manifest.json
├── latest/                     copy of the most recent run
└── state/                      baseline the Lambda uses for change detection
```

The run id (UTC, e.g. `20260908T063802Z`) names the run folder and is the first
column of both CSVs.

> **Short-term Bedrock API keys can't be inventoried.** IAM never stores them
> (they're tokens derived from the caller's session, valid up to 12 hours).
> Detect their use with CloudTrail; see
> [`README.detailed.md`](./README.detailed.md#short-term-bedrock-api-keys).

---

## Deploy

Run from your **Organizations management account** with AWS CLI v2 and Python 3.

```bash
PROFILE=<your-management-account-profile>
REGION=us-east-1

# one-time: allow StackSets to manage org accounts
aws cloudformation activate-organizations-access --profile "$PROFILE"

# 1) read-only audit role in every member account (first, for a new deployment)
./deploy-audit-role-stackset.sh "$PROFILE" "$REGION"

# 2) the Lambda and S3 bucket
./deploy.sh "$PROFILE" "$REGION"
```

Accounts without `OrgAccessKeyAuditRole` are reported as errors: the Lambda only
falls back to the admin roles `OrganizationAccountAccessRole` /
`AWSControlTowerExecution` if you deploy with `ALLOW_ADMIN_ROLE_FALLBACK=true`.
Updating an existing deployment: run `deploy.sh` first, then the StackSet script
([details](./README.detailed.md#deploy)).

`deploy.sh` asks two optional questions:

- **Alert email**: blank for no alerts, or an address for SNS alerts on errors (confirm the email AWS sends).
- **Schedule**: `N` to run on demand, or Daily / Weekly / Every 12h / Monthly / a day of the month.

---

## Run & download

```bash
STACK=org-access-key-inventory
BUCKET=$(aws cloudformation describe-stacks --stack-name "$STACK" \
  --profile "$PROFILE" --region "$REGION" \
  --query "Stacks[0].Outputs[?OutputKey=='BucketName'].OutputValue" --output text)

# run it now (or wait for the schedule)
aws lambda invoke --function-name "$STACK-inventory" --profile "$PROFILE" --region "$REGION" \
  --cli-binary-format raw-in-base64-out out.json && cat out.json

# download the latest reports
aws s3 cp "s3://$BUCKET/credential-inventory/latest/access-keys.csv" . --profile "$PROFILE" --region "$REGION"
aws s3 cp "s3://$BUCKET/credential-inventory/latest/bedrock-api-keys.csv" . --profile "$PROFILE" --region "$REGION"
```

The output's `status` is `OK`, or `ATTENTION_REQUIRED` if an account or file
failed (details in `errors`, `bedrock.errors`, and `write_errors`). Earlier runs
stay in `runs/YYYY/MM/DD/<run-id>/`.

---

## Metrics & history

Each run publishes CloudWatch metrics (namespace `OrgAccessKeyInventory`) and
updates the dashboard `<stack>-access-keys`:

| Metric | Meaning |
| --- | --- |
| `KeysTotal` / `KeysActive` / `KeysInactive` | Access keys by status. |
| `KeysStale` / `KeysStaleActive` | Keys at least `StaleAgeDays` old (default 90): all, and active only. |
| `KeysNeverUsed` / `KeysLastUsedUnknown` | Keys never used, and keys whose last-used lookup failed. |
| `AccountsScanned` / `AccountsWithErrors` | Run coverage. |
| `KeysAdded` / `KeysRemoved` / `KeysActivated` / `KeysDeactivated` | Changes since the previous run. |
| `BedrockKeysTotal` / `Active` / `Inactive` / `Expired`, `BedrockKeysStale` / `StaleActive`, `BedrockKeysAdded` / `Removed` / `Activated` / `Deactivated` | The same measures for Bedrock API keys. |
| `BedrockKeysNoExpiry` / `BedrockKeysNoExpiryActive` / `BedrockKeysExpiringSoon` | Bedrock keys that never expire, and active ones expiring within `BedrockExpiryWarnDays` (default 30). |
| `BedrockAccountsWithErrors` | Accounts whose Bedrock API keys couldn't be listed. |

Open the dashboard from the stack output:

```bash
aws cloudformation describe-stacks --stack-name "$STACK" \
  --profile "$PROFILE" --region "$REGION" \
  --query "Stacks[0].Outputs[?OutputKey=='DashboardUrl'].OutputValue" --output text
```

The single-value widgets show the latest datapoint in the selected time range,
so use a range ending at "now" and refresh after a run.

The first run only records a baseline. Keys in an account listed for the first
time are also baselined (under `changes.baselined_accounts`) rather than counted
as added. Set `PublishMetrics=false` to skip metrics and the dashboard.

---

## Teardown

```bash
./destroy.sh "$PROFILE" "$REGION"                     # Lambda stack (bucket kept)
./destroy-audit-role-stackset.sh "$PROFILE" "$REGION" # audit role in all accounts
```

Both scripts ask you to type the stack/StackSet name (`FORCE=1` skips the prompt).

---

## Files

| File | Purpose |
| --- | --- |
| `template.yaml` | Main stack: Lambda, role, S3, alarms, optional SNS/schedule/dashboard. |
| `lambda/lambda_function.py` | The inventory handler. |
| `deploy.sh` / `destroy.sh` | Deploy / remove the main stack. |
| `member-audit-role.yaml` | Read-only role for member accounts. |
| `deploy-audit-role-stackset.sh` / `destroy-audit-role-stackset.sh` | Deploy / remove that role org-wide. |
| `tests/test_bedrock_keys.py` | Offline unit tests (`python3 -m unittest discover -s tests -v`). |
| `README.detailed.md` | Full documentation. |
| `SECURITY.md` | How to report a vulnerability privately. |
