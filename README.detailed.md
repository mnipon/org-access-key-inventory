# Org-wide IAM Access Key Inventory

Inventory **every IAM user access key across all accounts in an AWS Organization**
and write a consolidated CSV to S3 on every run (one folder per run plus a
`latest/` copy; see [S3 layout](#s3-layout)). Runs as a Lambda in the management
account, with cross-account read access via a dedicated role deployed org-wide by
a CloudFormation StackSet.

Each row includes the access key's **true creation date** and **last-used** info —
data that org-level IAM Access Analyzer and AWS Config cannot give you (Config has
no `AWS::IAM::AccessKey` resource type, and Access Analyzer only reports _unused_
keys). See [Why this exists](#why-this-exists).

The same run also inventories **long-term Amazon Bedrock API keys** into a
separate CSV (see [Bedrock API keys](#bedrock-api-keys)). Short-term Bedrock API
keys can't be inventoried by any API; see
[Short-term Bedrock API keys](#short-term-bedrock-api-keys).

---

## Architecture

```
                        ┌─────────────────────────────────────────────┐
                        │            MANAGEMENT ACCOUNT                 │
                        │                                               │
  EventBridge (opt.) ──▶│  InventoryFunction (Lambda, python3.12)       │
                        │    1. organizations:ListAccounts              │
                        │    2. for each account:                       │
                        │         - mgmt account  → IAM directly        │
                        │         - member account→ sts:AssumeRole ─────┼──┐
                        │    3. iam:ListUsers / ListAccessKeys /        │  │
                        │       GetAccessKeyLastUsed /                  │  │
                        │       ListServiceSpecificCredentials (Bedrock)│  │
                        │    4. write run CSVs → S3 (SSE, versioned)    │  │
                        │    5. diff vs. state → changelog, new state   │  │
                        │    6. publish CloudWatch metrics              │  │
                        │    7. write run manifest; refresh latest/     │  │
                        │    8. log RUN SUMMARY; alert on errors        │  │
                        │                                               │  │
                        │  ReportBucket (S3)   AlertTopic (SNS)         │  │
                        │  CloudWatch metrics + dashboard + alarms      │  │
                        └─────────────────────────────────────────────┘  │
                                                                          │ assume
   ┌──────────────────────────────────────────────────────────────────┐ │ OrgAccessKeyAuditRole
   │   MEMBER ACCOUNTS  (role deployed by service-managed StackSet)     │◀┘
   │   OrgAccessKeyAuditRole  → iam:ListUsers/ListAccessKeys/           │
   │                            GetAccessKeyLastUsed/                   │
   │                            ListServiceSpecificCredentials          │
   │                            (all read-only)                         │
   │   Trust: <mgmt account> + condition aws:PrincipalOrgID = <org>     │
   └────────────────────────────────────────────────────────────────────┘
```

The Lambda tries each name in `CANDIDATE_ROLES` (default
`OrgAccessKeyAuditRole,OrganizationAccountAccessRole,AWSControlTowerExecution`)
and uses the first it can assume. Any account it cannot reach is recorded as an
**error** (not silently skipped) and triggers admin alerting.

---

## Files

| File                             | Purpose                                                                           |
| -------------------------------- | --------------------------------------------------------------------------------- |
| `lambda/lambda_function.py`      | Lambda handler: fan-out, CSV build, S3 run folder + manifest + `latest/`, logging, SNS alert. |
| `template.yaml`                  | Main stack: Lambda, IAM role, S3 bucket, SNS topic, alarms, optional schedule.    |
| `deploy.sh`                      | Package + deploy the main stack.                                                  |
| `destroy.sh`                     | Delete the main stack (report bucket **retained** by design).                     |
| `member-audit-role.yaml`         | Parameterized read-only role for member accounts (StackSet or standalone).        |
| `deploy-audit-role-stackset.sh`  | Deploy that role org-wide via a service-managed StackSet (IDs auto-discovered).   |
| `destroy-audit-role-stackset.sh` | Remove that StackSet + roles from every member account (root ID auto-discovered). |
| `tests/test_bedrock_keys.py`     | Offline unit tests (no AWS calls). See [Running the unit tests](#running-the-unit-tests). |

> **No account IDs are hardcoded anywhere.** The management account ID, org ID,
> and org root are discovered at deploy time via `describe-organization` /
> `list-roots` and passed as parameters.

---

## Prerequisites

- You run these commands from the **Organizations management account** (or a
  delegated administrator) with admin/`sts:AssumeRoot`-free admin credentials.
- AWS CLI v2 and Python 3 locally.
- For the org-wide role: **trusted access between Organizations and CloudFormation
  StackSets** (one-time):
  ```bash
  aws cloudformation activate-organizations-access --profile <mgmt-profile>
  ```

> Throughout this doc, `<mgmt-profile>` is your AWS CLI profile for the
> Organizations **management account**. `<new-mgmt-profile>` (in
> [Redeploy to another organization](#redeploy-to-another-organization)) is the
> management-account profile of a _different_ org.

---

## Deploy

```bash
PROFILE=<mgmt-profile>       # AWS CLI profile for your Organizations management account
REGION=us-east-1        # IAM is global; a single region is fine

# 1) Deploy the read-only audit role to every member account (auto-covers new accounts)
./deploy-audit-role-stackset.sh "$PROFILE" "$REGION"

# 2) Deploy the Lambda + bucket (+ optional alerting) stack
#    deploy.sh PROMPTS for an alert email. Leave it blank for NO alerting,
#    or provide one to create the SNS topic + alarms.
./deploy.sh "$PROFILE" "$REGION"
```

> **Order matters.** Step 1 must finish before step 2 runs the Lambda: the
> member role needs `iam:ListServiceSpecificCredentials` for the Bedrock API key
> inventory. `deploy-audit-role-stackset.sh` waits for each StackSet operation
> to reach `SUCCEEDED`, and exits non-zero if it ends `FAILED` or `STOPPED`
> (it prints the `list-stack-set-operation-results` command to see why).
> Upgrading an existing deployment? See
> [Upgrading an existing deployment](#upgrading-an-existing-deployment).

`deploy.sh` will prompt:

```
Alert email address (optional):
```

- **Leave blank** → the stack is deployed with **no SNS topic, no subscription,
  and no CloudWatch alarms**. Errors still appear in the return payload and the
  CloudWatch logs (`RUN SUMMARY` / `ADMIN ACTION REQUIRED`).
- **Enter an email** → an SNS topic, email subscription, and alarms are created.
  **AWS then emails you a one-time "Confirm subscription" link that you must
  click**, or no alerts will be delivered. `deploy.sh` prints this reminder too.

Then it prompts for an optional recurring schedule:

```
Run the inventory automatically on a schedule? [y/N]: y
How often should it run?
  1) Daily              rate(1 day)
  2) Weekly             rate(7 days)
  3) Every 12 hours     rate(12 hours)
  4) Monthly            (00:00 UTC on the 1st of each month)
  5) Specific day of month (you pick the day; runs 00:00 UTC)
```

- **Answer `N`** (default) → no EventBridge rule is created; run the Lambda on
  demand.
- **Answer `y`** → pick a frequency. **Monthly** runs at 00:00 UTC on the 1st;
  **Specific day of month** asks for a day **1–28** (capped at 28 so it fires
  every month — days 29–31 don't exist in February) and runs at 00:00 UTC.

You can also pass both non-interactively — email as the 4th arg, schedule as the
5th (`none` to disable). The 5th arg accepts any EventBridge expression:

```bash
# daily run + email alerts, no prompts
./deploy.sh "$PROFILE" "$REGION" org-access-key-inventory you@example.com "rate(1 day)"

# monthly on the 15th, no alerting, no prompts
./deploy.sh "$PROFILE" "$REGION" org-access-key-inventory "" "cron(0 0 15 * ? *)"

# no schedule, no alerting, no prompts
./deploy.sh "$PROFILE" "$REGION" org-access-key-inventory "" none

# reports under a different S3 root (default credential-inventory); see S3 layout
REPORT_PREFIX=my-reports ./deploy.sh "$PROFILE" "$REGION" org-access-key-inventory "" none

# or drive CloudFormation directly (after deploy.sh has packaged the code).
# Pass Prefix explicitly: parameters you leave out keep their previous values.
aws cloudformation deploy --template-file packaged.yaml \
  --stack-name org-access-key-inventory --capabilities CAPABILITY_IAM \
  --profile "$PROFILE" --region "$REGION" \
  --parameter-overrides \
      AlertEmail=you@example.com \
      EnableSchedule=true ScheduleExpression="rate(1 day)" \
      Prefix=credential-inventory
```

`deploy.sh` always passes `Prefix` (from `REPORT_PREFIX`, default
`credential-inventory`), because `cloudformation deploy` would otherwise keep an
existing stack's previous `Prefix`. `LEGACY_REPORT_PREFIX` is only needed when
upgrading a stack that used a custom `Prefix` (see
[Upgrading to the run-centric S3 layout](#upgrading-to-the-run-centric-s3-layout)).

> **Email confirmation is required.** If you set `AlertEmail`, click the
> "Confirm subscription" link in the email AWS sends you (one-time), or alerts
> won't be delivered. With no email, no SNS resources are created at all.

---

## Run it

```bash
FN=$(aws cloudformation describe-stacks --stack-name org-access-key-inventory \
  --profile "$PROFILE" --region "$REGION" \
  --query "Stacks[0].Outputs[?OutputKey=='FunctionName'].OutputValue" --output text)

aws lambda invoke --function-name "$FN" \
  --profile "$PROFILE" --region "$REGION" \
  --cli-binary-format raw-in-base64-out out.json && cat out.json
```

Sample response:

```json
{
  "status": "OK",
  "accounts_scanned": 5,
  "keys_found": 4,
  "errors": [],
  "s3_location": "s3://<bucket>/credential-inventory/runs/2026/09/08/20260908T063802Z/access-keys.csv",
  "metrics": {
    "KeysTotal": 4,
    "KeysActive": 3,
    "KeysInactive": 1,
    "KeysNeverUsed": 1,
    "KeysLastUsedUnknown": 0,
    "KeysStale": 2,
    "KeysStaleActive": 1,
    "AccountsScanned": 5,
    "AccountsWithErrors": 0
  },
  "changes": {
    "first_run": false,
    "added": 1,
    "removed": 0,
    "activated": 0,
    "deactivated": 1,
    "baselined_accounts": []
  },
  "history_location": "s3://<bucket>/credential-inventory/runs/2026/09/08/20260908T063802Z/changes-access-keys.json",
  "bedrock": {
    "enabled": true,
    "service_name": "bedrock.amazonaws.com",
    "keys_found": 3,
    "errors": [],
    "s3_location": "s3://<bucket>/credential-inventory/runs/2026/09/08/20260908T063802Z/bedrock-api-keys.csv",
    "metrics": {
      "BedrockKeysTotal": 3,
      "BedrockKeysActive": 2,
      "BedrockKeysInactive": 0,
      "BedrockKeysExpired": 1,
      "BedrockKeysStale": 1,
      "BedrockKeysStaleActive": 0,
      "BedrockAccountsWithErrors": 0,
      "BedrockKeysNoExpiry": 1,
      "BedrockKeysNoExpiryActive": 1,
      "BedrockKeysExpiringSoon": 1
    },
    "changes": {
      "first_run": false,
      "added": 1,
      "removed": 0,
      "activated": 0,
      "deactivated": 1,
      "baselined_accounts": []
    },
    "history_location": "s3://<bucket>/credential-inventory/runs/2026/09/08/20260908T063802Z/changes-bedrock-api-keys.json",
    "listing_mode": "all_users",
    "expiry_supported": true,
    "botocore_version": "1.40.4"
  },
  "run_id": "20260908T063802Z",
  "manifest_location": "s3://<bucket>/credential-inventory/runs/2026/09/08/20260908T063802Z/manifest.json",
  "latest_prefix": "s3://<bucket>/credential-inventory/latest/",
  "write_errors": []
}
```

The response also has an `access_keys` block with the same shape as `bedrock`
(`keys_found`, `errors`, `s3_location`, `metrics`, `changes`,
`history_location`), matching the manifest's `access_keys` section. The
top-level access-key fields shown above are kept for backward compatibility
and carry the same values; prefer `access_keys.*` in new tooling.

`status` is `OK` when every account was inventoried and every file was written,
or `ATTENTION_REQUIRED` when one or more accounts failed, their Bedrock API keys
couldn't be listed, or an S3 write failed (see below). `metrics` and `changes`
mirror what is published to CloudWatch and recorded in the history changelog
(see [Metrics & history](#metrics--history)).

Top-level fields:

- `run_id`: the run's UTC timestamp id. It names the run folder and is the first
  column of both CSVs.
- `s3_location`: the run's `access-keys.csv`, or `null` if writing it failed.
- `history_location`: the run's `changes-access-keys.json`, or `null` when
  nothing changed (or the write failed).
- `manifest_location`: the run's `manifest.json`, or `null` if writing it
  failed. It lists every file of the run (see [S3 layout](#s3-layout)).
- `latest_prefix`: where the copy of the most recent run lives.
- `write_errors[]`: every S3 write that failed, including `latest/`
  (`{s3_uri, error}`). Empty on a healthy run.
- `changes.baselined_accounts[]`: accounts listed for the first time, whose
  existing keys were recorded as baseline instead of "added"
  (`{account_id, account_name, keys}`; see
  [History](#history-change-detection)).

The `bedrock` block is additive; every other key keeps its meaning.
With `IncludeBedrockKeys=false` it is just `{"enabled": false}`. Inside it:

- `errors[]`: accounts whose access keys were inventoried but whose Bedrock API
  keys couldn't be listed (`{account_id, account_name, error}`). Accounts that
  failed completely stay in the top-level `errors[]` only.
- `s3_location`: the run's `bedrock-api-keys.csv`, or `null` if writing it
  failed. `history_location`: the run's `changes-bedrock-api-keys.json`, or `null`.
- `changes`: zeros on the first Bedrock run, which only records a baseline.
- `listing_mode`: `all_users` (one paginated call per account) or `per_user`
  (one call per IAM user, used with an older bundled SDK). `listing_mode` and
  `expiry_supported` are `null` if no account was listed successfully.
- `expiry_supported`: `false` means the Lambda's bundled botocore predates
  1.39.0 and can't report expiration dates (see
  [Listing mode and SDK version](#listing-mode-and-sdk-version)).

### Download the latest report

`latest/` always holds a copy of the most recent run, so no listing is needed:

```bash
BUCKET=$(aws cloudformation describe-stacks --stack-name org-access-key-inventory \
  --profile "$PROFILE" --region "$REGION" \
  --query "Stacks[0].Outputs[?OutputKey=='BucketName'].OutputValue" --output text)

aws s3 cp "s3://$BUCKET/credential-inventory/latest/access-keys.csv" ./access-keys.csv \
  --profile "$PROFILE" --region "$REGION"
cat access-keys.csv

# which run it came from, and whether each latest/ file was refreshed by that run
aws s3 cp "s3://$BUCKET/credential-inventory/latest/manifest.json" - \
  --profile "$PROFILE" --region "$REGION"
```

To find **a specific run**, list the run folders of a day, then open that run's
manifest (its `files` map has the URI of every file the run wrote). The invoke
result's `manifest_location` points straight at it.

```bash
aws s3 ls "s3://$BUCKET/credential-inventory/runs/2026/09/08/" --profile "$PROFILE" --region "$REGION"
aws s3 cp "s3://$BUCKET/credential-inventory/runs/2026/09/08/20260908T063802Z/manifest.json" - \
  --profile "$PROFILE" --region "$REGION"
aws s3 cp "s3://$BUCKET/credential-inventory/runs/2026/09/08/20260908T063802Z/access-keys.csv" ./access-keys.csv \
  --profile "$PROFILE" --region "$REGION"
```

### CSV columns

| Column                       | Meaning                                                                                                                                                                     |
| ---------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `run_id`                     | The run that produced the row (UTC, e.g. `20260908T063802Z`); the same on every row and in the run folder name.                                                             |
| `account_id`, `account_name` | Owning account.                                                                                                                                                             |
| `user`                       | IAM user name.                                                                                                                                                              |
| `access_key_id`              | The `AKIA...` key ID, **masked** to first/last 4 chars (e.g. `AKIA************MPLE`). No secret is ever exposed. Tune with `MaskHead`/`MaskTail` (both `0` = show full id). |
| `status`                     | `Active` / `Inactive`.                                                                                                                                                      |
| `create_date`                | **True key creation timestamp** (from `ListAccessKeys`).                                                                                                                    |
| `age_days`                   | Age of the key in days (rotation signal).                                                                                                                                   |
| `last_used`                  | Last-used timestamp; `Never` if IAM has no record of the key being used; `Unknown` if the last-used lookup failed (logged as a WARNING).                                     |

---

## Bedrock API keys

Amazon Bedrock API keys come in two kinds, and only one of them can be inventoried.

### Long-term Bedrock API keys (inventoried)

- They are **IAM service-specific credentials** for the service
  `bedrock.amazonaws.com`. Each one belongs to an IAM user, a user can have at
  most 2, and the credential ID starts with `ACCA`.
- A key created in the **Bedrock console** gets its own IAM user named
  `BedrockAPIKey-xxxx`. These users show up in `ListUsers`, but usually have no
  access keys, so they never appear in the access-key CSV.
- In every account the Lambda already reads, it calls
  `iam:ListServiceSpecificCredentials` (metadata only) with the same IAM client.
  It never calls `CreateServiceSpecificCredential` or
  `ResetServiceSpecificCredential`, the calls that return a secret.
- Results go to a **separate CSV** in the same run folder, next to
  `access-keys.csv`:
  `s3://<bucket>/<prefix>/runs/YYYY/MM/DD/<run-id>/bedrock-api-keys.csv` (and a
  copy in `<prefix>/latest/bedrock-api-keys.csv`). The header is written even
  when there are no keys.
- Turn the feature off with the `IncludeBedrockKeys=false` stack parameter.
  The run folder then has no `bedrock-api-keys.csv`, and
  `latest/manifest.json` marks `latest/bedrock-api-keys.csv` as `disabled` (an
  older copy may still be there; its `run_id` column says which run wrote it).

Download the latest one:

```bash
aws s3 cp "s3://$BUCKET/credential-inventory/latest/bedrock-api-keys.csv" ./bedrock-api-keys.csv \
  --profile "$PROFILE" --region "$REGION"
cat bedrock-api-keys.csv
```

| Column                       | Meaning                                                                                                                         |
| ---------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| `run_id`                     | The run that produced the row (same as in the access-key CSV of that run).                                                      |
| `account_id`, `account_name` | Owning account.                                                                                                                 |
| `user`                       | IAM user the key belongs to (`BedrockAPIKey-xxxx` for console-created keys).                                                    |
| `credential_id`              | The `ACCA...` credential ID, **masked** like access key IDs (`MaskHead`/`MaskTail`).                                            |
| `service_name`               | Always `bedrock.amazonaws.com`.                                                                                                 |
| `status`                     | As reported by IAM: `Active` / `Inactive` / `Expired`.                                                                          |
| `create_date`, `age_days`    | Creation timestamp and age in days.                                                                                             |
| `expiration_date`            | Expiration timestamp; `Never` if the key has no expiration; `Unknown` if the Lambda's SDK can't report it (see below).          |
| `days_to_expiry`             | Whole days until expiration (negative once expired); empty for `Never` / `Unknown`.                                             |
| `never_expires`              | `true` / `false` / `Unknown` (same cases as `expiration_date`).                                                                 |
| `user_active_access_keys`    | Number of **active IAM access keys** the same user holds (from this run's access-key pass). A second Bedrock key is its own row. |

What's deliberately **not** in the report:

- **Last used.** IAM has no last-used API for service-specific credentials. Use
  CloudTrail instead: Bedrock events with `eventSource = bedrock.amazonaws.com`
  and `additionalEventData.callWithBearerToken = true` were made with a Bedrock
  API key; for a long-term key, `userIdentity.userName` is the IAM user that
  owns it.
- **The credential alias** (`ServiceCredentialAlias`, the public part of the
  key) is never written anywhere, nor is `ServiceUserName`.

Expired keys: a key counts as expired if IAM reports `Expired` **or** its
expiration date has passed. In the metrics an expired key counts only as
expired, so `BedrockKeysTotal = BedrockKeysActive + BedrockKeysInactive + BedrockKeysExpired`.

#### Listing mode and SDK version

The Lambda uses the boto3/botocore bundled with the `python3.12` runtime; nothing
is vendored, and the bundled version can differ by Region. At runtime the Lambda
checks the SDK's IAM model and logs `SDK boto3=<v> botocore=<v>` once per run:

- **botocore ≥ 1.39.0**: one `AllUsers` call per account, paginated with
  `Marker` (`listing_mode = all_users`), and expiration dates are reported.
- **Older botocore**: one call per IAM user (`listing_mode = per_user`), which
  adds one IAM call per user to the run time. Older botocore also drops
  `ExpirationDate`, so `expiration_date` is `Unknown`, `expiry_supported` is
  `false`, the `BedrockKeysNoExpiry*` and `BedrockKeysExpiringSoon` metrics are
  **not** published, and a single WARNING is logged.

If you see `expiry_supported: false`, the fix is to vendor an exact, pinned
boto3/botocore version (≥ 1.39.0) into `lambda/`. This project doesn't do that
for you.

### Short-term Bedrock API keys

Short-term Bedrock API keys **can't be inventoried by this tool or by any AWS
API**:

- They're presigned (SigV4) tokens built **on the client** from the caller's
  existing session, so creating one makes no AWS call and leaves no CloudTrail
  event.
- They're never stored in IAM, so there's nothing to list.
- They last 12 hours or until the generating session expires, whichever comes
  first. They work only in the Region where they were made, and have the same
  permissions as the principal that made them.

What you can do instead:

- **Detect use** with CloudTrail: Bedrock calls made with an API key (short- or
  long-term) are logged with `additionalEventData.callWithBearerToken = true`.
  Building this detection (an org trail plus Athena / CloudTrail Lake queries,
  or EventBridge rules) is future work and not part of this tool.
- **Prevent or limit use** with IAM policies or SCPs:
  - deny `bedrock:CallWithBearerToken` **and** `bedrock-mantle:CallWithBearerToken`
    to block all API key use;
  - add the `bedrock:bearerTokenType` / `bedrock-mantle:bearerTokenType`
    condition key (`SHORT_TERM` or `LONG_TERM`) to block only one kind;
  - deny `iam:CreateServiceSpecificCredential`, or limit it with
    `iam:ServiceSpecificCredentialServiceName` and
    `iam:ServiceSpecificCredentialAgeDays`, to control long-term key creation.

  See [Control permissions for generating and using Amazon Bedrock API keys](https://docs.aws.amazon.com/bedrock/latest/userguide/api-keys-permissions.html)
  and [Securing Amazon Bedrock API keys](https://aws.amazon.com/blogs/security/securing-amazon-bedrock-api-keys-best-practices-for-implementation-and-management/).

---

## Metrics & history

Beyond the point-in-time CSV, each run turns the inventory into a **tracked time
series** and a **run-to-run changelog**.

### CloudWatch metrics

After building the report, the Lambda publishes custom metrics to the namespace
set by `MetricNamespace` (default `OrgAccessKeyInventory`) via
`cloudwatch:PutMetricData`:

| Metric                              | Stat to graph | Meaning                                                           |
| ----------------------------------- | ------------- | ----------------------------------------------------------------- |
| `KeysTotal`                         | Max           | All access keys across the org.                                   |
| `KeysActive` / `KeysInactive`       | Max           | Status split.                                                     |
| `KeysNeverUsed`                     | Max           | Keys IAM reports as never used (`last_used` = `Never`; dormant).  |
| `KeysLastUsedUnknown`               | Max           | Keys whose last-used lookup failed (`last_used` = `Unknown`).     |
| `KeysStale`                         | Max           | Keys aged ≥ `StaleAgeDays` (default 90) — rotation candidates.    |
| `KeysStaleActive`                   | Max           | Stale keys that are **still Active** — the ones that matter most. |
| `AccountsScanned`                   | Max           | Accounts inventoried in the run.                                  |
| `AccountsWithErrors`                | Max           | Accounts that could not be inventoried.                           |
| `KeysAdded` / `KeysRemoved`         | Sum           | Keys created / deleted since the previous run. Keys in an account listed for the first time are baselined, not added. |
| `KeysActivated` / `KeysDeactivated` | Sum           | Keys whose status flipped since the previous run.                 |

Bedrock API key metrics (published when `IncludeBedrockKeys=true`, same namespace, no dimensions):

| Metric                                            | Stat to graph | Meaning                                                                                       |
| ------------------------------------------------- | ------------- | --------------------------------------------------------------------------------------------- |
| `BedrockKeysTotal`                                | Max           | All long-term Bedrock API keys across the org.                                                |
| `BedrockKeysActive` / `BedrockKeysInactive`       | Max           | Status split of the keys that haven't expired.                                                |
| `BedrockKeysExpired`                              | Max           | Keys IAM reports as `Expired`, or whose expiration date has passed.                           |
| `BedrockKeysNoExpiry` / `BedrockKeysNoExpiryActive` | Max         | Keys that never expire / those that are also active. Omitted if `expiry_supported` is false. |
| `BedrockKeysExpiringSoon`                         | Max           | Active keys expiring within `BedrockExpiryWarnDays` (default 30). Omitted if `expiry_supported` is false. |
| `BedrockKeysStale` / `BedrockKeysStaleActive`     | Max           | Keys aged ≥ `StaleAgeDays` / those that are also active.                                     |
| `BedrockAccountsWithErrors`                       | Max           | Accounts whose access keys were read but whose Bedrock API keys couldn't be listed.           |
| `BedrockKeysAdded` / `BedrockKeysRemoved`         | Sum           | Bedrock API keys created / deleted since the previous run (not on the first Bedrock run; keys in a newly covered account are baselined, not added). |
| `BedrockKeysActivated` / `BedrockKeysDeactivated` | Sum           | Status changes since the previous run; a change to `Expired` counts as deactivated.           |

Metric publishing is best-effort: if it fails, the run still succeeds and the
failure is logged. Disable it entirely with `PublishMetrics=false`.

### Dashboard

When `PublishMetrics=true` (the default), the stack creates a CloudWatch
dashboard named `<stack>-access-keys` with these widgets:

- **Current counts (latest run)** — a full-width single-value strip:
  `KeysTotal`, `KeysActive`, `KeysInactive`, `KeysNeverUsed`,
  `KeysLastUsedUnknown`, `KeysStale`, `AccountsScanned`, `AccountsWithErrors`.
- **Keys by status over time** — `KeysTotal`, `KeysActive`, `KeysInactive`,
  `KeysNeverUsed`.
- **Rotation risk** — `KeysStale`, `KeysStaleActive`, `KeysNeverUsed`.
- **History: changes since previous run** — `KeysAdded`, `KeysRemoved`,
  `KeysActivated`, `KeysDeactivated`.
- **Run health** — Lambda `Invocations` and `Errors`.
- **Amazon Bedrock API keys (long-term)** section (empty if `IncludeBedrockKeys=false`):
  - **Bedrock API keys: current counts** — single-value strip:
    `BedrockKeysTotal`, `BedrockKeysActive`, `BedrockKeysInactive`,
    `BedrockKeysNoExpiryActive`, `BedrockKeysExpiringSoon`, `BedrockKeysExpired`,
    `BedrockKeysStaleActive`, `BedrockAccountsWithErrors`.
  - **Bedrock API keys by status** — Total, Active, Inactive, Expired.
  - **Bedrock API key expiry risk** — NoExpiry, NoExpiryActive, ExpiringSoon,
    StaleActive.
  - **Bedrock history** — `BedrockKeysAdded`, `BedrockKeysRemoved`,
    `BedrockKeysActivated`, `BedrockKeysDeactivated`.
  - **Bedrock coverage** — `BedrockAccountsWithErrors` next to
    `AccountsWithErrors`.

> The single-value strip shows the value of the **most recent datapoint within
> the selected time range**, not a peak or a running total. Use a _relative_
> range (e.g. 1h/3h/1d) that ends at "now" and refresh after a run, otherwise it
> can display an older run's numbers.

Grab the direct link from the stack outputs:

```bash
aws cloudformation describe-stacks --stack-name org-access-key-inventory \
  --profile "$PROFILE" --region "$REGION" \
  --query "Stacks[0].Outputs[?OutputKey=='DashboardUrl'].OutputValue" --output text
```

### History (change detection)

To know _what changed_, the Lambda keeps a small state file at
`s3://<bucket>/<prefix>/state/access-keys.json`. It maps **hashed** key
identifiers (`sha256(account_id:access_key_id)`, so no raw key ID is persisted)
to lightweight descriptors (account, user, masked key ID, status, create date),
and records which accounts have ever been listed successfully:

```json
{
  "schema_version": 2,
  "run_id": "20260908T063802Z",
  "updated_at": "2026-09-08T06:38:02.123456+00:00",
  "covered_accounts": ["111111111111", "222222222222"],
  "keys": { "<sha256>": { "account_id": "…", "user": "…", "access_key_id": "AKIA****…", "status": "Active", "create_date": "…" } }
}
```

On each run it:

1. Loads the previous state (absent on the first run → establishes a baseline).
2. Diffs it against the current inventory to find added / removed / activated /
   deactivated keys.
3. Overwrites the state file with the current snapshot.
4. If anything changed, writes a changelog to the run folder:
   `s3://<bucket>/<prefix>/runs/YYYY/MM/DD/<run-id>/changes-access-keys.json`:

```json
{
  "run_id": "20260908T063802Z",
  "run_time": "2026-09-08T06:38:02.123456+00:00",
  "report": "s3://<bucket>/credential-inventory/runs/2026/09/08/20260908T063802Z/access-keys.csv",
  "counts": { "added": 1, "removed": 0, "activated": 0, "deactivated": 1 },
  "changes": {
    "added": [
      {
        "account_id": "…",
        "user": "…",
        "access_key_id": "AKIA****…****MPLE",
        "status": "Active",
        "create_date": "…"
      }
    ],
    "removed": [],
    "activated": [],
    "deactivated": [
      {
        "account_id": "…",
        "user": "…",
        "access_key_id": "AKIA****…****MPLE",
        "status": "Inactive",
        "old_status": "Active"
      }
    ]
  },
  "baselined_accounts": []
}
```

`report` is `null` if that run's CSV could not be written.

The **first run** records only the baseline state — no changelog and no change
metrics, since there is nothing to compare against yet. A stored state that is
empty (zero keys last run) is a valid baseline, not a first run, so the first key
created afterwards is reported as added.

**Coverage and baselining.** `covered_accounts` grows by every account whose
keys were listed successfully (it never shrinks, so a later failure doesn't
reset it). When an account is listed **for the first time** (a newly invited
account, or one whose role was missing until now), its keys already existed,
so they're recorded as baseline instead of "added": they're left out of
`changes.added` and `KeysAdded`, and the account is listed in
`changes.baselined_accounts` as `{account_id, account_name, keys}` (also in the
manifest and the changelog). A changelog is written when a change count is
non-zero or a baselined account holds keys; a new account with zero keys alone
doesn't create one.

**Legacy state fallback.** If `<prefix>/state/access-keys.json` doesn't exist
yet, the Lambda reads the old layout's state once, read-only:
`<LegacyPrefix>/state/keys-state.json` (default `access-key-reports/...`). It
never writes, moves, or deletes anything there; the new state is written only
to `<prefix>/state/`, so from the next run on the old file is no longer read.
The manifest's `previous_state` shows which file was used. The old format has
no `covered_accounts`, so coverage is inferred from the accounts that own old
entries. Keys in an account with **no** old entries are baselined, not added,
and the Lambda logs one WARNING (`Legacy state has no coverage info: … recorded
as baseline, not as added …`). That avoids a false "added" spike for accounts
that failed during the old runs, at the cost of one possible miss: a key created
between the last old run and the first new one, in an account that had no keys
before. Check the `create_date` of the listed accounts' keys in the CSV.

**Bedrock API keys** have their own, independent history with the same logic:

- state: `s3://<bucket>/<prefix>/state/bedrock-api-keys.json` (same v2 format),
  keyed by `sha256(account_id:credential_id)` with descriptors `account_id,
  account_name, user, credential_id (masked), service_name, status,
  create_date, expiration_date`; legacy fallback:
  `<LegacyPrefix>/bedrock-api-keys/state/keys-state.json`;
- changelog: `runs/YYYY/MM/DD/<run-id>/changes-bedrock-api-keys.json`
  (same shape as above, with `credential_id` instead of `access_key_id`, plus
  `service_name` and `expiration_date`);
- the first run after you enable the feature is the Bedrock baseline
  (`bedrock.changes.first_run = true`), whatever the access-key history says;
- coverage is tracked per credential type: an account whose Bedrock API keys
  couldn't be listed doesn't become Bedrock-covered, so when it recovers its
  Bedrock API keys are baselined, not added;
- a status change to `Expired` is listed under `deactivated`, with `status` and
  `old_status`;
- accounts whose Bedrock API keys couldn't be listed keep their previous Bedrock
  entries, so they don't show up as removed.

---

## S3 layout

Everything lives under the stack's `Prefix` (default `credential-inventory`):

```
credential-inventory/
  runs/YYYY/MM/DD/<run-id>/              # one folder per run, e.g. runs/2026/09/08/20260908T063802Z/
    manifest.json                        # what the run wrote and found (written LAST)
    access-keys.csv
    bedrock-api-keys.csv                 # omitted when IncludeBedrockKeys=false
    changes-access-keys.json             # only when something changed
    changes-bedrock-api-keys.json        # only when something changed
  latest/                                # copy of the most recent run
    manifest.json                        # written last of all
    access-keys.csv
    bedrock-api-keys.csv
  state/                                 # change-detection baseline (see History)
    access-keys.json
    bedrock-api-keys.json
```

The run id is the run's start time in UTC (`YYYYMMDDTHHMMSSZ`). Every file of
the run uses it: the folder name, the first column of both CSVs, the manifests,
the state files, and `x-amz-meta-run-id` on the `latest/` objects. The stack
outputs `RunsPrefix`, `LatestPrefix` and `StatePrefix` give the three roots.

**Write order.** The run CSVs, then each state file and changelog, then the
run's `manifest.json`, then the `latest/` CSVs, and `latest/manifest.json` last.
So a manifest only exists once everything it describes has been attempted.

**Run manifest** (`manifest_version` 1), trimmed:

```json
{
  "manifest_version": 1,
  "run_id": "20260908T063802Z",
  "run_time": "2026-09-08T06:38:02.123456+00:00",
  "status": "OK",
  "bucket": "<bucket>",
  "prefix": "credential-inventory",
  "run_prefix": "s3://<bucket>/credential-inventory/runs/2026/09/08/20260908T063802Z/",
  "manifest": "s3://<bucket>/credential-inventory/runs/2026/09/08/20260908T063802Z/manifest.json",
  "files": {
    "access-keys.csv": "s3://<bucket>/credential-inventory/runs/2026/09/08/20260908T063802Z/access-keys.csv",
    "bedrock-api-keys.csv": "s3://<bucket>/credential-inventory/runs/2026/09/08/20260908T063802Z/bedrock-api-keys.csv",
    "changes-access-keys.json": "s3://<bucket>/credential-inventory/runs/2026/09/08/20260908T063802Z/changes-access-keys.json"
  },
  "state_files": {
    "state/access-keys.json": "s3://<bucket>/credential-inventory/state/access-keys.json",
    "state/bedrock-api-keys.json": "s3://<bucket>/credential-inventory/state/bedrock-api-keys.json"
  },
  "write_errors": [],
  "accounts_scanned": 5,
  "errors": [],
  "access_keys": { "keys_found": 4, "metrics": { "…": 0 }, "changes": { "…": 0 },
                   "previous_state": "s3://<bucket>/credential-inventory/state/access-keys.json" },
  "bedrock": { "enabled": true, "service_name": "bedrock.amazonaws.com", "keys_found": 3, "errors": [],
               "metrics": { "…": 0 }, "changes": { "…": 0 },
               "previous_state": "s3://<bucket>/credential-inventory/state/bedrock-api-keys.json",
               "listing_mode": "all_users", "expiry_supported": true, "botocore_version": "1.40.4" },
  "sdk": { "boto3": "…", "botocore": "…" }
}
```

- `files` lists the run-folder files this run attempted. A file that failed to
  write is `null` and has a matching `write_errors` entry (`{s3_uri, error}`);
  it is never shown as written. A changelog that wasn't needed is absent.
- `state_files` uses the same rule for `state/`.
- `previous_state` is the state file the diff was based on (`null` on a first
  run; an `access-key-reports/...` path on the first run after the upgrade).
- With `IncludeBedrockKeys=false`, `bedrock` is `{"enabled": false}` and there
  are no Bedrock entries in `files` or `state_files`.

**`latest/`.** Every object in `latest/` is a byte-identical copy of a run-folder
file. `latest/manifest.json` is the run manifest plus a `latest` block that says,
per CSV, whether this run replaced it:

```json
"latest": {
  "run_manifest": "s3://<bucket>/credential-inventory/runs/2026/09/08/20260908T063802Z/manifest.json",
  "files": {
    "access-keys.csv": { "status": "updated", "s3_uri": "s3://<bucket>/credential-inventory/latest/access-keys.csv",
                         "source": "s3://<bucket>/credential-inventory/runs/2026/09/08/20260908T063802Z/access-keys.csv" },
    "bedrock-api-keys.csv": { "status": "not_updated", "s3_uri": "…", "reason": "the run copy could not be written",
                              "note": "Not replaced by this run: …" }
  }
}
```

- `updated`: replaced with this run's copy (`source`).
- `not_updated`: this run's copy failed, so `latest/` was left alone rather than
  overwritten with something that has no run copy. Nothing is deleted or
  blanked (a header-only file would look like "zero keys").
- `failed`: the run copy exists (`source`), but the `latest/` write failed
  (`error`).
- `disabled`: `IncludeBedrockKeys=false`.

For every status other than `updated`, any object at that path is from an
earlier run; its `run_id` column and `x-amz-meta-run-id` metadata say which.
The top-level `status` and `write_errors` of `latest/manifest.json` describe the
run's own files, as in the run manifest. A failed `latest/` write or run
manifest write shows up in `latest.files`, in `latest.run_manifest` (`null` if
the run manifest failed) and in the invoke result's `write_errors[]`.

**Same-second runs.** Two invocations that start in the same second get the
same run id, so the second overwrites the first's run folder. The bucket is
versioned, so the earlier objects remain as noncurrent versions.

**Lifecycle.** The bucket expires **noncurrent** versions under
`<prefix>/latest/` and `<prefix>/state/` after 30 days (rules
`expire-noncurrent-latest` and `expire-noncurrent-state`), since those keys are
overwritten every run. Nothing under `runs/` ever expires, and current versions
never expire. CloudFormation owns the bucket's lifecycle configuration, so it
replaces any rules added by hand.

---

## Error logging & admin alerting

This is designed so an administrator can tell **at a glance whether a run needs
attention**, three independent ways:

1. **Return payload** — `status` is `OK` or `ATTENTION_REQUIRED`, with an
   `errors[]` array listing each `{account_id, account_name, error}`, plus
   `bedrock.errors[]` for accounts whose Bedrock API keys couldn't be listed,
   and `write_errors[]` (`{s3_uri, error}`) for S3 files that couldn't be
   written. The run manifest records the same file failures.

2. **CloudWatch Logs** (`/aws/lambda/<stack>-inventory`, 90-day retention):
   - Per account: `[OK] ...` (INFO) or `[ERR] ...` (ERROR). With Bedrock
     enabled the `[OK]` line includes `bedrock_keys=N`, or `bedrock_keys=ERR`
     next to a `[WARN] <id> <name> Bedrock API keys could not be listed: <code>`
     line (WARNING).
   - Each failed S3 write: `Failed to write s3://<bucket>/<key>: <error>` (ERROR).
   - Final line: `RUN SUMMARY: status=... accounts_scanned=... keys_found=...
     errors=... report=<uri|none>` (plus `bedrock_keys_found=... bedrock_errors=...
     bedrock_report=...`), then `run_id=... manifest=<uri|none> write_errors=<n>`.
   - On failure the summary is logged at **ERROR** with the marker
     **`ADMIN ACTION REQUIRED`** — easy to search or alarm on:
     ```bash
     aws logs filter-log-events --log-group-name "/aws/lambda/<stack>-inventory" \
       --filter-pattern '"ADMIN ACTION REQUIRED"' --profile "$PROFILE" --region "$REGION"
     ```

3. **SNS alerts** — created **only if you provided an `AlertEmail`** at deploy
   time (with no email, none of the SNS/alarm resources below exist). When
   enabled, the topic `AlertTopic` (output `AlertTopicArn`) fires to your
   `AlertEmail` in two cases:
   - **`AdminActionAlarm`** — the run completed but ≥1 account could not be
     inventoried, its Bedrock API keys could not be listed, or a report/state
     file could not be written to S3 (metric filter on the
     `ADMIN ACTION REQUIRED` log line). The Lambda also publishes a detailed
     message listing the failing accounts or files and the fix.
   - **`FunctionErrorAlarm`** — the Lambda invocation itself crashed or timed out
     (`AWS/Lambda Errors > 0`).

### Bedrock-only failures

If the Lambda reaches an account but can't list its Bedrock API keys, it
**keeps that account's access-key rows** and the run still completes. The
failure is never silent, though:

- the account goes in `bedrock.errors[]`, not in the top-level `errors[]`
  (which still means "the whole account failed"), and a `[WARN]` line is logged;
- `BedrockAccountsWithErrors` counts it;
- the account's previous Bedrock state is carried forward (no phantom "removed");
- `status` becomes `ATTENTION_REQUIRED`, so the `ADMIN ACTION REQUIRED` log
  line, the SNS message (with a separate Bedrock section) and `AdminActionAlarm`
  all fire.

The most common cause is an `AccessDenied` from a member role created before
this feature, so **redeploy the StackSet** (see the table below).

### S3 write failures

Every S3 write is checked. A file that can't be written (for example, a bucket
policy denies `s3:PutObject`) doesn't abort the run:

- the rest of the run still happens: the other files, the state, metrics, the
  manifest and the alert;
- the file is `null` in the manifest's `files` / `state_files` and is listed in
  `write_errors[]` (manifest and invoke result); its payload field
  (`s3_location`, `history_location`, `manifest_location`) is `null`;
- a failed run CSV is **not** copied to `latest/`, so `latest/` never holds a
  file with no matching run copy (see [S3 layout](#s3-layout));
- `status` becomes `ATTENTION_REQUIRED`, and the SNS message gets a section
  `N report/state file(s) could NOT be written to S3`, listing each URI.

A failed **state** write matters most: the next run then diffs against the last
state that was saved (on the first run after the upgrade, that is the legacy
state again), so its changes span two runs.

### What "needs admin to check" means and how to fix it

An account shows up as an error when the Lambda cannot assume any role in
`CANDIDATE_ROLES` there. Common causes and fixes (the last row is about S3, not
accounts):

| Cause                                                                                                          | Fix                                                                                                                                             |
| -------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| Account has none of the candidate roles (e.g. an **invited** account with no `OrganizationAccountAccessRole`). | Deploy `OrgAccessKeyAuditRole` there — via the StackSet (auto for org members) or hand the owner `member-audit-role.yaml` to deploy standalone. |
| An SCP denies `sts:AssumeRole` / IAM reads.                                                                    | Adjust the SCP to allow the audit role.                                                                                                         |
| Account is suspended / being closed.                                                                           | Usually safe to ignore.                                                                                                                         |
| `bedrock.errors[]` shows `AccessDenied` (on `ListServiceSpecificCredentials`).                                 | The member role predates Bedrock support. Re-run `./deploy-audit-role-stackset.sh`, wait for `SUCCEEDED`, then re-run the Lambda. If it persists, check SCPs for a deny on `iam:ListServiceSpecificCredentials`. |
| `bedrock.errors[]` shows `NotSupportedService`.                                                                | The partition/Region doesn't support Bedrock API keys. Deploy with `IncludeBedrockKeys=false`.                                                  |
| `write_errors[]` is not empty.                                                                                 | Check the function role's `s3:PutObject` permission and the bucket policy, then re-run. The run's other files and its manifest say exactly what is missing. |

---

## Redeploy to another organization

Nothing is org-specific in the code. In a new management account:

```bash
aws cloudformation activate-organizations-access --profile <new-mgmt-profile>
./deploy-audit-role-stackset.sh <new-mgmt-profile>
./deploy.sh <new-mgmt-profile>
```

The scripts discover that org's management account ID, org ID, and root
automatically.

---

## Teardown

Setup has **two parts**, so teardown does too. Each `deploy` script has a
matching `destroy` script that removes exactly what it created:

| Script                             | Removes                                                                                                                | Undeploys what `deploy` script created |
| ---------------------------------- | ---------------------------------------------------------------------------------------------------------------------- | -------------------------------------- |
| `./destroy.sh`                     | The **main stack** in the management account: Lambda, its IAM role, S3 report bucket (retained), SNS/alarms, schedule. | `deploy.sh`                            |
| `./destroy-audit-role-stackset.sh` | The **`OrgAccessKeyAuditRole`** in **every member account**, plus the StackSet itself.                                 | `deploy-audit-role-stackset.sh`        |

Run whichever you need. To remove **everything**, run both (order doesn't matter):

```bash
# 1) Main stack (Lambda + bucket + alerting). Report bucket is RETAINED.
./destroy.sh "$PROFILE" "$REGION"

# 2) The cross-account audit role in all member accounts (root ID auto-discovered).
./destroy-audit-role-stackset.sh "$PROFILE" "$REGION"
```

> `destroy.sh` prints a reminder about step 2, so you won't forget the role is
> still deployed in your member accounts.

For a **full clean slate**, also empty and delete the retained buckets (the
report bucket is versioned, so `--force` removes versions too):

```bash
ACCOUNT_ID=$(aws sts get-caller-identity --profile "$PROFILE" --query Account --output text)
REPORT=$(aws cloudformation describe-stacks --stack-name org-access-key-inventory \
  --profile "$PROFILE" --region "$REGION" \
  --query "Stacks[0].Outputs[?OutputKey=='BucketName'].OutputValue" --output text 2>/dev/null)

# (run BEFORE destroy.sh if you want the report bucket name from the stack outputs)
aws s3 rb "s3://$REPORT" --force --profile "$PROFILE"   # report bucket (retained)
aws s3 rb "s3://access-key-audit-artifacts-${ACCOUNT_ID}-${REGION}" --force --profile "$PROFILE"
```

---

## Security notes

- The Lambda role is **least-privilege**: `organizations:ListAccounts`,
  `sts:AssumeRole` only on the three specific audit-role ARNs, read-only IAM in
  the management account, `s3:PutObject`/`s3:GetObject` only on the report bucket
  (the latter to read the small history state file), `cloudwatch:PutMetricData`
  restricted to the `MetricNamespace` via an IAM condition, and `sns:Publish`
  only to the alert topic. It has no `s3:DeleteObject` or `s3:ListBucket`, so it
  can't remove or move old reports (including the legacy `access-key-reports/`
  objects it reads once during the upgrade).
- The history state, changelogs and manifests store **masked** key IDs, S3 URIs
  and a one-way `sha256` of `account_id:access_key_id` as the identifier — no
  raw key IDs and never any secret keys.
- The member-account role is **read-only** (`ListUsers`, `ListAccessKeys`,
  `GetAccessKeyLastUsed`, `ListServiceSpecificCredentials`) and trusts **only**
  the management account **and** only principals from your org
  (`aws:PrincipalOrgID` condition).
- For Bedrock API keys the Lambda reads **metadata only**. It never calls
  `CreateServiceSpecificCredential` or `ResetServiceSpecificCredential` (the
  calls that return a secret), never stores the credential alias, masks
  credential IDs, and stores only a `sha256(account_id:credential_id)` as the
  state identifier.
- The report contains key **IDs and metadata only — never secret keys**. The
  bucket is private (all public access blocked), encrypted (SSE-S3), and
  versioned. The lifecycle rules only expire **noncurrent** versions under
  `latest/` and `state/` (after 30 days); run folders and current versions are
  never expired.
- Consider restricting who can read the report bucket via a bucket policy/SCP.

---

## Running the unit tests

The tests in `tests/` are offline: every AWS client is a `botocore.stub.Stubber`
or a mock, dummy credentials are set, and any real HTTP request fails the test.
Run them from the repo root:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
```

With botocore ≥ 1.39.0 every test runs. With an older botocore the two
`AllUsers` pagination tests are skipped, and the per-user fallback is tested
against that older IAM model instead. `PYTHONDONTWRITEBYTECODE=1` keeps
`__pycache__` out of `tests/` (the test module already keeps it out of `lambda/`,
which `cloudformation package` zips as-is).

---

## Upgrading an existing deployment

Deployments from before Bedrock API key support need the new
`iam:ListServiceSpecificCredentials` permission in every member account, so
**redeploy the StackSet first, then the main stack**. Until the StackSet update
reaches an account, that account is reported in `bedrock.errors[]` (its access
keys are still inventoried).

```bash
PROFILE=<mgmt-profile>; REGION=us-east-1; STACK=org-access-key-inventory

# 0) Note your current main-stack settings: deploy.sh always overrides AlertEmail/EnableSchedule/ScheduleExpression
aws cloudformation describe-stacks --stack-name "$STACK" --profile "$PROFILE" --region "$REGION" \
  --query "Stacks[0].Parameters[?ParameterKey=='AlertEmail'||ParameterKey=='EnableSchedule'||ParameterKey=='ScheduleExpression']" --output table

# 1) FIRST update the member audit role (adds iam:ListServiceSpecificCredentials); the script waits for SUCCEEDED
./deploy-audit-role-stackset.sh "$PROFILE" "$REGION"
aws cloudformation list-stack-instances --stack-set-name org-access-key-audit-role --profile "$PROFILE" --region "$REGION" \
  --query "Summaries[?Status!='CURRENT'].[Account,Status,StatusReason]" --output table   # expect no rows

# 2) THEN redeploy the main stack, re-entering the SAME email/schedule from step 0 (a blank email removes SNS alerting).
#    If you had no alert email, an empty 4th arg still triggers the prompt -- just press Enter there.
./deploy.sh "$PROFILE" "$REGION" "$STACK" "<same-alert-email>" "<same-schedule-expression-or-none>"

# 3) Invoke and check: bedrock.enabled=true, bedrock.errors=[], listing_mode=all_users, expiry_supported=true,
#    bedrock.changes.first_run=true on this first Bedrock run (baseline)
aws lambda invoke --function-name "$STACK-inventory" --profile "$PROFILE" --region "$REGION" \
  --cli-binary-format raw-in-base64-out out.json && cat out.json
```

The new stack parameters `IncludeBedrockKeys` (default `true`) and
`BedrockExpiryWarnDays` (default `30`) take their defaults on the first deploy
and keep their previous values on later ones; `deploy.sh` doesn't override them.

**Roll back / opt out** without touching other settings (parameters you don't
override keep their previous values):

```bash
aws cloudformation deploy --template-file packaged.yaml --stack-name "$STACK" \
  --capabilities CAPABILITY_IAM --parameter-overrides IncludeBedrockKeys=false \
  --profile "$PROFILE" --region "$REGION"
```

The extra read-only permission in the member role is harmless to leave in place.
If `expiry_supported` comes back `false`, see
[Listing mode and SDK version](#listing-mode-and-sdk-version).

### Upgrading to the run-centric S3 layout

Older versions wrote everything under `access-key-reports/`: dated CSVs
(`YYYY/MM/DD/org-access-keys-<ts>.csv`), `state/keys-state.json`,
`history/...` changelogs, and the same again under `bedrock-api-keys/`. Linking
one run's files meant matching timestamps across folders. The new layout puts
each run in one folder with a manifest (see [S3 layout](#s3-layout)). No
StackSet change is needed for this part.

1. **Redeploy** with `./deploy.sh` (same email/schedule arguments as above). It
   now always passes `Prefix`, default `credential-inventory`:
   - keep the old root instead: `REPORT_PREFIX=access-key-reports ./deploy.sh ...`;
   - if the old stack used a **custom** `Prefix`, also set
     `LEGACY_REPORT_PREFIX=<old-prefix>` so the first run finds the old state.
     Otherwise the new `LegacyPrefix` parameter takes its default,
     `access-key-reports`.
2. **Invoke once and check** that `changes.first_run=false` and
   `bedrock.changes.first_run=false`, and that the run manifest's
   `access_keys.previous_state` / `bedrock.previous_state` point at
   `access-key-reports/...`. That first run read the old state once,
   read-only; from then on only `credential-inventory/state/` is used. Accounts
   with no entries in the old state appear once under `baselined_accounts`
   (with a WARNING if they hold keys; see
   [History](#history-change-detection)).
3. **Old reports stay where they are.** Nothing is deleted or moved. To keep
   everything under one root, copy them yourself (optional):
   ```bash
   aws s3 cp "s3://$BUCKET/access-key-reports/" "s3://$BUCKET/credential-inventory/legacy/access-key-reports/" \
     --recursive --profile "$PROFILE" --region "$REGION"
   ```
   This copies current versions only. The copies don't go into `runs/`, have
   no manifest, and keep their old file names and columns.

**Breaking changes** to check before you upgrade:

- `run_id` is the **first column** of both CSVs. Update any parser that reads
  columns by position.
- The stack output `BedrockReportPrefix` is replaced by `RunsPrefix`,
  `LatestPrefix` and `StatePrefix`.
- `s3_location`, `bedrock.s3_location`, `history_location` and
  `manifest_location` can be `null` when that write failed, and
  `ATTENTION_REQUIRED` (with `AdminActionAlarm`) now also covers S3 write
  failures (`write_errors[]`). Before, a failed access-key CSV write crashed the
  invocation instead.
- Keys in an account listed for the first time are baselined, not counted in
  `KeysAdded` / `BedrockKeysAdded`.
- `last_used` no longer uses `N/A`: it is `Never` when IAM has no record of use
  and `Unknown` when the lookup failed. `KeysNeverUsed` counts only `Never`;
  failed lookups go to the new `KeysLastUsedUnknown` metric.
- `never_expires` in the Bedrock CSV uses `Unknown` (was `unknown`) when the
  SDK can't report expiration dates.
- The new lifecycle rules expire noncurrent versions under `latest/` and
  `state/` after 30 days. CloudFormation now owns the bucket's lifecycle
  configuration and replaces any rules you added by hand.

**Roll back** by redeploying the previous code with
`Prefix=access-key-reports` (pass it explicitly; otherwise the stack keeps
`credential-inventory`). The old code reads its own old state, which dates from
before the upgrade, so its first run diffs against that older baseline and
reports every change since then. If you later roll forward again, the
new-layout state (from before the rollback) is used, not the newer legacy
state; the diffs are still correct relative to it.

---

## Why this exists

| Approach                            | Org-wide?        | Creation date? | Key ID? | Notes                                            |
| ----------------------------------- | ---------------- | -------------- | ------- | ------------------------------------------------ |
| **This solution**                   | ✅               | ✅             | ✅      | Complete inventory of _all_ keys.                |
| IAM Access Analyzer – unused access | ✅               | ❌             | ❌      | Only _unused_ keys; good for cleanup.            |
| AWS Config aggregator               | ✅               | n/a            | n/a     | No `AWS::IAM::AccessKey` resource type.          |
| IAM credential report               | ❌ (per-account) | proxy only     | ❌      | `last_rotated` ≈ creation only if never rotated. |
