# Org-wide IAM Access Key Inventory

Inventory **every IAM user access key across all accounts in an AWS Organization**
and write a single consolidated CSV to S3. Runs as a Lambda in the management
account, with cross-account read access via a dedicated role deployed org-wide by
a CloudFormation StackSet.

Each row includes the access key's **true creation date** and **last-used** info —
data that org-level IAM Access Analyzer and AWS Config cannot give you (Config has
no `AWS::IAM::AccessKey` resource type, and Access Analyzer only reports *unused*
keys). See [Why this exists](#why-this-exists).

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
                        │       GetAccessKeyLastUsed                    │  │
                        │    4. write CSV → S3 (SSE, versioned)         │  │
                        │    5. log RUN SUMMARY; alert on errors        │  │
                        │                                               │  │
                        │  ReportBucket (S3)   AlertTopic (SNS)         │  │
                        │  CloudWatch alarms + metric filter            │  │
                        └─────────────────────────────────────────────┘  │
                                                                          │ assume
   ┌──────────────────────────────────────────────────────────────────┐ │ OrgAccessKeyAuditRole
   │   MEMBER ACCOUNTS  (role deployed by service-managed StackSet)     │◀┘
   │   OrgAccessKeyAuditRole  → iam:ListUsers/ListAccessKeys/           │
   │                            GetAccessKeyLastUsed (read-only)        │
   │   Trust: <mgmt account> + condition aws:PrincipalOrgID = <org>     │
   └────────────────────────────────────────────────────────────────────┘
```

The Lambda tries each name in `CANDIDATE_ROLES` (default
`OrgAccessKeyAuditRole,OrganizationAccountAccessRole,AWSControlTowerExecution`)
and uses the first it can assume. Any account it cannot reach is recorded as an
**error** (not silently skipped) and triggers admin alerting.

---

## Files

| File | Purpose |
|------|---------|
| `lambda/lambda_function.py` | Lambda handler: fan-out, CSV build, S3 write, logging, SNS alert. |
| `template.yaml` | Main stack: Lambda, IAM role, S3 bucket, SNS topic, alarms, optional schedule. |
| `deploy.sh` | Package + deploy the main stack. |
| `destroy.sh` | Delete the main stack (report bucket **retained** by design). |
| `member-audit-role.yaml` | Parameterized read-only role for member accounts (StackSet or standalone). |
| `deploy-audit-role-stackset.sh` | Deploy that role org-wide via a service-managed StackSet (IDs auto-discovered). |
| `destroy-audit-role-stackset.sh` | Remove that StackSet + roles from every member account (root ID auto-discovered). |

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
> management-account profile of a *different* org.

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

# or drive CloudFormation directly (after deploy.sh has packaged the code):
aws cloudformation deploy --template-file packaged.yaml \
  --stack-name org-access-key-inventory --capabilities CAPABILITY_IAM \
  --profile "$PROFILE" --region "$REGION" \
  --parameter-overrides \
      AlertEmail=you@example.com \
      EnableSchedule=true ScheduleExpression="rate(1 day)"
```

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
  "s3_location": "s3://<bucket>/access-key-reports/2026/09/08/org-access-keys-20260908T063802Z.csv"
}
```

`status` is `OK` when every account was inventoried, or `ATTENTION_REQUIRED` when
one or more accounts failed (see below).

### Download the latest report

```bash
BUCKET=$(aws cloudformation describe-stacks --stack-name org-access-key-inventory \
  --profile "$PROFILE" --region "$REGION" \
  --query "Stacks[0].Outputs[?OutputKey=='BucketName'].OutputValue" --output text)

KEY=$(aws s3api list-objects-v2 --bucket "$BUCKET" \
  --prefix "access-key-reports/$(date -u +%Y/%m/%d)/" \
  --profile "$PROFILE" --region "$REGION" \
  --query "sort_by(Contents,&LastModified)[-1].Key" --output text)

aws s3 cp "s3://$BUCKET/$KEY" ./report.csv --profile "$PROFILE" --region "$REGION"
cat report.csv
```

### CSV columns

| Column | Meaning |
|--------|---------|
| `account_id`, `account_name` | Owning account. |
| `user` | IAM user name. |
| `access_key_id` | The `AKIA...` key ID, **masked** to first/last 4 chars (e.g. `AKIA************MPLE`). No secret is ever exposed. Tune with `MaskHead`/`MaskTail` (both `0` = show full id). |
| `status` | `Active` / `Inactive`. |
| `create_date` | **True key creation timestamp** (from `ListAccessKeys`). |
| `age_days` | Age of the key in days (rotation signal). |
| `last_used` | Last-used timestamp, or `N/A` if never used. |

---

## Error logging & admin alerting

This is designed so an administrator can tell **at a glance whether a run needs
attention**, three independent ways:

1. **Return payload** — `status` is `OK` or `ATTENTION_REQUIRED`, with an
   `errors[]` array listing each `{account_id, account_name, error}`.

2. **CloudWatch Logs** (`/aws/lambda/<stack>-inventory`, 90-day retention):
   - Per account: `[OK] ...` (INFO) or `[ERR] ...` (ERROR).
   - Final line: `RUN SUMMARY: status=... accounts_scanned=... errors=...`.
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
     inventoried (metric filter on the `ADMIN ACTION REQUIRED` log line). The
     Lambda also publishes a detailed message listing the failing accounts and
     the fix.
   - **`FunctionErrorAlarm`** — the Lambda invocation itself crashed or timed out
     (`AWS/Lambda Errors > 0`).

### What "needs admin to check" means and how to fix it

An account shows up as an error when the Lambda cannot assume any role in
`CANDIDATE_ROLES` there. Common causes and fixes:

| Cause | Fix |
|-------|-----|
| Account has none of the candidate roles (e.g. an **invited** account with no `OrganizationAccountAccessRole`). | Deploy `OrgAccessKeyAuditRole` there — via the StackSet (auto for org members) or hand the owner `member-audit-role.yaml` to deploy standalone. |
| An SCP denies `sts:AssumeRole` / IAM reads. | Adjust the SCP to allow the audit role. |
| Account is suspended / being closed. | Usually safe to ignore. |

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

| Script | Removes | Undeploys what `deploy` script created |
|--------|---------|----------------------------------------|
| `./destroy.sh` | The **main stack** in the management account: Lambda, its IAM role, S3 report bucket (retained), SNS/alarms, schedule. | `deploy.sh` |
| `./destroy-audit-role-stackset.sh` | The **`OrgAccessKeyAuditRole`** in **every member account**, plus the StackSet itself. | `deploy-audit-role-stackset.sh` |

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
  the management account, `s3:PutObject` only to the report bucket, and
  `sns:Publish` only to the alert topic.
- The member-account role is **read-only** (`ListUsers`, `ListAccessKeys`,
  `GetAccessKeyLastUsed`) and trusts **only** the management account **and** only
  principals from your org (`aws:PrincipalOrgID` condition).
- The report contains key **IDs and metadata only — never secret keys**. The
  bucket is private (all public access blocked), encrypted (SSE-S3), and
  versioned.
- Consider restricting who can read the report bucket via a bucket policy/SCP.

---

## Why this exists

| Approach | Org-wide? | Creation date? | Key ID? | Notes |
|----------|-----------|----------------|---------|-------|
| **This solution** | ✅ | ✅ | ✅ | Complete inventory of *all* keys. |
| IAM Access Analyzer – unused access | ✅ | ❌ | ❌ | Only *unused* keys; good for cleanup. |
| AWS Config aggregator | ✅ | n/a | n/a | No `AWS::IAM::AccessKey` resource type. |
| IAM credential report | ❌ (per-account) | proxy only | ❌ | `last_rotated` ≈ creation only if never rotated. |
