# Org-wide IAM Access Key Inventory

List **every IAM user access key in every account of your AWS Organization** —
with each key's **creation date**, age, and last-used — into one CSV in S3.

A Lambda runs in the management account, assumes a read-only role in each member
account, and writes the report. Optionally emails you on errors and runs on a
schedule.

> Need more detail (architecture, security notes, troubleshooting)? See
> [`README.detailed.md`](./README.detailed.md).

---

## What you get

- One consolidated CSV: `account_id, account_name, user, access_key_id, status, create_date, age_days, last_used`.
- Key IDs are **masked** (e.g. `AKIA************MPLE`); secret keys are never touched.
- Report stored in a private, encrypted, versioned S3 bucket.

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

`deploy.sh` asks two optional questions:
- **Alert email** — blank = no alerting; an address = SNS alerts on errors (you must click the confirmation email AWS sends).
- **Schedule** — `N` = run on demand; or pick Daily / Weekly / Every 12h / Monthly / a specific day of month.

---

## Run & download

```bash
FN=$(aws cloudformation describe-stacks --stack-name org-access-key-inventory \
  --profile "$PROFILE" --region "$REGION" \
  --query "Stacks[0].Outputs[?OutputKey=='FunctionName'].OutputValue" --output text)

# run it
aws lambda invoke --function-name "$FN" --profile "$PROFILE" --region "$REGION" \
  --cli-binary-format raw-in-base64-out out.json && cat out.json

# download the latest report
BUCKET=$(aws cloudformation describe-stacks --stack-name org-access-key-inventory \
  --profile "$PROFILE" --region "$REGION" \
  --query "Stacks[0].Outputs[?OutputKey=='BucketName'].OutputValue" --output text)
KEY=$(aws s3api list-objects-v2 --bucket "$BUCKET" \
  --prefix "access-key-reports/$(date -u +%Y/%m/%d)/" --profile "$PROFILE" --region "$REGION" \
  --query "sort_by(Contents,&LastModified)[-1].Key" --output text)
aws s3 cp "s3://$BUCKET/$KEY" ./report.csv --profile "$PROFILE" --region "$REGION" && cat report.csv
```

The invoke result shows `status` (`OK` or `ATTENTION_REQUIRED`), counts, and the S3 path.

---

## Did anything fail?

If an account can't be inventoried (missing role, SCP, suspended), it's reported
three ways: the `errors[]` in the result, an `ADMIN ACTION REQUIRED` line in the
Lambda's CloudWatch logs, and (if you set an email) an SNS alert. Fix: make sure
`OrgAccessKeyAuditRole` exists there (re-run step 1, or have the owner deploy
`member-audit-role.yaml`).

---

## Teardown

Two parts to set up, two to tear down:

```bash
./destroy.sh "$PROFILE" "$REGION"                     # Lambda stack (bucket kept)
./destroy-audit-role-stackset.sh "$PROFILE" "$REGION" # audit role in all accounts
```

---

## Files

| File | Purpose |
|------|---------|
| `template.yaml` | Main stack: Lambda, role, S3, optional SNS/alarms/schedule. |
| `lambda/lambda_function.py` | The inventory handler. |
| `deploy.sh` / `destroy.sh` | Deploy / remove the main stack. |
| `member-audit-role.yaml` | Read-only role for member accounts. |
| `deploy-audit-role-stackset.sh` / `destroy-audit-role-stackset.sh` | Deploy / remove that role org-wide. |
| `README.detailed.md` | Full documentation. |
