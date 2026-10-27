#!/usr/bin/env bash
# Deploy the org-wide access-key inventory Lambda stack.
# Usage: ./deploy.sh <aws-profile> [region] [stack-name] [alert-email] [schedule-expression]
#
# If <alert-email> is not passed, you'll be prompted for it interactively.
# Leave it blank to deploy WITHOUT SNS alerting (no topic/subscription; the
# FunctionErrorAlarm is still created, without notifications).
#
# If <schedule-expression> is not passed, you'll be prompted to (optionally)
# enable a recurring run and choose how often. Pass "none" to skip the prompt
# and deploy with no schedule.
#
# Optional environment variables:
#   REPORT_PREFIX         S3 root for reports (default: credential-inventory).
#                         Always passed as the stack's Prefix, because
#                         `cloudformation deploy` otherwise keeps an existing
#                         stack's previous Prefix. Set REPORT_PREFIX=access-key-reports
#                         to keep writing under the old root.
#   LEGACY_REPORT_PREFIX  Prefix of the previous S3 layout, read once (never
#                         written) to seed change detection. Only needed if the
#                         old stack used a custom Prefix; otherwise the stack's
#                         LegacyPrefix (default access-key-reports) is kept.
#   CANDIDATE_ROLES       Member-account role names to try (default
#                         OrgAccessKeyAuditRole).
#   ALLOW_ADMIN_ROLE_FALLBACK  "true" also tries the admin roles
#                         OrganizationAccountAccessRole / AWSControlTowerExecution
#                         (sessions stay read-only). Default false.
#                         Both are always passed, because `cloudformation deploy`
#                         otherwise keeps an existing stack's previous values.
#
# The stack name must be at most 49 characters: the Lambda role is named
# <stack>-inventory-role and IAM role names max out at 64.
#
# Updating an existing deployment: run this script first, then
# ./deploy-audit-role-stackset.sh (the member roles then trust only
# <stack>-inventory-role).
set -euo pipefail
# template.yaml, packaged.yaml and lambda/ are resolved relative to this repo.
cd "$(dirname "$0")"

PROFILE="${1:?usage: ./deploy.sh <profile> [region] [stack-name] [alert-email] [schedule-expression]}"
REGION="${2:-us-east-1}"
STACK="${3:-org-access-key-inventory}"
ALERT_EMAIL="${4:-}"
SCHEDULE_EXPR="${5:-__PROMPT__}"
REPORT_PREFIX="${REPORT_PREFIX:-credential-inventory}"
CANDIDATE_ROLES="${CANDIDATE_ROLES:-OrgAccessKeyAuditRole}"
ALLOW_ADMIN_ROLE_FALLBACK="${ALLOW_ADMIN_ROLE_FALLBACK:-false}"

# The Lambda role is named <stack>-inventory-role; IAM role names max out at 64.
if [ "${#STACK}" -gt 49 ]; then
  echo "!! Stack name '$STACK' is longer than 49 characters ($STACK-inventory-role must fit IAM's 64-character limit)." >&2
  exit 1
fi

# Prompt for an alert email if not supplied as an argument.
if [ -z "$ALERT_EMAIL" ]; then
  echo
  echo "Error alerts (accounts that can't be inventoried, or a failed run) can be"
  echo "emailed to you via SNS. Leave blank to deploy WITHOUT any SNS alerting."
  read -r -p "Alert email address (optional): " ALERT_EMAIL
fi

# Prompt for a schedule if not supplied as an argument.
if [ "$SCHEDULE_EXPR" = "__PROMPT__" ]; then
  echo
  read -r -p "Run the inventory automatically on a schedule? [y/N]: " WANT_SCHED
  case "$WANT_SCHED" in
    [Yy]*)
      echo "How often should it run?"
      echo "  1) Daily              rate(1 day)"
      echo "  2) Weekly             rate(7 days)"
      echo "  3) Every 12 hours     rate(12 hours)"
      echo "  4) Monthly            (00:00 UTC on the 1st of each month)"
      echo "  5) Specific day of month (you pick the day; runs 00:00 UTC)"
      read -r -p "Choose [1-5]: " CHOICE
      case "$CHOICE" in
        1) SCHEDULE_EXPR="rate(1 day)" ;;
        2) SCHEDULE_EXPR="rate(7 days)" ;;
        3) SCHEDULE_EXPR="rate(12 hours)" ;;
        4) SCHEDULE_EXPR="cron(0 0 1 * ? *)" ;;
        5) read -r -p "Day of month to run [1-28]: " DOM
           if [[ "$DOM" =~ ^([1-9]|1[0-9]|2[0-8])$ ]]; then
             SCHEDULE_EXPR="cron(0 0 $DOM * ? *)"
           else
             echo "Invalid day (must be 1-28) -- deploying with NO schedule."
             SCHEDULE_EXPR=""
           fi ;;
        *) echo "Unrecognized choice -- deploying with NO schedule."; SCHEDULE_EXPR="" ;;
      esac
      ;;
    *) SCHEDULE_EXPR="" ;;
  esac
elif [ "$SCHEDULE_EXPR" = "none" ]; then
  SCHEDULE_EXPR=""
fi

# Derive the boolean the template expects.
if [ -n "$SCHEDULE_EXPR" ]; then ENABLE_SCHEDULE="true"; else ENABLE_SCHEDULE="false"; fi

ACCOUNT_ID="$(aws sts get-caller-identity --profile "$PROFILE" --query Account --output text)"
ARTIFACT_BUCKET="access-key-audit-artifacts-${ACCOUNT_ID}-${REGION}"

echo ">> Account: $ACCOUNT_ID  Region: $REGION  Stack: $STACK"
if [ -n "$ALERT_EMAIL" ]; then
  echo ">> Alerting: ENABLED -> $ALERT_EMAIL"
else
  echo ">> Alerting: DISABLED (no SNS topic/subscription; FunctionErrorAlarm is created without notifications)"
fi
if [ "$ENABLE_SCHEDULE" = "true" ]; then
  echo ">> Schedule: ENABLED -> $SCHEDULE_EXPR"
else
  echo ">> Schedule: DISABLED (run the Lambda manually / on demand)"
fi
echo ">> Reports:  <bucket>/$REPORT_PREFIX/{runs,latest,state}/ (override with REPORT_PREFIX=...)"
echo ">> Member roles: $CANDIDATE_ROLES (admin-role fallback: $ALLOW_ADMIN_ROLE_FALLBACK)"

# Ensure an artifact bucket exists to hold the packaged Lambda code. The name is
# predictable, so it is only used once --expected-bucket-owner confirms this
# account owns it: otherwise someone who pre-claimed the name could receive (and
# swap) the Lambda code.
OWNER=(--expected-bucket-owner "$ACCOUNT_ID")
if ! aws s3api head-bucket --bucket "$ARTIFACT_BUCKET" "${OWNER[@]}" --profile "$PROFILE" --region "$REGION" 2>/dev/null; then
  echo ">> Creating artifact bucket $ARTIFACT_BUCKET"
  # create-bucket fails (BucketAlreadyExists) if another account owns the name,
  # and set -e stops the deploy.
  if [ "$REGION" = "us-east-1" ]; then
    aws s3api create-bucket --bucket "$ARTIFACT_BUCKET" --profile "$PROFILE" --region "$REGION"
  else
    aws s3api create-bucket --bucket "$ARTIFACT_BUCKET" --profile "$PROFILE" --region "$REGION" \
      --create-bucket-configuration LocationConstraint="$REGION"
  fi
fi

# Harden the artifact bucket on every deploy (idempotent; also upgrades buckets
# created by older versions of this script). deploy.sh owns this bucket's policy.
aws s3api put-public-access-block --bucket "$ARTIFACT_BUCKET" "${OWNER[@]}" --profile "$PROFILE" --region "$REGION" \
  --public-access-block-configuration BlockPublicAcls=true,BlockPublicPolicy=true,IgnorePublicAcls=true,RestrictPublicBuckets=true
aws s3api put-bucket-ownership-controls --bucket "$ARTIFACT_BUCKET" "${OWNER[@]}" --profile "$PROFILE" --region "$REGION" \
  --ownership-controls 'Rules=[{ObjectOwnership=BucketOwnerEnforced}]'
aws s3api put-bucket-versioning --bucket "$ARTIFACT_BUCKET" "${OWNER[@]}" --profile "$PROFILE" --region "$REGION" \
  --versioning-configuration Status=Enabled
aws s3api put-bucket-policy --bucket "$ARTIFACT_BUCKET" "${OWNER[@]}" --profile "$PROFILE" --region "$REGION" \
  --policy "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"DenyInsecureTransport\",\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":\"s3:*\",\"Resource\":[\"arn:aws:s3:::$ARTIFACT_BUCKET\",\"arn:aws:s3:::$ARTIFACT_BUCKET/*\"],\"Condition\":{\"Bool\":{\"aws:SecureTransport\":\"false\"}}}]}"

echo ">> Note: member accounts need the current audit role from"
echo "   ./deploy-audit-role-stackset.sh, which trusts only $STACK-inventory-role."
echo "   New deployment: run it before invoking the Lambda. Updating an existing"
echo "   deployment: run it AFTER this script finishes:"
echo "     ./deploy-audit-role-stackset.sh \"$PROFILE\" \"$REGION\" OrgAccessKeyAuditRole \"$STACK\""

# Re-check ownership right before uploading code (fail closed).
if ! aws s3api head-bucket --bucket "$ARTIFACT_BUCKET" "${OWNER[@]}" --profile "$PROFILE" --region "$REGION"; then
  echo "!! Artifact bucket $ARTIFACT_BUCKET is not owned by account $ACCOUNT_ID; not uploading the Lambda code." >&2
  exit 1
fi
# cloudformation package zips ./lambda as-is: never ship stale bytecode.
find lambda -type d -name __pycache__ -prune -exec rm -rf {} +

echo ">> Packaging Lambda code"
aws cloudformation package \
  --template-file template.yaml \
  --s3-bucket "$ARTIFACT_BUCKET" \
  --output-template-file packaged.yaml \
  --profile "$PROFILE" --region "$REGION"

echo ">> Deploying stack"
OVERRIDES=(EnableSchedule="$ENABLE_SCHEDULE" ScheduleExpression="${SCHEDULE_EXPR:-rate(1 day)}"
           AlertEmail="$ALERT_EMAIL" Prefix="$REPORT_PREFIX"
           CandidateRoles="$CANDIDATE_ROLES" AllowAdminRoleFallback="$ALLOW_ADMIN_ROLE_FALLBACK")
if [ -n "${LEGACY_REPORT_PREFIX:-}" ]; then
  OVERRIDES+=(LegacyPrefix="$LEGACY_REPORT_PREFIX")
fi
aws cloudformation deploy \
  --template-file packaged.yaml \
  --stack-name "$STACK" \
  --capabilities CAPABILITY_NAMED_IAM \
  --profile "$PROFILE" --region "$REGION" \
  --parameter-overrides "${OVERRIDES[@]}"

echo ">> Outputs:"
aws cloudformation describe-stacks --stack-name "$STACK" --profile "$PROFILE" --region "$REGION" \
  --query "Stacks[0].Outputs" --output table

# Remind the user to confirm the SNS subscription.
if [ -n "$ALERT_EMAIL" ]; then
  echo
  echo "============================================================================"
  echo " ACTION REQUIRED: confirm your email subscription"
  echo "   AWS has sent a confirmation email to: $ALERT_EMAIL"
  echo "   You MUST click the 'Confirm subscription' link in that email, or alerts"
  echo "   will NOT be delivered. (Check spam if you don't see it within a minute.)"
  echo "============================================================================"
fi
