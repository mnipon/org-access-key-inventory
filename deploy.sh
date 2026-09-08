#!/usr/bin/env bash
# Deploy the org-wide access-key inventory Lambda stack.
# Usage: ./deploy.sh <aws-profile> [region] [stack-name] [alert-email] [schedule-expression]
#
# If <alert-email> is not passed, you'll be prompted for it interactively.
# Leave it blank to deploy WITHOUT any SNS alerting (no topic/subscription/alarms).
#
# If <schedule-expression> is not passed, you'll be prompted to (optionally)
# enable a recurring run and choose how often. Pass "none" to skip the prompt
# and deploy with no schedule.
set -euo pipefail

PROFILE="${1:?usage: ./deploy.sh <profile> [region] [stack-name] [alert-email] [schedule-expression]}"
REGION="${2:-us-east-1}"
STACK="${3:-org-access-key-inventory}"
ALERT_EMAIL="${4:-}"
SCHEDULE_EXPR="${5:-__PROMPT__}"

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
  echo ">> Alerting: DISABLED (no SNS topic/subscription/alarms will be created)"
fi
if [ "$ENABLE_SCHEDULE" = "true" ]; then
  echo ">> Schedule: ENABLED -> $SCHEDULE_EXPR"
else
  echo ">> Schedule: DISABLED (run the Lambda manually / on demand)"
fi

# Ensure an artifact bucket exists to hold the packaged Lambda code.
if ! aws s3api head-bucket --bucket "$ARTIFACT_BUCKET" --profile "$PROFILE" 2>/dev/null; then
  echo ">> Creating artifact bucket $ARTIFACT_BUCKET"
  if [ "$REGION" = "us-east-1" ]; then
    aws s3api create-bucket --bucket "$ARTIFACT_BUCKET" --profile "$PROFILE" --region "$REGION"
  else
    aws s3api create-bucket --bucket "$ARTIFACT_BUCKET" --profile "$PROFILE" --region "$REGION" \
      --create-bucket-configuration LocationConstraint="$REGION"
  fi
  aws s3api put-public-access-block --bucket "$ARTIFACT_BUCKET" --profile "$PROFILE" \
    --public-access-block-configuration BlockPublicAcls=true,BlockPublicPolicy=true,IgnorePublicAcls=true,RestrictPublicBuckets=true
fi

echo ">> Packaging Lambda code"
aws cloudformation package \
  --template-file template.yaml \
  --s3-bucket "$ARTIFACT_BUCKET" \
  --output-template-file packaged.yaml \
  --profile "$PROFILE" --region "$REGION"

echo ">> Deploying stack"
aws cloudformation deploy \
  --template-file packaged.yaml \
  --stack-name "$STACK" \
  --capabilities CAPABILITY_IAM \
  --profile "$PROFILE" --region "$REGION" \
  --parameter-overrides EnableSchedule="$ENABLE_SCHEDULE" ScheduleExpression="${SCHEDULE_EXPR:-rate(1 day)}" AlertEmail="$ALERT_EMAIL"

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
