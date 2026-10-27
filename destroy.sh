#!/usr/bin/env bash
# Tear down PART 1 of 2: the main inventory stack (Lambda, IAM role, S3 bucket,
# optional SNS/alarms/schedule) -- i.e. everything created by deploy.sh.
#
# This does NOT remove the cross-account audit role deployed by
# deploy-audit-role-stackset.sh. To remove that too, run:
#     ./destroy-audit-role-stackset.sh <profile> [region]
#
# The report S3 bucket is RETAINED by design (DeletionPolicy: Retain) so reports
# are not lost. Empty/delete it manually if you truly want it gone.
#
# You are asked to type the stack name to confirm (no input aborts). FORCE=1
# skips the prompt, e.g. for automation.
#
# Usage: ./destroy.sh <aws-profile> [region] [stack-name]
set -euo pipefail
cd "$(dirname "$0")"

PROFILE="${1:?usage: ./destroy.sh <profile> [region] [stack-name]}"
REGION="${2:-us-east-1}"
STACK="${3:-org-access-key-inventory}"

if [ "${FORCE:-}" != "1" ]; then
  read -r -p "Delete stack '$STACK' (region $REGION, profile $PROFILE)? Type the stack name to confirm: " CONFIRM || CONFIRM=""
  [ "$CONFIRM" = "$STACK" ] || { echo "Aborted: nothing was deleted." >&2; exit 1; }
fi

echo ">> Deleting main stack '$STACK' (report bucket is retained)"
aws cloudformation delete-stack --stack-name "$STACK" --profile "$PROFILE" --region "$REGION"
aws cloudformation wait stack-delete-complete --stack-name "$STACK" --profile "$PROFILE" --region "$REGION"
echo ">> Done (main stack removed)."
echo
echo "NOTE: the cross-account audit role (OrgAccessKeyAuditRole) is still deployed"
echo "      in your member accounts. To remove it as well, run:"
echo "        ./destroy-audit-role-stackset.sh \"$PROFILE\" \"$REGION\""
