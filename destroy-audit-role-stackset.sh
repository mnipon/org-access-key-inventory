#!/usr/bin/env bash
# Remove the audit-role StackSet and its instances from every member account.
# The org root ID is DISCOVERED at runtime -- no placeholder to fill in.
#
# You are asked to type the StackSet name to confirm (no input aborts). FORCE=1
# skips the prompt. If deleting the instances ends FAILED or STOPPED, the
# StackSet is kept and the script exits non-zero.
#
# Usage: ./destroy-audit-role-stackset.sh <mgmt-profile> [region]
set -euo pipefail
cd "$(dirname "$0")"

PROFILE="${1:?usage: ./destroy-audit-role-stackset.sh <mgmt-profile> [region]}"
REGION="${2:-us-east-1}"
STACKSET="org-access-key-audit-role"

# Discover the org root id (same value the deploy script targets).
ROOT_ID=$(aws organizations list-roots --profile "$PROFILE" \
  --query "Roots[0].Id" --output text)

echo ">> Root: $ROOT_ID  StackSet: $STACKSET  Region: $REGION"

if ! aws cloudformation describe-stack-set --stack-set-name "$STACKSET" \
      --profile "$PROFILE" --region "$REGION" >/dev/null 2>&1; then
  echo ">> StackSet '$STACKSET' not found -- nothing to do."
  exit 0
fi

if [ "${FORCE:-}" != "1" ]; then
  read -r -p "This removes the audit role from every member account under $ROOT_ID. Type '$STACKSET' to confirm: " CONFIRM || CONFIRM=""
  [ "$CONFIRM" = "$STACKSET" ] || { echo "Aborted: nothing was deleted." >&2; exit 1; }
fi

echo ">> Deleting stack instances from all accounts under $ROOT_ID"
OP=$(aws cloudformation delete-stack-instances --stack-set-name "$STACKSET" \
  --deployment-targets OrganizationalUnitIds="$ROOT_ID" --regions "$REGION" \
  --no-retain-stacks --profile "$PROFILE" --region "$REGION" \
  --query OperationId --output text)
echo "   delete-instances operation: $OP"

echo ">> Waiting for instance deletion to complete"
while : ; do
  STATUS=$(aws cloudformation describe-stack-set-operation --stack-set-name "$STACKSET" \
    --operation-id "$OP" --profile "$PROFILE" --region "$REGION" \
    --query "StackSetOperation.Status" --output text)
  echo "   $STATUS"
  case "$STATUS" in
    SUCCEEDED) break ;;
    FAILED|STOPPED)
      # Instances may remain, so deleting the StackSet now would just fail.
      echo "!! Instance deletion ended with $STATUS; the StackSet was NOT deleted. Per-account details:" >&2
      echo "   aws cloudformation list-stack-set-operation-results --stack-set-name \"$STACKSET\" --operation-id \"$OP\" --profile \"$PROFILE\" --region \"$REGION\"" >&2
      exit 1 ;;
  esac
  sleep 10
done

echo ">> Deleting the StackSet"
aws cloudformation delete-stack-set --stack-set-name "$STACKSET" \
  --profile "$PROFILE" --region "$REGION"
echo ">> Done. OrgAccessKeyAuditRole removed from all member accounts."
