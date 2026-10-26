#!/usr/bin/env bash
# Deploy the read-only audit role to every member account via a service-managed
# StackSet (auto-deploys to accounts added later). All IDs are DISCOVERED at
# runtime -- none are hardcoded.
#
# Prereqs: trusted access between AWS Organizations and CloudFormation StackSets
#   aws cloudformation activate-organizations-access --profile <mgmt>
#
# Usage: ./deploy-audit-role-stackset.sh <mgmt-profile> [region] [role-name]
set -euo pipefail

PROFILE="${1:?usage: ./deploy-audit-role-stackset.sh <mgmt-profile> [region] [role-name]}"
REGION="${2:-us-east-1}"
ROLE_NAME="${3:-OrgAccessKeyAuditRole}"
STACKSET="org-access-key-audit-role"

# Discover management account id, org id, and org root id -- nothing hardcoded.
MGMT_ID=$(aws organizations describe-organization --profile "$PROFILE" \
  --query "Organization.MasterAccountId" --output text)
ORG_ID=$(aws organizations describe-organization --profile "$PROFILE" \
  --query "Organization.Id" --output text)
ROOT_ID=$(aws organizations list-roots --profile "$PROFILE" \
  --query "Roots[0].Id" --output text)

echo ">> Mgmt account: $MGMT_ID  Org: $ORG_ID  Root: $ROOT_ID  Role: $ROLE_NAME"

# Block until a StackSet operation finishes, so the inventory Lambda never runs
# against member roles that haven't been updated yet. Returns non-zero on
# FAILED/STOPPED (which stops this script under `set -e`).
wait_for_op() {
  local op_id="$1" status
  while true; do
    status=$(aws cloudformation describe-stack-set-operation --stack-set-name "$STACKSET" \
      --operation-id "$op_id" --query StackSetOperation.Status --output text \
      --profile "$PROFILE" --region "$REGION")
    echo "   operation $op_id: $status"
    case "$status" in
      SUCCEEDED) return 0 ;;
      FAILED|STOPPED)
        echo "!! StackSet operation $op_id ended with $status. Per-account details:" >&2
        echo "   aws cloudformation list-stack-set-operation-results --stack-set-name \"$STACKSET\" --operation-id \"$op_id\" --profile \"$PROFILE\" --region \"$REGION\"" >&2
        return 1 ;;
    esac
    sleep 15
  done
}

echo ">> Creating/updating StackSet"
if aws cloudformation describe-stack-set --stack-set-name "$STACKSET" --profile "$PROFILE" --region "$REGION" >/dev/null 2>&1; then
  OP_ID=$(aws cloudformation update-stack-set --stack-set-name "$STACKSET" \
    --template-body file://member-audit-role.yaml \
    --permission-model SERVICE_MANAGED \
    --auto-deployment Enabled=true,RetainStacksOnAccountRemoval=false \
    --capabilities CAPABILITY_NAMED_IAM \
    --parameters ParameterKey=RoleName,ParameterValue="$ROLE_NAME" \
                 ParameterKey=TrustedAccountId,ParameterValue="$MGMT_ID" \
                 ParameterKey=OrgId,ParameterValue="$ORG_ID" \
    --query OperationId --output text \
    --profile "$PROFILE" --region "$REGION")
  echo ">> Waiting for the StackSet update to reach every existing member account"
  wait_for_op "$OP_ID"
else
  aws cloudformation create-stack-set --stack-set-name "$STACKSET" \
    --template-body file://member-audit-role.yaml \
    --permission-model SERVICE_MANAGED \
    --auto-deployment Enabled=true,RetainStacksOnAccountRemoval=false \
    --capabilities CAPABILITY_NAMED_IAM \
    --parameters ParameterKey=RoleName,ParameterValue="$ROLE_NAME" \
                 ParameterKey=TrustedAccountId,ParameterValue="$MGMT_ID" \
                 ParameterKey=OrgId,ParameterValue="$ORG_ID" \
    --profile "$PROFILE" --region "$REGION"
fi

echo ">> Creating stack instances across the org root (auto-covers new accounts)"
# IAM is global -> deploy to a single region only. Service-managed StackSets
# skip the management account automatically (Lambda reads it directly).
if OP_ID=$(aws cloudformation create-stack-instances --stack-set-name "$STACKSET" \
  --deployment-targets OrganizationalUnitIds="$ROOT_ID" \
  --regions "$REGION" \
  --query OperationId --output text \
  --profile "$PROFILE" --region "$REGION"); then
  wait_for_op "$OP_ID"
else
  echo "(stack instances may already exist -- run update-stack-instances if needed)"
fi

echo ">> Done. Verify every instance is CURRENT with:"
echo "   aws cloudformation list-stack-instances --stack-set-name \"$STACKSET\" --profile \"$PROFILE\" --region \"$REGION\""
