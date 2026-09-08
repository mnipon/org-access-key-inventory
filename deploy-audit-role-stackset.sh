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

echo ">> Creating/updating StackSet"
if aws cloudformation describe-stack-set --stack-set-name "$STACKSET" --profile "$PROFILE" --region "$REGION" >/dev/null 2>&1; then
  aws cloudformation update-stack-set --stack-set-name "$STACKSET" \
    --template-body file://member-audit-role.yaml \
    --permission-model SERVICE_MANAGED \
    --auto-deployment Enabled=true,RetainStacksOnAccountRemoval=false \
    --capabilities CAPABILITY_NAMED_IAM \
    --parameters ParameterKey=RoleName,ParameterValue="$ROLE_NAME" \
                 ParameterKey=TrustedAccountId,ParameterValue="$MGMT_ID" \
                 ParameterKey=OrgId,ParameterValue="$ORG_ID" \
    --profile "$PROFILE" --region "$REGION"
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
aws cloudformation create-stack-instances --stack-set-name "$STACKSET" \
  --deployment-targets OrganizationalUnitIds="$ROOT_ID" \
  --regions "$REGION" \
  --profile "$PROFILE" --region "$REGION" || \
  echo "(stack instances may already exist -- run update-stack-instances if needed)"

echo ">> Done. Verify with: aws cloudformation list-stack-instances --stack-set-name $STACKSET --profile $PROFILE --region $REGION"
