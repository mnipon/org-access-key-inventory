# Security policy

## Reporting a vulnerability

Please report security issues privately with GitHub's private vulnerability
reporting: open this repository's **Security** tab and choose
**Report a vulnerability**. Please don't open a public issue, pull request, or
discussion for a suspected vulnerability.

Include what you found, the affected file or commit, and steps to reproduce.
Redact real account IDs, names, key IDs, and report contents.

Only the latest commit on `main` is supported. Fixes are best effort.

## Scope

The tool reads IAM metadata only (plus your organization's account list): IAM
users, access key IDs with their status, creation and last-used dates, and
long-term Amazon Bedrock API key metadata. It never reads or returns secret
access keys or Bedrock API key secrets.

In scope: the Lambda code, the CloudFormation templates, and the deploy/destroy
scripts in this repository. Report vulnerabilities in AWS services themselves to
AWS: https://aws.amazon.com/security/vulnerability-reporting/
