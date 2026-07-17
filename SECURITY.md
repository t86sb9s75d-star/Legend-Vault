# Security and privacy

Legend Vault processes archives that may contain highly sensitive personal data.

## Rules

1. Keep source archives and generated records out of Git.
2. Process private archives locally.
3. Never claim origin authenticity from an internal hash ledger alone.
4. Treat `integrity/hashes.json` as requiring an external receipt.
5. Review staged files with `git status` and `git diff --cached` before pushing.
6. Do not place secrets, access tokens, private conversations, or account exports
   in issues, pull requests, CI logs, or release artifacts.

## Reporting

Use a private communication channel for security reports. Do not attach private
Legend Vault records to public issues.
