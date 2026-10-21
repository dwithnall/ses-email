# CLAUDE.md

## What this is

A single-purpose Python CLI that provisions a domain for Amazon SES transactional email, mainly so WordPress sites can send through SES via [FluentSMTP](https://fluentsmtp.com/). For one domain it:

1. Verifies the domain identity and DKIM in SES, sets a custom MAIL FROM subdomain, and toggles feedback forwarding.
2. Creates a least-privilege IAM user and policy that can only send as that domain.
3. Generates an access key for that user and prints it as AWS keys, SMTP credentials and FluentMail `define()` lines.
4. Creates the required DNS records in Cloudflare (SES TXT, 3 DKIM CNAMEs, MAIL FROM MX + SPF, DMARC). With `--no-cloudflare` it prints them for manual setup instead.

It can also tear things down with `--remove-cloudflare-records` and/or `--remove-aws-resources`. Teardown does **not** delete the SES identity.

`README.md` is the user-facing doc and covers the IAM policy the runner needs, the Cloudflare token scopes and all flags in detail.

## Running

```bash
pip install -r requirements.txt          # boto3, cloudflare (v4 SDK)
cp config.ini.bak config.ini             # fill in [AWS] and [Cloudflare]
python provision_ses_domain.py example.com [--config path] [--mail-from-subdomain mail] \
    [--no-cloudflare] [--enable-feedback] [--remove-cloudflare-records] [--remove-aws-resources]
```

A devcontainer (`.devcontainer/devcontainer.json`, Python 3.12) installs the requirements automatically on create and bind-mounts the Windows `~/.claude` (plus a copy of `~/.claude.json`) so Claude Code reuses the host login. The mount sources are hardcoded `/mnt/c/Users/dave/...` paths because VS Code runs Docker through WSL (`dev.containers.executeInWSL`), where `${localEnv:HOME}` is the WSL home, not the Windows one. If login is still requested, run `claude` → `/login` in the container terminal and paste the code manually. `config.ini` lives in the workspace, so it is available inside the container.

There are no tests, no linter config and no build step. Every run makes **real changes** to AWS and Cloudflare, so don't run the script to "try something" unless the user asks you to and gives you a domain to use.

## Layout

All modules are flat at the repo root and import each other directly (not a package).

| File | Role |
|---|---|
| `provision_ses_domain.py` | Entry point: argparse, orchestrates the cleanup path or the provisioning path |
| `config.py` | Loads `config.ini` (`[AWS]` access_key_id / secret_access_key / region, `[Cloudflare]` api_token) |
| `aws_clients.py` | Builds boto3 SES/IAM/STS clients from explicit config credentials and looks up the account ID |
| `ses_ops.py` | SES identity, DKIM, MAIL FROM, feedback forwarding |
| `iam_ops.py` | Create/remove the IAM user and policy, create the access key |
| `cloudflare_ops.py` | Zone lookup, create records (idempotent), find and delete SES records |
| `output.py` | Final credentials banner, next steps, manual DNS instructions |
| `utils.py` | `log_print` (tees to stdout and a module-global log file), log file lifecycle |

## Conventions

- **Use `log_print` instead of `print`** so output also lands in `ses-provision-<domain>-<timestamp>.log` (gitignored). Pass `file=sys.stderr` for errors.
- Progress messages follow the `\n[Step N/7] ...` header style, then `  > ...` detail lines (`    - ...` for sub-items). Cleanup uses `[Cleanup]`.
- Fatal errors call `log_print(..., file=sys.stderr)` and then `sys.exit(1)`. There's no exception propagation to `main`.
- Operations are meant to be **idempotent**: an existing IAM user or policy and duplicate DNS records (Cloudflare error codes `81057` / `1009`) are logged as "Info: ... already exists" and skipped.
- Resource names come from the domain with dots replaced by dashes: `ses-sender-<domain>` for the IAM user and `ses-send-only-<domain>` for the policy. This logic is duplicated in `create_iam_user_and_policy` and `remove_iam_user_and_policy`, so keep the two in sync.
- Cloudflare records are tagged with the comment `Provisioned by SES`. TXT content is auto-wrapped in quotes by `create_cf_record`.
- If you change the permissions the script needs or the user policy it creates, update the JSON policies in `README.md` to match.

## Secrets

`config.ini`, `*.log`, `*.key` and `*.pem` are gitignored. Log files contain the generated secret access key in plain text. Never commit, echo or paste the contents of `config.ini` or log files.

## Known gaps (as of 2026-10)

- `--skip-ses`, `--skip-cloudflare` and `--skip-mx` are parsed in `provision_ses_domain.py` but never used. `create_ses_dns_records` and `print_manual_dns_records` accept `skip_mx`, but `main` doesn't pass it, so the MX record is always created. The README documents `--skip-mx` as working.
- The "SMTP Password" printed is the raw IAM secret access key. SES SMTP actually requires a password derived from the secret (HMAC-SHA256 SigV4 derivation, region-specific). The FluentMail API-key `define()` lines are fine, but SMTP login with the printed password will fail.
- README says the sample config is `config.bak`, but the file is `config.ini.bak`.

## Unrelated content

`gummedical-site/` (a React + Cloudflare Workers site) was merged in via PR #1 but has nothing to do with this tool. It's currently deleted in the working tree, pending removal.
