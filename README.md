# cf-access-provisioner

A Cloudflare Worker that turns a small JSON config into a hardened Cloudflare Access app, idempotently, and audits the whole account for apps that let in more people than they should.

## The problem

Cloudflare Access apps built by hand in the dashboard drift. Someone adds an `email_domain` rule to one app, copies the app, copies it again, and a while later you have dozens of apps sharing a domain wildcard plus a pile of stray emails. Nobody can say who can reach what.

This worker does two things about it:

1. **Provision from config.** One POST creates or updates the app and its allow policy. Re-running the same config changes nothing. The allow policy points at a shared Access group, so adding a person means editing the group and nothing else.
2. **Audit the account.** One GET classifies every app: `only-allowlisted`, `broad`, `no-allow-policy` or `everyone`.

It also answers "is this email in Access group X?" live against Cloudflare, because Access doesn't expose that.

## Quick start

```bash
npm install
npm test
npx wrangler secret put ADMIN_TOKEN     # bearer callers must present
npx wrangler secret put CF_API_TOKEN    # token with Access edit scope
npx wrangler secret put CF_ACCOUNT_ID
npx wrangler deploy
```

The shared allowlist group must already exist in the Zero Trust dashboard. The worker refuses to create an empty one.

Provision an app:

```bash
curl -X POST https://provisioner.example.workers.dev/v1/access/provision \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{
    "domain": "app.example.com",
    "app_name": "Example App",
    "allowlist_group": "allowed-users",
    "allowed_idps": ["github", "otp"],
    "override_emails": [],
    "session_duration": "24h"
  }'
```

Only `domain`, `app_name` and `allowlist_group` are required. Unknown keys are rejected.

Audit the account:

```bash
curl -H "Authorization: Bearer $ADMIN_TOKEN" \
  "https://provisioner.example.workers.dev/v1/access/audit?expected=alice@example.com,bob@example.com"
```

## Endpoints

All `/v1/access/*` routes need `Authorization: Bearer <ADMIN_TOKEN>`.

| Method | Path | What it does |
|---|---|---|
| GET | `/health` | Liveness, no auth. |
| POST | `/v1/access/provision` | Validate config, check hardening, upsert app and policy, re-check the live policies, check IdPs, then do a live login round-trip. |
| POST | `/v1/access/validate` | Live login round-trip for `{"hostname": "..."}`. |
| GET | `/v1/access/audit?expected=a@x,b@x` | Classify every app. `expected` is required. |
| GET | `/v1/access/membership?email=…&groups=a,b` | Live verdict per group. `sub=<Access user id>` works instead of `email=`. |

## How it works

- `schemas.ts` parses the config. Wildcard entries (`@domain`, anything with `*`) in `override_emails` are rejected, and so are unknown keys.
- `harden.ts` checks the config before anything is written (session length, cookie flags), then checks the app's live policies after (no `email_domain`, no `everyone`, at least one allow, service-token policies are `non_identity`). It collects every violation, not just the first.
- `provision.ts` finds the app by exact domain and updates it, or creates it. It never rewrites an existing group's members. If the config expects members the live group lacks, it logs a drift line and leaves the group alone.
- `audit.ts` reads every app's allow policies and flags extra emails, `email_domain`, `everyone` and IP rules.
- `membership.ts` reads the group from Cloudflare on every request and evaluates `include`, `exclude` and `require` rules. A rule it can't decide from an email (IP, country, IdP groups, email lists) makes the group unresolvable. That returns 502, never `false`.
- `validate-live.ts` follows the Access redirect to the login page and checks each provider's authorize URL for the right callback.

## Limits

- The audit doesn't open groups. An app whose allow policy is `group: X` counts as `only-allowlisted` even if group X holds a wildcard. Check the groups themselves.
- It only manages `self_hosted` apps and allow / `non_identity` policies.
- Hardening failures after a write (a live policy that came back wrong) are reported with a 422, but the write has already happened. The config-level checks run before any write.
- Membership supports `email`, `email_domain`, `everyone` and nested `group` rules only.
- The tests mock `fetch`. Nothing here has been run against a real Cloudflare account by the test suite.
- No rate limiting and no retries on the Cloudflare API.

## Tests

```bash
scripts/verify.sh     # install, typecheck, test; last line is the verdict
npm test              # tests only
```
