# cs-cloudflare-access-rules-bouncer

A [CrowdSec](https://crowdsec.net) bouncer that blocks the IPs CrowdSec banned
at Cloudflare's edge, using **IP Access Rules**. It works on the Free plan.

## Why IP Access Rules

| | Custom List (official bouncer) | Workers bouncer | IP Access Rules (this) |
|---|---|---|---|
| Plan | Free | Workers Paid | Free |
| Capacity | 1 list, 10,000 items | KV-bound | 50,000 rules per account |
| Update path | async bulk operations, rate limited | KV writes | one synchronous call per IP, live in seconds |
| Custom rule slot | uses 1 of 5 | none | none |
| Zones covered | per rule | per route | every zone in the account (account-level) |

## How it works

- Pulls decisions from the LAPI stream (`/v1/decisions/stream`). By default it takes only
  `crowdsec` and `cscli` origins: IPs that attacked *you*, not the community blocklist.
- Each ban becomes one IP Access Rule (`BAN_MODE`); each captcha becomes `CAPTCHA_MODE`.
  When an IP has both, the ban wins.
- IPv6 addresses are widened to their /64 (`IPV6_PREFIX`), so an attacker can't
  rotate through its own prefix.
- Writes are paced (`CF_RATE`) and sent in batches, newest decisions first, so a
  large initial seed never starves new bans. A 429 is retried after `Retry-After`.
- Every `REFRESH_INTERVAL` it re-reads Cloudflare and converges, so restarts,
  missed events and hand-deleted rules fix themselves. It keeps no state on disk.
- It only touches rules whose notes start with `NOTE_PREFIX`. Rules you made by
  hand (including allowlist entries for the same IP) are left alone.
- If LAPI is unreachable, existing rules stay in place.
- It refuses to delete more than `MAX_DELETES` rules in one go.

## Cloudflare token

Create an API token with:

- Account-level rules: **Account → Account Firewall Access Rules → Edit**
- Zone-level rules (`CF_ZONE_IDS`): **Zone → Firewall Services → Edit** on those zones

## Configuration

Every variable also accepts `<NAME>_FILE`, which reads the value from a file
(Docker secrets).

| Variable | Default | |
|---|---|---|
| `CROWDSEC_LAPI_URL` | `http://crowdsec:8080` | |
| `CROWDSEC_LAPI_KEY` | required | from `cscli bouncers add cloudflare-access-rules` |
| `CROWDSEC_ORIGINS` | `crowdsec,cscli` | add `CAPI,lists` only if it fits in `MAX_RULES` |
| `CF_API_TOKEN` | required | |
| `CF_ACCOUNT_ID` | | account-level rules (all zones) |
| `CF_ZONE_IDS` | | comma-separated; zone-level rules |
| `BAN_MODE` | `block` | `block`, `managed_challenge`, `js_challenge`, `challenge` |
| `CAPTCHA_MODE` | `managed_challenge` | |
| `IPV6_PREFIX` | `64` | `32`, `48`, `64`, or `128` to disable widening |
| `EXCLUDE_CIDRS` | | never create rules overlapping these |
| `NOTE_PREFIX` | `crowdsec` | marks the rules this bouncer owns |
| `POLL_INTERVAL` | `10` | seconds between LAPI polls |
| `REFRESH_INTERVAL` | `600` | seconds between full Cloudflare re-reads |
| `CF_RATE` | `2` | Cloudflare writes per second (the API allows 1,200 per 5 minutes per user) |
| `BATCH_SIZE` | `100` | writes before re-polling LAPI |
| `MAX_RULES` | `10000` | newest decisions win when over |
| `MAX_DELETES` | `500` | per-sync delete cap |
| `DRY_RUN` | `false` | log writes instead of making them |
| `LOG_LEVEL` | `INFO` | |

Private addresses are never sent. Cloudflare accepts IPv4 ranges only as /16 and
/24, and IPv6 ranges only as /32, /48 and /64; other range decisions are skipped
and logged.

## Run

```yaml
services:
  cloudflare-bouncer:
    image: ghcr.io/priyankub/cs-cloudflare-access-rules-bouncer:latest
    restart: unless-stopped
    environment:
      CROWDSEC_LAPI_URL: http://crowdsec:8080
      CROWDSEC_LAPI_KEY_FILE: /run/secrets/lapi_key
      CF_API_TOKEN_FILE: /run/secrets/cf_token
      CF_ACCOUNT_ID: your-account-id
      BAN_MODE: managed_challenge
    secrets: [lapi_key, cf_token]

secrets:
  lapi_key:
    file: ./lapi_key
  cf_token:
    file: ./cf_token
```

The image is multi-arch (`linux/amd64`, `linux/arm64`), runs as `nobody`, and has a
Docker health check. Run a single instance per Cloudflare account; two would
duplicate each other's writes.

To remove every rule it created:

```sh
docker compose run --rm cloudflare-bouncer --purge
```

## Notes

- Access Rules apply only to traffic proxied by Cloudflare (orange cloud). Keep a
  bouncer at your origin too.
- Account-level rules show up under **Account → Configurations → IP Access Rules**,
  and their hits appear in Security Events.
