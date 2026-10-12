#!/usr/bin/env python3
"""CrowdSec bouncer that mirrors local decisions into Cloudflare IP Access Rules.

IP Access Rules are single synchronous objects (one POST/DELETE each, live in
seconds), allow 50,000 per account on every plan, and an account-level rule
covers every zone in the account. That sidesteps the free plan's limits on
custom Lists (1 list, 10,000 items, async bulk operations) and custom rules
(5 rules, 4,096-character expressions).

Only rules whose notes start with NOTE_PREFIX are ever touched.
"""

import ipaddress
import json
import logging
import os
import signal
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

log = logging.getLogger("bouncer")

HEALTH_FILE = "/tmp/healthy"
CF_API = os.environ.get("CF_API_URL", "https://api.cloudflare.com/client/v4")
VALID_MODES = {"block", "challenge", "js_challenge", "managed_challenge"}
# Cloudflare only accepts these range sizes in IP Access Rules.
V4_RANGES = {16, 24}
V6_RANGES = {32, 48, 64}


def env(name, default=None):
    """Read NAME, or the file named by NAME_FILE (Docker secrets style)."""
    path = os.environ.get(name + "_FILE")
    if path:
        with open(path) as f:
            return f.read().strip()
    return os.environ.get(name, default)


def env_bool(name, default=False):
    return env(name, str(default)).strip().lower() in ("1", "true", "yes", "on")


class Config:
    def __init__(self):
        self.lapi_url = env("CROWDSEC_LAPI_URL", "http://crowdsec:8080").rstrip("/")
        self.lapi_key = env("CROWDSEC_LAPI_KEY")
        self.origins = env("CROWDSEC_ORIGINS", "crowdsec,cscli")
        self.cf_token = env("CF_API_TOKEN")
        account = env("CF_ACCOUNT_ID", "")
        zones = [z.strip() for z in env("CF_ZONE_IDS", "").split(",") if z.strip()]
        self.bases = ([f"accounts/{account}"] if account else []) + [f"zones/{z}" for z in zones]
        self.ban_mode = env("BAN_MODE", "block")
        self.captcha_mode = env("CAPTCHA_MODE", "managed_challenge")
        self.note_prefix = env("NOTE_PREFIX", "crowdsec")
        self.ipv6_prefix = int(env("IPV6_PREFIX", "64"))
        self.exclude = [ipaddress.ip_network(c.strip(), strict=False)
                        for c in env("EXCLUDE_CIDRS", "").split(",") if c.strip()]
        self.poll_interval = float(env("POLL_INTERVAL", "10"))
        self.refresh_interval = float(env("REFRESH_INTERVAL", "600"))
        self.rate = float(env("CF_RATE", "2"))
        self.batch = int(env("BATCH_SIZE", "100"))
        self.max_rules = int(env("MAX_RULES", "10000"))
        self.max_deletes = int(env("MAX_DELETES", "500"))
        self.dry_run = env_bool("DRY_RUN")

        errors = []
        if not self.lapi_key:
            errors.append("CROWDSEC_LAPI_KEY is required")
        if not self.cf_token:
            errors.append("CF_API_TOKEN is required")
        if not self.bases:
            errors.append("set CF_ACCOUNT_ID and/or CF_ZONE_IDS")
        for name in ("ban_mode", "captcha_mode"):
            if getattr(self, name) not in VALID_MODES:
                errors.append(f"{name.upper()} must be one of {sorted(VALID_MODES)}")
        if self.ipv6_prefix not in V6_RANGES | {128}:
            errors.append("IPV6_PREFIX must be 32, 48, 64 or 128")
        if errors:
            sys.exit("config error: " + "; ".join(errors))


def http_json(method, url, headers, body=None, timeout=30):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read()
    return json.loads(raw) if raw else None


class Lapi:
    def __init__(self, cfg):
        self.cfg = cfg
        self.headers = {"X-Api-Key": cfg.lapi_key, "User-Agent": "cs-cloudflare-access-rules-bouncer"}

    def stream(self, startup):
        q = urllib.parse.urlencode({
            "startup": "true" if startup else "false",
            "origins": self.cfg.origins,
            "scopes": "ip,range",
        })
        r = http_json("GET", f"{self.cfg.lapi_url}/v1/decisions/stream?{q}", self.headers) or {}
        return r.get("new") or [], r.get("deleted") or []


class CloudflareError(Exception):
    pass


class Cloudflare:
    def __init__(self, cfg):
        self.cfg = cfg
        self.headers = {"Authorization": f"Bearer {cfg.cf_token}",
                        "User-Agent": "cs-cloudflare-access-rules-bouncer"}
        self.min_gap = 1.0 / cfg.rate
        self.last = 0.0

    def call(self, method, path, body=None):
        for attempt in range(4):
            wait = self.last + self.min_gap - time.monotonic()
            if wait > 0:
                time.sleep(wait)
            self.last = time.monotonic()
            try:
                r = http_json(method, f"{CF_API}/{path}", self.headers, body)
                if r and not r.get("success", True):
                    raise CloudflareError(r.get("errors"))
                return r
            except urllib.error.HTTPError as e:
                try:
                    errors = json.loads(e.read()).get("errors")
                except Exception:
                    errors = e.reason
                if e.code == 429 or e.code >= 500:
                    delay = int(e.headers.get("Retry-After") or 30 * (attempt + 1))
                    log.warning("cloudflare %s %s: HTTP %s, retrying in %ss", method, path, e.code, delay)
                    time.sleep(delay)
                    continue
                raise CloudflareError(f"HTTP {e.code}: {errors}") from None
            except (urllib.error.URLError, TimeoutError) as e:
                log.warning("cloudflare %s %s: %s, retrying", method, path, e)
                time.sleep(10 * (attempt + 1))
        raise CloudflareError(f"{method} {path}: gave up after retries")

    def list_rules(self, base):
        rules, page = [], 1
        while True:
            r = self.call("GET", f"{base}/firewall/access_rules/rules?per_page=500&page={page}")
            rules += r["result"]
            if page >= (r.get("result_info") or {}).get("total_pages", 1):
                return rules
            page += 1

    def create(self, base, target, value, mode, notes):
        return self.call("POST", f"{base}/firewall/access_rules/rules", {
            "mode": mode, "configuration": {"target": target, "value": value}, "notes": notes,
        })["result"]

    def update(self, base, rule_id, mode, notes):
        return self.call("PATCH", f"{base}/firewall/access_rules/rules/{rule_id}",
                         {"mode": mode, "notes": notes})

    def delete(self, base, rule_id):
        self.call("DELETE", f"{base}/firewall/access_rules/rules/{rule_id}")


def to_rule_target(cfg, scope, value):
    """Map a decision to Cloudflare's (target, value), or None if it can't be expressed."""
    try:
        net = ipaddress.ip_network(value, strict=False)
    except ValueError:
        return None
    if not net.is_global or any(net.overlaps(x) for x in cfg.exclude):
        return None
    if net.version == 6 and net.prefixlen > cfg.ipv6_prefix:
        net = net.supernet(new_prefix=cfg.ipv6_prefix)
    if net.prefixlen == net.max_prefixlen:
        return ("ip" if net.version == 4 else "ip6", str(net.network_address))
    if net.prefixlen in (V4_RANGES if net.version == 4 else V6_RANGES):
        return ("ip_range", str(net))
    return None


class Bouncer:
    def __init__(self, cfg):
        self.cfg = cfg
        self.lapi = Lapi(cfg)
        self.cf = Cloudflare(cfg)
        # (target, value) -> {decision id: (type, scenario)}
        self.desired = {}
        # base -> (target, value) -> {"id", "mode"}; only our own rules
        self.current = {}
        # base -> set of (target, value) held by rules we don't own
        self.foreign = {}
        self.skipped = set()
        self.over_cap = False

    def apply_decisions(self, new, deleted):
        for d in deleted:
            key = to_rule_target(self.cfg, d.get("scope", ""), d.get("value", ""))
            if key in self.desired:
                self.desired[key].pop(d["id"], None)
                if not self.desired[key]:
                    del self.desired[key]
        for d in new:
            if d.get("type") not in ("ban", "captcha"):
                continue
            key = to_rule_target(self.cfg, d.get("scope", ""), d.get("value", ""))
            if key is None:
                if d["value"] not in self.skipped:
                    self.skipped.add(d["value"])
                    log.info("skipping %s %s (private, excluded or unsupported range)", d["scope"], d["value"])
                continue
            self.desired.setdefault(key, {})[d["id"]] = (d["type"], d.get("scenario", ""))

    def resync_lapi(self):
        self.desired = {}
        self.apply_decisions(*self.lapi.stream(startup=True))
        log.info("lapi: %d decision targets", len(self.desired))

    def refresh_cloudflare(self):
        for base in self.cfg.bases:
            ours, foreign = {}, set()
            for r in self.cf.list_rules(base):
                key = (r["configuration"]["target"], r["configuration"]["value"])
                if (r.get("notes") or "").startswith(self.cfg.note_prefix):
                    if key in ours:  # duplicate from an earlier crash; drop the extra
                        self.do("delete", base, key, lambda rid=r["id"]: self.cf.delete(base, rid))
                        continue
                    ours[key] = {"id": r["id"], "mode": r["mode"]}
                else:
                    foreign.add(key)
            self.current[base], self.foreign[base] = ours, foreign
            log.info("cloudflare %s: %d managed rules, %d other rules", base, len(ours), len(foreign))

    def wanted(self):
        """The target set to enforce, capped at MAX_RULES (newest decisions win)."""
        items = []
        for key, decisions in self.desired.items():
            types = {t for t, _ in decisions.values()}
            mode = self.cfg.ban_mode if "ban" in types else self.cfg.captcha_mode
            newest = max(decisions)
            items.append((newest, key, mode, decisions[newest][1]))
        items.sort(reverse=True)
        over = len(items) > self.cfg.max_rules
        if over and not self.over_cap:
            log.warning("%d targets exceed MAX_RULES=%d; keeping the newest", len(items), self.cfg.max_rules)
        self.over_cap = over
        items = items[:self.cfg.max_rules]
        return items

    def do(self, verb, base, key, fn):
        """Run one Cloudflare write. Returns its result (truthy) or None on failure."""
        if self.cfg.dry_run:
            log.info("dry-run: would %s %s %s on %s", verb, key[0], key[1], base)
            return {"id": "dry-run"}
        try:
            return fn() or True
        except CloudflareError as e:
            if verb == "create" and "duplicate" in str(e).lower():
                # Someone added a rule for this target by hand since the last refresh.
                self.foreign[base].add(key)
                log.info("%s already has a rule on %s that we don't manage; leaving it", key[1], base)
            else:
                log.error("cloudflare %s %s on %s failed: %s", verb, key[1], base, e)
            return None

    def sync(self):
        """Converge Cloudflare toward the wanted set, at most BATCH_SIZE writes per call.

        Returns False when the batch ran out, so the caller polls LAPI and comes
        straight back instead of sleeping. Failed writes are retried next poll.
        """
        wanted = self.wanted()
        wanted_keys = {k for _, k, _, _ in wanted}
        budget = self.cfg.batch
        for base in self.cfg.bases:
            cur = self.current[base]
            stale = [k for k in cur if k not in wanted_keys]
            if len(stale) > self.cfg.max_deletes:
                log.error("refusing to delete %d rules on %s (MAX_DELETES=%d); "
                          "raise MAX_DELETES if this is intended", len(stale), base, self.cfg.max_deletes)
                stale = []
            for key in stale:
                if budget <= 0:
                    return False
                budget -= 1
                if self.do("delete", base, key, lambda: self.cf.delete(base, cur[key]["id"])):
                    del cur[key]
                    if not self.cfg.dry_run:
                        log.info("removed %s from %s", key[1], base)
            for _, key, mode, scenario in wanted:
                if key in self.foreign[base]:
                    continue
                notes = f"{self.cfg.note_prefix}: {scenario}"[:200]
                if key not in cur:
                    if budget <= 0:
                        return False
                    budget -= 1
                    r = self.do("create", base, key, lambda: self.cf.create(base, *key, mode, notes))
                    if r:
                        cur[key] = {"id": r["id"], "mode": mode}
                        if not self.cfg.dry_run:
                            log.info("added %s %s (%s) to %s", mode, key[1], scenario, base)
                elif cur[key]["mode"] != mode:
                    if budget <= 0:
                        return False
                    budget -= 1
                    if self.do("update", base, key, lambda: self.cf.update(base, cur[key]["id"], mode, notes)):
                        cur[key]["mode"] = mode
                        if not self.cfg.dry_run:
                            log.info("changed %s to %s on %s", key[1], mode, base)
        return True

    def run(self):
        log.info("starting: bases=%s origins=%s ban_mode=%s dry_run=%s",
                 self.cfg.bases, self.cfg.origins, self.cfg.ban_mode, self.cfg.dry_run)
        while True:
            try:
                self.resync_lapi()
                self.refresh_cloudflare()
                break
            except Exception as e:
                log.error("startup failed, retrying in 30s: %s", e)
                time.sleep(30)
        last_refresh = time.monotonic()
        while True:
            healthy = True
            try:
                self.apply_decisions(*self.lapi.stream(startup=False))
            except Exception as e:
                # Keep the rules already in place; a LAPI outage must not unblock anyone.
                log.error("lapi poll failed: %s", e)
                healthy = False
            try:
                if time.monotonic() - last_refresh > self.cfg.refresh_interval:
                    self.refresh_cloudflare()
                    last_refresh = time.monotonic()
                done = self.sync()
            except Exception as e:
                log.error("sync failed: %s", e)
                healthy, done = False, True
            if healthy:
                with open(HEALTH_FILE, "w") as f:
                    f.write(str(time.time()))
            if done:
                time.sleep(self.cfg.poll_interval)

    def purge(self):
        """Delete every rule this bouncer manages (uninstall)."""
        self.refresh_cloudflare()
        for base in self.cfg.bases:
            for key, rule in list(self.current[base].items()):
                self.do("delete", base, key, lambda: self.cf.delete(base, rule["id"]))
        log.info("purge done")


def healthcheck():
    max_age = 3 * float(env("POLL_INTERVAL", "10")) + 120
    try:
        with open(HEALTH_FILE) as f:
            age = time.time() - float(f.read())
    except (OSError, ValueError):
        return 1
    return 0 if age < max_age else 1


def main():
    if "--healthcheck" in sys.argv:
        sys.exit(healthcheck())
    logging.basicConfig(level=env("LOG_LEVEL", "INFO").upper(),
                        format="%(asctime)s %(levelname)s %(message)s")
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    bouncer = Bouncer(Config())
    if "--purge" in sys.argv:
        bouncer.purge()
    else:
        bouncer.run()


if __name__ == "__main__":
    main()
