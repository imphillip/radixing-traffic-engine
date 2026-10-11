# Standard scanner protection

Since 1.1.0, `createTds` and the standalone server enable two supporting security guards by default. Their order is: ingress hostname validation, enumeration guard, sensitive-path guard, request enrichment, ordered project rules, configured default. They terminate locally with an empty body and `Cache-Control: no-store`; blocked requests are never redirected to a destination.

| Guard | Evidence | Action |
| --- | --- | --- |
| Sensitive target | Actual request pathname matches the versioned [five-category probe catalog](rule-provenance.md) | 404 |
| Path enumeration | Trusted host observation `request.pathEnumeration === true` | 403 |

Sensitive targets include `.env` variants, `.git`/`.svn`, `.aws`, specific `phpinfo` forms and service-account JSON filenames. Raw paths, up to two percent-decoding rounds and backslash separators are checked. Request claims such as `trustedSignals["request.probe"] = false` cannot disable this guard; only an explicit runtime option can. Paths such as `/wp-login.php`, `/wp-json/`, `/robots.txt`, asset maps and ordinary campaign landing pages remain outside the catalog.

These are exposure-target and request-pattern checks, not a classification of visitor intent. No default guard blocks requests solely because of a bot User-Agent, VPN, datacenter, ASN, country or advertising source. This is not a general WAF, application vulnerability scanner, fraud detector or DDoS service. The application and edge still need their own access controls and resource limits.

## Standalone enumeration tracking

The Node adapter computes enumeration evidence for GET/HEAD requests to configured ingress domains. Each source is scoped by ingress hostname and canonical trusted client IP, including IPv4-mapped normalization. The client-IP trust boundary is described in [operations](operations.md).

- Window: the latest 60 requests within 15 seconds, excluding the exact lower boundary.
- Trigger: at least 60 requests and at least 40 distinct pathnames in that window.
- Penalty: a fixed 60-second cooldown. Requests during cooldown do not extend the penalty; counting restarts when it ends.
- Query parameters do not increase path diversity. Sensitive GET/HEAD probes contribute to the window; unsupported methods and unknown ingress hosts do not.
- Default capacity: 4096 source states; configurable with `--max-tracked-sources` or `ServerOptions.maxTrackedSources` (1-65536).

Only hashes of source keys and pathnames are stored in memory, with at most 60 path entries per source. Expired states are swept at most once per second during requests. At capacity, existing states and cooldowns are retained; new sources receive no enumeration evidence and continue through the sensitive-path guard and project policy. Invalid/missing client IP similarly contributes no enumeration evidence. `behaviorAvailable: false` in decision events exposes this degraded coverage.

State survives data refresh/reload within one process, but does not survive restart or aggregate across replicas. Backward clock movement resets the affected source's history. Shared-IP/NAT clients share counts within the same ingress domain, so measure false positives before using this redirect-ingress guard on a high-volume asset/API gateway. This guard intentionally uses the existing conservative ingress thresholds rather than a general request rate limit.

## Embedded host contract

The synchronous core does not retain history or inspect forwarded-IP headers. It blocks sensitive paths immediately and blocks enumeration only when the host supplies trusted evidence:

```ts
const observed = advanceBehavior(previousState, pathnameWithoutQuery, now);
// Persist observed.state using serialized, isolated host storage.
const result = tds.handle({
  request,
  ip: trustedClientIp,
  now,
  trustedSignals: { "request.pathEnumeration": observed.assessment.pathEnumeration },
});
```

The host must isolate property/source state, serialize updates, bound capacity and retention, and use a trustworthy client IP. Never copy the evidence flag from public headers/query parameters. Missing evidence means unknown, not a verified benign source. Node integrations can also use `createScannerTracker` from `@radixing/traffic-engine/node`; it is process-local rather than distributed storage. Low-level `evaluateRules` and `explainRules` remain policy-only APIs and do not install these guards.

## Explicit overrides

Defaults require no extra policy rules. Runtime overrides are independent of project rule priority and leave the published policy schema unchanged:

```ts
const tds = createTds(policy, snapshot, {
  scannerProtection: { sensitivePaths: true, pathEnumeration: false },
});
```

`startTdsServer` accepts the same `scannerProtection` object. CLI opt-outs are `--no-sensitive-path-protection` and `--no-path-enumeration-protection`. Both guards are enabled when their options are omitted. An explicit override may be needed for a project that intentionally serves a catalogued path or shares a busy source IP; review permitted-path traffic first. Disabling a guard does not disable any explicit project blocking rule.

## Evidence and upgrading from 1.0

Protection decisions use `evaluation.source: "protection"`, no evaluated project conditions, and a rule ID such as `builtin:probe:env-file` or `builtin:path-enumeration`. `evidence.protection.version` is 1 and records the kind plus probe/behavior versions. Probe catalog version is now 2; behavior thresholds/version remain 1. `evidence.parser` is `null` because enrichment was skipped, and source evidence arrays are empty rather than a claim that all sources were checked. No raw client IP, path, headers, queries or credentials are added to these events. Use the source discriminator rather than a rule-ID prefix alone to distinguish built-in decisions from project rules.

1.0 allowed unmatched probes to follow default routing. 1.1 intentionally changes that default; a catch-all redirect no longer overrides scanner guards. Review expected paths, shared-IP patterns, `evaluation.source` handling and the nullable parser field before upgrading. Embedded hosts need explicit state integration for enumeration; standalone users get local tracking automatically. Roll back the package or use a reviewed runtime override if these defaults are incompatible. Independently pinned hosted services still need their own integration, deployment and acceptance release.
