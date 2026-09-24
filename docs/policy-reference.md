# Policy and signal reference

Pass an untrusted policy object through `parsePublishedConfig` before evaluation. A published snapshot has a `schemaVersion`, `propertyId`, positive `version`, managed ingress `domains`, ordered `rules`, and a schema-specific default. The package does not publish or store snapshots.

## Policy versions

| Field or behavior | Schema v1 | Schema v2 |
| --- | --- | --- |
| Default | `defaultOrigin`: an HTTPS origin used by the host for unmatched `allow`/proxy traffic | `defaultAction`: an explicit HTTPS redirect |
| Unmatched decision | `{ action: { type: "allow" } }` | `{ action: defaultAction }` |
| Rule actions | `allow`, `block`, `redirect`, `route` | `block`, `redirect` |
| Ingress domains | One or more validated DNS hostnames | Exactly one validated DNS hostname |

Version 1 is retained for existing proxy-style policies. Version 2 does not silently proxy unmatched traffic. Both versions reject destinations that point back to a managed ingress domain. Redirect and route targets must be HTTPS without URL credentials; `route` accepts an origin only. The host decides how to execute an `allow` or `route` result.

This is a complete v2 policy with one explicit probe rule:

```ts
import { evaluateRules, parsePublishedConfig } from "@radixing/traffic-engine";

const config = parsePublishedConfig({
  schemaVersion: 2,
  propertyId: "example",
  version: 1,
  domains: ["go.example.com"],
  defaultAction: {
    type: "redirect", status: 302, url: "https://app.example.com",
  },
  rules: [{
    id: "sensitive-path",
    name: "Sensitive path",
    enabled: true,
    priority: 10,
    match: "all",
    conditions: [{ field: "request.probe", operator: "eq", value: true }],
    action: { type: "block", status: 404 },
  }],
});

const decision = evaluateRules(config, {
  "request.method": "GET",
  "request.path": "/.env",
  "request.probe": true,
});
// { ruleId: "sensitive-path", action: { type: "block", status: 404 } }
```

`request.probe` in this example must be supplied by the host, for example from `fingerprintSignals(analyzeFingerprint({ path }))`. The engine never infers it from `request.path` during rule evaluation.

## Matching rules

Enabled rules are evaluated by ascending numeric `priority`; equal priorities retain their configured array order. The first matching rule is terminal. `match: "all"` requires every condition, while `match: "any"` requires at least one. Disabled rules never match. `explainRules` reports which rules and conditions were evaluated, but omits the supplied signal values.

Conditions use `eq`, `neq`, `in`, `notIn`, `contains`, `startsWith`, or `exists`. `in` and `notIn` require non-empty scalar arrays. A missing signal does not satisfy `neq` or `notIn`; `exists` requires a present, non-empty value. `client.automation` and the boolean fingerprint fields accept only equality or set operators with typed values.

| Signal group | Supported fields |
| --- | --- |
| Geography | `geo.country`, `geo.region`, `geo.city` |
| Network | `network.ip`, `network.asn`, `network.organization` |
| Client and device | `client.bot`, `client.automation`, `client.headless`, `client.uaMismatch`, `device.type`, `device.os` |
| Request | `request.hostname`, `request.path`, `request.probe`, `request.pathEnumeration`, `request.method`, `request.referrer` |
| Campaign | `campaign.source`, `campaign.medium`, `campaign.name` |

The host supplies these values. `network.ip` is not an IP reputation lookup; its trust depends on the host's ingress validation. `client.automation` is `declared`, `suspected`, or `unknown`, never a verified human/bot identity. Missing evidence should remain absent rather than being guessed as benign.

## Evidence and actions

`analyzeFingerprint` accepts bounded User-Agent, Client Hints brand/platform, and path inputs. It returns versioned automation, headless, mismatch and probe observations; `fingerprintSignals` maps the rule-relevant fields. `analyzeProbePath` recognizes a small, versioned set of sensitive path segments. `advanceBehavior` accepts host-maintained state, a path and time, then returns a path-enumeration assessment; its current window is 60 requests with at least 40 distinct paths in 15 seconds, followed by a 60-second cooldown. None of these observations blocks a request by itself.

`block` supports HTTP 403, 404 or 410 and an optional short body. `redirect` supports 301, 302, 307 or 308 and optional `preservePath`; the host implements path/query forwarding. `allow` and `route` are v1-only. Optional `attribution` configuration is parsed and retained with a policy, but click IDs, forwarding, persistence and callbacks belong to the host.

The optional Jev path uses a **separate** policy bound to the published `propertyId` and `version`; it does not add a new static rule operator. See [architecture and host integration](architecture.md) and [Jev decision gateway](jev-gateway.md) before connecting it to live requests.
