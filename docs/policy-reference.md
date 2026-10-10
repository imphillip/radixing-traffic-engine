# Policy and signal reference

Use `parsePublishedConfig` before evaluating supplied configuration. `createTds` accepts schema 2 and enforces a single DNS ingress hostname, HTTPS destinations without URL credentials, an explicit default and no destination back to the ingress hostname. Unknown fields are not evaluated; unsupported signal fields or operators reject a condition.

Schema 1 remains available through `parsePublishedConfig`/`evaluateRules` for legacy embedding (`defaultOrigin`, `allow`, `route`). The standalone service does not proxy schema 1 policies. Schema 2 supports `redirect`, `split` and `block`; its default must be a redirect or split.

## Rules and fields

Enabled rules are evaluated by ascending integer priority. Equal priorities preserve configured order. The first match is terminal. `match: all` requires every condition; `match: any` requires one. An explicit default handles unmatched requests.

| Group | Fields |
| --- | --- |
| Geography | `geo.country`, `geo.region`, `geo.city` |
| Network | `network.ip`, `network.asn`, `network.organization`, `network.country`, `network.vpn`, `network.datacenter` |
| Client | `client.bot`, `client.automation`, `client.headless`, `client.uaMismatch`, `client.key` |
| Device/browser | `device.type`, `device.os`, `browser.name`, `browser.version` |
| Request | `request.hostname`, `request.path`, `request.method`, `request.referrer`, `request.probe`, `request.pathEnumeration` |
| Campaign | `campaign.source`, `campaign.medium`, `campaign.name` |

`network.asn` is numeric. Flags are booleans, `device.type` is `bot`/`desktop`/`mobile`/`tablet`, and `client.automation` is `declared`/`suspected`/`unknown`. Other fields are strings. Parser-derived device/browser/OS labels follow Bowser. Region/city and client keys require host-supplied observations; standalone mode does not invent client identity or collect browser API fingerprints.

Campaign fields come from bounded `utm_source`, `utm_medium`, `utm_campaign` query values. Referrer extraction retains only origin and path, excluding credentials, query and fragment. These request claims are not authenticated ad-platform attribution.

| Operator | Semantics |
| --- | --- |
| `eq`, `neq` | Typed exact equality/inequality |
| `in`, `notIn` | Typed membership in a non-empty array |
| `contains`, `startsWith` | Case-sensitive string comparison |
| `gte`, `lte` | Numeric ASN comparison |
| `exists` | Present and not an empty string |
| `inCidr`, `notInCidr` | IPv4/IPv6 network membership; only on `network.ip`, using an array of CIDRs |

Missing facts do not satisfy negative comparisons. Boolean and enum fields accept equality/set operators or `exists`. There are no temporal or model-class signal fields in 1.0.

## Redirects and blocks

Redirect statuses: 301/302/307/308. `preservePath: true` appends the incoming pathname to the configured target path without changing target host. Queries are not forwarded implicitly. `queryAllowlist` specifies up to 32 parameter names; selected incoming values replace the same target parameter, preserving multiple values and unrelated configured parameters. Choose this allowlist to exclude credentials and sensitive values.

Block statuses: 403/404/410, optional text body up to 500 characters. HEAD responses omit the body. HTTP execution accepts GET/HEAD only and rejects unconfigured hosts with 421. Redirect/block responses use `Cache-Control: no-store` because request features can select different actions.

## Stable A/B split

```json
{
  "type": "split",
  "status": 302,
  "key": "client.key",
  "salt": "experiment-1",
  "targets": [
    { "url": "https://a.example.com/", "weight": 3 },
    { "url": "https://b.example.com/", "weight": 1 }
  ],
  "fallbackUrl": "https://www.example.com/",
  "queryAllowlist": ["utm_source"]
}
```

There must be 2-20 unique targets with positive integer weights of 1-10000. Status is 302 or 307. The engine resolves the split to a concrete redirect using a fixed version 1 FNV-1a UTF-8 hash of `[salt, typeof key, key]`. It uses no random selection. Different keys distribute approximately according to weights; exact small-sample proportions are not guaranteed. Missing keys use `fallbackUrl`.

The host supplies a stable `client.key` when visitor-level assignment is needed. Choosing `network.ip` groups requests by address and does not identify individual visitors behind NAT. Changing keys, salt, target order or weights can change assignment.

## Explanation and supporting security

`explainRules` returns matching rule/config version and condition outcomes without raw signal values. TDS adds snapshot ID, source freshness/membership evidence and parser version. `analyzeFingerprint` retains bounded header consistency and probe checks; `advanceBehavior` remains a separate optional host-state helper. Neither adds automatic blocking rules.

Optional attribution configuration is retained for legacy hosts but does not enable tracking, cookies, callbacks or forwarding automatically. See [migration](migration-1.0.md) and [operations](operations.md).
