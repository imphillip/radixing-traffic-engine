# Jev decision gateway

The optional async flow composes with, but does not change, `evaluateRules`:

```text
request signals -> static first-match decision
  clear block/allow/route or non-eligible redirect -> execute static decision
  eligible redirect or opted-in v2 default -> Jev visitor class
    valid mapped class above both thresholds -> local candidate action
    unresolved/weak/unmapped/invalid/error/timeout -> static decision
```

Only an enabled redirect rule listed in `eligibleRuleIds`, or an explicit v2 default redirect with `classifyDefault: true`, can enter Jev. The flow also requires a GET and skips known `request.probe` or `request.pathEnumeration` evidence, including path enumeration in the feature object. A matched static block cannot be overridden. Version 1 unmatched traffic keeps its original `allow`/proxy fallback; version 2 unmatched traffic keeps its explicit default redirect. If the gateway is unavailable or the policy is invalid, the existing static result is returned.

`parseJevDecisionPolicy(config, value)` validates a separate policy bound to the same `propertyId` and published `configVersion`. It requires its own positive version, an `observe` or `enforce` mode, eligible paths, a 1-2000 ms wait limit, confidence and winning-choice-probability thresholds in `(0, 1]`, and at least one explicit class-to-action mapping. `unresolved` is never mappable. Redirect/origin destinations are HTTPS and cannot point back to a managed domain; v2 mappings may only redirect or block. No class has a built-in blocking action.

```ts
import {
  createOpenRouterJevGateway,
  decideWithJev,
  parseJevDecisionPolicy,
  parsePublishedConfig,
} from "@radixing/traffic-engine";

declare const secretFromHost: string;
declare const validatedClientIp: string;

const config = parsePublishedConfig({
  schemaVersion: 2,
  propertyId: "example",
  version: 1,
  domains: ["go.example.com"],
  defaultAction: { type: "redirect", status: 302, url: "https://app.example.com" },
  rules: [],
});

const policy = parseJevDecisionPolicy(config, {
  version: 1,
  propertyId: "example",
  configVersion: 1,
  mode: "observe",
  eligibleRuleIds: [],
  classifyDefault: true,
  maxWaitMs: 1000,
  minConfidence: 0.9,
  minChoiceProbability: 0.9,
  actions: { other_automation: { type: "block", status: 403 } },
});

const gateway = createOpenRouterJevGateway({ apiKey: secretFromHost });
const result = await decideWithJev({
  config,
  signals: { "request.method": "GET", "request.path": "/" },
  features: { method: "GET", navigation: true, clientIp: validatedClientIp },
  policy,
  gateway,
});
// In observe mode, result.decision stays static; candidateDecision is audit-only.
```

The host supplies the API key and validated observations; this package does not read environment variables. `sanitizeJevFeatures` allows only bounded feature version 2 fields. It can include a canonical client IP when the host explicitly provides one, but excludes raw paths, queries, User-Agent, cookies, authorization, bodies, and unknown keys. OpenRouter and its provider still process any IP sent in the request. The gateway pins `typesafe/jev-1.13`, requests zero data retention and denied provider data collection, rejects redirects, and bounds JSON responses to 8 KiB. It returns only one of five typed visitor classes and validates the complete probability distribution. [OpenRouter's Jev model](https://openrouter.ai/typesafe/jev-1.13/api) and [provider privacy controls](https://openrouter.ai/docs/guides/get-started/sovereign-ai) describe the external API and routing options.

`decideWithJev` aborts the gateway at the policy deadline and returns the static decision even if an adapter ignores abort. The result separates `staticDecision`, selected `decision`, optional `candidateDecision`, and a small Jev status/label/score record. It never echoes features or provider error text. The host must enforce request budgets, rate limits, circuit breaking, retries policy, secret handling, telemetry retention, and exactly-once action execution. A timeout can stop waiting for a response but cannot guarantee that an already-sent provider request incurs no cost.

Jev confidence measures the model's answer distribution, not accuracy on a merchant's traffic. Before enabling `mode: "enforce"`, review labeled non-synthetic visits and replay thresholds, especially false positives. Keep `observe` mode while the mapping is uncalibrated. No public engine release changes a hosted service automatically; its owner must pin a reviewed commit, verify the service, deploy Edge before Console when fields change, and validate production responses.
