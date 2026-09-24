# Radixing Traffic Decision Engine

A small, deterministic TypeScript library for evaluating versioned traffic policies. It parses a policy, derives narrow evidence from supplied request observations, and returns a selected action with an optional explanation. It performs no network, storage, origin fetch, or action execution.

```ts
import { analyzeFingerprint, evaluateRules, fingerprintSignals, parsePublishedConfig } from "@radixing/traffic-engine";

const policy = parsePublishedConfig({
  schemaVersion: 2,
  propertyId: "example",
  version: 1,
  domains: ["go.example.com"],
  defaultAction: { type: "redirect", status: 302, url: "https://app.example.com" },
  rules: [{
    id: "sensitive-path",
    name: "Sensitive file probe",
    enabled: true,
    priority: 1,
    match: "all",
    conditions: [{ field: "request.probe", operator: "eq", value: true }],
    action: { type: "block", status: 404 },
  }],
});

const evidence = analyzeFingerprint({ path: "/.env", userAgent: "curl/8.0" });
const decision = evaluateRules(policy, { "request.path": "/.env", ...fingerprintSignals(evidence) });
// decision = { ruleId: "sensitive-path", action: { type: "block", status: 404 } }
```

The host application extracts signals, keeps any behavioral state, executes the selected action, and records its own audit trail. Evidence does not automatically block traffic. Missing signals are unknown, not a human classification. `explainRules` returns condition indices and match results without echoing signal values. Version 1 policies retain their legacy `allow` fallback for host-side proxying; version 2 requires an explicit default redirect.

The probe catalog is deliberately narrow and versioned. See [rule provenance](docs/rule-provenance.md). All fixtures in this repository are synthetic; merchant traffic, IP lists, customer configuration, credentials, and model-provider calls are outside this package.

Run `npm ci && npm run check` to typecheck, test, and build. The package exports ESM JavaScript and declarations from `dist/`.
