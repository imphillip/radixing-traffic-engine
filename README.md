# Radixing Traffic Decision Engine

[![CI](https://github.com/imphillip/radixing-traffic-engine/actions/workflows/ci.yml/badge.svg)](https://github.com/imphillip/radixing-traffic-engine/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A small, deterministic TypeScript policy engine for traffic classification and routing decisions. It parses versioned policies, derives narrow evidence from supplied request observations, and selects an explicit action with an optional explanation. It is the open-source decision core used by [Radixing](https://radixing.com).

## Where it fits

- **Traffic cloaking and conditional delivery:** evaluate ordered rules for supplied geography, network, device, campaign, and request signals, then select an explicit redirect, block, allow, or route action. Your application controls signal collection and execution.
- **WAF integrations:** turn specific probe-path evidence into a policy signal and evaluate explicit block rules. This is not a managed WAF, IP reputation feed, challenge service, or DDoS defense.
- **Bot-aware routing:** combine bounded User-Agent and Client Hints analysis with versioned probe and path-diversity evidence. `declared`, `suspected`, and `unknown` are observations, not verified visitor identities or automatic enforcement decisions.
- **Policy simulation:** call `explainRules` to inspect the first matching rule and condition results without echoing raw signal values.

The library performs no network or storage I/O, origin fetch, or action execution. It does not include a proxy, browser SDK, IP database, model provider, or merchant data. Hosts supply trusted observations, maintain behavioral state, execute the selected action, and record their own audit trail.

## Install

```bash
npm install git+https://github.com/imphillip/radixing-traffic-engine.git#main
```

The package is currently distributed from GitHub, not the npm registry. Pin a full commit SHA for reproducible production builds.

## Example

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

Evidence does not automatically block traffic. Missing signals are unknown, not a human classification. Version 1 policies retain their legacy `allow` fallback for host-side proxying; version 2 requires an explicit default redirect. In both versions, the first matching rule wins.

The probe catalog is deliberately narrow and versioned. See [rule provenance](docs/rule-provenance.md). All fixtures in this repository are synthetic; merchant traffic, IP lists, customer configuration, credentials, and model-provider calls are outside this package.

## Development

Run `npm ci && npm run check` to typecheck, test, and build. The package exports ESM JavaScript and TypeScript declarations from `dist/`. Rule changes should include positive and negative synthetic tests and a version bump when evidence semantics change.
