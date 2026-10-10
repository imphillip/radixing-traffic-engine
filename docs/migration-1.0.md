# Migration to 1.0.0

This is a breaking major release, directly following 0.4.0. The product is now a deterministic TDS with automated open data, not a model-assisted traffic classifier or learning engine.

## Removed

- Jev gateway, OpenRouter/model constants, feature serialization and classification parsers.
- `decideWithJev`, its observe/enforce configuration and model action mapping.
- Rule proposal, replay and learning/review APIs.
- Temporal event/window/replay/provider APIs and all `temporal.*` policy fields.
- Model, learning and temporal documentation and tests.

There are no compatibility shims that make model calls, and old credentials are not read. Old source/model configuration should be removed by the integrating host according to its own deployment process. Updating the public repository does not disable an independently pinned host's existing classifier.

## Retained and extended

The schema 1/2 parser, ordered evaluator, explanation, bounded fingerprint/probe analysis and optional behavior helper remain. Schema 2 gains deterministic weighted `split` actions and redirect `queryAllowlist`. `network.asn` values are numeric; boolean fields require actual booleans, and other field values use typed strings/enums. CIDR predicates use arrays of IPv4/IPv6 prefixes. Invalid legacy condition types must be corrected before publication.

`evaluateRules` resolves split actions to concrete redirects. Hosts using split or query forwarding must support those semantics before adopting policies that use the new fields. No schema number is changed for existing redirect/block policies; package 1.0 adds explicit opt-in action and feature capabilities.

## New

- `createTds`, `enrichRequest`, `parseFeatureSnapshot`, `compileFeatureSnapshot`.
- Network VPN/datacenter/country and browser/key signals.
- `@radixing/traffic-engine/node`: source definitions, snapshot builder/sync/load/rollback and server.
- `radixing-tds` CLI with sync, serve and rollback commands.
- Default daily background source refresh, freshness handling, checksum/source metadata and atomic dataset publication.

## Host adoption checklist

1. Pin the 1.0 release or exact commit in an isolated integration build.
2. Remove imports and configuration for deleted APIs; reject old temporal policies.
3. Establish which observations come from trusted ingress and which datasets are needed.
4. Sync/validate the dataset and test default behavior when facts are absent or stale.
5. Compare destination decisions against existing project policies with representative authorized fixtures.
6. Deploy supported execution semantics before publishing policies using new actions or fields.
7. Record policy/data/parser versions and retain a working code/config/data rollback.

This public release ships no customer policy, production dataset, private service binding or deployment credentials. Hosted upgrades remain separate integration releases.
