# Radixing TDS 1.0.0

Radixing is now a deterministic Traffic Distribution System for paid-traffic ingress. Project policies select destinations from request and network facts; all Jev/LLM gateways, learning APIs and temporal processing APIs have been removed.

- Automatic offline refresh of IPtoASN IPv4/IPv6, X4B VPN/datacenter lists and crawler-user-agents.
- Pinned Bowser device/browser parsing and optional DB-IP country data.
- Source manifests, checksums, bounded downloads, validation, atomic publication and rollback.
- Deterministic ordered rules, CIDR matching, fixed-key weighted A/B and explicit defaults.
- Standalone Node.js redirect service and separately embeddable TypeScript core.
- English architecture diagrams, data/license documentation, operations and breaking-change migration guide.

No model or API keys are required. Data labels are observations, not verified visitor intent. No default rule blocks bots, VPNs or datacenter traffic. Optional country mode requires DB-IP attribution. Global datasets are downloaded by the operator and are not bundled in this release.

See `docs/migration-1.0.md` before upgrading existing integrations. Independently pinned hosted services require their own tested adoption release.
