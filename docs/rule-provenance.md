# Probe rule provenance

`PROBE_RULESET_VERSION = 2` recognizes a small set of sensitive path segments. It does not load a remote list or classify arbitrary assets, IP ranges, networks, or visitor identity. Version 2 preserves the five target categories and checks raw paths plus at most two percent-decoding rounds, treating backslashes as separators. A malformed unrelated segment cannot hide an otherwise recognized target; unrecognized malformed input remains unknown. This is bounded normalization, not a complete application-specific URL canonicalizer.

| Local ID | Target |
| --- | --- |
| `env-file` | `.env` and specific suffix forms |
| `vcs-metadata` | `.git` and `.svn` |
| `cloud-credentials` | `.aws` |
| `phpinfo` | `phpinfo` and explicit backup forms |
| `service-account-key` | Explicit service-account JSON filenames |

The original review compared exposure-target ideas in [ProjectDiscovery nuclei-templates](https://github.com/projectdiscovery/nuclei-templates/tree/03b6002657f7a2bd59a7b8c55c6f3df6aa772548), [OWASP Core Rule Set](https://github.com/coreruleset/coreruleset/tree/8d060761d2215bea3ce1fd6e4b611ad2e0641a64), [CrowdSec Hub](https://github.com/crowdsecurity/hub/tree/ec4ddc50bcb9f728ecafdbc1c94320998289bdbb), and [SecLists](https://github.com/danielmiessler/SecLists/tree/8756871d449c9abd5eb23ec219d05e2a0ac5cc1d). These were review inputs; no upstream rule list is vendored.

New evidence patterns require a stable ID, a version bump, positive and negative synthetic tests, and a host-application replay against permitted paths before they are used for routing. The low-level analyzer returns an observation. Since 1.1, `createTds` maps a recognized sensitive target to a default 404 before project rules. [Scanner protection](scanner-protection.md) documents explicit runtime overrides and the separate enumeration guard. Matching an exposure target does not establish the visitor's identity or motive.
