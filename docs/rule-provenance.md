# Probe rule provenance

`PROBE_RULESET_VERSION = 1` recognizes a small set of sensitive path segments. It does not load a remote list or classify arbitrary assets, IP ranges, networks, or visitor identity.

| Local ID | Target |
| --- | --- |
| `env-file` | `.env` and specific suffix forms |
| `vcs-metadata` | `.git` and `.svn` |
| `cloud-credentials` | `.aws` |
| `phpinfo` | `phpinfo` and explicit backup forms |
| `service-account-key` | Explicit service-account JSON filenames |

The original review compared exposure-target ideas in [ProjectDiscovery nuclei-templates](https://github.com/projectdiscovery/nuclei-templates/tree/03b6002657f7a2bd59a7b8c55c6f3df6aa772548), [OWASP Core Rule Set](https://github.com/coreruleset/coreruleset/tree/8d060761d2215bea3ce1fd6e4b611ad2e0641a64), [CrowdSec Hub](https://github.com/crowdsecurity/hub/tree/ec4ddc50bcb9f728ecafdbc1c94320998289bdbb), and [SecLists](https://github.com/danielmiessler/SecLists/tree/8756871d449c9abd5eb23ec219d05e2a0ac5cc1d). These were review inputs; no upstream rule list is vendored.

New evidence patterns require a stable ID, a version bump, positive and negative synthetic tests, and a host-application replay against permitted paths before they are used for routing. A probe match is an observation; only an explicitly configured policy rule can select a block action.
