# Operations

## Deployment

Build with Node.js 22 or later, sync data once, and start the standalone service with a reviewed project policy. The service listens on loopback by default. Put it behind your TLS reverse proxy, with the configured hostname preserved in the Host header. It is an HTTP redirect service, not an origin proxy or merchant management application.

```sh
npm ci
npm run data:sync -- --data .tds-data
npm start -- --policy /path/to/policy.json --data .tds-data --host 127.0.0.1 --port 8787
```

Full global data is compiled in memory. The initial default-feed smoke check used about 1.16 GiB peak RSS and 3.8 seconds to compile on one development machine; these are observations, not capacity guarantees. Allow substantial extra headroom for refreshing and compiling a second engine, and measure your own workload before deployment. Retain only necessary history under `snapshots/` according to your disk budget. Global snapshots are not suitable for blindly bundling into a small edge isolate.

## Client IP trust

Direct mode uses the socket peer and ignores all claimed forwarded IP headers. When running behind a trusted reverse proxy, configure exact socket-peer addresses and a header that the proxy overwrites with one actual client IP:

```sh
npm start -- --trusted-proxy 127.0.0.1 --client-ip-header x-real-ip
```

Peer comparison is exact, including IPv4-mapped IPv6 spelling when applicable. Lists of forwarded addresses are not accepted. An absent, invalid or multi-address trusted header leaves client IP unknown. Do not configure a public listener to trust arbitrary peers. The core takes `ip` explicitly from the host rather than guessing its trust from headers.

## Default scanner protection

Sensitive-file probes return 404 before project routing. The standalone runtime also tracks path enumeration by ingress hostname and trusted IP, returning 403 after 60 requests covering at least 40 paths in 15 seconds, with a fixed 60-second cooldown. Tracking is bounded to 4096 sources by default and survives dataset swaps; it is process-local and resets on restart. Read [scanner protection](scanner-protection.md) before using this ingress guard on shared-IP or asset/API workloads.

`--max-tracked-sources COUNT` changes capacity. `--no-sensitive-path-protection` and `--no-path-enumeration-protection` independently disable the corresponding default guard when explicitly needed. Neither changes explicit project rules. New sources at capacity or sources without a valid trusted IP receive no enumeration evidence; sensitive-path checks and project routing continue.

## Updates and rollback

Default automatic refresh interval: 24 hours. Maximum source age: 168 hours. External file reload interval: 60 seconds. No background scheduler or remote provider is used by the synchronous core.

A directory lock prevents concurrent sync/rollback writers. Source download, structural validation, record-count checks and compilation must all succeed before activation. The updater writes immutable history and previous-version data, then atomically replaces `current.json` on the same filesystem. A failed update leaves the active file and in-memory engine unchanged. Source facts eventually expire if refresh remains broken; configured default routing continues.

```sh
node dist/cli.js sync --data .tds-data
node dist/cli.js rollback --data .tds-data
node dist/cli.js rollback --data .tds-data --snapshot FULL_SHA256_ID
```

Manual rollback reloads within one minute. Automatic refresh can publish fresh data again at its next interval; suspend the updater or adjust its configuration when a rollback must remain pinned. Policy changes require a restart and do not happen through dataset refresh.

The lock is `.sync-lock/` inside the data directory. An abruptly killed updater can leave it behind. Confirm no sync/rollback process owns the directory before removing that lock. Temporary files and snapshot history are local operational data and must not be committed to this repository.

If no snapshot exists, startup requires a successful sync. A malformed or corrupt existing snapshot fails startup rather than silently replacing local state. Corrupt reloads leave the existing in-memory engine active. Checksums are integrity checks, not a defense against a malicious local administrator.

## Observability and privacy

Standalone stdout emits listening, update, reload and decision events. Decision events include response status, rule ID, policy version, snapshot ID and source evidence. Protection blocks include versioned `protection` evidence and `parser: null`; eligible requests expose `behaviorAvailable` so missing IP or tracking saturation is visible. They omit raw IP, path, UA, request queries and authorization headers. Model calls and API-key configuration do not exist.

Applications that need actual IP/environment storage can collect it separately within their authorized boundary. Exclude credentials, request bodies and sensitive query values. Dataset metadata is public-source operational information, not visitor data.

`startTdsServer` accepts an `onEvent` callback; callback failures do not alter routing. Export versions/statuses to your own monitoring. Repeated refresh failures, increasing stale sources, unavailable behavior tracking and disk/memory exhaustion require operator attention.

## Refresh configuration

`--country` opts into DB-IP and its attribution requirements. The current month's country file is selected on each refresh; all-source atomicity means a missing monthly file preserves the preceding complete snapshot. Custom deployments can use `SyncOptions.sources`, a host-supplied fetcher and size/deadline/count-drop limits. Source format and label IDs are fixed; use the documented parsers and preserve license/source metadata.

Weekly Dependabot updates are proposals for dependency releases. They do not automatically change live parser behavior. Review source changes and tests before publishing or deploying a new TDS package.
