#!/usr/bin/env node
import { parseArgs } from "node:util";
import { defaultSources, countrySource, syncFeatureData, rollbackFeatureData, startTdsServer } from "./node.js";

const { values, positionals } = parseArgs({ allowPositionals: true, options: {
  data: { type: "string", default: ".tds-data" }, policy: { type: "string", default: "examples/policy.json" },
  host: { type: "string", default: "127.0.0.1" }, port: { type: "string", default: "8787" },
  "refresh-hours": { type: "string", default: "24" }, "max-age-hours": { type: "string", default: "168" },
  country: { type: "boolean", default: false }, snapshot: { type: "string" },
  "trusted-proxy": { type: "string", multiple: true }, "client-ip-header": { type: "string" },
  "no-sensitive-path-protection": { type: "boolean", default: false }, "no-path-enumeration-protection": { type: "boolean", default: false },
  "max-tracked-sources": { type: "string", default: "4096" },
  help: { type: "boolean", default: false },
} });
function number(value: string, name: string, min: number, max: number): number {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed < min || parsed > max) throw new Error(`Invalid ${name}`);
  return parsed;
}
async function main() {
  if (values.help || !positionals.length) {
    console.log("Radixing TDS 1.1.0\nCommands: sync, serve, rollback\nOptions: --data DIR --policy FILE --host ADDRESS --port PORT --refresh-hours HOURS --max-age-hours HOURS --country --snapshot SHA256 --trusted-proxy PEER --client-ip-header HEADER --max-tracked-sources COUNT --no-sensitive-path-protection --no-path-enumeration-protection\nScanner protection is enabled by default. Country data is opt-in and requires DB-IP attribution. No model or API keys are used.");
    return;
  }
  if (positionals.length !== 1) throw new Error("Expected one command");
  const sources = [...defaultSources, ...(values.country ? [countrySource()] : [])];
  if (positionals[0] === "sync") {
    const snapshot = await syncFeatureData(values.data, { sources });
    console.log(JSON.stringify({ snapshotId: snapshot.id, sources: snapshot.sources }));
  } else if (positionals[0] === "rollback") {
    const snapshot = await rollbackFeatureData(values.data, values.snapshot);
    console.log(JSON.stringify({ snapshotId: snapshot.id, rolledBack: true }));
  } else if (positionals[0] === "serve") {
    const port = number(values.port, "port", 1, 65535);
    if (!Number.isInteger(port)) throw new Error("Port must be an integer");
    const runtime = await startTdsServer({ policyPath: values.policy, dataDirectory: values.data, host: values.host, port,
      refreshIntervalMs: number(values["refresh-hours"], "refresh-hours", 1, 24 * 24) * 3_600_000,
      maxDataAgeMs: number(values["max-age-hours"], "max-age-hours", 1, 24 * 365) * 3_600_000,
      maxTrackedSources: number(values["max-tracked-sources"], "max-tracked-sources", 1, 65_536),
      scannerProtection: { sensitivePaths: !values["no-sensitive-path-protection"], pathEnumeration: !values["no-path-enumeration-protection"] },
      sync: values.country ? { get sources() { return [...defaultSources, countrySource()]; } } : { sources },
      ...(values["trusted-proxy"] ? { trustedProxyPeers: values["trusted-proxy"] } : {}),
      ...(values["client-ip-header"] ? { clientIpHeader: values["client-ip-header"] } : {}),
      onEvent: (event) => console.log(JSON.stringify(event)),
    });
    console.log(JSON.stringify({ type: "listening", host: values.host, port }));
    for (const signal of ["SIGINT", "SIGTERM"] as const) process.once(signal, () => { void runtime.close().then(() => process.exit(0)); });
  } else throw new Error("Unknown command");
}
void main().catch((error: Error) => { console.error(error.message); process.exitCode = 1; });
