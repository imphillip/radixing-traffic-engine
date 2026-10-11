import { afterEach, describe, expect, it } from "vitest";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gzipSync } from "node:zlib";
import { request as httpRequest } from "node:http";
import { buildFeatureSnapshot, loadFeatureSnapshot, rollbackFeatureData, startTdsServer, syncFeatureData, type SourceDefinition, type SyncOptions } from "../src/node.js";
import { compileFeatureSnapshot } from "../src/features.js";
import { policy } from "./fixtures.js";

const definitions: SourceDefinition[] = [
  { id: "iptoasn-v4", url: "https://example.com/asn", license: "PDDL-1.0", format: "asn-tsv-gzip", minRecords: 1 },
  { id: "vpn", url: "https://example.com/vpn", license: "MIT", format: "cidr", minRecords: 1 },
  { id: "datacenter", url: "https://example.com/datacenter", license: "MIT", format: "cidr", minRecords: 1 },
  { id: "crawlers", url: "https://example.com/crawlers", license: "MIT", format: "crawler-json", minRecords: 1 },
];
const payload: Record<string, string> = { asn: "192.0.2.0\t192.0.2.255\t64500\tUnknown\tExample Network\n", vpn: "192.0.2.128/25\n", datacenter: "192.0.2.0/24\n", crawlers: JSON.stringify([{ pattern: "ExampleBot\\/", url: "https://example.com/bot" }]) };
function options(changes: Record<string, string> = {}, now = new Date()): SyncOptions {
  return { sources: definitions, now, fetcher: (async (input) => {
    const name = new URL(String(input)).pathname.slice(1);
    const text = changes[name] ?? payload[name]!;
    return new Response(name === "asn" ? new Uint8Array(gzipSync(text)) : text);
  }) as typeof fetch };
}
const directories: string[] = [];
async function directory() { const path = await mkdtemp(join(tmpdir(), "tds-test-")); directories.push(path); return path; }
function wire(url: string, options: { headers?: Record<string, string>; method?: string } = {}): Promise<Response> {
  return new Promise((done, reject) => {
    const request = httpRequest(url, options, (response) => {
      const chunks: Buffer[] = [];
      response.on("data", (chunk: Buffer) => chunks.push(chunk));
      response.on("end", () => done(new Response(Buffer.concat(chunks).length ? Buffer.concat(chunks) : null, { status: response.statusCode!, headers: Object.fromEntries(Object.entries(response.headers).filter((entry) => typeof entry[1] === "string")) as Record<string, string> })));
    });
    request.on("error", reject); request.end();
  });
}
afterEach(async () => { for (const path of directories.splice(0)) await rm(path, { recursive: true, force: true }); });

describe("automated data lifecycle", () => {
  it("parses real feed formats, normalizes unknown country and persists a verified snapshot", async () => {
    const path = await directory(), snapshot = await syncFeatureData(path, options());
    const loaded = await loadFeatureSnapshot(join(path, "current.json"));
    expect(loaded).toEqual(snapshot);
    const signals = compileFeatureSnapshot(loaded).lookup("192.0.2.200", "ExampleBot/1.0", Date.now(), 10_000).signals;
    expect(signals).toMatchObject({ "network.asn": 64500, "network.vpn": true, "client.bot": true });
    expect(signals["network.country"]).toBeUndefined();
    expect(snapshot.sources.every((source) => /^[a-f0-9]{64}$/.test(source.sha256))).toBe(true);
  });
  it("never activates a partial refresh, invalid regex, empty feed or suspicious data drop", async () => {
    const path = await directory(); await syncFeatureData(path, options());
    const original = await readFile(join(path, "current.json"), "utf8");
    for (const changes of [{ datacenter: "garbage" }, { crawlers: "[]" }, { crawlers: JSON.stringify([{ pattern: "(?=bot)" }]) }, { asn: "not\ta\tvalid\tfeed" }]) {
      await expect(syncFeatureData(path, options(changes))).rejects.toThrow();
      expect(await readFile(join(path, "current.json"), "utf8")).toBe(original);
    }
    const previous = await loadFeatureSnapshot(join(path, "current.json")); previous.sources[0]!.records = 100;
    await expect(buildFeatureSnapshot(options(), previous)).rejects.toThrow("record-count drop");
  });
  it("rolls back to previous or selected snapshot and rejects file tampering", async () => {
    const path = await directory(), first = await syncFeatureData(path, options());
    const second = await syncFeatureData(path, options({ vpn: "198.51.100.0/24\n" }));
    expect(second.id).not.toBe(first.id);
    expect((await rollbackFeatureData(path)).id).toBe(first.id);
    expect((await rollbackFeatureData(path, second.id)).id).toBe(second.id);
    await expect(rollbackFeatureData(path, "../../current")).rejects.toThrow("Invalid snapshot");
    const changed = await loadFeatureSnapshot(join(path, "current.json")); changed.data.vpn = ["203.0.113.0/24"];
    await writeFile(join(path, "current.json"), JSON.stringify(changed));
    await expect(loadFeatureSnapshot(join(path, "current.json"))).rejects.toThrow("checksum mismatch");
  });
  it("bounds downloads and expansion and releases the updater lock after failure", async () => {
    const path = await directory();
    await expect(syncFeatureData(path, { ...options(), maxDownloadBytes: 1 })).rejects.toThrow("download too large");
    await expect(syncFeatureData(path, { ...options(), maxExpandedBytes: 1 })).rejects.toThrow();
    await expect(syncFeatureData(path, options())).resolves.toHaveProperty("schemaVersion", 1);
  });
  it("serializes concurrent refreshes and retains the previous source on HTTP failure", async () => {
    const path = await directory(); await syncFeatureData(path, options());
    const previous = await readFile(join(path, "current.json"), "utf8");
    let release: (() => void) | undefined, entered: (() => void) | undefined;
    const waiting = new Promise<void>((done) => { entered = done; });
    const gate = new Promise<void>((done) => { release = done; });
    const config = options(), fetcher = config.fetcher!;
    const running = syncFeatureData(path, { ...config, fetcher: (async (...args) => { entered!(); await gate; return fetcher(...args); }) as typeof fetch });
    await waiting;
    await expect(syncFeatureData(path, options())).rejects.toThrow();
    release!(); await running;
    const stable = await readFile(join(path, "current.json"), "utf8");
    await expect(syncFeatureData(path, { ...options(), fetcher: (async () => new Response("unavailable", { status: 503 })) as typeof fetch })).rejects.toThrow("HTTP 503");
    expect(await readFile(join(path, "current.json"), "utf8")).toBe(stable);
    expect(previous.length).toBeGreaterThan(0);
  });
});

describe("standalone TDS", () => {
  it("applies standard scan defenses over HTTP while ignoring query diversity and untrusted source claims", async () => {
    const path = await directory(), policyPath = join(path, "policy.json"), events: Record<string, unknown>[] = [];
    await writeFile(policyPath, JSON.stringify(policy));
    const runtime = await startTdsServer({ policyPath, dataDirectory: path, port: 0, sync: options(),
      trustedProxyPeers: ["127.0.0.1"], clientIpHeader: "x-real-ip", maxTrackedSources: 2,
      onEvent: (event) => events.push(event) });
    try {
      const address = runtime.server.address(); if (!address || typeof address === "string") throw new Error("Missing address");
      const base = `http://127.0.0.1:${address.port}`;
      const headers = { host: "go.example.com", "x-real-ip": "192.0.2.1" };
      expect((await wire(`${base}/unconfigured`, { headers: { ...headers, host: "unknown.example.com" } })).status).toBe(421);
      for (const method of ["GET", "HEAD", "POST"]) expect((await wire(`${base}/%252eenv`, { headers, method })).status).toBe(404);
      const repeated = { host: "go.example.com", "x-real-ip": "192.0.2.2" };
      for (let index = 0; index < 65; index++) expect((await wire(`${base}/landing?utm_source=${index}`, { headers: repeated })).status).toBe(302);
      // The initial GET and HEAD probes already contributed two requests to this source.
      for (let index = 0; index < 56; index++) expect((await wire(`${base}/p-${index}`, { headers })).status).toBe(302);
      expect((await wire(`${base}/p-56`, { headers })).status).toBe(302);
      const triggered = await wire(`${base}/p-57`, { headers });
      expect(triggered.status).toBe(403); expect(triggered.headers.get("location")).toBeNull();
      await runtime.refresh();
      expect((await wire(`${base}/`, { headers })).status).toBe(403);
      expect((await wire(`${base}/landing`, { headers: repeated })).status).toBe(302);
      expect((await wire(`${base}/`, { headers: { ...headers, "x-real-ip": "192.0.2.3" } })).status).toBe(302);
      expect(events.some((event) => event.behaviorAvailable === false)).toBe(true);
      expect(events.some((event) => (event.protection as { kind?: string } | undefined)?.kind === "path-enumeration")).toBe(true);
      expect(JSON.stringify(events)).not.toContain("192.0.2.");
      expect(JSON.stringify(events)).not.toContain("utm_source");
    } finally { await runtime.close(); }
  });
  it("supports explicit standalone scanner protection opt-outs", async () => {
    const path = await directory(), policyPath = join(path, "policy.json");
    await writeFile(policyPath, JSON.stringify(policy));
    const runtime = await startTdsServer({ policyPath, dataDirectory: path, port: 0, sync: options(), scannerProtection: { sensitivePaths: false, pathEnumeration: false } });
    try {
      const address = runtime.server.address(); if (!address || typeof address === "string") throw new Error("Missing address");
      expect((await wire(`http://127.0.0.1:${address.port}/.env`, { headers: { host: "go.example.com" } })).status).toBe(302);
    } finally { await runtime.close(); }
  });
  it("serves real redirects, rejects forged ingress and untrusted IP headers, and preserves service after failed refresh", async () => {
    const path = await directory(), policyPath = join(path, "policy.json"), events: Record<string, unknown>[] = [];
    const configured = { ...policy, rules: [{ id: "network", name: "Network", enabled: true, priority: 1, match: "all", conditions: [{ field: "network.vpn", operator: "eq", value: true }], action: { type: "redirect", status: 302, url: "https://app.example.com/" } }] };
    await writeFile(policyPath, JSON.stringify(configured));
    let fail = false;
    const config = options(), fetcher = config.fetcher!;
    const runtime = await startTdsServer({ policyPath, dataDirectory: path, port: 0, sync: { ...config, fetcher: (async (...args) => fail ? new Response("unavailable", { status: 503 }) : fetcher(...args)) as typeof fetch }, onEvent: (event) => events.push(event) });
    try {
      const address = runtime.server.address(); if (!address || typeof address === "string") throw new Error("Missing server address");
      const url = `http://127.0.0.1:${address.port}/`;
      const response = await wire(url, { headers: { host: "go.example.com", "x-forwarded-for": "192.0.2.200", authorization: "Bearer synthetic" } });
      expect(response.status).toBe(302); expect(response.headers.get("location")).toBe("https://www.example.com/");
      expect((await wire(url)).status).toBe(421);
      expect((await wire(url, { method: "POST", headers: { host: "go.example.com" } })).status).toBe(405);
      fail = true; await expect(runtime.refresh()).rejects.toThrow("HTTP 503");
      expect((await wire(url, { headers: { host: "go.example.com" } })).status).toBe(302);
      expect((await wire(`${url}.env`, { headers: { host: "go.example.com" } })).status).toBe(404);
      expect(JSON.stringify(events)).not.toContain("192.0.2.200"); expect(JSON.stringify(events)).not.toContain("Bearer");
    } finally { await runtime.close(); }
  });
  it("uses the configured single-IP header only from the configured socket peer", async () => {
    const path = await directory(), policyPath = join(path, "policy.json");
    await writeFile(policyPath, JSON.stringify({ ...policy, rules: [{ id: "network", name: "Network", enabled: true, priority: 1, match: "all", conditions: [{ field: "network.vpn", operator: "eq", value: true }], action: { type: "redirect", status: 302, url: "https://app.example.com/" } }] }));
    const runtime = await startTdsServer({ policyPath, dataDirectory: path, port: 0, sync: options(), trustedProxyPeers: ["127.0.0.1"], clientIpHeader: "x-real-ip" });
    try {
      const address = runtime.server.address(); if (!address || typeof address === "string") throw new Error("Missing address");
      const url = `http://127.0.0.1:${address.port}/`;
      expect((await wire(url, { headers: { host: "go.example.com", "x-real-ip": "192.0.2.200" } })).headers.get("location")).toBe("https://app.example.com/");
      expect((await wire(url, { headers: { host: "go.example.com", "x-real-ip": "192.0.2.200, 198.51.100.1" } })).headers.get("location")).toBe("https://www.example.com/");
    } finally { await runtime.close(); }
  });
});
