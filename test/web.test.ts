import { describe, expect, it, vi } from "vitest";
import { createHash } from "node:crypto";
import { gzipSync } from "node:zlib";
import { buildFeatureSnapshot, computeFeatureSnapshotId, defaultSources, type SourceDefinition, type WebSyncOptions } from "../src/web.js";
import { buildFeatureSnapshot as buildNodeSnapshot } from "../src/node.js";
import { compileFeatureSnapshot } from "../src/features.js";

const now = new Date("2026-10-11T00:00:00.000Z");
const sources: SourceDefinition[] = [
  { id: "vpn", url: "https://example.com/vpn", license: "MIT", format: "cidr", minRecords: 1 },
  { id: "datacenter", url: "https://example.com/datacenter", license: "MIT", format: "cidr", minRecords: 1 },
  { id: "crawlers", url: "https://example.com/crawlers", license: "MIT", format: "crawler-json", minRecords: 1 },
];
const payloads: Record<string, string> = { vpn: "# Synthetic prefixes\r\n192.0.2.128/25\r\n", datacenter: "192.0.2.0/24\n", crawlers: JSON.stringify([{ pattern: "ExampleBot\\/", url: "https://example.com/bot" }]) };
function options(changes: Record<string, string> = {}): WebSyncOptions {
  return { sources, now, fetcher: async (url) => new Response(changes[new URL(String(url)).pathname.slice(1)] ?? payloads[new URL(String(url)).pathname.slice(1)]!) };
}

describe("portable feature builder", () => {
  it("produces schema-1 snapshots and byte-identical Node IDs without fetching unselected feeds", async () => {
    const config = options(), calls: string[] = [];
    const candidate = await buildFeatureSnapshot({ ...config, fetcher: async (url, init) => {
      calls.push(String(url)); expect(init?.redirect).toBe("manual"); return config.fetcher!(url, init);
    } });
    expect(calls).toEqual(sources.map((source) => source.url));
    expect(defaultSources.filter((source) => ["vpn", "datacenter", "crawlers"].includes(source.id))).toHaveLength(3);
    expect(candidate).toEqual(await buildNodeSnapshot(config));
    const expectedId = createHash("sha256").update(JSON.stringify({ sources: candidate.sources, data: candidate.data })).digest("hex");
    expect(candidate.id).toBe(expectedId);
    expect(await computeFeatureSnapshotId(candidate)).toBe(expectedId);
    expect(candidate.data.asn).toEqual([]); expect(candidate.data.country).toEqual([]);
    expect(candidate.sources[0]!.sha256).toBe(createHash("sha256").update(payloads.vpn!).digest("hex"));
    expect(compileFeatureSnapshot(candidate).lookup("192.0.2.200", "ExampleBot/1.0", now.getTime(), 1000).signals).toMatchObject({ "network.vpn": true, "network.datacenter": true, "client.bot": true });
  });
  it("awaits host shard validation and rejects a failed validation without modifying previous metadata", async () => {
    const previous = await buildFeatureSnapshot(options()), saved = JSON.stringify(previous);
    let validated = false;
    await buildFeatureSnapshot({ ...options(), validateSnapshot: async (candidate) => {
      await Promise.resolve(); expect(candidate.id).toMatch(/^[a-f0-9]{64}$/); validated = true;
    } }, { sources: previous.sources });
    expect(validated).toBe(true);
    await expect(buildFeatureSnapshot({ ...options(), validateSnapshot() { throw new Error("Invalid shard"); } }, previous)).rejects.toThrow("Invalid shard");
    await expect(buildFeatureSnapshot({ ...options(), validateSnapshot(candidate) { candidate.data.vpn = []; } })).rejects.toThrow("must not mutate");
    expect(JSON.stringify(previous)).toBe(saved);
  });
  it("uses previous source counts alone to reject drops and permits the configured boundary", async () => {
    const previous = await buildFeatureSnapshot(options()); previous.sources[0]!.records = 3;
    await expect(buildFeatureSnapshot(options(), { sources: previous.sources })).rejects.toThrow("record-count drop");
    previous.sources[0]!.records = 2;
    await expect(buildFeatureSnapshot(options(), previous)).resolves.toHaveProperty("schemaVersion", 1);
  });
  it.each([
    { vpn: "bad-prefix\n" }, { crawlers: "[]" },
    { crawlers: JSON.stringify([{ pattern: "(?=bot)" }]) },
    { crawlers: JSON.stringify([{ pattern: "bot", url: "x".repeat(2049) }]) },
  ])("rejects malformed prefixes, undersized feeds and unsupported crawler rules: %j", async (changes) => {
    await expect(buildFeatureSnapshot(options(changes))).rejects.toThrow();
  });
  it("rejects invalid configuration before any download", async () => {
    const fetcher = vi.fn(options().fetcher!);
    const invalid: Partial<WebSyncOptions>[] = [
      { sources: [] }, { sources: [sources[0]!, sources[0]!] },
      { sources: [{ ...sources[0]!, url: "http://example.com/vpn" }] },
      { sources: [{ ...sources[0]!, url: "https://user:password@example.com/vpn" }] },
      { sources: [{ ...sources[0]!, format: "crawler-json" }] },
      { sources: [{ ...sources[0]!, minRecords: 0 }] },
      { timeoutMs: 0 }, { maxDownloadBytes: NaN }, { maxExpandedBytes: -1 },
      { maxRecordsPerSource: 0 }, { maxSnapshotBytes: 1.1 }, { maxDropFraction: 1.1 },
    ];
    for (const config of invalid) await expect(buildFeatureSnapshot({ ...options(), ...config, fetcher })).rejects.toThrow();
    expect(fetcher).not.toHaveBeenCalled();
  });
  it("bounds download, expanded bytes, accepted records and canonical snapshot size", async () => {
    await expect(buildFeatureSnapshot({ ...options(), maxDownloadBytes: 1 })).rejects.toThrow("download too large");
    await expect(buildFeatureSnapshot({ ...options(), maxExpandedBytes: 1 })).rejects.toThrow("expanded data too large");
    await expect(buildFeatureSnapshot({ ...options({ vpn: "192.0.2.0/25\n192.0.2.128/25\n" }), maxRecordsPerSource: 1 })).rejects.toThrow("too many records");
    await expect(buildFeatureSnapshot({ ...options(), maxSnapshotBytes: 1 })).rejects.toThrow("snapshot too large");
  });
  it("rejects redirects and HTTP errors without following their Location", async () => {
    for (const status of [301, 302, 307, 308, 503]) {
      const fetcher = vi.fn(async () => new Response("", { status, headers: { location: "https://other.example.com/" } }));
      await expect(buildFeatureSnapshot({ ...options(), fetcher })).rejects.toThrow(`HTTP ${status}`);
      expect(fetcher).toHaveBeenCalledTimes(1);
    }
  });
  it("cancels an oversized stream and times out stalled headers and body reads", async () => {
    let cancelled = false;
    const oversized = new ReadableStream<Uint8Array>({ pull(controller) { controller.enqueue(new Uint8Array(10)); }, cancel() { cancelled = true; } });
    await expect(buildFeatureSnapshot({ ...options(), maxDownloadBytes: 1, fetcher: async () => new Response(oversized) })).rejects.toThrow("download too large");
    expect(cancelled).toBe(true);
    await expect(buildFeatureSnapshot({ ...options(), timeoutMs: 10, fetcher: () => new Promise<Response>(() => {}) })).rejects.toThrow("timed out");
    cancelled = false;
    const stalled = new ReadableStream<Uint8Array>({ cancel() { cancelled = true; } });
    await expect(buildFeatureSnapshot({ ...options(), timeoutMs: 10, fetcher: async () => new Response(stalled) })).rejects.toThrow("timed out");
    expect(cancelled).toBe(true);
  });
  it("uses standard gzip decompression with bounded expansion and normalized ASN/country rows", async () => {
    const definitions: SourceDefinition[] = [
      { id: "iptoasn-v4", url: "https://example.com/asn", license: "PDDL-1.0", format: "asn-tsv-gzip", minRecords: 1 },
      { id: "dbip-country", url: "https://example.com/country", license: "CC-BY-4.0", format: "country-csv-gzip", minRecords: 1 },
    ];
    const config: WebSyncOptions = { sources: definitions, now, fetcher: async (url) => new Response(new Uint8Array(gzipSync(String(url).endsWith("asn")
      ? "192.0.2.0\t192.0.2.255\t64500\tUnknown\tExample Network\n"
      : '"192.0.2.0","192.0.2.255","US"\n'))) };
    const snapshot = await buildFeatureSnapshot(config);
    expect(snapshot).toEqual(await buildNodeSnapshot(config));
    expect(snapshot.data.asn[0]!.country).toBe("ZZ");
    expect(snapshot.data.country[0]!.country).toBe("US");
    await expect(buildFeatureSnapshot({ ...config, maxExpandedBytes: 1 })).rejects.toThrow("expanded data too large");
  });
  it("keeps full index acceptance in Node while allowing the Web host to validate its own shards", async () => {
    const source: SourceDefinition = { id: "iptoasn-v4", url: "https://example.com/asn", license: "PDDL-1.0", format: "asn-tsv-gzip", minRecords: 1 };
    const config: WebSyncOptions = { sources: [source], now, fetcher: async () => new Response(new Uint8Array(gzipSync("192.0.2.0\t192.0.2.255\t64500\tUS\tExample\n192.0.2.0\t192.0.2.127\t64501\tUS\tOverlap\n"))) };
    await expect(buildFeatureSnapshot(config)).resolves.toHaveProperty("schemaVersion", 1);
    await expect(buildFeatureSnapshot({ ...config, validateSnapshot: (candidate) => { compileFeatureSnapshot(candidate); } })).rejects.toThrow("Overlapping");
    await expect(buildNodeSnapshot(config)).rejects.toThrow("Overlapping");
  });
});
