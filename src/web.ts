import { parse } from "csv-parse/browser/esm/sync";
import { RE2JS } from "re2js";
import { parseFeatureSnapshot, type AsnRange, type CountryRange, type CrawlerPattern, type FeatureSnapshot, type FeatureSource } from "./features.js";

export type { FeatureSnapshot, FeatureSource } from "./features.js";

export interface SourceDefinition {
  id: FeatureSource["id"];
  url: string;
  license: string;
  format: "asn-tsv-gzip" | "cidr" | "crawler-json" | "country-csv-gzip";
  minRecords: number;
}
export const defaultSources: readonly SourceDefinition[] = [
  { id: "iptoasn-v4", url: "https://iptoasn.com/data/ip2asn-v4.tsv.gz", license: "PDDL-1.0", format: "asn-tsv-gzip", minRecords: 10_000 },
  { id: "iptoasn-v6", url: "https://iptoasn.com/data/ip2asn-v6.tsv.gz", license: "PDDL-1.0", format: "asn-tsv-gzip", minRecords: 1_000 },
  { id: "vpn", url: "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv4.txt", license: "MIT", format: "cidr", minRecords: 10 },
  { id: "datacenter", url: "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/datacenter/ipv4.txt", license: "MIT", format: "cidr", minRecords: 100 },
  { id: "crawlers", url: "https://raw.githubusercontent.com/monperrus/crawler-user-agents/master/crawler-user-agents.json", license: "MIT", format: "crawler-json", minRecords: 100 },
];
export function countrySource(now = new Date()): SourceDefinition {
  return { id: "dbip-country", url: `https://download.db-ip.com/free/dbip-country-lite-${now.toISOString().slice(0, 7)}.csv.gz`, license: "CC-BY-4.0", format: "country-csv-gzip", minRecords: 10_000 };
}

export interface SyncOptions {
  sources?: readonly SourceDefinition[];
  fetcher?: typeof fetch;
  now?: Date;
  timeoutMs?: number;
  maxDownloadBytes?: number;
  maxExpandedBytes?: number;
  maxDropFraction?: number;
  maxRecordsPerSource?: number;
  maxSnapshotBytes?: number;
  /** Host-specific shard/index checks must finish before return and must not mutate the candidate. */
  validateSnapshot?: (snapshot: FeatureSnapshot) => void | Promise<void>;
}
export interface WebSyncOptions extends SyncOptions {
  /** Explicit selection prevents accidental global ASN/country downloads on small runtimes. */
  sources: readonly SourceDefinition[];
}

async function sha256(bytes: Uint8Array<ArrayBuffer>): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}
/** Hash the normalized schema-1 payload; identical to the Node 1.1 snapshot ID. */
export async function computeFeatureSnapshotId(snapshot: Pick<FeatureSnapshot, "sources" | "data">): Promise<string> {
  return sha256(new TextEncoder().encode(JSON.stringify({ sources: snapshot.sources, data: snapshot.data })));
}

function positive(value: number, name: string, maximum = Number.MAX_SAFE_INTEGER): number {
  if (!Number.isSafeInteger(value) || value < 1 || value > maximum) throw new Error(`Invalid ${name}`);
  return value;
}

function abortable<T>(promise: Promise<T>, signal: AbortSignal): Promise<T> {
  if (signal.aborted) return Promise.reject(signal.reason);
  return new Promise<T>((resolve, reject) => {
    const abort = () => reject(signal.reason);
    signal.addEventListener("abort", abort, { once: true });
    promise.then(resolve, reject).finally(() => signal.removeEventListener("abort", abort));
  });
}

async function readBounded(stream: ReadableStream<Uint8Array>, limit: number, message: string, signal?: AbortSignal): Promise<Uint8Array<ArrayBuffer>> {
  const reader = stream.getReader(), chunks: Uint8Array[] = [];
  let length = 0;
  try {
    for (;;) {
      const chunk = await (signal ? abortable(reader.read(), signal) : reader.read());
      if (chunk.done) break;
      length += chunk.value.byteLength;
      if (length > limit) throw new Error(message);
      chunks.push(chunk.value);
    }
  } finally {
    // Cancellation must not delay an already-failed refresh on an unresponsive stream.
    void reader.cancel().catch(() => {});
  }
  const bytes = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
  return bytes;
}

async function download(source: SourceDefinition, options: SyncOptions): Promise<Uint8Array<ArrayBuffer>> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(new Error("download timed out")), options.timeoutMs ?? 60_000);
  try {
    // Workers supports manual redirects; reject their non-2xx responses without following them.
    const response = await abortable((options.fetcher ?? fetch)(source.url, { signal: controller.signal, redirect: "manual" }), controller.signal);
    if (!response.ok || !response.body || response.redirected) {
      void response.body?.cancel().catch(() => {});
      throw new Error(`HTTP ${response.status}${response.redirected ? " (redirect refused)" : ""}`);
    }
    const bytes = await readBounded(response.body, options.maxDownloadBytes ?? 4 * 1024 * 1024, "download too large", controller.signal);
    if (!bytes.length) throw new Error("empty download");
    return bytes;
  } catch (error) {
    const cause = error as Error & { cause?: { code?: string } };
    throw new Error(`Source ${source.id}: ${cause.message}${cause.cause?.code ? ` (${cause.cause.code})` : ""}`);
  } finally { clearTimeout(timer); }
}

async function expand(raw: Uint8Array<ArrayBuffer>, source: SourceDefinition, limit: number): Promise<Uint8Array<ArrayBuffer>> {
  if (!source.format.endsWith("gzip")) {
    if (raw.byteLength > limit) throw new Error(`Source ${source.id}: expanded data too large`);
    return raw;
  }
  const input = new ReadableStream<BufferSource>({ start(controller) { controller.enqueue(raw); controller.close(); } });
  return readBounded(input.pipeThrough(new DecompressionStream("gzip")), limit, `Source ${source.id}: expanded data too large`);
}

function validateDefinitions(definitions: readonly SourceDefinition[]): void {
  if (!definitions.length || new Set(definitions.map((source) => source.id)).size !== definitions.length) throw new Error("Sources must be non-empty and unique");
  const formats: Record<FeatureSource["id"], SourceDefinition["format"]> = {
    "iptoasn-v4": "asn-tsv-gzip", "iptoasn-v6": "asn-tsv-gzip", vpn: "cidr", datacenter: "cidr", crawlers: "crawler-json", "dbip-country": "country-csv-gzip",
  };
  for (const source of definitions) {
    const url = new URL(source.url);
    if (url.protocol !== "https:" || url.username || url.password || url.hash || source.url.length > 2048) throw new Error("Feature sources must use credential-free HTTPS");
    if (!Object.hasOwn(formats, source.id) || formats[source.id] !== source.format) throw new Error(`Source ${source.id}: incompatible format`);
    if (typeof source.license !== "string" || !source.license || source.license.length > 128) throw new Error("Invalid source license");
    positive(source.minRecords, "minimum records");
  }
}

export async function buildFeatureSnapshot(options: WebSyncOptions, previous?: Pick<FeatureSnapshot, "sources">): Promise<FeatureSnapshot> {
  const definitions = options.sources;
  validateDefinitions(definitions);
  positive(options.timeoutMs ?? 60_000, "timeout", 2147483647);
  positive(options.maxDownloadBytes ?? 4 * 1024 * 1024, "download limit");
  const expandedLimit = positive(options.maxExpandedBytes ?? 8 * 1024 * 1024, "expanded limit");
  const recordLimit = positive(options.maxRecordsPerSource ?? 100_000, "record limit");
  const snapshotLimit = positive(options.maxSnapshotBytes ?? 16 * 1024 * 1024, "snapshot limit");
  const now = options.now ?? new Date(), fetchedAt = now.toISOString();
  const maxDrop = options.maxDropFraction ?? 0.5;
  if (!Number.isFinite(maxDrop) || maxDrop < 0 || maxDrop > 1) throw new Error("Invalid maximum record drop");
  if (previous && (new Set(previous.sources.map((source) => source.id)).size !== previous.sources.length || previous.sources.some((source) => !Number.isSafeInteger(source.records) || source.records < 1))) throw new Error("Invalid previous source counts");
  const snapshot: FeatureSnapshot = { schemaVersion: 1, id: "0".repeat(64), sources: [], data: { asn: [], vpn: [], datacenter: [], crawlers: [], country: [] } };
  // Sequential downloads bound memory. No partial candidate is returned or published.
  for (const source of definitions) {
    const raw = await download(source, options);
    const expanded = await expand(raw, source, expandedLimit);
    const content = new TextDecoder("utf-8", { fatal: true }).decode(expanded);
    let records = 0;
    if (source.format === "asn-tsv-gzip") {
      const rows: string[][] = parse(content, { delimiter: "\t", skip_empty_lines: true, relax_quotes: true });
      const ranges: AsnRange[] = [];
      for (const row of rows) {
        if (row.length !== 5 || !/^\d+$/.test(row[2]!)) throw new Error(`Source ${source.id}: malformed TSV`);
        const asn = Number(row[2]);
        if (asn === 0) continue;
        if (ranges.length >= recordLimit) throw new Error(`Source ${source.id}: too many records`);
        ranges.push({ start: row[0]!, end: row[1]!, asn, country: row[3] === "Unknown" ? "ZZ" : row[3]!, organization: row[4]! });
      }
      snapshot.data.asn = snapshot.data.asn.concat(ranges);
      records = ranges.length;
    } else if (source.format === "cidr") {
      if (source.id !== "vpn" && source.id !== "datacenter") throw new Error("CIDR source must identify its network label");
      const prefixes = content.split(/\r?\n/).map((line) => line.trim()).filter((line) => line && !line.startsWith("#"));
      snapshot.data[source.id] = prefixes;
      records = prefixes.length;
    } else if (source.format === "country-csv-gzip") {
      const rows: string[][] = parse(content, { skip_empty_lines: true });
      if (rows.length > recordLimit) throw new Error(`Source ${source.id}: too many records`);
      snapshot.data.country = rows.map((row): CountryRange => {
        if (row.length !== 3) throw new Error("Malformed country CSV");
        return { start: row[0]!, end: row[1]!, country: row[2]! };
      });
      records = rows.length;
    } else {
      const rows: unknown = JSON.parse(content);
      if (!Array.isArray(rows)) throw new Error("Malformed crawler JSON");
      if (rows.length > recordLimit) throw new Error(`Source ${source.id}: too many records`);
      const patterns: CrawlerPattern[] = [];
      for (const row of rows) {
        if (!row || typeof row.pattern !== "string" || !row.pattern || row.pattern.length > 1024) throw new Error("Malformed crawler entry");
        const pattern = row.pattern.replace(/\\\//g, "/");
        RE2JS.compile(pattern, RE2JS.CASE_INSENSITIVE);
        patterns.push({ pattern, ...(typeof row.url === "string" ? { url: row.url } : {}) });
      }
      snapshot.data.crawlers = patterns;
      records = patterns.length;
    }
    if (records > recordLimit) throw new Error(`Source ${source.id}: too many records`);
    if (records < source.minRecords) throw new Error(`Source ${source.id}: too few records (${records})`);
    const old = previous?.sources.find((entry) => entry.id === source.id);
    if (old && records < old.records * (1 - maxDrop)) throw new Error(`Source ${source.id}: suspicious record-count drop`);
    snapshot.sources.push({ id: source.id, url: source.url, license: source.license, fetchedAt, sha256: await sha256(raw), records });
  }
  const normalized = parseFeatureSnapshot(snapshot);
  const bytes = new TextEncoder().encode(JSON.stringify({ sources: normalized.sources, data: normalized.data }));
  if (bytes.byteLength > snapshotLimit) throw new Error("Feature snapshot too large");
  normalized.id = await sha256(bytes);
  if (options.validateSnapshot) {
    const id = normalized.id;
    await options.validateSnapshot(normalized);
    if (normalized.id !== id || await computeFeatureSnapshotId(normalized) !== id) throw new Error("Snapshot validation must not mutate the candidate");
  }
  return normalized;
}
