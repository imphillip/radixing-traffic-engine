import { createHash, randomUUID } from "node:crypto";
import { mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { resolve, dirname } from "node:path";
import { gunzipSync } from "node:zlib";
import { createServer, type IncomingMessage, type Server } from "node:http";
import { parse } from "csv-parse/sync";
import { RE2JS } from "re2js";
import { compileFeatureSnapshot, parseFeatureSnapshot, type AsnRange, type CountryRange, type CrawlerPattern, type FeatureSnapshot, type FeatureSource } from "./features.js";
import { createTds } from "./tds.js";

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
}
const hash = (value: string | Uint8Array) => createHash("sha256").update(value).digest("hex");
function snapshotHash(snapshot: Pick<FeatureSnapshot, "sources" | "data">): string { return hash(JSON.stringify({ sources: snapshot.sources, data: snapshot.data })); }

async function download(source: SourceDefinition, options: SyncOptions): Promise<Uint8Array> {
  if (!source.url.startsWith("https://")) throw new Error("Feature sources must use HTTPS");
  const controller = new AbortController(), timer = setTimeout(() => controller.abort(), options.timeoutMs ?? 60_000);
  try {
    const response = await (options.fetcher ?? fetch)(source.url, { signal: controller.signal, redirect: "error" });
    if (!response.ok || !response.body) throw new Error(`Source ${source.id}: HTTP ${response.status}`);
    const reader = response.body.getReader(), chunks: Uint8Array[] = [];
    let length = 0;
    try {
      for (;;) {
        const chunk = await reader.read();
        if (chunk.done) break;
        length += chunk.value.length;
        if (length > (options.maxDownloadBytes ?? 32 * 1024 * 1024)) throw new Error(`Source ${source.id}: download too large`);
        chunks.push(chunk.value);
      }
    } finally { await reader.cancel(); }
    const bytes = Buffer.concat(chunks);
    if (!bytes.length) throw new Error(`Source ${source.id}: empty download`);
    return bytes;
  } catch (error) {
    const cause = error as Error & { cause?: { code?: string } };
    throw new Error(`Source ${source.id}: ${cause.message}${cause.cause?.code ? ` (${cause.cause.code})` : ""}`);
  } finally { clearTimeout(timer); }
}

export async function buildFeatureSnapshot(options: SyncOptions = {}, previous?: FeatureSnapshot): Promise<FeatureSnapshot> {
  const definitions = options.sources ?? defaultSources;
  if (!definitions.length || new Set(definitions.map((source) => source.id)).size !== definitions.length) throw new Error("Sources must be non-empty and unique");
  const now = options.now ?? new Date();
  const maxDrop = options.maxDropFraction ?? 0.5;
  if (!Number.isFinite(maxDrop) || maxDrop < 0 || maxDrop > 1) throw new Error("Invalid maximum record drop");
  const snapshot: FeatureSnapshot = { schemaVersion: 1, id: "0".repeat(64), sources: [], data: { asn: [], vpn: [], datacenter: [], crawlers: [], country: [] } };
  // Fetch sequentially to bound peak memory and avoid an incomplete mixed-source activation.
  for (const source of definitions) {
    const raw = await download(source, options);
    const limit = options.maxExpandedBytes ?? 128 * 1024 * 1024;
    const expanded = source.format.endsWith("gzip") ? gunzipSync(raw, { maxOutputLength: limit }) : raw;
    if (expanded.byteLength > limit) throw new Error(`Source ${source.id}: expanded data too large`);
    const content = new TextDecoder("utf-8", { fatal: true }).decode(expanded);
    let records = 0;
    if (source.format === "asn-tsv-gzip") {
      const rows: string[][] = parse(content, { delimiter: "\t", skip_empty_lines: true, relax_quotes: true });
      const ranges: AsnRange[] = [];
      for (const row of rows) {
        if (row.length !== 5 || !/^\d+$/.test(row[2]!)) throw new Error(`Source ${source.id}: malformed TSV`);
        const asn = Number(row[2]);
        if (asn === 0) continue;
        ranges.push({ start: row[0]!, end: row[1]!, asn, country: row[3] === "Unknown" ? "ZZ" : row[3]!, organization: row[4]! });
      }
      snapshot.data.asn.push(...[]); // Large range sets are appended without spreading into function arguments.
      snapshot.data.asn = snapshot.data.asn.concat(ranges);
      records = ranges.length;
    } else if (source.format === "cidr") {
      if (source.id !== "vpn" && source.id !== "datacenter") throw new Error("CIDR source must identify its network label");
      snapshot.data[source.id] = content.split(/\r?\n/).map((line) => line.trim()).filter((line) => line && !line.startsWith("#"));
      records = snapshot.data[source.id].length;
    } else if (source.format === "country-csv-gzip") {
      const rows: string[][] = parse(content, { skip_empty_lines: true });
      snapshot.data.country = rows.map((row): CountryRange => {
        if (row.length !== 3) throw new Error("Malformed country CSV");
        return { start: row[0]!, end: row[1]!, country: row[2]! };
      });
      records = rows.length;
    } else {
      const rows: unknown = JSON.parse(content);
      if (!Array.isArray(rows)) throw new Error("Malformed crawler JSON");
      const patterns: CrawlerPattern[] = [];
      for (const row of rows) {
        if (!row || typeof row.pattern !== "string" || !row.pattern || row.pattern.length > 1024) throw new Error("Malformed crawler entry");
        const pattern = row.pattern.replace(/\\\//g, "/");
        // Reject the entire refresh rather than silently dropping an unsupported upstream rule.
        RE2JS.compile(pattern, RE2JS.CASE_INSENSITIVE);
        patterns.push({ pattern, ...(typeof row.url === "string" ? { url: row.url } : {}) });
      }
      snapshot.data.crawlers = patterns;
      records = patterns.length;
    }
    if (records < source.minRecords) throw new Error(`Source ${source.id}: too few records (${records})`);
    const old = previous?.sources.find((entry) => entry.id === source.id);
    if (old && records < old.records * (1 - maxDrop)) throw new Error(`Source ${source.id}: suspicious record-count drop`);
    snapshot.sources.push({ id: source.id, url: source.url, license: source.license, fetchedAt: now.toISOString(), sha256: hash(raw), records });
  }
  const normalized = parseFeatureSnapshot(snapshot);
  normalized.id = snapshotHash(normalized);
  compileFeatureSnapshot(normalized);
  return normalized;
}

export async function loadFeatureSnapshot(path: string): Promise<FeatureSnapshot> {
  const bytes = await readFile(path);
  if (bytes.length > 256 * 1024 * 1024) throw new Error("Snapshot file too large");
  const snapshot = parseFeatureSnapshot(JSON.parse(bytes.toString("utf8")));
  if (snapshot.id !== snapshotHash(snapshot)) throw new Error("Snapshot checksum mismatch");
  return snapshot;
}
async function atomicWrite(path: string, content: string): Promise<void> {
  const temporary = `${path}.${randomUUID()}.tmp`;
  try { await writeFile(temporary, content, { mode: 0o600 }); await rename(temporary, path); }
  finally { await rm(temporary, { force: true }); }
}
export async function syncFeatureData(directory: string, options: SyncOptions = {}): Promise<FeatureSnapshot> {
  const root = resolve(directory);
  await mkdir(root, { recursive: true });
  const lock = resolve(root, ".sync-lock");
  await mkdir(lock); // One updater owns this directory; a second process fails without touching current.json.
  try {
    let previous: FeatureSnapshot | undefined;
    try { previous = await loadFeatureSnapshot(resolve(root, "current.json")); }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
    const snapshot = await buildFeatureSnapshot(options, previous);
    await mkdir(resolve(root, "snapshots"), { recursive: true });
    const bytes = JSON.stringify(snapshot);
    await atomicWrite(resolve(root, "snapshots", `${snapshot.id}.json`), bytes);
    if (previous) await atomicWrite(resolve(root, "previous.json"), JSON.stringify(previous));
    await atomicWrite(resolve(root, "current.json"), bytes);
    return snapshot;
  } finally { await rm(lock, { recursive: true, force: true }); }
}
export async function rollbackFeatureData(directory: string, snapshotId?: string): Promise<FeatureSnapshot> {
  if (snapshotId !== undefined && !/^[a-f0-9]{64}$/.test(snapshotId)) throw new Error("Invalid snapshot id");
  const root = resolve(directory), lock = resolve(root, ".sync-lock");
  await mkdir(lock);
  try {
    const snapshot = await loadFeatureSnapshot(snapshotId ? resolve(root, "snapshots", `${snapshotId}.json`) : resolve(root, "previous.json"));
    compileFeatureSnapshot(snapshot);
    const previous = await loadFeatureSnapshot(resolve(root, "current.json"));
    await atomicWrite(resolve(root, "previous.json"), JSON.stringify(previous));
    await atomicWrite(resolve(root, "current.json"), JSON.stringify(snapshot));
    return snapshot;
  } finally { await rm(lock, { recursive: true, force: true }); }
}

export interface ServerOptions {
  policyPath: string;
  dataDirectory: string;
  host?: string;
  port?: number;
  refreshIntervalMs?: number;
  reloadIntervalMs?: number;
  maxDataAgeMs?: number;
  sync?: SyncOptions;
  /** Exact socket-peer addresses allowed to supply a single client IP header. */
  trustedProxyPeers?: string[];
  clientIpHeader?: string;
  onEvent?: (event: Record<string, unknown>) => void;
}
export async function startTdsServer(options: ServerOptions): Promise<{ server: Server; refresh(): Promise<void>; close(): Promise<void> }> {
  const policy = JSON.parse(await readFile(options.policyPath, "utf8"));
  const path = resolve(options.dataDirectory, "current.json");
  let snapshot: FeatureSnapshot;
  try { snapshot = await loadFeatureSnapshot(path); }
  catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; snapshot = await syncFeatureData(options.dataDirectory, options.sync); }
  const settings = options.maxDataAgeMs === undefined ? {} : { maxDataAgeMs: options.maxDataAgeMs };
  let engine = createTds(policy, snapshot, settings);
  let busy = false;
  const emit = (event: Record<string, unknown>) => { try { options.onEvent?.(event); } catch { /* Observability must not change execution. */ } };
  async function refresh(): Promise<void> {
    if (busy) return;
    busy = true;
    try {
      const candidate = await syncFeatureData(options.dataDirectory, options.sync);
      const next = createTds(policy, candidate, settings);
      engine = next; snapshot = candidate;
      emit({ type: "data_updated", snapshotId: snapshot.id, sources: snapshot.sources });
    } catch (error) { emit({ type: "data_update_failed", message: (error as Error).message }); throw error; }
    finally { busy = false; }
  }
  const peers = new Set(options.trustedProxyPeers ?? []);
  const headerName = options.clientIpHeader?.toLowerCase();
  if (headerName && !/^[a-z0-9-]+$/.test(headerName)) throw new Error("Invalid client IP header");
  if (peers.size && !headerName) throw new Error("Trusted proxies require an explicit single-IP header");
  function clientIp(request: IncomingMessage): string | undefined {
    const peer = request.socket.remoteAddress;
    if (peer && peers.has(peer) && headerName) {
      const value = request.headers[headerName];
      return typeof value === "string" && !value.includes(",") ? value.trim() : undefined;
    }
    return peer;
  }
  const server = createServer((incoming, outgoing) => {
    try {
      const host = incoming.headers.host;
      if (!host || !/^[a-zA-Z0-9.-]+(?::\d+)?$/.test(host) || !incoming.url?.startsWith("/") || incoming.url.length > 8192) { outgoing.writeHead(400); outgoing.end(); return; }
      const headers = new Headers();
      for (const [name, value] of Object.entries(incoming.headers)) if (value !== undefined) headers.set(name, Array.isArray(value) ? value.join(",") : value);
      const request = new Request(`https://${host}${incoming.url}`, { method: incoming.method ?? "GET", headers });
      const ip = clientIp(incoming);
      const result = engine.handle({ request, ...(ip ? { ip } : {}), now: Date.now() });
      outgoing.writeHead(result.response.status, Object.fromEntries(result.response.headers));
      void result.response.text().then((body) => outgoing.end(body), () => outgoing.end());
      // Decision events contain versions and rule IDs, never raw IP, UA, URL queries or credentials.
      emit({ type: "decision", status: result.response.status, ...(result.decision ? { ruleId: result.decision.ruleId ?? null, configVersion: result.decision.evaluation.configVersion, ...result.decision.evidence } : {}) });
    } catch { outgoing.writeHead(500, { "cache-control": "no-store" }); outgoing.end("TDS execution failed"); }
  });
  server.requestTimeout = 10_000; server.headersTimeout = 10_000;
  const refreshInterval = options.refreshIntervalMs ?? 24 * 3_600_000;
  const reloadInterval = options.reloadIntervalMs ?? 60_000;
  if (![refreshInterval, reloadInterval].every((interval) => Number.isSafeInteger(interval) && interval >= 1_000 && interval <= 2147483647)) throw new Error("Invalid update interval");
  await new Promise<void>((done, reject) => { server.once("error", reject); server.listen(options.port ?? 8787, options.host ?? "127.0.0.1", () => { server.removeListener("error", reject); done(); }); });
  const updateTimer = setInterval(() => { void refresh().catch(() => {}); }, refreshInterval);
  const reloadTimer = setInterval(() => {
    if (busy) return;
    busy = true;
    void loadFeatureSnapshot(path).then((candidate) => {
      if (candidate.id !== snapshot.id) { const next = createTds(policy, candidate, settings); engine = next; snapshot = candidate; emit({ type: "data_reloaded", snapshotId: candidate.id }); }
    }).catch((error: Error) => emit({ type: "data_reload_failed", message: error.message })).finally(() => { busy = false; });
  }, reloadInterval);
  updateTimer.unref(); reloadTimer.unref();
  return { server, refresh, async close() { clearInterval(updateTimer); clearInterval(reloadTimer); await new Promise<void>((done, reject) => server.close((error) => error ? reject(error) : done())); } };
}
