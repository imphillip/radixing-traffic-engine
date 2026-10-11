import { createHash, randomUUID } from "node:crypto";
import { mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { resolve, dirname } from "node:path";
import { createServer, type IncomingMessage, type Server } from "node:http";
import { compileFeatureSnapshot, parseFeatureSnapshot, type FeatureSnapshot } from "./features.js";
import { buildFeatureSnapshot as buildWebFeatureSnapshot, defaultSources, type SyncOptions } from "./web.js";
import { createTds, type ScannerProtectionOptions } from "./tds.js";
import { parsePublishedConfig } from "./policy.js";
import { createScannerTracker } from "./scanner-tracker.js";
export { createScannerTracker } from "./scanner-tracker.js";

export { defaultSources, countrySource, type SourceDefinition, type SyncOptions } from "./web.js";
const hash = (value: string | Uint8Array) => createHash("sha256").update(value).digest("hex");
function snapshotHash(snapshot: Pick<FeatureSnapshot, "sources" | "data">): string { return hash(JSON.stringify({ sources: snapshot.sources, data: snapshot.data })); }

export async function buildFeatureSnapshot(options: SyncOptions = {}, previous?: FeatureSnapshot): Promise<FeatureSnapshot> {
  const snapshot = await buildWebFeatureSnapshot({
    maxDownloadBytes: 32 * 1024 * 1024, maxExpandedBytes: 128 * 1024 * 1024,
    maxRecordsPerSource: 3_000_000, maxSnapshotBytes: 256 * 1024 * 1024,
    ...options, sources: options.sources ?? defaultSources,
  }, previous);
  compileFeatureSnapshot(snapshot);
  return snapshot;
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
  scannerProtection?: ScannerProtectionOptions;
  maxTrackedSources?: number;
  sync?: SyncOptions;
  /** Exact socket-peer addresses allowed to supply a single client IP header. */
  trustedProxyPeers?: string[];
  clientIpHeader?: string;
  onEvent?: (event: Record<string, unknown>) => void;
}
export async function startTdsServer(options: ServerOptions): Promise<{ server: Server; refresh(): Promise<void>; close(): Promise<void> }> {
  const policy = parsePublishedConfig(JSON.parse(await readFile(options.policyPath, "utf8")));
  const path = resolve(options.dataDirectory, "current.json");
  let snapshot: FeatureSnapshot;
  try { snapshot = await loadFeatureSnapshot(path); }
  catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; snapshot = await syncFeatureData(options.dataDirectory, options.sync); }
  const settings = { ...(options.maxDataAgeMs === undefined ? {} : { maxDataAgeMs: options.maxDataAgeMs }),
    ...(options.scannerProtection ? { scannerProtection: { ...options.scannerProtection } } : {}) };
  let engine = createTds(policy, snapshot, settings);
  const tracker = createScannerTracker(options.maxTrackedSources);
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
      const now = Date.now(), entry = new URL(request.url);
      const eligible = settings.scannerProtection?.pathEnumeration !== false && policy.domains.includes(entry.hostname.toLowerCase()) && ["GET", "HEAD"].includes(request.method);
      const behavior = eligible ? tracker.observe(entry.hostname, ip, entry.pathname, now) : undefined;
      const result = engine.handle({ request, ...(ip ? { ip } : {}), now,
        ...(behavior ? { trustedSignals: { "request.pathEnumeration": behavior.pathEnumeration } } : {}) });
      outgoing.writeHead(result.response.status, Object.fromEntries(result.response.headers));
      void result.response.text().then((body) => outgoing.end(body), () => outgoing.end());
      // Decision events contain versions and rule IDs, never raw IP, UA, URL queries or credentials.
      emit({ type: "decision", status: result.response.status, ...(eligible ? { behaviorAvailable: behavior !== undefined } : {}), ...(result.decision ? { ruleId: result.decision.ruleId ?? null, configVersion: result.decision.evaluation.configVersion, ...result.decision.evidence } : {}) });
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
