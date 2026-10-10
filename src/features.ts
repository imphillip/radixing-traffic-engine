import ipaddr from "ipaddr.js";
import { RE2JS } from "re2js";
import type { TrafficSignals } from "./policy.js";

export interface FeatureSource {
  id: "iptoasn-v4" | "iptoasn-v6" | "vpn" | "datacenter" | "crawlers" | "dbip-country";
  url: string;
  license: string;
  fetchedAt: string;
  sha256: string;
  records: number;
}
export interface AsnRange { start: string; end: string; asn: number; organization: string; country: string }
export interface CountryRange { start: string; end: string; country: string }
export interface CrawlerPattern { pattern: string; url?: string }
export interface FeatureSnapshot {
  schemaVersion: 1;
  id: string;
  sources: FeatureSource[];
  data: { asn: AsnRange[]; vpn: string[]; datacenter: string[]; crawlers: CrawlerPattern[]; country: CountryRange[] };
}
export interface IpValue { address: string; version: 4 | 6; value: bigint }

export function parseIp(value: string): IpValue {
  // ipaddr.js accepts historical IPv4 notation; ingress only accepts canonical decimal IPv4 or IPv6.
  if (!value.includes(":")) {
    if (!/^\d{1,3}(?:\.\d{1,3}){3}$/.test(value) || value.split(".").some((part) => part.length > 1 && part.startsWith("0"))) throw new Error("Invalid IP address");
  } else if (value.includes("%")) throw new Error("Scoped addresses are unsupported");
  const parsed = ipaddr.process(value);
  const bytes = parsed.toByteArray();
  return { address: parsed.toString(), version: bytes.length === 4 ? 4 : 6,
    value: bytes.reduce((number, byte) => (number << 8n) | BigInt(byte), 0n) };
}

export function cidrRange(value: string): { start: string; end: string } {
  const [address, bits] = ipaddr.parseCIDR(value);
  const bytes = address.toByteArray();
  const total = bytes.length * 8;
  const number = bytes.reduce((result, byte) => (result << 8n) | BigInt(byte), 0n);
  const size = 1n << BigInt(total - bits);
  const start = (number / size) * size;
  const stringify = (number: bigint): string => ipaddr.fromByteArray(Array.from({ length: bytes.length }, (_, index) => Number((number >> BigInt((bytes.length - index - 1) * 8)) & 255n))).toString();
  return { start: stringify(start), end: stringify(start + size - 1n) };
}

function record(value: unknown): value is Record<string, unknown> { return typeof value === "object" && value !== null && !Array.isArray(value); }
function text(value: unknown, limit: number): value is string { return typeof value === "string" && value.length <= limit; }
const sourceIds = new Set(["iptoasn-v4", "iptoasn-v6", "vpn", "datacenter", "crawlers", "dbip-country"]);
const digest = /^[a-f0-9]{64}$/;
const country = /^[A-Z]{2}$/;

export function parseFeatureSnapshot(value: unknown): FeatureSnapshot {
  if (!record(value) || value.schemaVersion !== 1 || typeof value.id !== "string" || !digest.test(value.id) || !Array.isArray(value.sources) || value.sources.length > 6 || !record(value.data)) throw new Error("Invalid feature snapshot");
  const sources = value.sources.map((source): FeatureSource => {
    if (!record(source) || !sourceIds.has(source.id as string) || !text(source.url, 2048) || !source.url.startsWith("https://") || !text(source.license, 128) || !text(source.fetchedAt, 64) || !Number.isFinite(Date.parse(source.fetchedAt)) || !text(source.sha256, 64) || !digest.test(source.sha256) || !Number.isSafeInteger(source.records) || (source.records as number) < 1) throw new Error("Invalid feature source");
    return { id: source.id as FeatureSource["id"], url: source.url, license: source.license, fetchedAt: source.fetchedAt, sha256: source.sha256, records: source.records as number };
  });
  if (new Set(sources.map((source) => source.id)).size !== sources.length) throw new Error("Duplicate feature sources");
  function array(name: string, max: number): unknown[] {
    const entries = (value as Record<string, unknown>).data as Record<string, unknown>;
    if (!Array.isArray(entries[name]) || entries[name].length > max) throw new Error(`Invalid ${name} data`);
    return entries[name] as unknown[];
  }
  const parseRange = (entry: unknown): CountryRange => {
    if (!record(entry) || !text(entry.start, 64) || !text(entry.end, 64) || !text(entry.country, 2) || !country.test(entry.country)) throw new Error("Invalid address range");
    const start = parseIp(entry.start), end = parseIp(entry.end);
    if (start.version !== end.version || start.value > end.value) throw new Error("Invalid address range order");
    return { start: start.address, end: end.address, country: entry.country };
  };
  const asn = array("asn", 3_000_000).map((entry): AsnRange => {
    const range = parseRange(entry);
    if (!record(entry) || !Number.isSafeInteger(entry.asn) || (entry.asn as number) < 1 || (entry.asn as number) > 4294967295 || !text(entry.organization, 1024)) throw new Error("Invalid ASN range");
    return { ...range, asn: entry.asn as number, organization: entry.organization };
  });
  const cidrs = (name: string) => array(name, 500_000).map((entry) => {
    if (!text(entry, 64)) throw new Error("Invalid network prefix");
    cidrRange(entry);
    return entry;
  });
  const crawlers = array("crawlers", 10_000).map((entry): CrawlerPattern => {
    if (!record(entry) || !text(entry.pattern, 1024) || !entry.pattern || (entry.url !== undefined && !text(entry.url, 2048))) throw new Error("Invalid crawler pattern");
    return { pattern: entry.pattern, ...(typeof entry.url === "string" ? { url: entry.url } : {}) };
  });
  return { schemaVersion: 1, id: value.id, sources, data: { asn, vpn: cidrs("vpn"), datacenter: cidrs("datacenter"), crawlers, country: array("country", 3_000_000).map(parseRange) } };
}

interface IndexedRange<T> { start: bigint; end: bigint; value: T }
function rangeIndex<T extends { start: string; end: string }>(ranges: T[]): Map<4 | 6, IndexedRange<T>[]> {
  const index = new Map<4 | 6, IndexedRange<T>[]>([[4, []], [6, []]]);
  for (const range of ranges) {
    const start = parseIp(range.start);
    index.get(start.version)!.push({ start: start.value, end: parseIp(range.end).value, value: range });
  }
  for (const entries of index.values()) {
    entries.sort((left, right) => left.start < right.start ? -1 : left.start > right.start ? 1 : 0);
    for (let i = 1; i < entries.length; i++) if (entries[i]!.start <= entries[i - 1]!.end) throw new Error("Overlapping feature ranges");
  }
  return index;
}
function find<T>(index: Map<4 | 6, IndexedRange<T>[]>, ip: IpValue): T | undefined {
  const entries = index.get(ip.version)!;
  let low = 0, high = entries.length - 1;
  while (low <= high) {
    const middle = (low + high) >>> 1, range = entries[middle]!;
    if (ip.value < range.start) high = middle - 1;
    else if (ip.value > range.end) low = middle + 1;
    else return range.value;
  }
  return undefined;
}
function prefixIndex(prefixes: string[]): Map<4 | 6, IndexedRange<boolean>[]> {
  const grouped = new Map<4 | 6, IndexedRange<boolean>[]>([[4, []], [6, []]]);
  for (const prefix of prefixes) {
    const range = cidrRange(prefix), start = parseIp(range.start);
    grouped.get(start.version)!.push({ start: start.value, end: parseIp(range.end).value, value: true });
  }
  for (const [version, ranges] of grouped) {
    ranges.sort((left, right) => left.start < right.start ? -1 : left.start > right.start ? 1 : 0);
    const merged: IndexedRange<boolean>[] = [];
    for (const range of ranges) {
      const last = merged.at(-1);
      if (last && range.start <= last.end + 1n) last.end = last.end > range.end ? last.end : range.end;
      else merged.push({ ...range });
    }
    grouped.set(version, merged);
  }
  return grouped;
}

export interface FeatureIndex {
  id: string;
  sources: FeatureSource[];
  lookup(ip: string | undefined, ua: string | undefined, now: number, maxAgeMs: number): { signals: TrafficSignals; staleSources: string[]; matchedSources: string[] };
}
export function compileFeatureSnapshot(input: unknown): FeatureIndex {
  const snapshot = parseFeatureSnapshot(input);
  const asn = rangeIndex(snapshot.data.asn), geo = rangeIndex(snapshot.data.country);
  const vpn = prefixIndex(snapshot.data.vpn), datacenter = prefixIndex(snapshot.data.datacenter);
  const crawler = snapshot.data.crawlers.length ? RE2JS.compile(snapshot.data.crawlers.map((entry) => `(?:${entry.pattern.replace(/\\\//g, "/")})`).join("|"), RE2JS.CASE_INSENSITIVE) : undefined;
  // Capture immutable lookup state; callers may inspect but cannot mutate source metadata used for freshness.
  const sources = snapshot.sources.map((source) => ({ ...source }));
  return { id: snapshot.id, sources: sources.map((source) => ({ ...source })), lookup(ip, ua, now, maxAgeMs) {
    const fresh = new Set(sources.filter((source) => now >= Date.parse(source.fetchedAt) && now - Date.parse(source.fetchedAt) <= maxAgeMs).map((source) => source.id));
    const staleSources = sources.filter((source) => !fresh.has(source.id)).map((source) => source.id);
    const signals: TrafficSignals = {}, matchedSources: string[] = [];
    let address: IpValue | undefined;
    try { if (ip) address = parseIp(ip); } catch { /* Invalid or missing addresses remain unknown. */ }
    if (address) {
      signals["network.ip"] = address.address;
      const asnSource = address.version === 4 ? "iptoasn-v4" : "iptoasn-v6";
      const network = fresh.has(asnSource) ? find(asn, address) : undefined;
      if (network) { signals["network.asn"] = network.asn; signals["network.organization"] = network.organization; if (network.country !== "ZZ") signals["network.country"] = network.country; matchedSources.push(asnSource); }
      const location = fresh.has("dbip-country") ? find(geo, address) : undefined;
      if (location && location.country !== "ZZ") { signals["geo.country"] = location.country; matchedSources.push("dbip-country"); }
      // These upstream feeds cover IPv4 only. An IPv6 miss is unknown, never false.
      for (const [id, index, field] of [["vpn", vpn, "network.vpn"], ["datacenter", datacenter, "network.datacenter"]] as const) {
        if (address.version === 4 && fresh.has(id)) {
          signals[field] = find(index, address) === true;
          if (signals[field]) matchedSources.push(id);
        }
      }
    }
    if (ua && ua.length <= 2048 && crawler && fresh.has("crawlers")) {
      signals["client.bot"] = crawler.matcher(ua).find();
      if (signals["client.bot"]) matchedSources.push("crawlers");
    }
    return { signals, staleSources, matchedSources };
  } };
}
