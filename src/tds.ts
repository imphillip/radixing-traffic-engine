import Bowser from "bowser";
import { explainRules, type RuleExplanation } from "./evaluator.js";
import { analyzeFingerprint, fingerprintSignals } from "./fingerprint.js";
import { compileFeatureSnapshot, parseIp, type FeatureIndex } from "./features.js";
import { parsePublishedConfig, type TrafficSignals } from "./policy.js";
import { analyzeProbePath, type ProbeRuleId } from "./probe-rules.js";
import { BEHAVIOR_VERSION } from "./behavior.js";

export const SCANNER_PROTECTION_VERSION = 1 as const;
export interface ScannerProtectionOptions {
  sensitivePaths?: boolean;
  pathEnumeration?: boolean;
}

export interface TdsInput {
  request: Request;
  /** Supplied by the host after authenticating its ingress/proxy boundary. */
  ip?: string;
  clientKey?: string;
  trustedSignals?: TrafficSignals;
  now: number;
}
export interface TdsOptions { maxDataAgeMs?: number; scannerProtection?: ScannerProtectionOptions }
export interface TdsDecision extends RuleExplanation {
  evidence: {
    snapshotId: string; staleSources: string[]; matchedSources: string[]; parser: "bowser@2.14.1" | null;
    protection?: {
      version: typeof SCANNER_PROTECTION_VERSION;
      kind: "sensitive-path" | "path-enumeration";
      probeRule?: ProbeRuleId;
      probeRulesetVersion?: number;
      behaviorVersion?: number;
    };
  };
}
export function enrichRequest(input: TdsInput, features: FeatureIndex, maxDataAgeMs = 7 * 86_400_000): { signals: TrafficSignals; evidence: TdsDecision["evidence"] } {
  if (!Number.isFinite(input.now) || !Number.isFinite(maxDataAgeMs) || maxDataAgeMs < 1) throw new Error("Invalid feature clock or maximum age");
  const request = input.request, url = new URL(request.url), ua = request.headers.get("user-agent") ?? undefined;
  const lookup = features.lookup(input.ip, ua, input.now, maxDataAgeMs);
  const signals: TrafficSignals = {
    ...fingerprintSignals(analyzeFingerprint({ userAgent: ua, brands: request.headers.get("sec-ch-ua") ?? undefined, platform: request.headers.get("sec-ch-ua-platform") ?? undefined, path: url.pathname })),
    ...lookup.signals,
    "request.hostname": url.hostname.toLowerCase(), "request.path": url.pathname, "request.method": request.method,
  };
  if (ua && ua.length <= 2048) {
    const parsed = Bowser.parse(ua);
    if (["mobile", "tablet", "desktop"].includes(parsed.platform.type ?? "")) signals["device.type"] = parsed.platform.type as "mobile" | "tablet" | "desktop";
    if (parsed.os.name) signals["device.os"] = parsed.os.name;
    if (parsed.browser.name) signals["browser.name"] = parsed.browser.name;
    if (parsed.browser.version) signals["browser.version"] = parsed.browser.version;
  }
  for (const [parameter, field] of [["utm_source", "campaign.source"], ["utm_medium", "campaign.medium"], ["utm_campaign", "campaign.name"]] as const) {
    const value = url.searchParams.get(parameter);
    if (value && value.length <= 256) signals[field] = value;
  }
  const referrer = request.headers.get("referer");
  if (referrer && referrer.length <= 2048) {
    try { const parsed = new URL(referrer); if (parsed.protocol === "https:" || parsed.protocol === "http:") signals["request.referrer"] = parsed.origin + parsed.pathname; } catch { /* Omit malformed referrers. */ }
  }
  if (input.clientKey && input.clientKey.length <= 256) signals["client.key"] = input.clientKey;
  // Explicit host-supplied observations override inferred facts; request identity cannot be overwritten.
  Object.assign(signals, input.trustedSignals);
  signals["request.hostname"] = url.hostname.toLowerCase(); signals["request.path"] = url.pathname; signals["request.method"] = request.method;
  delete signals["network.ip"];
  try { if (input.ip) signals["network.ip"] = parseIp(input.ip).address; } catch { /* Keep unknown. */ }
  return { signals, evidence: { snapshotId: features.id, staleSources: lookup.staleSources, matchedSources: lookup.matchedSources, parser: "bowser@2.14.1" } };
}

export function createTds(policy: unknown, snapshot: unknown, options: TdsOptions = {}) {
  const config = parsePublishedConfig(policy);
  if (config.schemaVersion !== 2) throw new Error("TDS requires schemaVersion 2; legacy evaluation remains available separately");
  const features = compileFeatureSnapshot(snapshot);
  const maxDataAgeMs = options.maxDataAgeMs ?? 7 * 86_400_000;
  if (!Number.isFinite(maxDataAgeMs) || maxDataAgeMs < 1) throw new Error("Invalid maximum feature age");
  const protection = { sensitivePaths: true, pathEnumeration: true, ...options.scannerProtection };
  if (typeof protection.sensitivePaths !== "boolean" || typeof protection.pathEnumeration !== "boolean") throw new Error("Invalid scanner protection options");
  function protect(input: TdsInput): TdsDecision | undefined {
    let detail: NonNullable<TdsDecision["evidence"]["protection"]> | undefined;
    if (protection.pathEnumeration && input.trustedSignals?.["request.pathEnumeration"] === true) {
      detail = { version: SCANNER_PROTECTION_VERSION, kind: "path-enumeration", behaviorVersion: BEHAVIOR_VERSION };
    } else if (protection.sensitivePaths) {
      const probe = analyzeProbePath(new URL(input.request.url).pathname);
      if (probe?.probe) detail = { version: SCANNER_PROTECTION_VERSION, kind: "sensitive-path", probeRule: probe.rule!, probeRulesetVersion: probe.version };
    }
    if (!detail) return undefined;
    return {
      action: { type: "block", status: detail.kind === "path-enumeration" ? 403 : 404 },
      ruleId: detail.probeRule ? `builtin:probe:${detail.probeRule}` : "builtin:path-enumeration",
      evaluation: { version: 1, configVersion: config.version, source: "protection", rules: [] },
      evidence: { snapshotId: features.id, staleSources: [], matchedSources: [], parser: null, protection: detail },
    };
  }
  function decide(input: TdsInput): TdsDecision {
    if (!config.domains.includes(new URL(input.request.url).hostname.toLowerCase())) throw new Error("Unconfigured ingress hostname");
    if (!Number.isFinite(input.now)) throw new Error("Invalid feature clock");
    const guarded = protect(input);
    if (guarded) return guarded;
    const { signals, evidence } = enrichRequest(input, features, maxDataAgeMs);
    return { ...explainRules(config, signals), evidence };
  }
  function handle(input: TdsInput): { response: Response; decision?: TdsDecision } {
    if (!config.domains.includes(new URL(input.request.url).hostname.toLowerCase())) return { response: new Response("Unconfigured ingress", { status: 421 }) };
    if (input.request.method !== "GET" && input.request.method !== "HEAD" && !protect(input)) return { response: new Response("Method not allowed", { status: 405, headers: { Allow: "GET, HEAD" } }) };
    const decision = decide(input), action = decision.action;
    const headers = { "cache-control": "no-store", "content-type": "text/plain; charset=utf-8", "x-content-type-options": "nosniff" };
    if (action.type === "block") return { decision, response: new Response(input.request.method === "HEAD" ? null : action.body ?? "", { status: action.status, headers }) };
    if (action.type !== "redirect") throw new Error("Unsupported TDS action");
    const target = new URL(action.url), entry = new URL(input.request.url);
    if (action.preservePath) target.pathname = target.pathname.replace(/\/$/, "") + entry.pathname;
    for (const name of action.queryAllowlist ?? []) {
      const values = entry.searchParams.getAll(name);
      if (values.length) { target.searchParams.delete(name); for (const value of values) target.searchParams.append(name, value); }
    }
    return { decision, response: new Response(null, { status: action.status, headers: { ...headers, location: target.toString() } }) };
  }
  return { decide, handle };
}
