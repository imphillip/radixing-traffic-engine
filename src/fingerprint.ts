import { parseItem, parseList } from "structured-headers";
import type { AutomationKind, TrafficSignals } from "./policy.js";
import { analyzeProbePath, type ProbeRuleId, PROBE_RULESET_VERSION } from "./probe-rules.js";

export const FINGERPRINT_ANALYSIS_VERSION = 1;
export const fingerprintEvidence = [
  "headless_ua", "headless_hint", "automation_ua", "bot_ua",
  "version_mismatch", "platform_mismatch", "sensitive_path",
] as const;
export type FingerprintEvidence = (typeof fingerprintEvidence)[number];

export interface FingerprintInput {
  userAgent?: string | undefined;
  brands?: string | undefined;
  platform?: string | undefined;
  path?: string | undefined;
}

export interface FingerprintAssessment {
  version: typeof FINGERPRINT_ANALYSIS_VERSION;
  automation: AutomationKind;
  headless: boolean | undefined;
  uaMismatch: boolean | undefined;
  probe: boolean | undefined;
  probeRulesetVersion?: typeof PROBE_RULESET_VERSION;
  probeRule?: ProbeRuleId;
  evidence: FingerprintEvidence[];
}

function bounded(value: string | undefined, limit: number): string | undefined {
  return value && value.length <= limit ? value : undefined;
}

function brands(value: string | undefined): Map<string, string> | undefined {
  if (!value) return undefined;
  try {
    const list = parseList(value);
    if (list.length === 0 || list.length > 16) return undefined;
    const result = new Map<string, string>();
    for (const [brand, params] of list) {
      const version = params.get("v");
      if (typeof brand !== "string" || typeof version !== "string" || !/^\d+(?:\.\d+)*$/.test(version)) return undefined;
      if (result.has(brand)) return undefined;
      result.set(brand, version.split(".")[0]!);
    }
    return result;
  } catch {
    return undefined;
  }
}

function platform(value: string | undefined): string | undefined {
  if (!value) return undefined;
  try {
    const [item] = parseItem(value);
    return typeof item === "string" ? item : undefined;
  } catch {
    return undefined;
  }
}

function uaPlatform(ua: string | undefined): string | undefined {
  if (!ua) return undefined;
  if (/\bAndroid\b/i.test(ua)) return "Android";
  if (/\b(?:iPhone|iPad|iPod)\b/i.test(ua)) return "iOS";
  if (/\bWindows NT\b/i.test(ua)) return "Windows";
  if (/\bCrOS\b/.test(ua)) return "Chrome OS";
  if (/\b(?:Macintosh|Mac OS X)\b/.test(ua)) return "macOS";
  if (/\bLinux\b/.test(ua)) return "Linux";
  return undefined;
}

export function analyzeFingerprint(input: FingerprintInput): FingerprintAssessment {
  const ua = bounded(input.userAgent, 2048);
  const brandMap = brands(bounded(input.brands, 4096));
  const hintPlatform = platform(bounded(input.platform, 128));
  const evidence: FingerprintEvidence[] = [];
  const uaHeadless = Boolean(ua && /\b(?:HeadlessChrome|PhantomJS)\//i.test(ua));
  const hintHeadless = brandMap?.has("HeadlessChrome") === true;
  if (uaHeadless) evidence.push("headless_ua");
  if (hintHeadless) evidence.push("headless_hint");
  if (ua && /^(?:curl|wget|python-requests|python-httpx|Go-http-client|okhttp|axios|node-fetch|undici|PostmanRuntime)\//i.test(ua)) evidence.push("automation_ua");
  if (ua && /\b(?:[a-z0-9._-]*bot|[a-z0-9._-]*crawler|[a-z0-9._-]*spider|slurp|facebookexternalhit)\b/i.test(ua)) evidence.push("bot_ua");

  let uaMismatch: boolean | undefined;
  const chromeMajor = ua?.match(/\b(?:Chrome|Chromium|HeadlessChrome)\/(\d+)\./)?.[1];
  const hintMajors = ["Chromium", "Google Chrome", "HeadlessChrome"].flatMap((name) => {
    const version = brandMap?.get(name);
    return version ? [version] : [];
  });
  if (chromeMajor && hintMajors.length) {
    uaMismatch = hintMajors.some((version) => version !== chromeMajor);
    if (uaMismatch) evidence.push("version_mismatch");
  }
  const system = uaPlatform(ua);
  if (system && hintPlatform && ["Android", "iOS", "Windows", "Chrome OS", "macOS", "Linux"].includes(hintPlatform)) {
    // iPad desktop mode may advertise macOS in the UA and iOS in client hints.
    if (!(system === "macOS" && hintPlatform === "iOS")) {
      const mismatch = system !== hintPlatform;
      uaMismatch = uaMismatch === true || mismatch;
      if (mismatch) evidence.push("platform_mismatch");
    }
  }
  const probeAssessment = analyzeProbePath(bounded(input.path, 4096));
  const probe = probeAssessment?.probe;
  if (probe) evidence.push("sensitive_path");
  const declared = evidence.some((item) => ["headless_ua", "headless_hint", "automation_ua", "bot_ua"].includes(item));
  return {
    version: FINGERPRINT_ANALYSIS_VERSION,
    automation: declared ? "declared" : uaMismatch || probe ? "suspected" : "unknown",
    headless: uaHeadless || hintHeadless ? true : ua || brandMap ? false : undefined,
    uaMismatch,
    probe,
    ...(probeAssessment ? { probeRulesetVersion: probeAssessment.version } : {}),
    ...(probeAssessment?.rule ? { probeRule: probeAssessment.rule } : {}),
    evidence,
  };
}

export function fingerprintSignals(assessment: FingerprintAssessment): TrafficSignals {
  return {
    "client.automation": assessment.automation,
    "client.headless": assessment.headless,
    "client.uaMismatch": assessment.uaMismatch,
    "request.probe": assessment.probe,
  };
}
