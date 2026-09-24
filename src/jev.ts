export const JEV_MODEL = "typesafe/jev-1.13";
export const JEV_FEATURE_VERSION = 2;
export const JEV_MAX_RESPONSE_BYTES = 8192;

export const jevVisitorClasses = [
  "ordinary_visitor",
  "benign_bot_candidate",
  "professional_probe",
  "other_automation",
  "unresolved",
] as const;

export type JevVisitorClass = (typeof jevVisitorClasses)[number];
export type JevActionableClass = Exclude<JevVisitorClass, "unresolved">;

export interface JevFeatureState {
  clientIp?: string;
  asn?: number;
  country?: string;
  method?: "GET";
  pathDepth?: number;
  pathLengthBucket?: number;
  hasExtension?: boolean;
  navigation?: boolean;
  userActivated?: boolean;
  fetchMetadataPresent?: boolean;
  acceptsHtml?: boolean;
  languagePresent?: boolean;
  clientHintsPresent?: boolean;
  referrerPresent?: boolean;
  deviceType?: "bot" | "desktop" | "mobile" | "tablet" | "unknown";
  deviceOs?: "ios" | "android" | "windows" | "macos" | "linux" | "unknown";
  declaredBot?: boolean;
  automation?: "declared" | "suspected" | "unknown";
  headless?: boolean;
  uaMismatch?: boolean;
  behaviorAvailable?: boolean;
  recentRequests?: number;
  recentDistinctPaths?: number;
  pathEnumeration?: boolean;
}

export interface JevClassification {
  label: JevVisitorClass;
  confidence: number;
  probabilities: Record<JevVisitorClass, number>;
}

export interface JevGateway {
  classify(features: JevFeatureState, signal: AbortSignal): Promise<unknown>;
}

export type JevGatewayErrorCode =
  | "provider_error"
  | "network_error"
  | "invalid_content_type"
  | "invalid_body"
  | "invalid_response"
  | "unavailable"
  | "rate_limited"
  | "circuit_open";

export class JevGatewayError extends Error {
  constructor(readonly code: JevGatewayErrorCode) {
    super(code);
    this.name = "JevGatewayError";
  }
}

function record(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown> : null;
}

function canonicalIp(value: unknown): string | null {
  if (typeof value !== "string" || value.length === 0 || value.length > 45) return null;
  if (/^(0|[1-9]\d{0,2})(\.(0|[1-9]\d{0,2})){3}$/.test(value)) {
    return value.split(".").every((part) => Number(part) <= 255) ? value : null;
  }
  if (!value.includes(":") || !/^[a-fA-F0-9:.]+$/.test(value)) return null;
  try {
    return new URL(`https://[${value}]/`).hostname.slice(1, -1);
  } catch {
    return null;
  }
}

function boundedInteger(value: unknown, minimum: number, maximum: number): number | undefined {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= minimum && value <= maximum
    ? value : undefined;
}

export function sanitizeJevFeatures(value: unknown): JevFeatureState {
  const input = record(value);
  if (!input) return {};
  const result: JevFeatureState = {};
  const ip = canonicalIp(input.clientIp);
  if (ip) result.clientIp = ip;
  const asn = boundedInteger(input.asn, 1, 4294967295);
  if (asn !== undefined) result.asn = asn;
  if (typeof input.country === "string" && /^[A-Z]{2}$/.test(input.country)) result.country = input.country;
  if (input.method === "GET") result.method = "GET";
  const pathDepth = boundedInteger(input.pathDepth, 0, 5);
  if (pathDepth !== undefined) result.pathDepth = pathDepth;
  const pathLengthBucket = boundedInteger(input.pathLengthBucket, 0, 5);
  if (pathLengthBucket !== undefined) result.pathLengthBucket = pathLengthBucket;
  const recentRequests = boundedInteger(input.recentRequests, 0, 60);
  if (recentRequests !== undefined) result.recentRequests = recentRequests;
  const recentDistinctPaths = boundedInteger(input.recentDistinctPaths, 0, 60);
  if (recentDistinctPaths !== undefined) result.recentDistinctPaths = recentDistinctPaths;
  if (["bot", "desktop", "mobile", "tablet", "unknown"].includes(input.deviceType as string)) {
    result.deviceType = input.deviceType as NonNullable<JevFeatureState["deviceType"]>;
  }
  if (["ios", "android", "windows", "macos", "linux", "unknown"].includes(input.deviceOs as string)) {
    result.deviceOs = input.deviceOs as NonNullable<JevFeatureState["deviceOs"]>;
  }
  if (["declared", "suspected", "unknown"].includes(input.automation as string)) {
    result.automation = input.automation as NonNullable<JevFeatureState["automation"]>;
  }
  const booleanFields = [
    "hasExtension", "navigation", "userActivated", "fetchMetadataPresent", "acceptsHtml",
    "languagePresent", "clientHintsPresent", "referrerPresent", "declaredBot", "headless",
    "uaMismatch", "behaviorAvailable", "pathEnumeration",
  ] as const;
  for (const field of booleanFields) {
    if (typeof input[field] === "boolean") Object.assign(result, { [field]: input[field] });
  }
  return result;
}

export function parseJevClassification(value: unknown): JevClassification | null {
  const answer = record(value);
  if (!answer || !jevVisitorClasses.includes(answer.label as JevVisitorClass)) return null;
  if (typeof answer.confidence !== "number" || !Number.isFinite(answer.confidence)
    || answer.confidence < 0 || answer.confidence > 1) return null;
  const supplied = record(answer.probabilities);
  if (!supplied) return null;
  const probabilities = {} as Record<JevVisitorClass, number>;
  for (const label of jevVisitorClasses) {
    const probability = supplied[label];
    if (typeof probability !== "number" || !Number.isFinite(probability)
      || probability < 0 || probability > 1) return null;
    probabilities[label] = probability;
  }
  const sum = jevVisitorClasses.reduce((total, label) => total + probabilities[label], 0);
  const label = answer.label as JevVisitorClass;
  if (sum < 0.98 || sum > 1.02 || probabilities[label] < Math.max(...Object.values(probabilities))) return null;
  return { label, confidence: answer.confidence, probabilities };
}

async function boundedJson(response: Response): Promise<unknown> {
  if (Number(response.headers.get("content-length")) > JEV_MAX_RESPONSE_BYTES || !response.body) {
    throw new JevGatewayError("invalid_body");
  }
  const reader = response.body.getReader();
  const parts: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > JEV_MAX_RESPONSE_BYTES) throw new JevGatewayError("invalid_body");
      parts.push(value);
    }
  } finally {
    await reader.cancel().catch(() => {});
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const part of parts) {
    bytes.set(part, offset);
    offset += part.length;
  }
  try {
    return JSON.parse(new TextDecoder().decode(bytes));
  } catch {
    throw new JevGatewayError("invalid_body");
  }
}

export function createOpenRouterJevGateway(options: { apiKey: string; fetch?: typeof fetch }): JevGateway {
  if (!options.apiKey.trim()) throw new Error("apiKey must be provided");
  const apiKey = options.apiKey;
  const fetcher = options.fetch ?? fetch;
  return {
    async classify(features, signal) {
      let response: Response;
      try {
        response = await fetcher("https://openrouter.ai/api/alpha/decisions", {
          method: "POST",
          redirect: "manual",
          signal,
          headers: {
            authorization: `Bearer ${apiKey}`,
            "content-type": "application/json",
          },
          body: JSON.stringify({
            model: JEV_MODEL,
            provider: { zdr: true, data_collection: "deny" },
            state: sanitizeJevFeatures(features),
            questions: {
              visitor_class: {
                type: "choice",
                instructions: "Classify the likely visitor type for a request that passed static expert rules. Use combined IP/network, HTTP environment and recent behavior evidence. An IP or self-declared user agent alone cannot prove a benign identity; missing evidence is not proof of a human. Choose unresolved when evidence is weak or contradictory.",
                criteria: {
                  ordinary_visitor: "Likely ordinary visitor navigating the application, with consistent browser signals and no meaningful automation evidence.",
                  benign_bot_candidate: "Likely legitimate crawler or service bot, supported by consistent network and behavioral evidence; identity is not independently verified.",
                  professional_probe: "Likely monitoring, research, compliance or security probe with professional tooling or a distinctive network and request pattern; intent is not verified.",
                  other_automation: "Likely scripted or bulk automation without sufficient evidence to call it a benign bot or professional probe.",
                  unresolved: "Missing or conflicting evidence prevents a reliable visitor classification.",
                },
              },
            },
          }),
        });
      } catch {
        throw new JevGatewayError("network_error");
      }
      if (!response.ok) throw new JevGatewayError("provider_error");
      if (!response.headers.get("content-type")?.toLowerCase().includes("application/json")) {
        throw new JevGatewayError("invalid_content_type");
      }
      const body = record(await boundedJson(response));
      const answers = record(body?.answers);
      const choice = record(answers?.visitor_class);
      if (choice?.type !== "choice") throw new JevGatewayError("invalid_response");
      const result = parseJevClassification({
        label: choice.choice,
        confidence: choice.confidence,
        probabilities: choice.probabilities,
      });
      if (!result) throw new JevGatewayError("invalid_response");
      return result;
    },
  };
}
