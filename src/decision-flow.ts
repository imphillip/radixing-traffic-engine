import { evaluateRules, type RuleDecision } from "./evaluator.js";
import { JevGatewayError, parseJevClassification, sanitizeJevFeatures } from "./jev.js";
import type { JevActionableClass, JevClassification, JevGateway, JevVisitorClass } from "./jev.js";
import { parsePolicyAction, type Action, type PublishedConfig, type TrafficSignals } from "./policy.js";

export interface JevDecisionPolicy {
  version: number;
  propertyId: string;
  configVersion: number;
  mode: "observe" | "enforce";
  eligibleRuleIds: string[];
  classifyDefault: boolean;
  maxWaitMs: number;
  minConfidence: number;
  minChoiceProbability: number;
  actions: Partial<Record<JevActionableClass, Action>>;
}

export type JevDecisionStatus =
  | "not_eligible"
  | "invalid_policy"
  | "insufficient_features"
  | "unavailable"
  | "rate_limited"
  | "circuit_open"
  | "timeout"
  | "provider_error"
  | "network_error"
  | "invalid_content_type"
  | "invalid_body"
  | "invalid_response"
  | "unresolved"
  | "low_confidence"
  | "unmapped"
  | "observed"
  | "applied";

export interface JevDecisionResult {
  source: "static" | "jev";
  decision: RuleDecision;
  staticDecision: RuleDecision;
  candidateDecision?: RuleDecision;
  jev: {
    version: 1;
    status: JevDecisionStatus;
    policyVersion?: number;
    label?: JevVisitorClass;
    confidence?: number;
    choiceProbability?: number;
  };
}

function record(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown> : null;
}

function threshold(value: unknown, path: string): number {
  if (typeof value !== "number" || !Number.isFinite(value) || value <= 0 || value > 1) {
    throw new Error(`${path} must be greater than 0 and at most 1`);
  }
  return value;
}

export function parseJevDecisionPolicy(config: PublishedConfig, value: unknown): JevDecisionPolicy {
  const input = record(value);
  if (!input) throw new Error("Jev decision policy must be an object");
  if (!Number.isSafeInteger(input.version) || (input.version as number) < 1) {
    throw new Error("Jev decision policy version must be a positive integer");
  }
  if (input.propertyId !== config.propertyId || input.configVersion !== config.version) {
    throw new Error("Jev decision policy must match the property and config version");
  }
  if (input.mode !== "observe" && input.mode !== "enforce") {
    throw new Error("Jev decision policy mode must be observe or enforce");
  }
  if (!Number.isSafeInteger(input.maxWaitMs) || (input.maxWaitMs as number) < 1 || (input.maxWaitMs as number) > 2000) {
    throw new Error("Jev decision policy maxWaitMs must be 1-2000");
  }
  if (!Array.isArray(input.eligibleRuleIds) || !input.eligibleRuleIds.every((id) => typeof id === "string" && id.length > 0)) {
    throw new Error("Jev decision policy eligibleRuleIds must be an array of rule IDs");
  }
  const eligibleRuleIds = input.eligibleRuleIds as string[];
  if (new Set(eligibleRuleIds).size !== eligibleRuleIds.length) {
    throw new Error("Jev decision policy eligibleRuleIds must be unique");
  }
  for (const id of eligibleRuleIds) {
    const rule = config.rules.find((candidate) => candidate.id === id);
    if (!rule || !rule.enabled || rule.action.type !== "redirect") {
      throw new Error(`Jev decision policy rule ${id} must be an enabled redirect`);
    }
  }
  if (input.classifyDefault !== undefined && typeof input.classifyDefault !== "boolean") {
    throw new Error("Jev decision policy classifyDefault must be a boolean");
  }
  const classifyDefault = input.classifyDefault === true;
  if (classifyDefault && (config.schemaVersion !== 2 || config.defaultAction?.type !== "redirect")) {
    throw new Error("Jev decision policy classifyDefault requires a v2 default redirect");
  }
  if (!classifyDefault && eligibleRuleIds.length === 0) {
    throw new Error("Jev decision policy must select a redirect rule or v2 default");
  }
  const suppliedActions = record(input.actions);
  if (!suppliedActions || Object.keys(suppliedActions).length === 0) {
    throw new Error("Jev decision policy actions must contain at least one class mapping");
  }
  const actions: Partial<Record<JevActionableClass, Action>> = {};
  for (const [label, value] of Object.entries(suppliedActions)) {
    if (!["ordinary_visitor", "benign_bot_candidate", "professional_probe", "other_automation"].includes(label)) {
      throw new Error(`Jev decision policy class ${label} is unsupported`);
    }
    const action = parsePolicyAction(value, `Jev decision policy actions.${label}`);
    if (config.schemaVersion === 2 && (action.type === "allow" || action.type === "route")) {
      throw new Error("Jev decision policy v2 actions must redirect or block");
    }
    const target = action.type === "redirect" ? action.url : action.type === "route" ? action.origin : null;
    if (target && config.domains.includes(new URL(target).hostname)) {
      throw new Error("Jev decision policy target cannot be a managed domain");
    }
    actions[label as JevActionableClass] = action;
  }
  return {
    version: input.version as number,
    propertyId: config.propertyId,
    configVersion: config.version,
    mode: input.mode,
    eligibleRuleIds: [...eligibleRuleIds],
    classifyDefault,
    maxWaitMs: input.maxWaitMs as number,
    minConfidence: threshold(input.minConfidence, "Jev decision policy minConfidence"),
    minChoiceProbability: threshold(input.minChoiceProbability, "Jev decision policy minChoiceProbability"),
    actions,
  };
}

export interface JevDecisionInput {
  config: PublishedConfig;
  signals: TrafficSignals;
  features: unknown;
  policy: JevDecisionPolicy;
  gateway?: JevGateway | null;
}

export async function decideWithJev(input: JevDecisionInput): Promise<JevDecisionResult> {
  const staticDecision = evaluateRules(input.config, input.signals);
  const fallback = (
    status: JevDecisionStatus,
    policy?: JevDecisionPolicy,
    classification?: JevClassification,
  ): JevDecisionResult => ({
    source: "static",
    decision: staticDecision,
    staticDecision,
    jev: {
      version: 1,
      status,
      ...(policy ? { policyVersion: policy.version } : {}),
      ...(classification ? {
        label: classification.label,
        confidence: classification.confidence,
        choiceProbability: classification.probabilities[classification.label],
      } : {}),
    },
  });

  let policy: JevDecisionPolicy;
  try {
    policy = parseJevDecisionPolicy(input.config, input.policy);
  } catch {
    return fallback("invalid_policy");
  }
  const eligible = input.signals["request.method"] === "GET"
    && input.signals["request.probe"] !== true
    && input.signals["request.pathEnumeration"] !== true
    && staticDecision.action.type === "redirect"
    && (staticDecision.ruleId
      ? policy.eligibleRuleIds.includes(staticDecision.ruleId)
      : policy.classifyDefault);
  if (!eligible) return fallback("not_eligible", policy);
  if (!input.gateway) return fallback("unavailable", policy);
  const features = sanitizeJevFeatures(input.features);
  if (features.pathEnumeration === true) return fallback("not_eligible", policy);
  if (features.method !== "GET" || !Object.keys(features).some((field) => field !== "method")) {
    return fallback("insufficient_features", policy);
  }

  const controller = new AbortController();
  let timeout: ReturnType<typeof setTimeout> | undefined;
  let timedOut = false;
  try {
    const deadline = new Promise<never>((_, reject) => {
      timeout = setTimeout(() => {
        timedOut = true;
        controller.abort();
        reject(new Error("timeout"));
      }, policy.maxWaitMs);
    });
    const raw = await Promise.race([input.gateway.classify(features, controller.signal), deadline]);
    const classification = parseJevClassification(raw);
    if (!classification) return fallback("invalid_response", policy);
    if (classification.label === "unresolved") return fallback("unresolved", policy, classification);
    const probability = classification.probabilities[classification.label];
    if (classification.confidence < policy.minConfidence || probability < policy.minChoiceProbability) {
      return fallback("low_confidence", policy, classification);
    }
    const action = policy.actions[classification.label];
    if (!action) return fallback("unmapped", policy, classification);
    const candidateDecision = { action };
    if (policy.mode === "observe") {
      return { ...fallback("observed", policy, classification), candidateDecision };
    }
    return {
      source: "jev",
      decision: candidateDecision,
      staticDecision,
      jev: {
        version: 1,
        status: "applied",
        policyVersion: policy.version,
        label: classification.label,
        confidence: classification.confidence,
        choiceProbability: probability,
      },
    };
  } catch (error) {
    return fallback(timedOut ? "timeout" : error instanceof JevGatewayError ? error.code : "network_error", policy);
  } finally {
    if (timeout !== undefined) clearTimeout(timeout);
  }
}
