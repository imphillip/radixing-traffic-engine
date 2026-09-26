import { evaluateRules, matchesRule } from "./evaluator.js";
import type { RuleDecision } from "./evaluator.js";
import { parsePublishedConfig } from "./policy.js";
import type { Action, Condition, PublishedConfig, Rule, TrafficSignals } from "./policy.js";

export interface RuleProposal {
  schemaVersion: 1;
  id: string;
  propertyId: string;
  baseConfigVersion: number;
  source: { kind: "analyst" | "llm" | "feed"; referenceId: string };
  evidenceIds: string[];
  createdAt: string;
  reviewAt: string;
  expiresAt?: string;
  rule: Rule;
}

export interface ReplayCase {
  signals: TrafficSignals;
  reviewedLabel?: "legitimate" | "unwanted";
}

export interface RuleReplaySummary {
  version: 1;
  proposalId: string;
  baseConfigVersion: number;
  total: number;
  matched: number;
  selected: number;
  changedAction: number;
  reviewedLegitimate: number;
  newlyBlockedLegitimate: number;
  reviewedUnwanted: number;
  selectedReviewedUnwanted: number;
}

export interface RuleReviewRecord {
  ruleId: string;
  reviewAt: string;
  expiresAt?: string;
}

export interface RuleReviewIssue {
  ruleId: string;
  kind: "missing_record" | "review_due" | "expired" | "duplicate" | "shadowed";
  relatedRuleId?: string;
}

export interface RuleSetReview {
  version: 1;
  configVersion: number;
  issues: RuleReviewIssue[];
}

const identifierPattern = /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/;
const sourceKinds = new Set(["analyst", "llm", "feed"]);

function record(value: unknown, path: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${path} must be an object`);
  }
  return value as Record<string, unknown>;
}

function onlyKeys(value: Record<string, unknown>, keys: string[], path: string): void {
  const allowed = new Set(keys);
  if (Object.keys(value).some((key) => !allowed.has(key))) {
    throw new Error(`${path} contains unsupported fields`);
  }
}

function identifier(value: unknown, path: string): string {
  if (typeof value !== "string" || !identifierPattern.test(value)) {
    throw new Error(`${path} must be an opaque identifier of at most 128 characters`);
  }
  return value;
}

function utcTimestamp(value: unknown, path: string): string {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value)) {
    throw new Error(`${path} must be a canonical UTC timestamp`);
  }
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds) || new Date(milliseconds).toISOString() !== value) {
    throw new Error(`${path} must be a valid UTC timestamp`);
  }
  return value;
}

export function parseRuleProposal(config: PublishedConfig, value: unknown): RuleProposal {
  const input = record(value, "proposal");
  onlyKeys(input, ["schemaVersion", "id", "propertyId", "baseConfigVersion", "source", "evidenceIds", "createdAt", "reviewAt", "expiresAt", "rule"], "proposal");
  if (input.schemaVersion !== 1) throw new Error("proposal.schemaVersion must be 1");
  if (input.propertyId !== config.propertyId || input.baseConfigVersion !== config.version) {
    throw new Error("proposal must match the property and base config version");
  }
  const source = record(input.source, "proposal.source");
  onlyKeys(source, ["kind", "referenceId"], "proposal.source");
  if (!sourceKinds.has(source.kind as string)) throw new Error("proposal.source.kind is unsupported");
  if (!Array.isArray(input.evidenceIds) || input.evidenceIds.length === 0 || input.evidenceIds.length > 32) {
    throw new Error("proposal.evidenceIds must contain 1-32 opaque identifiers");
  }
  const evidenceIds = input.evidenceIds.map((item, index) => identifier(item, `proposal.evidenceIds[${index}]`));
  if (new Set(evidenceIds).size !== evidenceIds.length) throw new Error("proposal.evidenceIds must be unique");
  const createdAt = utcTimestamp(input.createdAt, "proposal.createdAt");
  const reviewAt = utcTimestamp(input.reviewAt, "proposal.reviewAt");
  const expiresAt = input.expiresAt === undefined ? undefined : utcTimestamp(input.expiresAt, "proposal.expiresAt");
  if (source.kind !== "analyst" && expiresAt === undefined) {
    throw new Error("model and feed proposals require expiresAt");
  }
  if (reviewAt <= createdAt || (expiresAt !== undefined && (expiresAt <= createdAt || expiresAt < reviewAt))) {
    throw new Error("proposal review and expiry must follow creation in order");
  }

  // Reuse the published-policy parser so a proposed rule obeys the same action, field, and domain constraints.
  const candidateConfig = parsePublishedConfig({ ...config, rules: [...config.rules, input.rule] });
  const rule = candidateConfig.rules.at(-1)!;
  if (!rule.enabled) throw new Error("proposal.rule must be enabled for replay");
  if (config.rules.some((existing) => existing.enabled
    && (existing.action.type === "allow" || existing.action.type === "block")
    && rule.priority < existing.priority)) {
    throw new Error("proposal.rule cannot precede an existing allow or block rule");
  }

  return {
    schemaVersion: 1,
    id: identifier(input.id, "proposal.id"),
    propertyId: config.propertyId,
    baseConfigVersion: config.version,
    source: {
      kind: source.kind as RuleProposal["source"]["kind"],
      referenceId: identifier(source.referenceId, "proposal.source.referenceId"),
    },
    evidenceIds,
    createdAt,
    reviewAt,
    ...(expiresAt ? { expiresAt } : {}),
    rule,
  };
}

export function reviewRuleProposal(proposal: RuleProposal, asOf: string): { reviewDue: boolean; expired: boolean } {
  const now = utcTimestamp(asOf, "asOf");
  return { reviewDue: now >= proposal.reviewAt, expired: proposal.expiresAt !== undefined && now >= proposal.expiresAt };
}

function sameAction(left: Action, right: Action): boolean {
  if (left.type !== right.type) return false;
  if (left.type === "allow") return true;
  if (left.type === "block" && right.type === "block") return left.status === right.status && left.body === right.body;
  if (left.type === "redirect" && right.type === "redirect") {
    return left.status === right.status && left.url === right.url && left.preservePath === right.preservePath;
  }
  return left.type === "route" && right.type === "route" && left.origin === right.origin;
}

function newlyBlocksLegitimate(before: RuleDecision, after: RuleDecision, label: ReplayCase["reviewedLabel"]): boolean {
  return label === "legitimate" && before.action.type !== "block" && after.action.type === "block";
}

export function replayRuleProposal(config: PublishedConfig, proposal: RuleProposal, cases: ReplayCase[]): RuleReplaySummary {
  const parsed = parseRuleProposal(config, proposal);
  const candidateConfig: PublishedConfig = { ...config, rules: [...config.rules, parsed.rule] };
  const summary: RuleReplaySummary = {
    version: 1,
    proposalId: parsed.id,
    baseConfigVersion: config.version,
    total: 0,
    matched: 0,
    selected: 0,
    changedAction: 0,
    reviewedLegitimate: 0,
    newlyBlockedLegitimate: 0,
    reviewedUnwanted: 0,
    selectedReviewedUnwanted: 0,
  };
  for (const item of cases) {
    if (!item || typeof item !== "object" || !item.signals || typeof item.signals !== "object") {
      throw new Error("replay cases must provide signals");
    }
    if (item.reviewedLabel !== undefined && item.reviewedLabel !== "legitimate" && item.reviewedLabel !== "unwanted") {
      throw new Error("replay reviewedLabel must be legitimate or unwanted");
    }
    const before = evaluateRules(config, item.signals);
    const after = evaluateRules(candidateConfig, item.signals);
    const selected = after.ruleId === parsed.rule.id;
    summary.total += 1;
    if (matchesRule(parsed.rule, item.signals)) summary.matched += 1;
    if (selected) summary.selected += 1;
    if (!sameAction(before.action, after.action)) summary.changedAction += 1;
    if (item.reviewedLabel === "legitimate") summary.reviewedLegitimate += 1;
    if (newlyBlocksLegitimate(before, after, item.reviewedLabel)) summary.newlyBlockedLegitimate += 1;
    if (item.reviewedLabel === "unwanted") {
      summary.reviewedUnwanted += 1;
      if (selected) summary.selectedReviewedUnwanted += 1;
    }
  }
  return summary;
}

function conditionKey(condition: Condition): string {
  const value = Array.isArray(condition.value)
    ? condition.value.map((item) => JSON.stringify(item)).sort()
    : condition.value === undefined ? null : JSON.stringify(condition.value);
  return JSON.stringify([condition.field, condition.operator, value]);
}

function predicateKey(rule: Rule): string {
  return JSON.stringify([rule.match, rule.conditions.map(conditionKey).sort()]);
}

export function reviewRuleSet(config: PublishedConfig, records: RuleReviewRecord[], asOf: string): RuleSetReview {
  const now = utcTimestamp(asOf, "asOf");
  const knownIds = new Set(config.rules.map((rule) => rule.id));
  const metadata = new Map<string, RuleReviewRecord>();
  for (const item of records) {
    if (!knownIds.has(item.ruleId) || metadata.has(item.ruleId)) {
      throw new Error("review records must reference distinct configured rules");
    }
    const reviewAt = utcTimestamp(item.reviewAt, `records.${item.ruleId}.reviewAt`);
    const expiresAt = item.expiresAt === undefined ? undefined : utcTimestamp(item.expiresAt, `records.${item.ruleId}.expiresAt`);
    metadata.set(item.ruleId, { ruleId: item.ruleId, reviewAt, ...(expiresAt ? { expiresAt } : {}) });
  }

  const issues: RuleReviewIssue[] = [];
  const earlierByPredicate = new Map<string, Rule>();
  const ordered = config.rules.map((rule, index) => ({ rule, index }))
    .sort((left, right) => left.rule.priority - right.rule.priority || left.index - right.index);
  for (const { rule } of ordered) {
    if (!rule.enabled) continue;
    const item = metadata.get(rule.id);
    if (!item) issues.push({ ruleId: rule.id, kind: "missing_record" });
    if (item && now >= item.reviewAt) issues.push({ ruleId: rule.id, kind: "review_due" });
    if (item?.expiresAt && now >= item.expiresAt) issues.push({ ruleId: rule.id, kind: "expired" });
    const key = predicateKey(rule);
    const earlier = earlierByPredicate.get(key);
    if (earlier) {
      issues.push({ ruleId: rule.id, kind: sameAction(earlier.action, rule.action) ? "duplicate" : "shadowed", relatedRuleId: earlier.id });
    } else {
      earlierByPredicate.set(key, rule);
    }
  }
  return { version: 1, configVersion: config.version, issues };
}
