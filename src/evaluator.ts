import type { Action, ResolvedAction, Condition, PublishedConfig, Rule, Scalar, TrafficSignals } from "./policy.js";
import ipaddr from "ipaddr.js";

export interface RuleDecision {
  action: ResolvedAction;
  ruleId?: string;
}

export interface ConditionEvaluation {
  index: number;
  matched: boolean;
  missing: boolean;
}

export interface RuleEvaluation {
  ruleId: string;
  priority: number;
  status: "disabled" | "not_matched" | "matched" | "not_evaluated";
  conditions: ConditionEvaluation[];
}

export interface RuleExplanation extends RuleDecision {
  evaluation: {
    version: 1;
    configVersion: number;
    source: "rule" | "default";
    rules: RuleEvaluation[];
  };
}

function equal(left: Scalar | undefined, right: Scalar): boolean {
  return typeof left === typeof right && left === right;
}

export function matchesCondition(condition: Condition, signals: TrafficSignals): boolean {
  const actual = signals[condition.field];

  switch (condition.operator) {
    case "exists":
      return actual !== undefined && actual !== "";
    case "eq":
      return !Array.isArray(condition.value) && condition.value !== undefined && equal(actual, condition.value);
    case "neq":
      return actual !== undefined && !Array.isArray(condition.value) && condition.value !== undefined && !equal(actual, condition.value);
    case "in":
      return Array.isArray(condition.value) && condition.value.some((candidate) => equal(actual, candidate));
    case "notIn":
      return actual !== undefined && Array.isArray(condition.value) && !condition.value.some((candidate) => equal(actual, candidate));
    case "contains":
      return typeof actual === "string" && typeof condition.value === "string" && actual.includes(condition.value);
    case "startsWith":
      return typeof actual === "string" && typeof condition.value === "string" && actual.startsWith(condition.value);
    case "gte":
      return typeof actual === "number" && typeof condition.value === "number" && Number.isFinite(actual) && actual >= condition.value;
    case "lte":
      return typeof actual === "number" && typeof condition.value === "number" && Number.isFinite(actual) && actual <= condition.value;
    case "inCidr":
    case "notInCidr": {
      if (typeof actual !== "string" || !Array.isArray(condition.value)) return false;
      try {
        const address = ipaddr.process(actual);
        const matched = condition.value.some((prefix) => {
          if (typeof prefix !== "string") return false;
          const [network, bits] = ipaddr.parseCIDR(prefix);
          return address.kind() === network.kind() && address.match(network, bits);
        });
        return condition.operator === "inCidr" ? matched : !matched;
      } catch { return false; }
    }
  }
}

function testRule(rule: Rule, signals: TrafficSignals, conditions?: ConditionEvaluation[]): boolean {
  if (!rule.enabled || rule.conditions.length === 0) return false;
  const matcher = rule.match === "all" ? "every" : "some";
  return rule.conditions[matcher]((condition, index) => {
    const matched = matchesCondition(condition, signals);
    conditions?.push({ index, matched, missing: signals[condition.field] === undefined });
    return matched;
  });
}

export function matchesRule(rule: Rule, signals: TrafficSignals): boolean {
  return testRule(rule, signals);
}

function evaluate(config: PublishedConfig, signals: TrafficSignals, trace?: RuleEvaluation[]): RuleDecision {
  let decision: RuleDecision | undefined;
  // Stable sorting preserves configured array order when priorities are equal.
  for (const rule of [...config.rules].sort((left, right) => left.priority - right.priority)) {
    if (!rule.enabled || decision) {
      trace?.push({ ruleId: rule.id, priority: rule.priority, status: rule.enabled ? "not_evaluated" : "disabled", conditions: [] });
      continue;
    }
    const conditions: ConditionEvaluation[] | undefined = trace ? [] : undefined;
    const matched = testRule(rule, signals, conditions);
    trace?.push({ ruleId: rule.id, priority: rule.priority, status: matched ? "matched" : "not_matched", conditions: conditions ?? [] });
    if (matched) {
      decision = { action: resolveAction(rule.action, signals), ruleId: rule.id };
      if (!trace) break;
    }
  }
  return decision ?? { action: config.schemaVersion === 2 ? resolveAction(config.defaultAction!, signals) : { type: "allow" } };
}

function resolveAction(action: Action, signals: TrafficSignals): ResolvedAction {
  if (action.type !== "split") return { ...action, ...(action.type === "redirect" && action.queryAllowlist ? { queryAllowlist: [...action.queryAllowlist] } : {}) };
  const key = signals[action.key];
  let url = action.fallbackUrl;
  if (key !== undefined && key !== "") {
    // Version 1 assignment: FNV-1a over UTF-8, fixed salt and typed key. Not an identity or security hash.
    let hash = 2166136261;
    for (const byte of new TextEncoder().encode(JSON.stringify([action.salt, typeof key, key]))) hash = Math.imul(hash ^ byte, 16777619) >>> 0;
    let bucket = (hash / 4294967296) * action.targets.reduce((sum, target) => sum + target.weight, 0);
    for (const target of action.targets) {
      if (bucket < target.weight) { url = target.url; break; }
      bucket -= target.weight;
    }
  }
  return { type: "redirect", status: action.status, url, ...(action.queryAllowlist ? { queryAllowlist: [...action.queryAllowlist] } : {}) };
}

export function evaluateRules(config: PublishedConfig, signals: TrafficSignals): RuleDecision {
  return evaluate(config, signals);
}

export function explainRules(config: PublishedConfig, signals: TrafficSignals): RuleExplanation {
  const rules: RuleEvaluation[] = [];
  const decision = evaluate(config, signals, rules);
  return {
    ...decision,
    evaluation: { version: 1, configVersion: config.version, source: decision.ruleId ? "rule" : "default", rules },
  };
}
