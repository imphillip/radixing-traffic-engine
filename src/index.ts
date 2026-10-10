export {
  signalFields,
  automationKinds,
  fingerprintBooleanFields,
  parsePublishedConfig,
  defaultTarget,
} from "./policy.js";
export type {
  Action,
  ResolvedAction,
  AttributionConfig,
  AutomationKind,
  Condition,
  DeviceType,
  Operator,
  PublishedConfig,
  Rule,
  Scalar,
  SignalField,
  TrafficSignals,
} from "./policy.js";
export { matchesCondition, matchesRule, evaluateRules, explainRules } from "./evaluator.js";
export type { RuleDecision, ConditionEvaluation, RuleEvaluation, RuleExplanation } from "./evaluator.js";
export { analyzeFingerprint, fingerprintSignals, fingerprintEvidence, FINGERPRINT_ANALYSIS_VERSION } from "./fingerprint.js";
export type { FingerprintInput, FingerprintAssessment, FingerprintEvidence } from "./fingerprint.js";
export { analyzeProbePath, probeRuleIds, PROBE_RULESET_VERSION } from "./probe-rules.js";
export type { ProbePathAssessment, ProbeRuleId } from "./probe-rules.js";
export {
  advanceBehavior,
  BEHAVIOR_VERSION,
  BEHAVIOR_WINDOW_MS,
  BEHAVIOR_REQUESTS,
  BEHAVIOR_PATHS,
  BEHAVIOR_COOLDOWN_MS,
} from "./behavior.js";
export type { BehaviorState, BehaviorAssessment } from "./behavior.js";
export { compileFeatureSnapshot, parseFeatureSnapshot, parseIp, cidrRange } from "./features.js";
export type { FeatureSnapshot, FeatureSource, AsnRange, CountryRange, CrawlerPattern, FeatureIndex } from "./features.js";
export { createTds, enrichRequest } from "./tds.js";
export type { TdsInput, TdsDecision, TdsOptions } from "./tds.js";
