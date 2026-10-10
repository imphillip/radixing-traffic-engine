import { parseRuleProposal, replayRuleProposal } from "./rule-learning.js";
import type { ReplayCase, RuleProposal, RuleReplaySummary } from "./rule-learning.js";
import { evaluateRules } from "./evaluator.js";
import type { PublishedConfig, TrafficSignals } from "./policy.js";

export const TEMPORAL_EVENT_VERSION = 1 as const;
export const TEMPORAL_EVIDENCE_VERSION = 1 as const;

export interface TemporalEvent {
  version: typeof TEMPORAL_EVENT_VERSION;
  featureVersion: number;
  propertyId: string;
  streamId: string;
  eventId: string;
  at: number;
  pathKey: string;
  fingerprintKey?: string;
  probe: boolean;
}

export interface TemporalOptions {
  windowMs: number;
  maxEvents: number;
  minSamples: number;
}

export interface TemporalState {
  version: 1;
  featureVersion: number;
  propertyId: string;
  streamId: string;
  options: TemporalOptions;
  startedAt: number;
  lastAt: number;
  incompleteUntil: number;
  events: TemporalEvent[];
}

export interface TemporalWindow {
  startExclusive: number;
  endInclusive: number;
  complete: boolean;
  requests: number;
  distinctPaths: number;
  repeatShare: number;
  probeShare: number;
  pathTransitionShare: number;
  fingerprintCoverage: number;
  dominantFingerprintShare?: number;
  peakMinuteRequests: number;
}

export interface TemporalEvidence {
  version: typeof TEMPORAL_EVIDENCE_VERSION;
  featureVersion: number;
  propertyId: string;
  streamId: string;
  asOf: number;
  windowMs: number;
  ready: boolean;
  reason?: "incomplete_history" | "insufficient_samples";
  current: TemporalWindow;
  previous: TemporalWindow;
  change?: {
    requestRateRatio: number;
    repeatShareDelta: number;
    probeShareDelta: number;
    pathTransitionShareDelta: number;
    fingerprintShareDelta?: number;
    peakMinuteRatio: number;
  };
}

const tokenPattern = /^[A-Za-z0-9_-]{1,128}$/;

function checkEvent(event: TemporalEvent): void {
  if (event.version !== 1) throw new Error("temporal event version must be 1");
  if (!Number.isSafeInteger(event.featureVersion) || event.featureVersion < 1) {
    throw new Error("temporal featureVersion must be a positive integer");
  }
  for (const field of ["propertyId", "streamId", "eventId", "pathKey", "fingerprintKey"] as const) {
    const value = event[field];
    if (value !== undefined && (typeof value !== "string" || !tokenPattern.test(value))) {
      throw new Error(`temporal event ${field} must be an opaque token`);
    }
  }
  if (!event.propertyId || !event.streamId || !event.eventId || !event.pathKey) {
    throw new Error("temporal event requires property, stream, event and path keys");
  }
  if (!Number.isSafeInteger(event.at) || event.at < 0 || typeof event.probe !== "boolean") {
    throw new Error("temporal event requires a nonnegative millisecond timestamp and probe boolean");
  }
}

function checkOptions(options: TemporalOptions): void {
  if (!Number.isSafeInteger(options.windowMs) || options.windowMs < 60_000 || options.windowMs > 86_400_000) {
    throw new Error("temporal windowMs must be between one minute and one day");
  }
  if (!Number.isSafeInteger(options.maxEvents) || options.maxEvents < 20 || options.maxEvents > 2048) {
    throw new Error("temporal maxEvents must be between 20 and 2048");
  }
  if (!Number.isSafeInteger(options.minSamples) || options.minSamples < 5 || options.minSamples > Math.floor(options.maxEvents / 2)) {
    throw new Error("temporal minSamples must be between 5 and half maxEvents");
  }
}

function summarize(events: TemporalEvent[], startExclusive: number, endInclusive: number, complete: boolean): TemporalWindow {
  const selected = events.filter((event) => event.at > startExclusive && event.at <= endInclusive);
  const requests = selected.length;
  const distinctPaths = new Set(selected.map((event) => event.pathKey)).size;
  const probes = selected.filter((event) => event.probe).length;
  let transitions = 0;
  const fingerprints = new Map<string, number>();
  const minuteBuckets = new Map<number, number>();
  for (let index = 0; index < selected.length; index += 1) {
    const event = selected[index]!;
    if (index > 0 && selected[index - 1]!.pathKey !== event.pathKey) transitions += 1;
    if (event.fingerprintKey) fingerprints.set(event.fingerprintKey, (fingerprints.get(event.fingerprintKey) ?? 0) + 1);
    const bucket = Math.floor(event.at / 60_000);
    minuteBuckets.set(bucket, (minuteBuckets.get(bucket) ?? 0) + 1);
  }
  const fingerprintCoverage = [...fingerprints.values()].reduce((sum, count) => sum + count, 0);
  return {
    startExclusive, endInclusive, complete, requests, distinctPaths,
    repeatShare: requests ? (requests - distinctPaths) / requests : 0,
    probeShare: requests ? probes / requests : 0,
    pathTransitionShare: requests > 1 ? transitions / (requests - 1) : 0,
    fingerprintCoverage,
    ...(fingerprintCoverage ? { dominantFingerprintShare: Math.max(...fingerprints.values()) / fingerprintCoverage } : {}),
    peakMinuteRequests: minuteBuckets.size ? Math.max(...minuteBuckets.values()) : 0,
  };
}

export function advanceTemporalWindow(
  previous: TemporalState | undefined,
  event: TemporalEvent,
  options: TemporalOptions,
): { state: TemporalState; evidence: TemporalEvidence } {
  checkEvent(event);
  checkOptions(options);
  if (event.at > Number.MAX_SAFE_INTEGER - 2 * options.windowMs) {
    throw new Error("temporal timestamp exceeds supported range");
  }
  if (previous) {
    if (previous.version !== 1 || previous.featureVersion !== event.featureVersion
      || previous.propertyId !== event.propertyId || previous.streamId !== event.streamId
      || previous.options.windowMs !== options.windowMs || previous.options.maxEvents !== options.maxEvents
      || previous.options.minSamples !== options.minSamples) {
      throw new Error("temporal state binding or options changed");
    }
    if (event.at < previous.lastAt) throw new Error("temporal events must arrive in timestamp order");
    if (!Array.isArray(previous.events) || previous.events.length > options.maxEvents
      || !Number.isSafeInteger(previous.startedAt) || !Number.isSafeInteger(previous.lastAt)
      || !Number.isSafeInteger(previous.incompleteUntil) || previous.startedAt > previous.lastAt
      || previous.events.some((item, index) => {
        checkEvent(item);
        return item.featureVersion !== event.featureVersion
          || item.propertyId !== event.propertyId || item.streamId !== event.streamId
          || item.at > previous.lastAt || (index > 0 && item.at < previous.events[index - 1]!.at);
      })) {
      throw new Error("temporal state is invalid or exceeds its bound");
    }
    if (previous.events.some((item) => item.eventId === event.eventId)) throw new Error("duplicate temporal event ID");
  }
  const retained = (previous?.events ?? []).filter((item) => item.at > event.at - 2 * options.windowMs);
  retained.push(event);
  let incompleteUntil = previous?.incompleteUntil ?? 0;
  if (retained.length > options.maxEvents) {
    const dropped = retained.splice(0, retained.length - options.maxEvents);
    incompleteUntil = Math.max(incompleteUntil, dropped.at(-1)!.at + 2 * options.windowMs);
  }
  const startedAt = previous?.startedAt ?? event.at;
  const current = summarize(retained, event.at - options.windowMs, event.at, startedAt <= event.at - options.windowMs && event.at >= incompleteUntil);
  const baseline = summarize(retained, event.at - 2 * options.windowMs, event.at - options.windowMs,
    startedAt <= event.at - 2 * options.windowMs && event.at >= incompleteUntil);
  const complete = current.complete && baseline.complete;
  const ready = complete && current.requests >= options.minSamples && baseline.requests >= options.minSamples;
  const change = ready ? {
    requestRateRatio: current.requests / baseline.requests,
    repeatShareDelta: current.repeatShare - baseline.repeatShare,
    probeShareDelta: current.probeShare - baseline.probeShare,
    pathTransitionShareDelta: current.pathTransitionShare - baseline.pathTransitionShare,
    ...(current.fingerprintCoverage === current.requests && baseline.fingerprintCoverage === baseline.requests
      ? { fingerprintShareDelta: current.dominantFingerprintShare! - baseline.dominantFingerprintShare! } : {}),
    peakMinuteRatio: current.peakMinuteRequests / baseline.peakMinuteRequests,
  } : undefined;
  const state: TemporalState = {
    version: 1, featureVersion: event.featureVersion,
    propertyId: event.propertyId, streamId: event.streamId, options: { ...options },
    startedAt, lastAt: event.at, incompleteUntil, events: retained,
  };
  const evidence: TemporalEvidence = {
    version: 1, featureVersion: event.featureVersion,
    propertyId: event.propertyId, streamId: event.streamId, asOf: event.at,
    windowMs: options.windowMs, ready,
    ...(!ready ? { reason: complete ? "insufficient_samples" as const : "incomplete_history" as const } : {}),
    current, previous: baseline, ...(change ? { change } : {}),
  };
  return { state, evidence };
}

export function temporalSignals(evidence: TemporalEvidence): TrafficSignals {
  if (!evidence.ready || !evidence.change || !evidence.current.complete || !evidence.previous.complete) return {};
  return {
    "temporal.ready": true,
    "temporal.requestRateRatio": evidence.change.requestRateRatio,
    "temporal.repeatShareDelta": evidence.change.repeatShareDelta,
    "temporal.probeShareDelta": evidence.change.probeShareDelta,
    "temporal.pathTransitionShareDelta": evidence.change.pathTransitionShareDelta,
    ...(evidence.change.fingerprintShareDelta === undefined ? {} : {
      "temporal.fingerprintShareDelta": evidence.change.fingerprintShareDelta,
    }),
    "temporal.peakMinuteRatio": evidence.change.peakMinuteRatio,
  };
}

export interface TemporalReplayCase {
  event: TemporalEvent;
  signals: TrafficSignals;
  reviewedOutcome?: { label: "legitimate" | "unwanted"; source: "manual" | "external_outcome" };
}

export interface TemporalReplaySummary extends RuleReplaySummary {
  temporalVersion: 1;
  validationStartAt: number;
  contextEvents: number;
  skippedIncomplete: number;
  newlyBlockedUnwanted: number;
}

export function replayTemporalProposal(
  config: PublishedConfig,
  proposal: RuleProposal,
  cases: TemporalReplayCase[],
  validationStartAt: number,
  options: TemporalOptions,
): TemporalReplaySummary {
  checkOptions(options);
  if (!Number.isSafeInteger(validationStartAt) || validationStartAt <= Date.parse(proposal.createdAt)) {
    throw new Error("temporal validation must start after proposal creation");
  }
  const parsed = parseRuleProposal(config, proposal);
  if (cases.length > 20_000) throw new Error("temporal replay exceeds 20000 events");
  const states = new Map<string, TemporalState>();
  const scored: ReplayCase[] = [];
  let contextEvents = 0;
  let skippedIncomplete = 0;
  let newlyBlockedUnwanted = 0;
  let lastAt = -1;
  let featureVersion: number | undefined;
  for (const item of cases) {
    if (item.event.at < lastAt) throw new Error("temporal replay events must be chronological");
    lastAt = item.event.at;
    if (item.event.propertyId !== config.propertyId) throw new Error("temporal replay property mismatch");
    if (featureVersion !== undefined && item.event.featureVersion !== featureVersion) {
      throw new Error("temporal replay cannot mix feature versions");
    }
    featureVersion = item.event.featureVersion;
    if (Object.keys(item.signals).some((field) => field.startsWith("temporal."))) {
      throw new Error("temporal replay signals must not contain precomputed temporal fields");
    }
    if (item.signals["request.probe"] !== undefined && item.signals["request.probe"] !== item.event.probe) {
      throw new Error("temporal replay probe signal must match the event");
    }
    if (item.reviewedOutcome && !["manual", "external_outcome"].includes(item.reviewedOutcome.source)) {
      throw new Error("temporal reviewed outcome must have an independent source");
    }
    const key = item.event.streamId;
    if (!states.has(key) && states.size >= 1000) throw new Error("temporal replay exceeds 1000 streams");
    const { state, evidence } = advanceTemporalWindow(states.get(key), item.event, options);
    states.set(key, state);
    if (item.event.at < validationStartAt) {
      contextEvents += 1;
      continue;
    }
    if (!evidence.ready) {
      skippedIncomplete += 1;
      continue;
    }
    const signals = { ...item.signals, ...temporalSignals(evidence) };
    if (item.reviewedOutcome?.label === "unwanted"
      && evaluateRules(config, signals).action.type !== "block"
      && evaluateRules({ ...config, rules: [...config.rules, parsed.rule] }, signals).action.type === "block") {
      newlyBlockedUnwanted += 1;
    }
    scored.push({ signals,
      ...(item.reviewedOutcome ? { reviewedLabel: item.reviewedOutcome.label } : {}) });
  }
  return {
    ...replayRuleProposal(config, proposal, scored), temporalVersion: 1, validationStartAt,
    contextEvents, skippedIncomplete, newlyBlockedUnwanted,
  };
}

export interface TemporalCandidateProvider {
  propose(evidence: readonly TemporalEvidence[], signal: AbortSignal): Promise<unknown>;
}
