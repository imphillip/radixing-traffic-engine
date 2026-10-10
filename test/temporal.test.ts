import { describe, expect, it } from "vitest";
import {
  advanceTemporalWindow, evaluateRules, parsePublishedConfig, parseRuleProposal,
  replayTemporalProposal, temporalSignals,
} from "../src/index.js";
import type { TemporalEvent, TemporalReplayCase, TemporalState } from "../src/index.js";

const origin = Date.parse("2026-10-01T00:00:00.000Z");
const options = { windowMs: 60_000, maxEvents: 100, minSamples: 5 };
const config = parsePublishedConfig({
  schemaVersion: 2, propertyId: "example", version: 1, domains: ["go.example.com"],
  defaultAction: { type: "redirect", status: 302, url: "https://app.example.com" }, rules: [],
});
const proposal = parseRuleProposal(config, {
  schemaVersion: 1, id: "temporal-candidate", propertyId: "example", baseConfigVersion: 1,
  source: { kind: "analyst", referenceId: "review-1" }, evidenceIds: ["batch-1"],
  createdAt: new Date(origin + 90_000).toISOString(),
  reviewAt: new Date(origin + 300_000).toISOString(),
  rule: { id: "repeat-change", name: "Reviewed repeat shift", enabled: true, priority: 1,
    match: "all", conditions: [
      { field: "temporal.ready", operator: "eq", value: true },
      { field: "temporal.repeatShareDelta", operator: "gte", value: 0.5 },
    ], action: { type: "block", status: 403 } },
});

function event(id: string, at: number, pathKey: string, fingerprintKey = id): TemporalEvent {
  return { version: 1, featureVersion: 1, propertyId: "example", streamId: "cohort_a", eventId: id,
    at, pathKey, fingerprintKey, probe: false };
}

function sequence(): TemporalEvent[] {
  return [
    event("seed", origin, "seed"),
    ...Array.from({ length: 5 }, (_, index) => event(`base_${index}`, origin + 65_000 + index * 1000, `base_${index}`)),
    ...Array.from({ length: 5 }, (_, index) => event(`current_${index}`, origin + 125_000 + index * 1000, "same", "same_fp")),
    event("last", origin + 180_000, "same", "same_fp"),
  ];
}

describe("temporal evidence", () => {
  it("emits bounded, versioned change signals only after full previous/current windows", () => {
    let state: TemporalState | undefined;
    let final;
    for (const item of sequence()) {
      const result = advanceTemporalWindow(state, item, options);
      state = result.state;
      final = result.evidence;
      if (item.eventId === "base_0") expect(temporalSignals(final)).toEqual({});
    }
    expect(state?.events).toHaveLength(11);
    expect(final).toMatchObject({ version: 1, ready: true,
      previous: { requests: 5, distinctPaths: 5, complete: true },
      current: { requests: 6, distinctPaths: 1, fingerprintCoverage: 6, complete: true },
      change: { requestRateRatio: 1.2, repeatShareDelta: 5 / 6, fingerprintShareDelta: 0.8 },
    });
    const signals = temporalSignals(final!);
    expect(signals["temporal.repeatShareDelta"]).toBeCloseTo(5 / 6);
    expect(evaluateRules(config, signals).action.type).toBe("redirect");
    expect(evaluateRules({ ...config, rules: [proposal.rule] }, signals).action.type).toBe("block");
    expect(JSON.stringify(final)).not.toContain("192.0.2.");
  });

  it("rejects cross-property state, old timestamps, duplicates and raw IP keys", () => {
    const first = advanceTemporalWindow(undefined, event("a", origin, "path"), options).state;
    expect(() => advanceTemporalWindow(first, { ...event("b", origin + 1, "path"), propertyId: "other" }, options)).toThrow("binding");
    expect(() => advanceTemporalWindow(first, { ...event("b", origin + 1, "path"), featureVersion: 2 }, options)).toThrow("binding");
    expect(() => advanceTemporalWindow(first, event("b", origin - 1, "path"), options)).toThrow("timestamp order");
    expect(() => advanceTemporalWindow(first, event("a", origin + 1, "path"), options)).toThrow("duplicate");
    expect(() => advanceTemporalWindow(first, event("b", origin + 1, "192.0.2.1"), options)).toThrow("opaque token");
  });

  it("withholds rule inputs when the event cap loses in-window history", () => {
    const small = { windowMs: 60_000, maxEvents: 20, minSamples: 5 };
    let state: TemporalState | undefined;
    for (let index = 0; index < 25; index += 1) {
      const result = advanceTemporalWindow(state, event(`id_${index}`, origin + index, "same"), small);
      state = result.state;
      if (index === 24) {
        expect(state.events).toHaveLength(20);
        expect(result.evidence.reason).toBe("incomplete_history");
        expect(temporalSignals(result.evidence)).toEqual({});
      }
    }
  });

  it("replays only later events with adequate earlier context and independent outcomes", () => {
    const cases: TemporalReplayCase[] = sequence().map((item) => ({
      event: item, signals: { "request.path": "/home", "request.method": "GET" },
      ...(item.eventId === "current_4" ? { reviewedOutcome: { label: "legitimate" as const, source: "manual" as const } } : {}),
      ...(item.eventId === "last" ? { reviewedOutcome: { label: "unwanted" as const, source: "external_outcome" as const } } : {}),
    }));
    const result = replayTemporalProposal(config, proposal, cases, origin + 120_000, options);
    expect(result).toMatchObject({ temporalVersion: 1, contextEvents: 6, skippedIncomplete: 4,
      total: 2, selected: 2, changedAction: 2, reviewedLegitimate: 1,
      newlyBlockedLegitimate: 1, reviewedUnwanted: 1, newlyBlockedUnwanted: 1 });
    expect(() => replayTemporalProposal(config, proposal, cases, origin + 80_000, options)).toThrow("after proposal creation");
    expect(() => replayTemporalProposal(config, proposal, [...cases].reverse(), origin + 120_000, options)).toThrow("chronological");
    expect(() => replayTemporalProposal(config, proposal,
      [cases[0]!, { ...cases[1]!, event: { ...cases[1]!.event, featureVersion: 2 } }],
      origin + 120_000, options)).toThrow("mix feature versions");
    expect(() => replayTemporalProposal(config, proposal,
      [{ ...cases[0]!, signals: { "temporal.ready": true } }], origin + 120_000, options)).toThrow("precomputed temporal");
    expect(() => replayTemporalProposal(config, proposal,
      [{ ...cases[0]!, signals: { "request.probe": true } }], origin + 120_000, options)).toThrow("probe signal");
  });

  it("validates numeric temporal thresholds and keeps missing evidence nonmatching", () => {
    expect(() => parsePublishedConfig({ ...config, rules: [{ ...proposal.rule,
      conditions: [{ field: "temporal.repeatShareDelta", operator: "gte", value: "0.5" }] }] })).toThrow("finite number");
    expect(() => parsePublishedConfig({ ...config, rules: [{ ...proposal.rule,
      conditions: [{ field: "request.path", operator: "gte", value: 2 }] }] })).toThrow("numeric signal");
    expect(evaluateRules({ ...config, rules: [proposal.rule] }, {}).action.type).toBe("redirect");
  });
});
