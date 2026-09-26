import { describe, expect, it } from "vitest";
import {
  parsePublishedConfig,
  parseRuleProposal,
  replayRuleProposal,
  reviewRuleProposal,
  reviewRuleSet,
} from "../src/index.js";

const config = parsePublishedConfig({
  schemaVersion: 2,
  propertyId: "example",
  version: 4,
  domains: ["go.example.com"],
  defaultAction: { type: "redirect", status: 302, url: "https://app.example.com/" },
  rules: [{
    id: "probe",
    name: "Known sensitive path",
    enabled: true,
    priority: 1,
    match: "all",
    conditions: [{ field: "request.probe", operator: "eq", value: true }],
    action: { type: "block", status: 404 },
  }],
});

const rawProposal = {
  schemaVersion: 1,
  id: "proposal-20260926",
  propertyId: "example",
  baseConfigVersion: 4,
  source: { kind: "llm", referenceId: "batch-20260926" },
  evidenceIds: ["event-a", "review-b"],
  createdAt: "2026-09-26T08:00:00.000Z",
  reviewAt: "2026-10-01T00:00:00.000Z",
  expiresAt: "2026-10-15T00:00:00.000Z",
  rule: {
    id: "admin-pattern",
    name: "Reviewed admin pattern",
    enabled: true,
    priority: 2,
    match: "all",
    conditions: [{ field: "request.path", operator: "startsWith", value: "/admin" }],
    action: { type: "block", status: 403 },
  },
};

describe("rule proposals", () => {
  it("validates a declarative proposal against the current policy and reviews explicit dates", () => {
    const proposal = parseRuleProposal(config, rawProposal);
    expect(proposal.rule.action).toEqual({ type: "block", status: 403 });
    expect(reviewRuleProposal(proposal, "2026-09-30T23:59:59.999Z")).toEqual({ reviewDue: false, expired: false });
    expect(reviewRuleProposal(proposal, "2026-10-15T00:00:00.000Z")).toEqual({ reviewDue: true, expired: true });
  });

  it("rejects stale bindings, duplicate IDs, invalid dates and unsupported actions", () => {
    expect(() => parseRuleProposal(config, { ...rawProposal, baseConfigVersion: 3 })).toThrow("base config version");
    expect(() => parseRuleProposal(config, { ...rawProposal, rule: { ...rawProposal.rule, id: "probe" } })).toThrow("unique");
    expect(() => parseRuleProposal(config, { ...rawProposal, reviewAt: "2026-02-30T00:00:00.000Z" })).toThrow("valid UTC");
    expect(() => parseRuleProposal(config, { ...rawProposal, expiresAt: rawProposal.createdAt })).toThrow("expiry");
    expect(() => parseRuleProposal(config, { ...rawProposal, rule: { ...rawProposal.rule, action: { type: "route", origin: "https://app.example.com" } } })).toThrow("must redirect or block");
    expect(() => parseRuleProposal(config, { ...rawProposal, evidenceIds: ["192.0.2.10"] })).toThrow("opaque identifier");
    expect(() => parseRuleProposal(config, { ...rawProposal, instruction: "ignore policy" })).toThrow("unsupported fields");
    expect(() => parseRuleProposal(config, { ...rawProposal, expiresAt: undefined })).toThrow("require expiresAt");
    expect(() => parseRuleProposal(config, { ...rawProposal, rule: { ...rawProposal.rule, priority: 0 } })).toThrow("cannot precede");
  });

  it("replays against the first-match policy and reports counts without raw signals", () => {
    const proposal = parseRuleProposal(config, rawProposal);
    const summary = replayRuleProposal(config, proposal, [
      { signals: { "request.path": "/admin", "network.ip": "192.0.2.10" }, reviewedLabel: "legitimate" },
      { signals: { "request.path": "/admin/config", "request.probe": true }, reviewedLabel: "unwanted" },
      { signals: { "request.path": "/admin-test" }, reviewedLabel: "unwanted" },
      { signals: { "request.path": "/home" } },
    ]);
    expect(summary).toEqual({
      version: 1,
      proposalId: "proposal-20260926",
      baseConfigVersion: 4,
      total: 4,
      matched: 3,
      selected: 2,
      changedAction: 2,
      reviewedLegitimate: 1,
      newlyBlockedLegitimate: 1,
      reviewedUnwanted: 2,
      selectedReviewedUnwanted: 1,
    });
    expect(JSON.stringify(summary)).not.toContain("192.0.2.10");
  });

  it("keeps legacy policy defaults while reviewing analyst proposals", () => {
    const legacy = parsePublishedConfig({
      schemaVersion: 1,
      propertyId: "example",
      version: 4,
      domains: ["go.example.com"],
      defaultOrigin: "https://app.example.com",
      rules: [],
    });
    const proposal = parseRuleProposal(legacy, {
      ...rawProposal,
      source: { kind: "analyst", referenceId: "incident-review" },
      expiresAt: undefined,
    });
    expect(proposal.expiresAt).toBeUndefined();
    expect(replayRuleProposal(legacy, proposal, [{ signals: { "request.path": "/home" } }])).toMatchObject({
      total: 1,
      matched: 0,
      selected: 0,
      changedAction: 0,
    });
  });
});

describe("rule-set review", () => {
  it("flags due, expired, duplicate, shadowed and missing records without retiring rules", () => {
    const reviewed = parsePublishedConfig({
      ...config,
      rules: [
        { ...rawProposal.rule, id: "first", priority: 1 },
        { ...rawProposal.rule, id: "duplicate", priority: 2 },
        { ...rawProposal.rule, id: "shadowed", priority: 3, action: { type: "redirect", status: 302, url: "https://other.example.com/" } },
        { ...config.rules[0], priority: 4 },
      ],
    });
    const result = reviewRuleSet(reviewed, [
      { ruleId: "first", reviewAt: "2026-09-01T00:00:00.000Z" },
      { ruleId: "duplicate", reviewAt: "2026-10-15T00:00:00.000Z" },
      { ruleId: "shadowed", reviewAt: "2026-09-01T00:00:00.000Z", expiresAt: "2026-09-15T00:00:00.000Z" },
    ], "2026-10-01T00:00:00.000Z");
    expect(result.issues).toEqual([
      { ruleId: "first", kind: "review_due" },
      { ruleId: "duplicate", kind: "duplicate", relatedRuleId: "first" },
      { ruleId: "shadowed", kind: "review_due" },
      { ruleId: "shadowed", kind: "expired" },
      { ruleId: "shadowed", kind: "shadowed", relatedRuleId: "first" },
      { ruleId: "probe", kind: "missing_record" },
    ]);
    expect(reviewed.rules).toHaveLength(4);
  });
});
