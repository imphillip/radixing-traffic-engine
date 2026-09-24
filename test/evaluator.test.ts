import { describe, expect, it } from "vitest";
import {
  analyzeFingerprint,
  evaluateRules,
  explainRules,
  fingerprintSignals,
  matchesCondition,
  parsePublishedConfig,
  type PublishedConfig,
} from "../src/index.js";

const legacy = parsePublishedConfig({
  schemaVersion: 1,
  propertyId: "example",
  version: 3,
  domains: ["go.example.com"],
  defaultOrigin: "https://app.example.com",
  rules: [
    { id: "probe", name: "Sensitive path", enabled: true, priority: 1, match: "all", conditions: [{ field: "request.probe", operator: "eq", value: true }], action: { type: "block", status: 404 } },
    { id: "entry", name: "Business entry", enabled: true, priority: 2, match: "all", conditions: [{ field: "request.path", operator: "startsWith", value: "/" }], action: { type: "redirect", status: 302, url: "https://app.example.com", preservePath: true } },
  ],
});

describe("deterministic decisions", () => {
  it("keeps legacy proxy fallback and v2 explicit redirect distinct", () => {
    expect(evaluateRules(legacy, {})).toEqual({ action: { type: "allow" } });
    const v2 = parsePublishedConfig({
      schemaVersion: 2,
      propertyId: "example",
      version: 1,
      domains: ["go.example.com"],
      defaultAction: { type: "redirect", status: 302, url: "https://app.example.com" },
      rules: [],
    });
    expect(evaluateRules(v2, {})).toEqual({ action: v2.defaultAction });
  });

  it("makes the first matching action terminal without mutating policy", () => {
    const before = JSON.stringify(legacy);
    const signals = { "request.path": "/.env", ...fingerprintSignals(analyzeFingerprint({ path: "/.env" })) };
    expect(evaluateRules(legacy, signals)).toMatchObject({ ruleId: "probe", action: { type: "block", status: 404 } });
    expect(explainRules(legacy, signals).evaluation.rules.map((rule) => rule.status)).toEqual(["matched", "not_evaluated"]);
    expect(JSON.stringify(legacy)).toBe(before);
  });

  it("never treats missing negative signals as matches or echoes signal values in traces", () => {
    expect(matchesCondition({ field: "network.ip", operator: "neq", value: "192.0.2.1" }, {})).toBe(false);
    const configured: PublishedConfig = { ...legacy, rules: [{ ...legacy.rules[0]!, conditions: [{ field: "network.ip", operator: "exists" }] }] };
    const trace = explainRules(configured, { "network.ip": "192.0.2.1" });
    expect(trace.ruleId).toBe("probe");
    expect(JSON.stringify(trace)).not.toContain("192.0.2.1");
  });
});
