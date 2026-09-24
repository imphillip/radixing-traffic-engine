import { describe, expect, it, vi } from "vitest";
import {
  createOpenRouterJevGateway,
  decideWithJev,
  JevGatewayError,
  parseJevDecisionPolicy,
  parsePublishedConfig,
  sanitizeJevFeatures,
  type JevClassification,
  type JevDecisionPolicy,
  type JevGateway,
} from "../src/index.js";

const config = parsePublishedConfig({
  schemaVersion: 1,
  propertyId: "example",
  version: 2,
  domains: ["go.example.com"],
  defaultOrigin: "https://app.example.com",
  rules: [
    { id: "deny-probe", name: "Probe", enabled: true, priority: 1, match: "all", conditions: [{ field: "request.probe", operator: "eq", value: true }], action: { type: "block", status: 404 } },
    { id: "entry", name: "Entry", enabled: true, priority: 2, match: "all", conditions: [{ field: "request.path", operator: "startsWith", value: "/" }], action: { type: "redirect", status: 302, url: "https://app.example.com", preservePath: true } },
  ],
});

const rawPolicy = {
  version: 1,
  propertyId: "example",
  configVersion: 2,
  mode: "enforce",
  eligibleRuleIds: ["entry"],
  classifyDefault: false,
  maxWaitMs: 50,
  minConfidence: 0.85,
  minChoiceProbability: 0.8,
  actions: { other_automation: { type: "block", status: 403 } },
};
const policy = parseJevDecisionPolicy(config, rawPolicy);
const signals = { "request.method": "GET", "request.path": "/signup" };
const features = { method: "GET" as const, clientIp: "192.0.2.7", asn: 64500, navigation: true, cookie: "secret" };

function classification(label: JevClassification["label"] = "other_automation", confidence = 0.94): JevClassification {
  return {
    label,
    confidence,
    probabilities: {
      ordinary_visitor: label === "ordinary_visitor" ? 0.9 : 0.025,
      benign_bot_candidate: label === "benign_bot_candidate" ? 0.9 : 0.025,
      professional_probe: label === "professional_probe" ? 0.9 : 0.025,
      other_automation: label === "other_automation" ? 0.9 : 0.025,
      unresolved: label === "unresolved" ? 0.9 : 0.025,
    },
  };
}

function gateway(answer: unknown): JevGateway {
  return { classify: vi.fn(async () => answer) };
}

describe("Jev decision flow", () => {
  it("keeps explicit blocks, non-GETs, and known probe evidence outside Jev", async () => {
    const model = gateway(classification());
    const blocked = await decideWithJev({ config, signals: { ...signals, "request.probe": true }, features, policy, gateway: model });
    expect(blocked).toMatchObject({ source: "static", decision: { ruleId: "deny-probe", action: { type: "block", status: 404 } }, jev: { status: "not_eligible" } });
    const head = await decideWithJev({ config, signals: { ...signals, "request.method": "HEAD" }, features, policy, gateway: model });
    expect(head.jev.status).toBe("not_eligible");
    const enumerating = await decideWithJev({ config, signals: { ...signals, "request.pathEnumeration": true }, features, policy, gateway: model });
    expect(enumerating.jev.status).toBe("not_eligible");
    const featureEnumeration = await decideWithJev({ config, signals, features: { ...features, pathEnumeration: true }, policy, gateway: model });
    expect(featureEnumeration.jev.status).toBe("not_eligible");
    expect(model.classify).not.toHaveBeenCalled();
  });

  it("maps a valid class through local policy without changing the static rule", async () => {
    const model = gateway(classification());
    const result = await decideWithJev({ config, signals, features, policy, gateway: model });
    expect(result).toMatchObject({
      source: "jev",
      decision: { action: { type: "block", status: 403 } },
      staticDecision: { ruleId: "entry", action: { type: "redirect", status: 302 } },
      jev: { version: 1, status: "applied", policyVersion: 1, label: "other_automation", confidence: 0.94, choiceProbability: 0.9 },
    });
    expect(result.decision.ruleId).toBeUndefined();
    expect(JSON.stringify(result)).not.toContain("192.0.2.7");
    expect(JSON.stringify(result)).not.toContain("secret");
    expect(model.classify).toHaveBeenCalledWith({ method: "GET", clientIp: "192.0.2.7", asn: 64500, navigation: true }, expect.any(AbortSignal));
  });

  it("supports observation without applying the candidate action", async () => {
    const observe: JevDecisionPolicy = { ...policy, mode: "observe" };
    const result = await decideWithJev({ config, signals, features, policy: observe, gateway: gateway(classification()) });
    expect(result).toMatchObject({ source: "static", decision: { ruleId: "entry" }, candidateDecision: { action: { type: "block", status: 403 } }, jev: { status: "observed" } });
  });

  it("falls back on low confidence, unresolved, unmapped, malformed, absent, or unavailable evidence", async () => {
    const cases: [unknown, string][] = [
      [classification("other_automation", 0.4), "low_confidence"],
      [classification("unresolved"), "unresolved"],
      [classification("ordinary_visitor"), "unmapped"],
      [{ ...classification(), probabilities: { ...classification().probabilities, other_automation: 0.1 } }, "invalid_response"],
    ];
    for (const [answer, status] of cases) {
      const result = await decideWithJev({ config, signals, features, policy, gateway: gateway(answer) });
      expect(result).toMatchObject({ source: "static", decision: { ruleId: "entry" }, jev: { status } });
    }
    expect((await decideWithJev({ config, signals, features, policy })).jev.status).toBe("unavailable");
    expect((await decideWithJev({ config, signals, features: { method: "GET", authorization: "secret" }, policy, gateway: gateway(classification()) })).jev.status).toBe("insufficient_features");
    expect((await decideWithJev({ config, signals, features: { navigation: true }, policy, gateway: gateway(classification()) })).jev.status).toBe("insufficient_features");
    expect((await decideWithJev({ config, signals, features, policy: { ...policy, maxWaitMs: 5000 }, gateway: gateway(classification()) })).jev.status).toBe("invalid_policy");
  });

  it("returns the static action on timeout even if the gateway ignores abort", async () => {
    const slow: JevGateway = { classify: () => new Promise(() => {}) };
    const result = await decideWithJev({ config, signals, features, policy: { ...policy, maxWaitMs: 5 }, gateway: slow });
    expect(result).toMatchObject({ source: "static", decision: { ruleId: "entry" }, jev: { status: "timeout" } });
  });

  it("keeps controlled provider failures separate without exposing their messages", async () => {
    const model: JevGateway = { classify: async () => { throw new JevGatewayError("rate_limited"); } };
    expect((await decideWithJev({ config, signals, features, policy, gateway: model })).jev.status).toBe("rate_limited");
    const unexpected: JevGateway = { classify: async () => { throw new Error("private diagnostic"); } };
    const result = await decideWithJev({ config, signals, features, policy, gateway: unexpected });
    expect(result.jev.status).toBe("network_error");
    expect(JSON.stringify(result)).not.toContain("private diagnostic");
  });

  it("can consult the v2 default only when explicitly configured", async () => {
    const v2 = parsePublishedConfig({ schemaVersion: 2, propertyId: "example", version: 1, domains: ["go.example.com"], defaultAction: { type: "redirect", status: 302, url: "https://app.example.com" }, rules: [] });
    const configured = parseJevDecisionPolicy(v2, { ...rawPolicy, configVersion: 1, eligibleRuleIds: [], classifyDefault: true });
    expect((await decideWithJev({ config: v2, signals, features, policy: configured, gateway: gateway(classification()) })).jev.status).toBe("applied");
    expect(() => parseJevDecisionPolicy(config, { ...rawPolicy, eligibleRuleIds: [], classifyDefault: true })).toThrow("v2 default");
  });
});

describe("Jev policy validation", () => {
  it("requires explicit eligible redirects and locally valid actions", () => {
    expect(() => parseJevDecisionPolicy(config, { ...rawPolicy, eligibleRuleIds: ["deny-probe"] })).toThrow("enabled redirect");
    expect(() => parseJevDecisionPolicy(config, { ...rawPolicy, eligibleRuleIds: ["missing"] })).toThrow("enabled redirect");
    expect(() => parseJevDecisionPolicy(config, { ...rawPolicy, actions: { unresolved: { type: "block", status: 403 } } })).toThrow("unsupported");
    expect(() => parseJevDecisionPolicy(config, { ...rawPolicy, actions: { other_automation: { type: "redirect", status: 302, url: "https://go.example.com" } } })).toThrow("managed domain");
    expect(() => parseJevDecisionPolicy(config, { ...rawPolicy, minConfidence: 0 })).toThrow("minConfidence");
    expect(() => parseJevDecisionPolicy(config, { ...rawPolicy, maxWaitMs: 2001 })).toThrow("maxWaitMs");
    expect(() => parseJevDecisionPolicy(config, { ...rawPolicy, propertyId: "other" })).toThrow("property and config version");
    expect(() => parseJevDecisionPolicy(config, { ...rawPolicy, configVersion: 1 })).toThrow("property and config version");
  });
});

describe("OpenRouter Jev gateway", () => {
  const answer = { answers: { visitor_class: { type: "choice", choice: "other_automation", confidence: 0.94, probabilities: classification().probabilities } } };

  it("runs a provider answer through the local action mapping", async () => {
    const fetcher = vi.fn(async () => Response.json(answer));
    const model = createOpenRouterJevGateway({ apiKey: "test-key", fetch: fetcher as typeof fetch });
    const result = await decideWithJev({ config, signals, features, policy, gateway: model });
    expect(result).toMatchObject({ source: "jev", decision: { action: { type: "block", status: 403 } }, jev: { status: "applied", label: "other_automation" } });
    expect(fetcher).toHaveBeenCalledOnce();
  });

  it("sends only allowlisted features under ZDR and denies provider data collection", async () => {
    const fetcher = vi.fn(async (_url: string | URL | Request, _init?: RequestInit) => Response.json(answer));
    const model = createOpenRouterJevGateway({ apiKey: "test-key", fetch: fetcher as typeof fetch });
    const result = await model.classify({ ...features, path: "/secret", cookie: "secret" } as typeof features, new AbortController().signal);
    expect(result).toMatchObject({ label: "other_automation", confidence: 0.94 });
    const [url, init] = fetcher.mock.calls[0]!;
    expect(url).toBe("https://openrouter.ai/api/alpha/decisions");
    expect(init).toMatchObject({ method: "POST", redirect: "manual", headers: { authorization: "Bearer test-key", "content-type": "application/json" } });
    const body = JSON.parse(String(init?.body)) as Record<string, unknown>;
    expect(body).toMatchObject({ model: "typesafe/jev-1.13", provider: { zdr: true, data_collection: "deny" }, state: { clientIp: "192.0.2.7", asn: 64500, navigation: true } });
    expect(JSON.stringify(body)).not.toContain("/secret");
    expect(JSON.stringify(body)).not.toContain("cookie");
    expect(JSON.stringify(body)).not.toContain("secret");
  });

  it("rejects invalid provider responses and never follows redirects", async () => {
    for (const [response, code] of [
      [new Response(null, { status: 302, headers: { location: "https://elsewhere.example.com" } }), "provider_error"],
      [new Response("text", { headers: { "content-type": "text/plain" } }), "invalid_content_type"],
      [new Response("x".repeat(8193), { headers: { "content-type": "application/json" } }), "invalid_body"],
      [Response.json({ answers: {} }), "invalid_response"],
    ] as const) {
      const model = createOpenRouterJevGateway({ apiKey: "test-key", fetch: vi.fn(async () => response) as typeof fetch });
      await expect(model.classify({ method: "GET" }, new AbortController().signal)).rejects.toMatchObject({ code });
    }
  });

  it("canonicalizes IPs and omits unknown or invalid outbound fields", () => {
    expect(sanitizeJevFeatures({ clientIp: "2001:0DB8:0:0:0:0:0:1", asn: -1, country: "usa", path: "/login", authorization: "secret", deviceOs: "secret", recentRequests: 61, headless: false })).toEqual({ clientIp: "2001:db8::1", headless: false });
    expect(sanitizeJevFeatures({ deviceOs: "linux" })).toEqual({ deviceOs: "linux" });
  });
});
