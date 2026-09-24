import { describe, expect, it } from "vitest";
import { parsePublishedConfig, type Condition } from "../src/index.js";

const base = {
  schemaVersion: 1,
  propertyId: "example",
  version: 1,
  domains: ["go.example.com"],
  defaultOrigin: "https://merchant.example.com",
  rules: [],
};

describe("redirect-only ingress config", () => {
  const redirect = {
    schemaVersion: 2,
    propertyId: "example",
    version: 1,
    domains: ["go.example.com"],
    defaultAction: { type: "redirect", status: 302, url: "https://merchant.example.com/signup", preservePath: false },
    rules: [],
  };

  it("accepts an explicit URL default without an origin", () => {
    expect(parsePublishedConfig(redirect)).toMatchObject({ schemaVersion: 2, defaultAction: { url: "https://merchant.example.com/signup" } });
  });

  it("rejects an implicit proxy, managed-domain loop and proxy rules", () => {
    expect(() => parsePublishedConfig({ ...redirect, defaultOrigin: "https://merchant.example.com" })).toThrow("cannot use defaultOrigin");
    expect(() => parsePublishedConfig({ ...redirect, defaultAction: { type: "allow" } })).toThrow("must be a redirect");
    expect(() => parsePublishedConfig({ ...redirect, defaultAction: { ...redirect.defaultAction, url: "https://go.example.com/" } })).toThrow("managed domain");
    expect(() => parsePublishedConfig({ ...redirect, domains: ["go.example.com", "via.example.com"] })).toThrow("one ingress domain");
    expect(() => parsePublishedConfig({ ...redirect, rules: [{ id: "proxy", name: "Proxy", enabled: true, priority: 1, match: "all", conditions: [{ field: "request.path", operator: "exists" }], action: { type: "route", origin: "https://merchant.example.com" } }] })).toThrow("must redirect or block");
  });
});

describe("fingerprint rule contracts", () => {
  function configured(condition: Condition) {
    return { ...base, rules: [{ id: "fingerprint", name: "Evidence", enabled: true, priority: 1, match: "all", conditions: [condition], action: { type: "block", status: 403 } }] };
  }
  it("accepts typed optional fingerprint rules", () => {
    for (const condition of [
      { field: "client.automation", operator: "in", value: ["declared", "suspected"] },
      { field: "client.headless", operator: "eq", value: true },
      { field: "client.uaMismatch", operator: "exists" },
      { field: "request.probe", operator: "notIn", value: [true] },
      { field: "request.pathEnumeration", operator: "eq", value: true },
    ] satisfies Condition[]) expect(parsePublishedConfig(configured(condition)).rules[0]?.conditions[0]).toEqual(condition);
  });
  it("rejects string booleans, unsupported categories and meaningless operators", () => {
    for (const condition of [
      { field: "client.headless", operator: "eq", value: "true" },
      { field: "client.automation", operator: "eq", value: "human" },
      { field: "client.automation", operator: "contains", value: "declared" },
      { field: "request.probe", operator: "in", value: [] },
      { field: "request.pathEnumeration", operator: "eq", value: "true" },
    ] satisfies Condition[]) expect(() => parsePublishedConfig(configured(condition))).toThrow();
  });
});

describe("published attribution config", () => {
  it("preserves an explicit attribution capture allowlist", () => {
    expect(parsePublishedConfig({
      ...base,
      attribution: {
        enabled: true,
        partnerQueryParameter: "code",
        entryQueryPrefixes: ["entry_"],
      },
    }).attribution).toEqual({
      enabled: true,
      partnerQueryParameter: "code",
      entryQueryPrefixes: ["entry_"],
    });
  });

  it("rejects disabled or unsafe attribution configuration", () => {
    expect(() => parsePublishedConfig({
      ...base,
      attribution: { enabled: false },
    })).toThrow("attribution.enabled must be true");
    expect(() => parsePublishedConfig({
      ...base,
      attribution: { enabled: true, partnerQueryParameter: "bad name" },
    })).toThrow("valid query parameter name");
    expect(() => parsePublishedConfig({
      ...base,
      attribution: { enabled: true, entryQueryPrefixes: ["entry_", "entry_"] },
    })).toThrow("must be unique");
  });
});
