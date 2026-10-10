import { describe, expect, it } from "vitest";
import { compileFeatureSnapshot, createTds, enrichRequest, matchesCondition, parsePublishedConfig, parseIp } from "../src/index.js";
import { fixtureSnapshot, now, policy, ua } from "./fixtures.js";

describe("open feature enrichment", () => {
  it("looks up range boundaries, overlapping prefixes and independent country evidence", () => {
    const index = compileFeatureSnapshot(fixtureSnapshot());
    for (const ip of ["192.0.2.0", "192.0.2.255"]) expect(index.lookup(ip, "ExampleBot/1.0", now, 1000).signals).toMatchObject({ "network.asn": 64500, "network.country": "US", "geo.country": "CA", "network.datacenter": true, "client.bot": true });
    expect(index.lookup("192.0.2.127", ua, now, 1000).signals["network.vpn"]).toBe(false);
    expect(index.lookup("192.0.2.128", ua, now, 1000).signals["network.vpn"]).toBe(true);
    expect(index.lookup("192.0.3.0", ua, now, 1000).signals["network.asn"]).toBeUndefined();
  });
  it("preserves IPv6 VPN coverage gaps and missing or stale facts as unknown", () => {
    const index = compileFeatureSnapshot(fixtureSnapshot());
    expect(index.lookup("2001:db8::1", undefined, now, 1000).signals).toMatchObject({ "network.asn": 64501 });
    expect(index.lookup("2001:db8::1", undefined, now, 1000).signals["network.vpn"]).toBeUndefined();
    const stale = index.lookup("192.0.2.1", "ExampleBot/1.0", now + 1001, 1000);
    expect(stale.signals).toEqual({ "network.ip": "192.0.2.1" });
    expect(stale.staleSources).toHaveLength(6);
    expect(index.lookup(undefined, undefined, now, 1000).signals).toEqual({});
  });
  it("normalizes mapped IPv4 and rejects ambiguous or invalid IP notation", () => {
    expect(parseIp("::ffff:192.0.2.1").address).toBe("192.0.2.1");
    for (const ip of ["192.0.2.999", "0xc0000201", "192.00.2.1", "fe80::1%eth0"]) expect(() => parseIp(ip)).toThrow();
  });
  it("rejects overlapping ASN data and unsafe regex syntax at compilation", () => {
    const snapshot = fixtureSnapshot();
    snapshot.data.asn.push({ ...snapshot.data.asn[0]! });
    expect(() => compileFeatureSnapshot(snapshot)).toThrow("Overlapping");
    const unsupported = fixtureSnapshot(); unsupported.data.crawlers[0]!.pattern = "(?=bot)";
    expect(() => compileFeatureSnapshot(unsupported)).toThrow();
  });
  it("extracts device and campaign signals without accepting forwarded-IP claims", () => {
    const input = { request: new Request("https://go.example.com/?utm_source=newsletter", { headers: { "user-agent": ua, "x-forwarded-for": "192.0.2.1" } }), now };
    const result = enrichRequest(input, compileFeatureSnapshot(fixtureSnapshot()));
    expect(result.signals).toMatchObject({ "device.type": "mobile", "device.os": "Android", "browser.name": "Chrome", "campaign.source": "newsletter" });
    expect(result.signals["network.ip"]).toBeUndefined();
    expect(enrichRequest({ ...input, trustedSignals: { "geo.country": "FR", "request.hostname": "wrong.example.com" } }, compileFeatureSnapshot(fixtureSnapshot())).signals).toMatchObject({ "geo.country": "FR", "request.hostname": "go.example.com" });
  });
});

describe("deterministic routing and execution", () => {
  it("executes project network rules and applies default on stale data", () => {
    const configured = { ...policy, rules: [{ id: "network", name: "Network", enabled: true, priority: 1, match: "all", conditions: [{ field: "network.vpn", operator: "eq", value: true }], action: { type: "redirect", status: 302, url: "https://app.example.com/" } }] };
    const tds = createTds(configured, fixtureSnapshot(), { maxDataAgeMs: 1000 });
    const input = { request: new Request("https://go.example.com/"), ip: "192.0.2.255", now };
    expect(tds.handle(input).response.headers.get("location")).toBe("https://app.example.com/");
    expect(tds.handle({ ...input, now: now + 1001 }).response.headers.get("location")).toBe("https://www.example.com/");
    expect(tds.decide(input)).toEqual(tds.decide(input));
    expect(JSON.stringify(tds.decide(input))).not.toContain(input.ip);
  });
  it("uses stable split assignment, explicit missing-key fallback and no random routing", () => {
    const split = { type: "split", status: 302, key: "client.key", salt: "experiment-1", fallbackUrl: "https://www.example.com/", targets: [{ url: "https://a.example.com/", weight: 3 }, { url: "https://b.example.com/", weight: 1 }] };
    const tds = createTds({ ...policy, defaultAction: split }, fixtureSnapshot());
    const input = { request: new Request("https://go.example.com/"), now, clientKey: "synthetic-visitor" };
    expect(tds.decide(input)).toEqual(tds.decide(input));
    expect(tds.decide({ request: input.request, now }).action).toMatchObject({ url: split.fallbackUrl });
    const urls = Array.from({ length: 200 }, (_, index) => tds.handle({ ...input, clientKey: `visitor-${index}` }).response.headers.get("location"));
    expect(new Set(urls).size).toBe(2);
    expect(() => parsePublishedConfig({ ...policy, defaultAction: { ...split, targets: [{ url: "https://go.example.com/", weight: 1 }, split.targets[1]] } })).toThrow("managed domain");
  });
  it("isolates active policy/data from caller and returned-action mutations", () => {
    const configured = { ...policy, defaultAction: { ...policy.defaultAction, queryAllowlist: ["utm_source"] } };
    const snapshot = fixtureSnapshot(), tds = createTds(configured, snapshot);
    const input = { request: new Request("https://go.example.com/?utm_source=newsletter"), ip: "192.0.2.1", now };
    configured.defaultAction.url = "https://changed.example.com/";
    snapshot.sources[0]!.fetchedAt = "2000-01-01T00:00:00Z";
    snapshot.data.asn[0]!.asn = 1;
    const decision = tds.decide(input);
    if (decision.action.type !== "redirect") throw new Error("Expected redirect");
    decision.action.url = "https://changed.example.com/"; decision.action.queryAllowlist!.push("credential");
    expect(tds.handle(input).response.headers.get("location")).toBe("https://www.example.com/?utm_source=newsletter");
    expect(tds.decide(input).evidence.staleSources).toEqual([]);
  });
  it("forwards only allowed query parameters and appends path without changing destination host", () => {
    const tds = createTds({ ...policy, defaultAction: { ...policy.defaultAction, url: "https://www.example.com/base?fixed=1", preservePath: true, queryAllowlist: ["utm_source"] } }, fixtureSnapshot());
    const result = tds.handle({ request: new Request("https://go.example.com//other.example.com/path?utm_source=one&utm_source=two&credential=secret"), now });
    const url = new URL(result.response.headers.get("location")!);
    expect(url.hostname).toBe("www.example.com"); expect(url.pathname).toBe("/base//other.example.com/path");
    expect(url.searchParams.getAll("utm_source")).toEqual(["one", "two"]);
    expect(url.searchParams.has("credential")).toBe(false); expect(url.searchParams.get("fixed")).toBe("1");
    expect(result.response.headers.get("cache-control")).toBe("no-store");
  });
  it("enforces configured hosts and methods and suppresses HEAD bodies", async () => {
    const tds = createTds(policy, fixtureSnapshot());
    expect(tds.handle({ request: new Request("https://unknown.example.com/"), now }).response.status).toBe(421);
    expect(tds.handle({ request: new Request("https://go.example.com/", { method: "POST" }), now }).response.status).toBe(405);
    const blocked = createTds({ ...policy, rules: [{ id: "all", name: "All", enabled: true, priority: 1, match: "all", conditions: [{ field: "request.path", operator: "exists" }], action: { type: "block", status: 404, body: "Unavailable" } }] }, fixtureSnapshot());
    expect(await blocked.handle({ request: new Request("https://go.example.com/", { method: "HEAD" }), now }).response.text()).toBe("");
  });
  it("matches IPv4/IPv6 CIDR conditions and never matches unknown negative evidence", () => {
    for (const [address, prefix] of [["192.0.2.1", "192.0.2.0/24"], ["2001:db8::1", "2001:db8::/32"]]) expect(matchesCondition({ field: "network.ip", operator: "inCidr", value: [prefix!] }, { "network.ip": address! })).toBe(true);
    expect(matchesCondition({ field: "network.ip", operator: "notInCidr", value: ["192.0.2.0/24"] }, {})).toBe(false);
    expect(matchesCondition({ field: "network.ip", operator: "notInCidr", value: ["192.0.2.0/24"] }, { "network.ip": "invalid" })).toBe(false);
  });
});
