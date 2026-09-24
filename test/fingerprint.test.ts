import { describe, expect, it } from "vitest";
import { analyzeFingerprint, analyzeProbePath, fingerprintSignals, matchesCondition } from "../src/index.js";

const chrome = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36";

describe("fingerprint evidence", () => {
  it("identifies hidden headless declarations and contradictory major versions", () => {
    const assessment = analyzeFingerprint({
      userAgent: chrome,
      brands: '"Not;A=Brand";v="99", "HeadlessChrome";v="139", "Chromium";v="139"',
      platform: '"Linux"',
      path: "/",
    });
    expect(assessment).toEqual({ version: 1, automation: "declared", headless: true, uaMismatch: true, probe: false, probeRulesetVersion: 1, evidence: ["headless_hint", "version_mismatch"] });
    expect(matchesCondition({ field: "client.headless", operator: "eq", value: true }, fingerprintSignals(assessment))).toBe(true);
  });

  it("parses GREASE brands and keeps coherent browser observations inconclusive", () => {
    const result = analyzeFingerprint({ userAgent: chrome, brands: '"Not,A;Brand";v="99", "Chromium";v="119", "Google Chrome";v="119"', platform: '"Linux"', path: "/" });
    expect(result).toMatchObject({ automation: "unknown", headless: false, uaMismatch: false, evidence: [] });
  });

  it.each(["curl/8.7.1", "Go-http-client/1.1", "python-requests/2.32.0"])("recognizes declared HTTP client %s without requiring navigation headers", (userAgent) => {
    expect(analyzeFingerprint({ userAgent, path: "/" })).toMatchObject({ automation: "declared", evidence: ["automation_ua"] });
  });

  it.each(["Googlebot/2.1", "Mozilla/5.0 (compatible; ExampleCrawler/1.0)", "HeadlessChrome/139.0.0.0"])("recognizes explicit UA automation %s", (userAgent) => {
    expect(analyzeFingerprint({ userAgent }).automation).toBe("declared");
  });

  it.each([
    ["/.env", "env-file"],
    ["/www/.env.production", "env-file"],
    ["/.env~", "env-file"],
    ["/.env1", "env-file"],
    ["/.env2", "env-file"],
    ["/%2egit/config", "vcs-metadata"],
    ["/.SVN/entries", "vcs-metadata"],
    ["/.AWS/credentials", "cloud-credentials"],
    ["/administrator/phpinfo.php", "phpinfo"],
    ["/firebase-adminsdk.json", "service-account-key"],
  ] as const)("marks %s as probe evidence under %s", (path, probeRule) => {
    expect(analyzeFingerprint({ userAgent: chrome, path })).toMatchObject({
      automation: "suspected",
      probe: true,
      probeRulesetVersion: 1,
      probeRule,
      evidence: ["sensitive_path"],
    });
  });

  it.each(["/", "/environment", "/.environment", "/blog/phpinfo-guide", "/wp-login.php", "/products/robotics", "/assets/status"])("does not infer automation from ordinary path %s", (path) => {
    expect(analyzeFingerprint({ userAgent: chrome, path })).toMatchObject({ automation: "unknown", probe: false, probeRulesetVersion: 1, evidence: [] });
  });

  it.each([
    "/",
    "/robots.txt",
    "/favicon.ico",
    "/assets/index-Dz_YQBJt.js.map",
    "/_next/static/chunks/392bztk23uk91.js.map",
    "/wp-json/",
    "/js/antibot-client.js",
    "/static/style/protect/index.js",
  ])("keeps non-sensitive paths outside the probe catalog: %s", (path) => {
    expect(analyzeProbePath(path)).toEqual({ version: 1, probe: false });
  });

  it("does not invent consistency from absent or malformed hints", () => {
    for (const brands of [undefined, '"Chromium";v="119', '("Chromium";v="119")', '"Chromium";v="119", "Chromium";v="120"', '"Chromium";v=119', "x".repeat(5000)]) {
      const result = analyzeFingerprint({ userAgent: chrome, brands });
      expect(result.automation).toBe("unknown");
      expect(result.uaMismatch).toBeUndefined();
      expect(matchesCondition({ field: "client.uaMismatch", operator: "neq", value: true }, fingerprintSignals(result))).toBe(false);
    }
  });

  it("preserves unknown values for absent or oversized observations", () => {
    expect(analyzeFingerprint({})).toEqual({ version: 1, automation: "unknown", headless: undefined, uaMismatch: undefined, probe: undefined, evidence: [] });
    expect(analyzeFingerprint({ userAgent: "x".repeat(3000), platform: "x".repeat(200), path: "/%ZZ" })).toMatchObject({ automation: "unknown", headless: undefined, uaMismatch: undefined, probe: undefined });
  });

  it("reports platform contradictions but accommodates iPad desktop mode", () => {
    expect(analyzeFingerprint({ userAgent: chrome, platform: '"Windows"' })).toMatchObject({ automation: "suspected", uaMismatch: true, evidence: ["platform_mismatch"] });
    expect(analyzeFingerprint({ userAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Version/17.0 Safari/605.1.15", platform: '"iOS"' })).toMatchObject({ automation: "unknown", uaMismatch: undefined });
  });

  it("does not treat an arbitrary brand containing HeadlessChrome as the declared brand", () => {
    expect(analyzeFingerprint({ userAgent: chrome, brands: '"NotHeadlessChrome";v="119"' })).toMatchObject({ automation: "unknown", headless: false });
  });
});
