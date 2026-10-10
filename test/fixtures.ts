import { createHash } from "node:crypto";
import { parseFeatureSnapshot, type FeatureSnapshot, type FeatureSource } from "../src/features.js";
export const now = Date.parse("2026-01-15T00:00:00Z");
export const ua = "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36";
export const policy = { schemaVersion: 2, propertyId: "example", version: 1, domains: ["go.example.com"], defaultAction: { type: "redirect", status: 302, url: "https://www.example.com/" }, rules: [] };
export function fixtureSnapshot(): FeatureSnapshot {
  const ids: FeatureSource["id"][] = ["iptoasn-v4", "iptoasn-v6", "vpn", "datacenter", "crawlers", "dbip-country"];
  const snapshot = parseFeatureSnapshot({ schemaVersion: 1, id: "0".repeat(64), sources: ids.map((id) => ({ id, url: `https://example.com/${id}`, license: "MIT", fetchedAt: new Date(now).toISOString(), sha256: "1".repeat(64), records: 1 })), data: {
    asn: [{ start: "192.0.2.0", end: "192.0.2.255", asn: 64500, organization: "Example Network", country: "US" }, { start: "2001:db8::", end: "2001:db8::ffff", asn: 64501, organization: "Example IPv6", country: "DE" }],
    vpn: ["192.0.2.128/25"], datacenter: ["192.0.2.0/24", "192.0.2.0/25"], crawlers: [{ pattern: "ExampleBot/", url: "https://example.com/bot" }], country: [{ start: "192.0.2.0", end: "192.0.2.255", country: "CA" }],
  } });
  snapshot.id = createHash("sha256").update(JSON.stringify({ sources: snapshot.sources, data: snapshot.data })).digest("hex");
  return snapshot;
}
