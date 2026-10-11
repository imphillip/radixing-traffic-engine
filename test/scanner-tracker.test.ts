import { describe, expect, it } from "vitest";
import { createScannerTracker } from "../src/node.js";

describe("bounded standalone scanner tracking", () => {
  it("isolates hosts/IPs, normalizes mapped addresses and preserves fixed cooldown expiry", () => {
    const tracker = createScannerTracker();
    for (let index = 0; index < 59; index++) {
      expect(tracker.observe("go.example.com", index % 2 ? "::ffff:192.0.2.1" : "192.0.2.1", `/p-${index}`, 1000 + index)?.pathEnumeration).toBe(false);
    }
    expect(tracker.observe("other.example.com", "192.0.2.1", "/p-59", 1059)?.pathEnumeration).toBe(false);
    expect(tracker.observe("go.example.com", "192.0.2.2", "/p-59", 1059)?.pathEnumeration).toBe(false);
    expect(tracker.observe("go.example.com", "192.0.2.1", "/p-59", 1059)).toMatchObject({ pathEnumeration: true, cooldownUntil: 61_059 });
    expect(tracker.observe("go.example.com", "192.0.2.1", "/", 61_058)?.cooldownUntil).toBe(61_059);
    expect(tracker.observe("go.example.com", "192.0.2.1", "/", 61_059)).toMatchObject({ pathEnumeration: false, requests: 1 });
  });
  it("requires both windowed volume and diversity and resets on clock regression", () => {
    const tracker = createScannerTracker();
    for (let index = 0; index < 80; index++) expect(tracker.observe("go.example.com", "192.0.2.1", `/p-${index % 39}`, index)?.pathEnumeration).toBe(false);
    expect(tracker.observe("go.example.com", "192.0.2.1", "/new", 16_000)?.requests).toBe(1);
    expect(tracker.observe("go.example.com", "192.0.2.1", "/newer", 15_999)?.requests).toBe(1);
  });
  it("caps sources, fails open for invalid/new sources and frees expired slots", () => {
    const tracker = createScannerTracker(1);
    expect(tracker.observe("go.example.com", "192.0.2.1", "/", 1000)).toBeDefined();
    expect(tracker.observe("go.example.com", "192.0.2.2", "/", 1001)).toBeUndefined();
    expect(tracker.observe("go.example.com", undefined, "/", 1001)).toBeUndefined();
    expect(tracker.observe("go.example.com", "invalid", "/", 1001)).toBeUndefined();
    expect(tracker.observe("go.example.com", "192.0.2.1", "/", 1002)?.requests).toBe(2);
    expect(tracker.observe("go.example.com", "192.0.2.2", "/", 17_000)?.requests).toBe(1);
    for (const capacity of [0, 1.5, 65_537]) expect(() => createScannerTracker(capacity)).toThrow("capacity");
  });
});
