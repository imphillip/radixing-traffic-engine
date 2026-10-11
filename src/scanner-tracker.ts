import { createHash } from "node:crypto";
import { advanceBehavior, BEHAVIOR_WINDOW_MS, type BehaviorAssessment, type BehaviorState } from "./behavior.js";
import { parseIp } from "./features.js";

/** Process-local, bounded tracking for the standalone redirect ingress. */
export function createScannerTracker(maxSources = 4096) {
  if (!Number.isSafeInteger(maxSources) || maxSources < 1 || maxSources > 65_536) throw new Error("Invalid scanner tracking capacity");
  const states = new Map<string, { state: BehaviorState; expiresAt: number; lastSeen: number }>();
  let nextSweep = 0;
  const digest = (value: string) => createHash("sha256").update(value).digest("base64");
  function observe(hostname: string, ip: string | undefined, path: string, now: number): BehaviorAssessment | undefined {
    if (!Number.isFinite(now)) throw new Error("Invalid scanner clock");
    if (now >= nextSweep) {
      for (const [key, entry] of states) if (now >= entry.expiresAt) states.delete(key);
      nextSweep = now + 1000;
    }
    let address: string;
    try { if (!ip) return undefined; address = parseIp(ip).address; } catch { return undefined; }
    const key = digest(JSON.stringify([hostname.toLowerCase(), address]));
    const previous = states.get(key);
    // At capacity, retain existing cooldowns and fail open for previously unseen sources.
    if (!previous && states.size >= maxSources) return undefined;
    const usable = previous && now >= previous.lastSeen && now < previous.expiresAt ? previous.state : undefined;
    const result = advanceBehavior(usable, digest(path), now);
    states.set(key, { state: result.state, expiresAt: Math.max(now + BEHAVIOR_WINDOW_MS, result.state.cooldownUntil), lastSeen: now });
    return result.assessment;
  }
  return { observe };
}
