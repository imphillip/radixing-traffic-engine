// Versioned, conservative evidence for redirect ingress, not a general asset rate limit.
export const BEHAVIOR_VERSION = 1 as const;
export const BEHAVIOR_WINDOW_MS = 15_000;
export const BEHAVIOR_REQUESTS = 60;
export const BEHAVIOR_PATHS = 40;
export const BEHAVIOR_COOLDOWN_MS = 60_000;

export interface BehaviorState {
  recent: { at: number; path: string }[];
  cooldownUntil: number;
  triggerPaths: number;
}

export interface BehaviorAssessment {
  version: typeof BEHAVIOR_VERSION;
  pathEnumeration: boolean;
  requests: number;
  paths: number;
  cooldownUntil: number;
}

export function advanceBehavior(previous: BehaviorState | undefined, path: string, now: number): {
  state: BehaviorState;
  assessment: BehaviorAssessment;
} {
  if (previous && now < previous.cooldownUntil) {
    return { state: previous, assessment: {
      version: BEHAVIOR_VERSION, pathEnumeration: true, requests: BEHAVIOR_REQUESTS,
      paths: previous.triggerPaths, cooldownUntil: previous.cooldownUntil,
    } };
  }
  // Reset after cooldown; blocked attempts never extend a client's penalty.
  const recent = (previous?.cooldownUntil ? [] : previous?.recent ?? [])
    .filter((entry) => entry.at > now - BEHAVIOR_WINDOW_MS)
    .slice(-(BEHAVIOR_REQUESTS - 1));
  recent.push({ at: now, path });
  const paths = new Set(recent.map((entry) => entry.path)).size;
  const pathEnumeration = recent.length >= BEHAVIOR_REQUESTS && paths >= BEHAVIOR_PATHS;
  const cooldownUntil = pathEnumeration ? now + BEHAVIOR_COOLDOWN_MS : 0;
  return {
    state: { recent: pathEnumeration ? [] : recent, cooldownUntil, triggerPaths: pathEnumeration ? paths : 0 },
    assessment: { version: BEHAVIOR_VERSION, pathEnumeration, requests: recent.length, paths, cooldownUntil },
  };
}
