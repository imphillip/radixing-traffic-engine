import { describe, expect, it } from "vitest";
import { advanceBehavior, type BehaviorState } from "../src/index.js";

describe("versioned path-diversity evidence", () => {
  it("requires volume and diversity, then expires a fixed cooldown", () => {
    let state: BehaviorState | undefined;
    for (let i = 0; i < 59; i++) {
      const result = advanceBehavior(state, `/page-${i}`, 1000 + i);
      expect(result.assessment.pathEnumeration).toBe(false);
      state = result.state;
    }
    const triggered = advanceBehavior(state, "/page-59", 1059);
    expect(triggered.assessment).toMatchObject({ version: 1, pathEnumeration: true, paths: 60, cooldownUntil: 61_059 });
    expect(advanceBehavior(triggered.state, "/", 61_058).assessment.pathEnumeration).toBe(true);
    expect(advanceBehavior(triggered.state, "/", 61_059).assessment.pathEnumeration).toBe(false);
  });

  it("does not trigger on repeated paths", () => {
    let state: BehaviorState | undefined;
    for (let i = 0; i < 60; i++) state = advanceBehavior(state, `/page-${i % 39}`, i).state;
    expect(advanceBehavior(state, "/page-0", 60).assessment.pathEnumeration).toBe(false);
  });
});
