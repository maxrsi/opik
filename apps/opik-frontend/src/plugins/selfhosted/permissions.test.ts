import { describe, expect, it } from "vitest";
import { DEFAULT_PERMISSIONS } from "@/types/permissions";
import { toFrontendPermissions } from "./permissions";

// Keep in sync with opik-auth's built-in role seeds (db/migrations).
const VIEWER = [
  "project_data_view",
  "dashboard_view",
  "experiment_view",
  "dataset_view",
  "annotation_queue_view",
  "prompt_view",
  "optimization_run_view",
  "online_evaluation_rule_view",
  "alert_view",
];

describe("toFrontendPermissions", () => {
  it("covers every frontend capability flag", () => {
    expect(Object.keys(toFrontendPermissions([])).sort()).toEqual(
      Object.keys(DEFAULT_PERMISSIONS.permissions).sort(),
    );
  });

  it("denies everything without permissions", () => {
    expect(
      Object.values(toFrontendPermissions([])).every((value) => !value),
    ).toBe(true);
  });

  it("viewer can see but not change", () => {
    const p = toFrontendPermissions(VIEWER);
    expect(p.canViewDatasets).toBe(true);
    expect(p.canViewExperiments).toBe(true);
    expect(p.canViewPrompts).toBe(true);
    expect(p.canCreateDatasets).toBe(false);
    expect(p.canDeleteTraces).toBe(false);
    expect(p.canCreateProjects).toBe(false);
    expect(p.canUsePlayground).toBe(false);
  });

  it("experiments require dataset view", () => {
    const p = toFrontendPermissions(["experiment_view", "experiment_create"]);
    expect(p.canViewExperiments).toBe(false);
    expect(p.canCreateExperiments).toBe(false);
  });
});
