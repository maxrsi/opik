import { Permissions } from "@/types/permissions";

/**
 * Maps opik-auth permission strings (opik-backend WorkspaceUserPermission values plus the frontend-only
 * management names) to the frontend's capability flags. Mirrors plugins/comet/useUserPermission.ts, but without
 * the "missing means allowed" default: a self-hosted role grants exactly what it lists.
 */
export const toFrontendPermissions = (granted: string[]): Permissions => {
  const has = (permission: string) => granted.includes(permission);
  const canViewDatasets = has("dataset_view");
  const canViewExperiments = canViewDatasets && has("experiment_view");

  return {
    canViewExperiments,
    canCreateExperiments: canViewExperiments && has("experiment_create"),
    canViewDashboards: has("dashboard_view"),
    canCreateDashboards: has("dashboard_create"),
    canEditDashboards: has("dashboard_edit"),
    canDeleteDashboards: has("dashboard_delete"),
    canViewDatasets,
    canCreateDatasets: has("dataset_create"),
    canEditDatasets: has("dataset_edit"),
    canDeleteDatasets: has("dataset_delete"),
    canCreateProjects: has("project_create"),
    canDeleteProjects: has("project_delete"),
    canCreateAnnotationQueues: has("annotation_queue_create"),
    canEditAnnotationQueues: has("annotation_queue_edit"),
    canDeleteAnnotationQueues: has("annotation_queue_delete"),
    canDeleteTraces: has("trace_delete"),
    canViewPrompts: has("prompt_view"),
    canCreatePrompts: has("prompt_create"),
    canEditPrompts: has("prompt_edit"),
    canDeletePrompts: has("prompt_delete"),
    canDeleteOptimizationRuns: has("optimization_run_delete"),
    canConfigureWorkspaceSettings: has("workspace_settings_configure"),
    canUpdateAIProviders: has("ai_provider_update"),
    canViewOnlineEvaluationRules: has("online_evaluation_rule_view"),
    canUpdateOnlineEvaluationRules: has("online_evaluation_rule_update"),
    canViewAlerts: has("alert_view"),
    canUpdateAlerts: has("alert_update"),
    canAnnotateTraceSpanThread: has("trace_span_thread_annotate"),
    canLogTraceSpanThread: has("trace_span_thread_log"),
    canUsePlayground: has("playground_use"),
    canViewAgentPlayground: has("agent_playground_use"),
    canUseOptimizationStudio: has("optimization_studio_use"),
    canViewOptimizationRuns: has("optimization_run_view"),
  };
};
