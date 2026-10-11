export type SelfHostedMe = {
  userId: string;
  username: string;
  displayName: string | null;
  email: string | null;
  userType: "human" | "service";
  role: string;
  permissions: string[];
  workspaceId: string;
  workspaceName: string;
  uiApiKey: string | null;
  mustChangePassword: boolean;
};

export type SelfHostedUser = {
  id: string;
  username: string;
  displayName: string | null;
  email: string | null;
  status: "active" | "disabled";
  userType: "human" | "service";
  mustChangePassword: boolean;
  createdAt: string;
  createdBy: string;
  lastLoginAt: string | null;
  roleId: string | null;
};

export type SelfHostedRole = {
  id: string;
  displayName: string;
  description: string | null;
  builtin: boolean;
  permissions: string[];
};

export type SelfHostedApiKey = {
  id: string;
  userId: string;
  username: string;
  name: string;
  keyPrefix: string;
  kind: string;
  roleId: string | null;
  createdAt: string;
  expiresAt: string | null;
  lastUsedAt: string | null;
  revokedAt: string | null;
  revokedBy: string | null;
};

export type CreatedApiKey = {
  id: string;
  name: string;
  key: string;
  keyPrefix: string;
  createdAt: string;
  expiresAt: string | null;
};

export type AuditLogItem = {
  id: string;
  eventTime: string;
  source: string;
  workspaceName: string;
  actor: string;
  actorType: string;
  credentialId: string;
  action: string;
  outcome: string;
  httpMethod: string;
  route: string;
  path: string;
  status: number;
  resourceType: string;
  resourceId: string;
  pathParams: Record<string, string>;
  requiredPermissions: string[];
  clientIp: string;
  userAgent: string;
  traceId: string;
  durationMs: number;
  details: string;
};

export type AuditLogPage = {
  page: number;
  size: number;
  total: number;
  content: AuditLogItem[];
};

export const SELFHOSTED_PERMISSIONS = {
  USER_MANAGE: "user_manage",
  AUDIT_LOG_VIEW: "audit_log_view",
} as const;
