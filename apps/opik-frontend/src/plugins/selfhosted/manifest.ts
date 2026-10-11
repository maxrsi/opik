import { lazy } from "react";
import { createRoute } from "@tanstack/react-router";
import { definePlugin } from "@/lib/plugins";

/**
 * Self-hosted auth plugin (opik-auth). Enabled by building the frontend with VITE_FE_PLUGINS=selfhosted
 * (docker build arg BUILD_PLUGINS=selfhosted). Session gate, permissions and user menu are provided through the
 * plugin store slots (WorkspacePreloader, PermissionsProvider, UserMenu, init); this manifest adds the pages.
 */
export default definePlugin({
  name: "selfhosted",
  routes: ({ workspaceGuard }) => [
    createRoute({
      path: "/$workspaceName/account/api-keys",
      getParentRoute: () => workspaceGuard,
      staticData: { title: "My API keys" },
      component: lazy(() =>
        import("./pages/ApiKeysPage").then((m) => ({
          default: m.MyApiKeysPage,
        })),
      ),
    }),
    createRoute({
      path: "/$workspaceName/admin/users",
      getParentRoute: () => workspaceGuard,
      staticData: { title: "Users & roles" },
      component: lazy(() => import("./pages/UsersPage")),
    }),
    createRoute({
      path: "/$workspaceName/admin/api-keys",
      getParentRoute: () => workspaceGuard,
      staticData: { title: "All API keys" },
      component: lazy(() =>
        import("./pages/ApiKeysPage").then((m) => ({
          default: m.AllApiKeysPage,
        })),
      ),
    }),
    createRoute({
      path: "/$workspaceName/admin/audit",
      getParentRoute: () => workspaceGuard,
      staticData: { title: "Audit log" },
      component: lazy(() => import("./pages/AuditLogPage")),
    }),
  ],
});
