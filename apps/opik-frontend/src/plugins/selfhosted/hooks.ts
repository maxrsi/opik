import {
  keepPreviousData,
  useMutation,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import { AxiosError } from "axios";
import authApi, {
  ALL_API_KEYS_KEY,
  AUDIT_LOGS_KEY,
  ME_KEY,
  MY_API_KEYS_KEY,
  ROLES_KEY,
  USERS_KEY,
} from "./api";
import {
  AuditLogPage,
  CreatedApiKey,
  SelfHostedApiKey,
  SelfHostedMe,
  SelfHostedRole,
  SelfHostedUser,
} from "./types";

/** Current user, or null when there is no valid session (401). */
export const useMe = () =>
  useQuery<SelfHostedMe | null>({
    queryKey: [ME_KEY],
    queryFn: async ({ signal }) => {
      try {
        const { data } = await authApi.get<SelfHostedMe>("/me", { signal });
        return data;
      } catch (error) {
        const status = (error as AxiosError)?.response?.status;
        if (status === 401 || status === 403) {
          return null;
        }
        throw error;
      }
    },
    retry: false,
    refetchOnWindowFocus: true,
    staleTime: 30_000,
  });

export const useLogin = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (body: { username: string; password: string }) => {
      const { data } = await authApi.post<{ mustChangePassword: boolean }>(
        "/login",
        body,
      );
      return data;
    },
    onSuccess: () => queryClient.invalidateQueries({ queryKey: [ME_KEY] }),
  });
};

export const useLogout = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async () => {
      await authApi.post("/logout");
    },
    onSettled: () => {
      queryClient.clear();
      window.location.assign(
        ((import.meta.env.VITE_BASE_URL as string | undefined) || "/").replace(
          /\/?$/,
          "/",
        ),
      );
    },
  });
};

export const useChangePassword = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (body: {
      currentPassword: string;
      newPassword: string;
    }) => {
      await authApi.post("/me/password", body);
    },
    onSuccess: () => queryClient.invalidateQueries({ queryKey: [ME_KEY] }),
  });
};

// ---------------------------------------------------------------- API keys

export const useMyApiKeys = () =>
  useQuery<SelfHostedApiKey[]>({
    queryKey: [MY_API_KEYS_KEY],
    queryFn: async ({ signal }) =>
      (await authApi.get<SelfHostedApiKey[]>("/me/api-keys", { signal })).data,
  });

export const useCreateApiKey = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (body: { name: string; expiresInDays?: number }) =>
      (await authApi.post<CreatedApiKey>("/me/api-keys", body)).data,
    onSuccess: () =>
      queryClient.invalidateQueries({ queryKey: [MY_API_KEYS_KEY] }),
  });
};

export const useRevokeApiKey = (scope: "me" | "all") => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (id: string) => {
      await authApi.delete(
        scope === "me" ? `/me/api-keys/${id}` : `/api-keys/${id}`,
      );
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: [MY_API_KEYS_KEY] });
      queryClient.invalidateQueries({ queryKey: [ALL_API_KEYS_KEY] });
    },
  });
};

export const useAllApiKeys = () =>
  useQuery<SelfHostedApiKey[]>({
    queryKey: [ALL_API_KEYS_KEY],
    queryFn: async ({ signal }) =>
      (await authApi.get<SelfHostedApiKey[]>("/api-keys", { signal })).data,
  });

// ---------------------------------------------------------------- users / roles

export const useUsers = () =>
  useQuery<SelfHostedUser[]>({
    queryKey: [USERS_KEY],
    queryFn: async ({ signal }) =>
      (await authApi.get<SelfHostedUser[]>("/users", { signal })).data,
  });

export const useRoles = () =>
  useQuery<SelfHostedRole[]>({
    queryKey: [ROLES_KEY],
    queryFn: async ({ signal }) =>
      (await authApi.get<SelfHostedRole[]>("/roles", { signal })).data,
    staleTime: 5 * 60_000,
  });

export type CreateUserBody = {
  username: string;
  displayName?: string;
  email?: string;
  role: string;
  userType: "human" | "service";
  password?: string;
};

export const useCreateUser = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (body: CreateUserBody) =>
      (
        await authApi.post<{ user: SelfHostedUser; initialPassword?: string }>(
          "/users",
          body,
        )
      ).data,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: [USERS_KEY] }),
  });
};

export const useUpdateUser = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({
      id,
      ...body
    }: {
      id: string;
      role?: string;
      status?: "active" | "disabled";
      displayName?: string;
      email?: string;
    }) => (await authApi.patch<SelfHostedUser>(`/users/${id}`, body)).data,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: [USERS_KEY] }),
  });
};

export const useResetPassword = () =>
  useMutation({
    mutationFn: async (id: string) =>
      (await authApi.post<{ password: string }>(`/users/${id}/reset-password`))
        .data,
  });

// ---------------------------------------------------------------- audit

export type AuditFilters = {
  from?: string;
  to?: string;
  actor?: string;
  action?: string;
  outcome?: string;
  source?: string;
  page: number;
  size: number;
};

export const auditQueryString = (
  filters: Omit<AuditFilters, "page" | "size">,
) =>
  new URLSearchParams(
    Object.entries(filters).filter(([, value]) => Boolean(value)) as [
      string,
      string,
    ][],
  ).toString();

export const useAuditLogs = (filters: AuditFilters) =>
  useQuery<AuditLogPage>({
    queryKey: [AUDIT_LOGS_KEY, filters],
    queryFn: async ({ signal }) =>
      (
        await authApi.get<AuditLogPage>("/audit-logs", {
          params: Object.fromEntries(
            Object.entries(filters).filter(([, value]) => Boolean(value)),
          ),
          signal,
        })
      ).data,
    placeholderData: keepPreviousData,
  });
