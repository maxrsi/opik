import axios, { AxiosError } from "axios";

const BASE_URL = ((import.meta.env.VITE_BASE_URL as string | undefined) || "/")
  .replace(/\/$/, "")
  .concat("/auth/api");

/** Client for opik-auth's public API. Cookie based, never sends the Opik API key. */
const authApi = axios.create({
  baseURL: BASE_URL,
  withCredentials: true,
  headers: { "Content-Type": "application/json" },
});

export const ME_KEY = "selfhosted-me";
export const USERS_KEY = "selfhosted-users";
export const ROLES_KEY = "selfhosted-roles";
export const MY_API_KEYS_KEY = "selfhosted-my-api-keys";
export const ALL_API_KEYS_KEY = "selfhosted-all-api-keys";
export const AUDIT_LOGS_KEY = "selfhosted-audit-logs";

export const AUTH_API_BASE_URL = BASE_URL;

/** Extracts opik-auth's {"msg": "..."} error message. */
export const errorMessage = (error: unknown, fallback = "Request failed") => {
  const axiosError = error as AxiosError<{ msg?: string; message?: string }>;
  return (
    axiosError?.response?.data?.msg ||
    axiosError?.response?.data?.message ||
    axiosError?.message ||
    fallback
  );
};

export default authApi;
