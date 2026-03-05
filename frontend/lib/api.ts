import axios from "axios";

const api = axios.create({
  baseURL: process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000",
});

// Attach JWT on every request, but don't overwrite an explicitly provided header
api.interceptors.request.use((config) => {
  const token =
    typeof window !== "undefined" ? localStorage.getItem("zets_token") : null;
  if (token && !config.headers.Authorization)
    config.headers.Authorization = `Bearer ${token}`;
  return config;
});

export default api;

// ── Auth ──────────────────────────────────────────────────────
export const register = (
  email: string,
  password: string,
  role: string,
  invite_token?: string,
) => api.post("/auth/register", { email, password, role, invite_token });

export const login = (email: string, password: string) =>
  api.post("/auth/login", { email, password });

export const verifyTwoFA = (temp_token: string, totp_code: string) =>
  api.post("/auth/verify-2fa", { temp_token, totp_code });

export const setup2FA = (tempToken: string) =>
  api.get("/auth/setup-2fa", {
    headers: { Authorization: `Bearer ${tempToken}` },
  });

export const getMe = () => api.get("/auth/me");

// ── Files ─────────────────────────────────────────────────────
export const uploadFile = (file: File) => {
  const fd = new FormData();
  fd.append("file", file);
  return api.post("/files/upload", fd);
};

export const listFiles = () => api.get("/files/");

export const downloadUrl = (id: string) =>
  `${process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"}/files/${id}/download`;

export const verifyFile = (id: string) => api.get(`/files/${id}/verify`);

// ── Admin ─────────────────────────────────────────────────────
export const getAuditLogs = (params?: {
  result?: string;
  action?: string;
  zone?: string;
  skip?: number;
  limit?: number;
}) => api.get("/admin/audit-logs", { params });

export const getAlerts = (limit = 50) =>
  api.get("/admin/alerts", { params: { limit } });

// ── Anomaly ───────────────────────────────────────────────────
export const getAnomalies = () => api.get("/admin/anomalies");
export const getAnomalyTimeline = (limit = 100) =>
  api.get("/admin/anomalies/timeline", { params: { limit } });
export const triggerRetrain = () => api.post("/admin/anomalies/retrain");
