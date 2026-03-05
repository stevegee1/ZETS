"use client";
import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { getMe, getAuditLogs } from "@/lib/api";

interface UserInfo { id: string; email: string; role: string; }
interface AuditEntry {
  id: string;
  user_id: string | null;
  action: string;
  resource: string;
  result: string;
  detail: string | null;
  sensitivity: string | null;
  zone: string | null;
  timestamp: string;
  ip_address: string | null;
}

const SENSITIVITY_COLORS: Record<string, string> = {
  LOW:      "#1d70b8",
  MEDIUM:   "#f47738",
  HIGH:     "#d4351c",
  CRITICAL: "#85004b",
};

const RESULT_STYLE: Record<string, React.CSSProperties> = {
  allowed: { background: "#cce2d8", color: "#005a30", padding: "2px 8px", borderRadius: 4, fontWeight: 700, fontSize: "0.8rem" },
  denied:  { background: "#fcd6cd", color: "#942514", padding: "2px 8px", borderRadius: 4, fontWeight: 700, fontSize: "0.8rem" },
};

export default function AdminAuditPage() {
  const router = useRouter();
  const [user, setUser] = useState<UserInfo | null>(null);
  const [logs, setLogs] = useState<AuditEntry[]>([]);
  const [loading, setLoading] = useState(true);

  // Filters
  const [resultFilter, setResultFilter] = useState("");
  const [actionFilter, setActionFilter] = useState("");
  const [zoneFilter, setZoneFilter] = useState("");

  useEffect(() => {
    const token = localStorage.getItem("zets_token");
    if (!token) { router.replace("/login?expired=1"); return; }

    getMe()
      .then((r) => {
        const u = r.data as UserInfo;
        if (u.role !== "admin") { router.replace("/dashboard"); return; }
        setUser(u);
      })
      .catch(() => { localStorage.removeItem("zets_token"); router.replace("/login?expired=1"); });
  }, [router]);

  useEffect(() => {
    if (!user) return;
    setLoading(true);
    getAuditLogs({
      result: resultFilter || undefined,
      action: actionFilter || undefined,
      zone:   zoneFilter   || undefined,
      limit: 200,
    })
      .then((r) => setLogs(r.data))
      .catch(() => {})
      .finally(() => setLoading(false));
  }, [user, resultFilter, actionFilter, zoneFilter]);

  if (!user) return <div style={{ padding: "3rem 1.5rem", color: "#505a5f" }}>Loading…</div>;

  return (
    <div>
      {/* Nav */}
      <nav className="nav">
        <span className="nav-brand">ZETS Platform</span>
        <div style={{ display: "flex", gap: "1rem", alignItems: "center" }}>
          <a href="/admin/alerts" style={{ color: "#f47738", fontWeight: 700, fontSize: "0.9rem", textDecoration: "none" }}>Alerts</a>
          <a href="/admin/anomalies" style={{ color: "#9b6dff", fontWeight: 700, fontSize: "0.9rem", textDecoration: "none" }}>Anomalies</a>
          <a href="/dashboard" style={{ color: "#aeb0b5", fontSize: "0.9rem", textDecoration: "none" }}>← Dashboard</a>
          <span style={{ background: "#85004b", color: "#fff", padding: "2px 10px", borderRadius: 4, fontSize: "0.8rem", fontWeight: 700 }}>ADMIN</span>
        </div>
      </nav>

      <div style={{ maxWidth: 1300, margin: "0 auto", padding: "2.5rem 1.5rem" }}>
        <h1 style={{ fontSize: "1.75rem", fontWeight: 700, marginBottom: "0.25rem" }}>Audit Log</h1>
        <p style={{ color: "#505a5f", marginBottom: "2rem", fontSize: "0.95rem" }}>
          Real-time security events from the PEP · PDP enforcement layer
        </p>

        {/* Filters */}
        <div style={{ display: "flex", gap: "1rem", marginBottom: "1.5rem", flexWrap: "wrap" }}>
          {[
            { label: "Result", value: resultFilter, set: setResultFilter, opts: ["", "allowed", "denied"] },
            { label: "Zone",   value: zoneFilter,   set: setZoneFilter,   opts: ["", "upload", "access", "auth"] },
          ].map(({ label, value, set, opts }) => (
            <div key={label} style={{ display: "flex", flexDirection: "column", gap: "0.25rem" }}>
              <label style={{ fontSize: "0.8rem", fontWeight: 700, color: "#505a5f" }}>{label}</label>
              <select
                value={value}
                onChange={(e) => set(e.target.value)}
                style={{ padding: "0.4rem 0.75rem", border: "2px solid #0b0c0c", fontSize: "0.9rem", background: "#fff" }}
              >
                {opts.map((o) => <option key={o} value={o}>{o || "All"}</option>)}
              </select>
            </div>
          ))}
          <div style={{ display: "flex", flexDirection: "column", gap: "0.25rem" }}>
            <label style={{ fontSize: "0.8rem", fontWeight: 700, color: "#505a5f" }}>Action</label>
            <input
              placeholder="e.g. INTEGRITY_VIOLATION"
              value={actionFilter}
              onChange={(e) => setActionFilter(e.target.value)}
              style={{ padding: "0.4rem 0.75rem", border: "2px solid #0b0c0c", fontSize: "0.9rem", width: 220 }}
            />
          </div>
        </div>

        {loading ? (
          <p style={{ color: "#505a5f" }}>Loading…</p>
        ) : logs.length === 0 ? (
          <p style={{ color: "#505a5f" }}>No events match the current filters.</p>
        ) : (
          <div style={{ overflowX: "auto" }}>
            <p style={{ color: "#505a5f", fontSize: "0.85rem", marginBottom: "0.75rem" }}>
              Showing {logs.length} events
            </p>
            <table className="table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>IP</th>
                  <th>Action</th>
                  <th>Resource</th>
                  <th>Zone</th>
                  <th>Sensitivity</th>
                  <th>Result</th>
                  <th>Detail</th>
                </tr>
              </thead>
              <tbody>
                {logs.map((l) => (
                  <tr key={l.id} style={{ background: l.result === "denied" ? "#fff4f2" : undefined }}>
                    <td style={{ color: "#505a5f", fontSize: "0.8rem", whiteSpace: "nowrap" }}>
                      {new Date(l.timestamp).toLocaleString("en-GB")}
                    </td>
                    <td style={{ fontSize: "0.8rem", fontFamily: "monospace" }}>{l.ip_address || "—"}</td>
                    <td style={{ fontWeight: 700, fontSize: "0.85rem" }}>{l.action}</td>
                    <td><code style={{ fontSize: "0.78rem", color: "#505a5f" }}>{l.resource}</code></td>
                    <td style={{ fontSize: "0.82rem" }}>
                      {l.zone ? (
                        <span style={{ background: "#f3f2f1", padding: "2px 7px", borderRadius: 4 }}>{l.zone}</span>
                      ) : "—"}
                    </td>
                    <td>
                      {l.sensitivity ? (
                        <span style={{
                          background: SENSITIVITY_COLORS[l.sensitivity] ?? "#505a5f",
                          color: "#fff", padding: "2px 7px", borderRadius: 4,
                          fontSize: "0.78rem", fontWeight: 700,
                        }}>
                          {l.sensitivity}
                        </span>
                      ) : "—"}
                    </td>
                    <td><span style={RESULT_STYLE[l.result] ?? {}}>{l.result}</span></td>
                    <td style={{ color: "#505a5f", fontSize: "0.8rem", maxWidth: 260, wordBreak: "break-word" }}>
                      {l.detail || "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
