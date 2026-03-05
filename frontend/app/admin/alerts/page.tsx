"use client";
import { useState, useEffect, useRef } from "react";
import { useRouter } from "next/navigation";
import { getMe, getAlerts } from "@/lib/api";

interface UserInfo { id: string; email: string; role: string; }
interface Alert {
  type: string;
  ip: string;
  user_id: string | null;
  path: string;
  detail: string;
  fired_at: string;
}

const ALERT_STYLES: Record<string, React.CSSProperties> = {
  BRUTE_FORCE:           { borderLeft: "5px solid #d4351c", background: "#fae9e8" },
  INTEGRITY_VIOLATION:   { borderLeft: "5px solid #85004b", background: "#f9e8f2" },
  PRIVILEGE_ESCALATION:  { borderLeft: "5px solid #f47738", background: "#fef5ec" },
  ANOMALY_DETECTED:      { borderLeft: "5px solid #9b6dff", background: "#f3efff" },
};

const ALERT_ICONS: Record<string, string> = {
  BRUTE_FORCE:          "🔐",
  INTEGRITY_VIOLATION:  "⚠️",
  PRIVILEGE_ESCALATION: "🚨",
  ANOMALY_DETECTED:     "🤖",
};

export default function AlertsPage() {
  const router = useRouter();
  const [user, setUser] = useState<UserInfo | null>(null);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);
  const [lastRefresh, setLastRefresh] = useState<Date | null>(null);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

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

  const fetchAlerts = () => {
    getAlerts(50)
      .then((r) => { setAlerts(r.data); setLastRefresh(new Date()); })
      .catch(() => {})
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    if (!user) return;
    fetchAlerts();
    // Auto-refresh every 10 seconds
    intervalRef.current = setInterval(fetchAlerts, 10_000);
    return () => { if (intervalRef.current) clearInterval(intervalRef.current); };
  }, [user]);

  if (!user) return <div style={{ padding: "3rem 1.5rem", color: "#505a5f" }}>Loading…</div>;

  return (
    <div>
      <nav className="nav">
        <span className="nav-brand">ZETS Platform</span>
        <div style={{ display: "flex", gap: "1rem", alignItems: "center" }}>
          <a href="/admin/anomalies" style={{ color: "#9b6dff", fontWeight: 700, fontSize: "0.9rem", textDecoration: "none" }}>Anomalies</a>
          <a href="/admin" style={{ color: "#aeb0b5", fontSize: "0.9rem", textDecoration: "none" }}>← Audit Log</a>
          <span style={{ background: "#85004b", color: "#fff", padding: "2px 10px", borderRadius: 4, fontSize: "0.8rem", fontWeight: 700 }}>ADMIN</span>
        </div>
      </nav>

      <div style={{ maxWidth: 960, margin: "0 auto", padding: "2.5rem 1.5rem" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "0.5rem" }}>
          <h1 style={{ fontSize: "1.75rem", fontWeight: 700 }}>Security Alerts</h1>
          <button
            onClick={fetchAlerts}
            style={{ padding: "0.4rem 1rem", background: "#1d70b8", color: "#fff", border: "none", fontWeight: 700, cursor: "pointer" }}
          >
            Refresh
          </button>
        </div>
        <p style={{ color: "#505a5f", marginBottom: "0.5rem", fontSize: "0.95rem" }}>
          Auto-refreshes every 10 s · Brute force · Integrity violations · Privilege escalation
        </p>
        {lastRefresh && (
          <p style={{ color: "#aeb0b5", fontSize: "0.8rem", marginBottom: "2rem" }}>
            Last updated: {lastRefresh.toLocaleTimeString("en-GB")}
          </p>
        )}

        {loading ? (
          <p style={{ color: "#505a5f" }}>Loading…</p>
        ) : alerts.length === 0 ? (
          <div style={{ padding: "3rem 2rem", textAlign: "center", background: "#f3f2f1", borderRadius: 8 }}>
            <p style={{ fontSize: "2rem", marginBottom: "0.5rem" }}>✅</p>
            <p style={{ fontWeight: 700, fontSize: "1.1rem" }}>No alerts</p>
            <p style={{ color: "#505a5f", fontSize: "0.9rem" }}>The system is operating normally.</p>
          </div>
        ) : (
          <div style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
            {alerts.map((a, i) => (
              <div
                key={i}
                style={{
                  padding: "1.25rem 1.5rem",
                  borderRadius: 6,
                  ...(ALERT_STYLES[a.type] ?? { borderLeft: "5px solid #505a5f", background: "#f3f2f1" }),
                }}
              >
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "0.5rem" }}>
                  <span style={{ fontWeight: 700, fontSize: "1rem" }}>
                    {ALERT_ICONS[a.type] ?? "⚠"} {a.type.replace(/_/g, " ")}
                  </span>
                  <span style={{ color: "#505a5f", fontSize: "0.8rem" }}>
                    {new Date(a.fired_at).toLocaleString("en-GB")}
                  </span>
                </div>
                <div style={{ display: "grid", gridTemplateColumns: "auto 1fr", gap: "0.25rem 1rem", fontSize: "0.875rem" }}>
                  <span style={{ fontWeight: 700, color: "#505a5f" }}>IP</span>
                  <code>{a.ip}</code>
                  <span style={{ fontWeight: 700, color: "#505a5f" }}>Path</span>
                  <code>{a.path}</code>
                  {a.user_id && <><span style={{ fontWeight: 700, color: "#505a5f" }}>User ID</span><code style={{ wordBreak: "break-all" }}>{a.user_id}</code></>}
                  <span style={{ fontWeight: 700, color: "#505a5f" }}>Detail</span>
                  <span>{a.detail}</span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
