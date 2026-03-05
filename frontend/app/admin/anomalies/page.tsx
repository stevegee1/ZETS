"use client";
import { useState, useEffect, useRef } from "react";
import { useRouter } from "next/navigation";
import { getMe, getAnomalies, getAnomalyTimeline, triggerRetrain } from "@/lib/api";

interface UserInfo { id: string; email: string; role: string; }
interface ScoreEntry { ip: string; user_id: string | null; score: number; updated_at: string; }
interface TimelineEntry {
  ip: string; user_id: string | null; path: string;
  sensitivity: string | null; result: string; score: number; timestamp: string;
}

export default function AnomaliesPage() {
  const router = useRouter();
  const [user, setUser]         = useState<UserInfo | null>(null);
  const [scores, setScores]     = useState<ScoreEntry[]>([]);
  const [timeline, setTimeline] = useState<TimelineEntry[]>([]);
  const [loading, setLoading]   = useState(true);
  const [retraining, setRetraining] = useState(false);
  const [retrainMsg, setRetrainMsg] = useState("");
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

  const fetchData = () => {
    Promise.all([getAnomalies(), getAnomalyTimeline(50)])
      .then(([sRes, tRes]) => {
        setScores(sRes.data);
        setTimeline(tRes.data);
        setLastRefresh(new Date());
      })
      .catch(() => {})
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    if (!user) return;
    fetchData();
    intervalRef.current = setInterval(fetchData, 15_000);
    return () => { if (intervalRef.current) clearInterval(intervalRef.current); };
  }, [user]);

  const handleRetrain = async () => {
    setRetraining(true);
    setRetrainMsg("");
    try {
      const r = await triggerRetrain();
      const { status, trained_on } = r.data;
      setRetrainMsg(status === "ok"
        ? `Model retrained on ${trained_on} samples.`
        : `Not enough data yet (${trained_on} samples collected, 30 required).`);
    } catch {
      setRetrainMsg("Retrain failed.");
    } finally {
      setRetraining(false);
    }
  };

  if (!user) return <div style={{ padding: "3rem 1.5rem", color: "#505a5f" }}>Loading…</div>;

  return (
    <div>
      <nav className="nav">
        <span className="nav-brand">ZETS Platform</span>
        <div style={{ display: "flex", gap: "1rem", alignItems: "center" }}>
          <a href="/admin/alerts" style={{ color: "#f47738", fontWeight: 700, fontSize: "0.9rem", textDecoration: "none" }}>Alerts</a>
          <a href="/admin" style={{ color: "#aeb0b5", fontSize: "0.9rem", textDecoration: "none" }}>← Audit Log</a>
          <span style={{ background: "#85004b", color: "#fff", padding: "2px 10px", borderRadius: 4, fontSize: "0.8rem", fontWeight: 700 }}>ADMIN</span>
        </div>
      </nav>

      <div style={{ maxWidth: 1100, margin: "0 auto", padding: "2.5rem 1.5rem" }}>
        <h1 style={{ fontSize: "1.75rem", fontWeight: 700, marginBottom: "0.25rem" }}>Anomaly Detection</h1>
        <p style={{ color: "#505a5f", fontSize: "0.95rem", marginBottom: "0.5rem" }}>
          IsolationForest behavioural scoring · Auto-refreshes every 15 s
        </p>
        {lastRefresh && (
          <p style={{ color: "#aeb0b5", fontSize: "0.8rem", marginBottom: "1.5rem" }}>
            Last updated: {lastRefresh.toLocaleTimeString("en-GB")}
          </p>
        )}

        <div style={{ display: "flex", gap: "0.75rem", marginBottom: "1.5rem" }}>
          <button onClick={fetchData}
            style={{ padding: "0.4rem 1rem", background: "#1d70b8", color: "#fff", border: "none", fontWeight: 700, cursor: "pointer", fontSize: "0.875rem" }}>
            Refresh
          </button>
          <button onClick={handleRetrain} disabled={retraining}
            style={{ padding: "0.4rem 1rem", background: "#fff", color: "#0b0c0c", border: "2px solid #0b0c0c", fontWeight: 700, cursor: retraining ? "not-allowed" : "pointer", fontSize: "0.875rem" }}>
            {retraining ? "Retraining…" : "Retrain model"}
          </button>
        </div>
        {retrainMsg && <p style={{ fontSize: "0.875rem", marginBottom: "1rem", color: "#505a5f" }}>{retrainMsg}</p>}

        {loading ? <p style={{ color: "#505a5f" }}>Loading…</p> : (
          <>
            <h2 style={{ fontSize: "1.1rem", fontWeight: 700, marginBottom: "0.75rem" }}>IP anomaly scores</h2>
            {scores.length === 0 ? (
              <p style={{ color: "#505a5f", marginBottom: "2rem" }}>No scores recorded yet. Scores appear as users make requests.</p>
            ) : (
              <div style={{ overflowX: "auto", marginBottom: "2.5rem" }}>
                <table className="table">
                  <thead>
                    <tr>
                      <th>IP address</th>
                      <th>Score</th>
                      <th>Risk level</th>
                      <th>Last updated</th>
                    </tr>
                  </thead>
                  <tbody>
                    {scores.map((s) => {
                      const pct = Math.round(s.score * 100);
                      const risk = s.score >= 0.85 ? "Blocked" : s.score >= 0.75 ? "High" : s.score >= 0.5 ? "Medium" : "Low";
                      const riskColor = s.score >= 0.75 ? "#d4351c" : s.score >= 0.5 ? "#f47738" : "#005a30";
                      return (
                        <tr key={s.ip}>
                          <td><code>{s.ip}</code></td>
                          <td style={{ fontWeight: 700 }}>{pct}%</td>
                          <td style={{ fontWeight: 700, color: riskColor }}>{risk}</td>
                          <td style={{ color: "#505a5f", fontSize: "0.88rem" }}>
                            {new Date(s.updated_at).toLocaleTimeString("en-GB")}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}

            <h2 style={{ fontSize: "1.1rem", fontWeight: 700, marginBottom: "0.75rem" }}>Recent scored events</h2>
            {timeline.length === 0 ? (
              <p style={{ color: "#505a5f" }}>No events yet.</p>
            ) : (
              <div style={{ overflowX: "auto" }}>
                <table className="table">
                  <thead>
                    <tr>
                      <th>Time</th>
                      <th>IP</th>
                      <th>Path</th>
                      <th>Sensitivity</th>
                      <th>Result</th>
                      <th>Score</th>
                    </tr>
                  </thead>
                  <tbody>
                    {timeline.map((t, i) => (
                      <tr key={i}>
                        <td style={{ fontSize: "0.8rem", color: "#505a5f", whiteSpace: "nowrap" }}>
                          {new Date(t.timestamp).toLocaleTimeString("en-GB")}
                        </td>
                        <td><code style={{ fontSize: "0.8rem" }}>{t.ip}</code></td>
                        <td><code style={{ fontSize: "0.78rem", color: "#505a5f" }}>{t.path}</code></td>
                        <td style={{ fontSize: "0.82rem" }}>{t.sensitivity || "—"}</td>
                        <td>
                          <span style={{
                            background: t.result === "allowed" ? "#cce2d8" : "#fcd6cd",
                            color: t.result === "allowed" ? "#005a30" : "#942514",
                            padding: "2px 7px", borderRadius: 4, fontSize: "0.78rem", fontWeight: 700
                          }}>
                            {t.result}
                          </span>
                        </td>
                        <td style={{ fontWeight: 700, fontSize: "0.9rem" }}>{Math.round(t.score * 100)}%</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}
