"use client";
import { useState, useEffect, useRef } from "react";
import { useRouter } from "next/navigation";
import { getMe, listFiles, uploadFile, getAuditLogs, downloadUrl } from "@/lib/api";

interface UserInfo { id: string; email: string; role: string; totp_enabled: boolean; }
interface FileItem { id: string; filename: string; sha256_hash: string; required_role: string; uploaded_at: string; }
interface AuditEntry { id: string; action: string; resource: string; result: string; detail: string | null; sensitivity: string | null; zone: string | null; timestamp: string; }

export default function DashboardPage() {
  const router = useRouter();
  const [user, setUser] = useState<UserInfo | null>(null);
  const [files, setFiles] = useState<FileItem[]>([]);
  const [logs, setLogs] = useState<AuditEntry[]>([]);
  const [uploading, setUploading] = useState(false);
  const [uploadMsg, setUploadMsg] = useState("");
  const [activeTab, setActiveTab] = useState<"files" | "logs">("files");
  const fileRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    const token = localStorage.getItem("zets_token");
    if (!token) { router.replace("/login?expired=1"); return; }

    getMe()
      .then((r) => setUser(r.data))
      .catch(() => { localStorage.removeItem("zets_token"); router.replace("/login?expired=1"); });

    listFiles().then((r) => setFiles(r.data)).catch(() => {});
    getAuditLogs().then((r) => setLogs(r.data)).catch(() => {});
  }, [router]);

  const handleUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setUploading(true);
    setUploadMsg("");
    try {
      await uploadFile(file);
      setUploadMsg(`File "${file.name}" uploaded successfully.`);
      const r = await listFiles();
      setFiles(r.data);
    } catch (err: any) {
      setUploadMsg(`Upload failed: ${err.response?.data?.detail || "Unknown error"}`);
    } finally {
      setUploading(false);
      if (fileRef.current) fileRef.current.value = "";
    }
  };

  const handleLogout = () => {
    localStorage.removeItem("zets_token");
    router.replace("/login");
  };

  const roleBadgeClass = (role: string) =>
    role === "teacher" ? "badge badge-teacher" : role === "admin" ? "badge badge-admin" : "badge badge-student";

  if (!user) {
    return <div style={{ padding: "3rem 1.5rem", color: "#505a5f" }}>Loading…</div>;
  }

  const isUploader = user.role === "teacher" || user.role === "admin";

  return (
    <div>
      {/* Nav */}
      <nav className="nav">
        <span className="nav-brand">ZETS Platform</span>
        <div style={{ display: "flex", alignItems: "center", gap: "1rem" }}>
          {user.role === "admin" && (
            <a
              href="/admin"
              style={{ color: "#f47738", fontWeight: 700, fontSize: "0.875rem", textDecoration: "none" }}
            >
              🔒 Admin
            </a>
          )}
          <span className={roleBadgeClass(user.role)}>{user.role}</span>
          <span style={{ fontSize: "0.85rem", color: "#aeb0b5" }}>{user.email}</span>
          <button
            onClick={handleLogout}
            style={{
              background: "transparent",
              border: "1px solid #aeb0b5",
              color: "#ffffff",
              padding: "0.3rem 0.75rem",
              fontSize: "0.85rem",
              cursor: "pointer",
              fontWeight: 600,
            }}
          >
            Sign out
          </button>
        </div>
      </nav>

      <div style={{ maxWidth: 1100, margin: "0 auto", padding: "2.5rem 1.5rem" }}>
        <h1 style={{ fontSize: "1.75rem", fontWeight: 700, marginBottom: "0.25rem" }}>
          {user.role === "teacher" ? "Teacher dashboard" : user.role === "admin" ? "Admin dashboard" : "Student dashboard"}
        </h1>
        <p style={{ color: "#505a5f", marginBottom: "2rem", fontSize: "0.95rem" }}>
          {isUploader
            ? "Upload course materials and review the security audit log."
            : "Access your course materials below."}
        </p>

        {/* Upload section — teachers/admins only */}
        {isUploader && (
          <div style={{ marginBottom: "2rem" }}>
            <h2 style={{ fontSize: "1.1rem", fontWeight: 700, marginBottom: "0.75rem" }}>Upload course material</h2>
            <div
              className="upload-zone"
              onClick={() => fileRef.current?.click()}
            >
              {uploading ? "Uploading…" : "Click to select a file to upload"}
            </div>
            <input ref={fileRef} type="file" style={{ display: "none" }} onChange={handleUpload} />
            {uploadMsg && (
              <div
                className={uploadMsg.startsWith("Upload failed") ? "error-msg" : "success-msg"}
                style={{ marginTop: "0.75rem" }}
              >
                {uploadMsg}
              </div>
            )}
          </div>
        )}

        {/* Tabs */}
        <div style={{ display: "flex", gap: "0", marginBottom: "1.5rem", borderBottom: "2px solid #0b0c0c" }}>
          {(["files", ...(isUploader ? ["logs"] : [])] as const).map((tab) => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab as "files" | "logs")}
              style={{
                padding: "0.6rem 1.25rem",
                border: "none",
                borderBottom: activeTab === tab ? "4px solid #1d70b8" : "4px solid transparent",
                background: "transparent",
                fontWeight: activeTab === tab ? 700 : 400,
                color: activeTab === tab ? "#0b0c0c" : "#505a5f",
                cursor: "pointer",
                fontSize: "0.95rem",
                marginBottom: "-2px",
              }}
            >
              {tab === "files" ? "Files" : "Audit log"}
            </button>
          ))}
        </div>

        {/* Files table */}
        {activeTab === "files" && (
          <div>
            <p style={{ marginBottom: "1rem", color: "#505a5f", fontSize: "0.9rem" }}>
              {files.length} file{files.length !== 1 ? "s" : ""} available
            </p>
            {files.length === 0 ? (
              <p style={{ color: "#505a5f" }}>
                {user.role === "student"
                  ? "No materials have been uploaded yet. Check back later."
                  : "No files uploaded yet. Use the upload area above."}
              </p>
            ) : (
              <table className="table">
                <thead>
                  <tr>
                    <th>Filename</th>
                    <th>SHA-256 (first 16 chars)</th>
                    <th>Access level</th>
                    <th>Uploaded</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {files.map((f) => (
                    <tr key={f.id}>
                      <td style={{ fontWeight: 600 }}>{f.filename}</td>
                      <td>
                        <code style={{ fontSize: "0.8rem", color: "#505a5f" }}>
                          {f.sha256_hash.substring(0, 16)}…
                        </code>
                      </td>
                      <td><span className={roleBadgeClass(f.required_role)}>{f.required_role}</span></td>
                      <td style={{ color: "#505a5f", fontSize: "0.9rem" }}>
                        {new Date(f.uploaded_at).toLocaleDateString("en-GB")}
                      </td>
                      <td>
                        <a
                          href={downloadUrl(f.id)}
                          target="_blank"
                          rel="noreferrer"
                          style={{ color: "#1d70b8", fontWeight: 700, fontSize: "0.9rem" }}
                        >
                          Download
                        </a>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        )}

        {/* Audit log — teachers/admins only */}
        {activeTab === "logs" && isUploader && (
          <div>
            <p style={{ marginBottom: "1rem", color: "#505a5f", fontSize: "0.9rem" }}>
              Showing last {logs.length} events
            </p>
            {logs.length === 0 ? (
              <p style={{ color: "#505a5f" }}>No events recorded yet.</p>
            ) : (
              <table className="table">
                <thead>
                  <tr>
                    <th>Timestamp</th>
                    <th>Action</th>
                    <th>Resource</th>
                    <th>Result</th>
                    <th>Detail</th>
                  </tr>
                </thead>
                <tbody>
                  {logs.map((l) => (
                    <tr key={l.id}>
                      <td style={{ color: "#505a5f", fontSize: "0.85rem", whiteSpace: "nowrap" }}>
                        {new Date(l.timestamp).toLocaleString("en-GB")}
                      </td>
                      <td style={{ fontWeight: 600, fontSize: "0.875rem" }}>{l.action}</td>
                      <td>
                        <code style={{ fontSize: "0.8rem", color: "#505a5f" }}>{l.resource}</code>
                      </td>
                      <td>
                        <span className={l.result === "allowed" ? "result-allowed" : "result-denied"}>
                          {l.result === "allowed" ? "Allowed" : "Denied"}
                        </span>
                      </td>
                      <td style={{ color: "#505a5f", fontSize: "0.85rem" }}>{l.detail || "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
