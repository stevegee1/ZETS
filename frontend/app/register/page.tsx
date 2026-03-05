"use client";
import { useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { register } from "@/lib/api";

export default function RegisterPage() {
  const router = useRouter();
  const [form, setForm] = useState({ email: "", password: "", role: "student" });
  const [showPassword, setShowPassword] = useState(false);
  const [inviteToken, setInviteToken] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      await register(form.email, form.password, form.role, form.role === "admin" ? inviteToken : undefined);
      localStorage.setItem("zets_reg_email", form.email);
      router.push("/login?registered=1");
    } catch (err: any) {
      setError(err.response?.data?.detail || "Registration failed. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ maxWidth: 480, margin: "0 auto", padding: "3rem 1.5rem" }}>
      <p style={{ fontSize: "0.85rem", color: "#505a5f", marginBottom: "0.5rem" }}>
        ZETS Platform
      </p>
      <h1 style={{ fontSize: "1.75rem", fontWeight: 700, marginBottom: "1.5rem", borderBottom: "2px solid #0b0c0c", paddingBottom: "0.75rem" }}>
        Create an account
      </h1>

      {error && <div className="error-msg" style={{ marginBottom: "1.25rem" }}>{error}</div>}

      <form onSubmit={handleSubmit}>
        <div className="form-group">
          <label className="label" htmlFor="email">Email address</label>
          <input
            id="email"
            className="input"
            type="email"
            placeholder="you@university.edu"
            value={form.email}
            onChange={(e) => setForm({ ...form, email: e.target.value })}
            autoComplete="email"
            required
          />
        </div>

        <div className="form-group">
          <label className="label" htmlFor="password">Password</label>
          <div style={{ position: "relative" }}>
            <input
              id="password"
              className="input"
              type={showPassword ? "text" : "password"}
              placeholder="Minimum 6 characters"
              value={form.password}
              onChange={(e) => setForm({ ...form, password: e.target.value })}
              autoComplete="new-password"
              required
              minLength={6}
              style={{ paddingRight: "2.75rem" }}
            />
            <button
              type="button"
              onClick={() => setShowPassword((v) => !v)}
              style={{ position: "absolute", right: "0.65rem", top: "50%", transform: "translateY(-50%)", background: "none", border: "none", cursor: "pointer", fontSize: "1.1rem", color: "#505a5f", lineHeight: 1 }}
              aria-label={showPassword ? "Hide password" : "Show password"}
            >
              {showPassword ? "🙈" : "👁"}
            </button>
          </div>
        </div>

        <div className="form-group">
          <label className="label" htmlFor="role">Account type</label>
          <select
            id="role"
            className="select"
            value={form.role}
            onChange={(e) => setForm({ ...form, role: e.target.value })}
          >
            <option value="student">Student</option>
            <option value="teacher">Teacher</option>
            <option value="admin">Admin</option>
          </select>
        </div>

        {form.role === "admin" && (
          <div className="form-group">
            <label className="label" htmlFor="invite-token">Invitation token</label>
            <input
              id="invite-token"
              className="input"
              type="text"
              placeholder="Paste your invitation token"
              value={inviteToken}
              onChange={(e) => setInviteToken(e.target.value.trim())}
              required
              autoComplete="off"
            />
            <p style={{ fontSize: "0.8rem", color: "#505a5f", marginTop: "0.25rem" }}>
              Admin accounts require an invitation token from an existing administrator.
            </p>
          </div>
        )}

        <button className="btn btn-primary" type="submit" disabled={loading} style={{ marginTop: "0.5rem" }}>
          {loading ? "Creating account…" : "Create account"}
        </button>
      </form>

      <p style={{ marginTop: "1.5rem", fontSize: "0.9rem", color: "#505a5f" }}>
        Already have an account?{" "}
        <Link href="/login" style={{ color: "#1d70b8", fontWeight: 700 }}>
          Sign in
        </Link>
      </p>

      <p style={{ marginTop: "1rem", fontSize: "0.8rem", color: "#505a5f", borderTop: "1px solid #b1b4b6", paddingTop: "1rem" }}>
        Two-factor authentication will be required after registration. All access is logged.
      </p>
    </div>
  );
}
