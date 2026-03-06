"use client";
import { useState, useEffect, Suspense } from "react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { login } from "@/lib/api";

// Inner component using useSearchParams — must be inside <Suspense>
function LoginForm() {
  const router = useRouter();
  const params = useSearchParams();
  const [form, setForm] = useState({ email: "", password: "" });
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState("");
  const [info, setInfo] = useState("");
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    localStorage.removeItem("zets_token");
    if (params.get("registered")) setInfo("Account created. Sign in and set up two-factor authentication.");
    if (params.get("expired")) setError("Your session has expired. Please sign in again.");
  }, [params]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(""); setInfo("");
    setLoading(true);
    try {
      const res = await login(form.email, form.password);
      localStorage.setItem("zets_temp_token", res.data.temp_token);
      router.push("/login/2fa");
    } catch (err: any) {
      setError(err.response?.data?.detail || "Invalid email address or password.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ maxWidth: 480, margin: "0 auto", padding: "3rem 1.5rem" }}>
      <p style={{ fontSize: "0.85rem", color: "#505a5f", marginBottom: "0.5rem" }}>
        ZETS Platform
      </p>
      <h1 style={{ fontSize: "1.75rem", fontWeight: 700, marginBottom: "0.25rem", borderBottom: "2px solid #0b0c0c", paddingBottom: "0.75rem" }}>
        Sign in
      </h1>
      <p style={{ fontSize: "0.9rem", color: "#505a5f", marginBottom: "1.5rem" }}>Step 1 of 2 — Enter your credentials</p>

      {error && <div className="error-msg" style={{ marginBottom: "1.25rem" }}>{error}</div>}
      {info  && <div className="success-msg" style={{ marginBottom: "1.25rem" }}>{info}</div>}

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
            autoComplete="username"
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
              placeholder="Your password"
              value={form.password}
              onChange={(e) => setForm({ ...form, password: e.target.value })}
              autoComplete="current-password"
              required
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

        <button className="btn btn-primary" type="submit" disabled={loading} style={{ marginTop: "0.5rem" }}>
          {loading ? "Signing in…" : "Continue"}
        </button>
      </form>

      <p style={{ marginTop: "1.5rem", fontSize: "0.9rem", color: "#505a5f" }}>
        No account?{" "}
        <Link href="/register" style={{ color: "#1d70b8", fontWeight: 700 }}>
          Create one
        </Link>
      </p>
    </div>
  );
}

// Page wraps the form in Suspense (required by Next.js 14 for useSearchParams)
export default function LoginPage() {
  return (
    <Suspense fallback={<div style={{ padding: "3rem 1.5rem", color: "#505a5f" }}>Loading…</div>}>
      <LoginForm />
    </Suspense>
  );
}
