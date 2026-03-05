"use client";
import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { setup2FA, verifyTwoFA } from "@/lib/api";

export default function TwoFAPage() {
  const router = useRouter();
  const [qr, setQr] = useState<string | null>(null);
  const [uri, setUri] = useState("");
  const [code, setCode] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [step, setStep] = useState<"scan" | "enter">("scan");

  useEffect(() => {
    const tempToken = localStorage.getItem("zets_temp_token");
    if (!tempToken) { router.replace("/login"); return; }

    setup2FA(tempToken)
      .then((res) => {
        setQr(res.data.qr_code_base64);
        setUri(res.data.provisioning_uri);
      })
      .catch(() => {
        setStep("enter");
        setQr(null);
      });
  }, [router]);

  const handleVerify = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setLoading(true);
    const tempToken = localStorage.getItem("zets_temp_token") || "";
    try {
      const res = await verifyTwoFA(tempToken, code);
      localStorage.setItem("zets_token", res.data.access_token);
      localStorage.removeItem("zets_temp_token");
      router.replace("/dashboard");
    } catch (err: any) {
      setError(err.response?.data?.detail || "Invalid code. Please try again.");
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
        Two-factor authentication
      </h1>
      <p style={{ fontSize: "0.9rem", color: "#505a5f", marginBottom: "1.5rem" }}>
        Step 2 of 2 — {step === "scan" ? "Scan the QR code with your authenticator app" : "Enter the code from your authenticator app"}
      </p>

      {error && <div className="error-msg" style={{ marginBottom: "1.25rem" }}>{error}</div>}

      {/* QR Code scan step */}
      {step === "scan" && qr && (
        <div style={{ marginBottom: "1.5rem" }}>
          <div style={{ background: "#ffffff", padding: "0.5rem", display: "inline-block", border: "1px solid #b1b4b6", marginBottom: "1rem" }}>
            {/* eslint-disable-next-line @next/next/no-img-element */}
            <img src={qr} alt="Two-factor authentication QR code" width={200} height={200} />
          </div>
          <p style={{ fontSize: "0.9rem", marginBottom: "0.5rem" }}>
            Use <strong>Google Authenticator</strong>, <strong>Authy</strong>, or any TOTP-compatible app to scan this code.
          </p>
          {uri && (
            <details style={{ marginBottom: "1rem" }}>
              <summary style={{ fontSize: "0.85rem", color: "#1d70b8", cursor: "pointer", fontWeight: 700 }}>
                Cannot scan? View the setup key manually
              </summary>
              <p style={{ marginTop: "0.5rem", fontSize: "0.8rem", wordBreak: "break-all", background: "#f3f2f1", padding: "0.5rem", border: "1px solid #b1b4b6" }}>
                {uri}
              </p>
            </details>
          )}
          <button className="btn btn-outline" onClick={() => setStep("enter")} style={{ maxWidth: 280 }}>
            I have scanned it — continue
          </button>
        </div>
      )}

      {/* Code entry step */}
      {(step === "enter" || qr === null) && (
        <form onSubmit={handleVerify}>
          <div className="form-group">
            <label className="label" htmlFor="totp-code">6-digit code</label>
            <input
              id="totp-code"
              className="input"
              type="text"
              inputMode="numeric"
              pattern="[0-9]{6}"
              maxLength={6}
              placeholder="000000"
              value={code}
              onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))}
              style={{ maxWidth: 180, fontSize: "1.5rem", letterSpacing: "0.3rem" }}
              autoFocus
              required
            />
            <p style={{ fontSize: "0.8rem", color: "#505a5f", marginTop: "0.25rem" }}>
              The code refreshes every 30 seconds.
            </p>
          </div>
          <button className="btn btn-primary" type="submit" disabled={loading || code.length !== 6} style={{ maxWidth: 280 }}>
            {loading ? "Verifying…" : "Sign in"}
          </button>
        </form>
      )}
    </div>
  );
}
