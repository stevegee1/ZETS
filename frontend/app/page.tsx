"use client";
import Link from "next/link";

export default function HomePage() {
  return (
    <div style={{ maxWidth: 640, margin: "0 auto", padding: "3rem 1.5rem" }}>
      <div style={{ borderBottom: "2px solid #0b0c0c", paddingBottom: "1rem", marginBottom: "2rem" }}>
        <p style={{ fontSize: "0.85rem", color: "#505a5f", marginBottom: "0.25rem", fontWeight: 700 }}>
          ZETS — Zero Trust Educational Security Platform
        </p>
        <h1 style={{ fontSize: "2rem", fontWeight: 700, color: "#0b0c0c" }}>
          Milestone 1: Identity & Access Management
        </h1>
      </div>

      <p style={{ fontSize: "1.1rem", marginBottom: "2rem", color: "#0b0c0c" }}>
        A role-based platform for students and teachers with mandatory two-factor authentication and full audit logging.
      </p>

      <div style={{ display: "flex", flexDirection: "column", gap: "0.75rem", marginBottom: "2.5rem", maxWidth: 220 }}>
        <Link href="/register">
          <button className="btn btn-primary">Create account</button>
        </Link>
        <Link href="/login">
          <button className="btn btn-outline">Sign in</button>
        </Link>
      </div>

      <div style={{ borderTop: "1px solid #b1b4b6", paddingTop: "1.5rem" }}>
        <h2 style={{ fontSize: "1rem", fontWeight: 700, marginBottom: "1rem" }}>Platform features</h2>
        <ul style={{ listStyle: "none", display: "flex", flexDirection: "column", gap: "0.5rem" }}>
          {[
            "Two-factor authentication required on every login",
            "Role-based access control: Student, Teacher, Admin",
            "Teacher-only file upload with SHA-256 integrity hash",
            "All access attempts logged and traceable",
          ].map((f) => (
            <li key={f} style={{ paddingLeft: "1rem", borderLeft: "4px solid #1d70b8", fontSize: "0.95rem" }}>
              {f}
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}
