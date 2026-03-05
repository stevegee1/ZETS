import re
from typing import Optional

# Sensitivity level ranking
SENSITIVITY_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

# Role ranking
ROLE_RANK = {"student": 0, "teacher": 1, "admin": 2}

# Resource policy registry: (regex pattern, sensitivity, min_role or None)
RESOURCE_POLICIES: list[tuple[str, str, Optional[str]]] = [
    # Auth endpoints — open (unauthenticated allowed)
    (r"^/auth/(register|login|verify-2fa|setup-2fa)$", "LOW",      None),
    (r"^/auth/invite$",                                 "CRITICAL", "admin"),
    (r"^/auth/me$",                                     "LOW",      "student"),
    # Health — open
    (r"^/health$",                                      "LOW", None),
    # File listing — any authenticated user
    (r"^/files/$",                                      "MEDIUM", "student"),
    # File download — role-matched (enforced separately in route)
    (r"^/files/[^/]+/download$",                        "MEDIUM", "student"),
    # File integrity verify — teachers/admins
    (r"^/files/[^/]+/verify$",                          "HIGH", "teacher"),
    # File upload — teachers/admins
    (r"^/files/upload$",                                "HIGH", "teacher"),
    # Admin read-only endpoints — teachers can access
    (r"^/admin/audit-logs",                              "HIGH",     "teacher"),
    (r"^/admin/alerts",                                  "HIGH",     "teacher"),
    # All other admin endpoints — critical, admin only
    (r"^/admin/",                                        "CRITICAL", "admin"),
    # Docs/openapi — open
    (r"^/(docs|redoc|openapi\.json)$",                  "LOW", None),
]
