import re
from typing import Optional


# Zone definitions: each zone has a name, path patterns, and min required role
ZONES: list[dict] = [
    {
        "name": "upload",
        "patterns": [r"^/files/upload", r"^/admin/"],
        "min_role": "teacher",
        "description": "Upload zone — teacher/admin only",
    },
    {
        "name": "access",
        "patterns": [r"^/files/"],
        "min_role": "student",
        "description": "Access zone — all authenticated users",
    },
    {
        "name": "auth",
        "patterns": [r"^/auth/"],
        "min_role": None,
        "description": "Authentication zone — open",
    },
]


def get_zone(path: str) -> Optional[dict]:
    """Return the zone dict for the given path, or None if unclassified."""
    for zone in ZONES:
        for pattern in zone["patterns"]:
            if re.search(pattern, path):
                return zone
    return None


def get_zone_name(path: str) -> Optional[str]:
    """Return just the zone name string for audit log entries."""
    zone = get_zone(path)
    return zone["name"] if zone else None
