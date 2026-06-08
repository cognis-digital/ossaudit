"""OSSAUDIT - OSS license compliance auditor.

Detects copyleft/AGPL contamination across a dependency tree and generates a
NOTICE / attribution file from collected license metadata. Standard library
only, zero install.
"""
from .core import (
    LicenseInfo,
    Dependency,
    AuditFinding,
    AuditReport,
    classify_license,
    normalize_license_id,
    is_compatible,
    audit_dependencies,
    load_dependencies,
    generate_notice,
    LICENSE_RULES,
    POLICY_PRESETS,
)

TOOL_NAME = "ossaudit"
TOOL_VERSION = "1.0.0"

__all__ = [
    "LicenseInfo",
    "Dependency",
    "AuditFinding",
    "AuditReport",
    "classify_license",
    "normalize_license_id",
    "is_compatible",
    "audit_dependencies",
    "load_dependencies",
    "generate_notice",
    "LICENSE_RULES",
    "POLICY_PRESETS",
    "TOOL_NAME",
    "TOOL_VERSION",
]
