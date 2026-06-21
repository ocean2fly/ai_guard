import re
from typing import Optional

# (compiled_regex, risk_level, human_label)
# Ordered so that the most specific patterns are checked first.
_RULES = [
    (re.compile(r"(?i)\bDROP\s+(TABLE|DATABASE|SCHEMA|INDEX|SEQUENCE|VIEW|FUNCTION|PROCEDURE|TRIGGER|EXTENSION)\b"),
     "high", "DROP"),
    (re.compile(r"(?i)\bTRUNCATE\b"),
     "high", "TRUNCATE"),
    # DELETE without WHERE (end of statement or semicolon follows table name)
    (re.compile(r"(?i)\bDELETE\s+FROM\s+\w[\w.]*\s*(?:;?\s*$)"),
     "high", "DELETE (no WHERE)"),
    # DELETE with WHERE — medium risk, default allow
    (re.compile(r"(?i)\bDELETE\s+FROM\s+\w[\w.]*\s+WHERE\b"),
     "medium", "DELETE (with WHERE)"),
    # ALTER TABLE ... DROP/RENAME COLUMN
    (re.compile(r"(?i)\bALTER\s+TABLE\b.{0,200}\b(DROP|RENAME)\s+COLUMN\b"),
     "medium", "ALTER TABLE (column change)"),
]


def classify(sql: str) -> tuple[Optional[str], Optional[str]]:
    """
    Returns (risk_level, label) if the query is potentially dangerous.
    Returns (None, None) for safe queries (SELECT, INSERT, UPDATE, etc.).

    risk_level: 'high' | 'medium'
    label:      short human-readable description
    """
    stripped = sql.strip()
    for pattern, risk, label in _RULES:
        if pattern.search(stripped):
            return risk, label
    return None, None
