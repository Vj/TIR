# engines/static/rules/sqli_heuristic.py
import re
from typing import List, Dict, Any
from core.models import Finding, Severity, CheckStatus

class SQLiHeuristicAnalyzer:
    """Performs contextual opcode and callsite analysis to detect unparameterized SQL operations."""

    # Methods that accept direct SQL statements
    DANGEROUS_SINKS = [
        "rawQuery(Ljava/lang/String;[Ljava/lang/String;)Landroid/database/Cursor;",
        "rawQueryWithFactory(",
        "execSQL(Ljava/lang/String;)V",
        "execSQL(Ljava/lang/String;[Ljava/lang/Object;)V",
    ]

    # ContentProvider query delegation
    PROVIDER_QUERY_SINKS = [
        "query(Landroid/net/Uri;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;"
    ]

    @classmethod
    def analyze_dex_code(cls, dex_filename: str, dex_content: str) -> List[Finding]:
        findings: List[Finding] = []

        # Pattern 1: StringBuilder/StringBuffer append pattern immediately preceding rawQuery / execSQL
        # In Smali/DEX: invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(...)
        # followed closely by rawQuery(..., null)
        concat_sink_pattern = re.compile(
            r"(?:StringBuilder|StringBuffer);->append\(.*?\).*?"
            r"(?:rawQuery|execSQL)\s*\(.*?(?:null|[vp]\d+)\)",
            re.DOTALL
        )

        # Pattern 2: Smali inline string concatenation feeding SQL sink
        raw_query_null_args = re.compile(
            r'const-string [vp]\d+,\s*"(SELECT|INSERT|UPDATE|DELETE)[^"]*"\s*'
            r'.*?invoke-virtual \{[vp]\d+,\s*[vp]\d+\},\s*Landroid/database/sqlite/SQLiteDatabase;->rawQuery\(.*?\)',
            re.DOTALL | re.IGNORECASE
        )

        # Match Pattern 1
        for match in concat_sink_pattern.finditer(dex_content):
            snippet = match.group(0)[:250]
            findings.append(Finding(
                check_id="STA-033",
                title="Dynamic SQL Query Built via String Concatenation",
                category="MASVS-STORAGE",
                tab_index=2,
                severity=Severity.HIGH,
                status=CheckStatus.FAIL,
                description=(
                    "An SQLite query is dynamically constructed using StringBuilder/StringBuffer operations "
                    "and dispatched to an execution sink without parameterized positional arguments."
                ),
                evidence=f"File: {dex_filename}\nOpcode sequence snippet:\n{snippet}...",
                remediation=(
                    "Use parameterized queries with selectionArgs placeholders ('?'):\n"
                    "db.rawQuery(\"SELECT * FROM users WHERE user = ?\", new String[]{userInput});"
                )
            ))
            break  # Deduplicate per DEX file to avoid alert fatigue

        # Pattern 3: Selection / SortOrder injection in ContentProvider
        if "Landroid/content/ContentProvider;" in dex_content and "sortOrder" in dex_content:
            if re.search(r"rawQuery\(.*?sortOrder.*?\)", dex_content):
                findings.append(Finding(
                    check_id="STA-033",
                    title="Potential SQL Injection via ContentProvider sortOrder Parameter",
                    category="MASVS-STORAGE",
                    tab_index=2,
                    severity=Severity.HIGH,
                    status=CheckStatus.FAIL,
                    description=(
                        "ContentProvider forwards unvalidated sortOrder parameters directly into rawQuery/execSQL sinks, "
                        "allowing callers to inject arbitrary subqueries or conditional logic."
                    ),
                    evidence=f"Identified ContentProvider sortOrder forwarding pattern in {dex_filename}.",
                    remediation="Validate sortOrder against an explicit whitelist of supported columns before query dispatch."
                ))

        return findings