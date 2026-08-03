"""Static framework mappings used by the compliance report.

Maps findings (via CWE-ID, falling back to name keywords) to CIS Controls v8,
NIST SP 800-53 rev5 and OWASP WSTG references "where available".
Pure report-generation data; no scanner logic lives here.
"""

from typing import Optional

CWE_FRAMEWORK_MAP: dict[str, dict[str, str]] = {
    # Input validation / injection
    "CWE-78": ("8.3", "SC-7; SI-10", "WSTG-INPV-15 Command Injection"),
    "CWE-79": ("9.2; 9.3", "SC-18; SI-10", "WSTG-INPV-01/02 Cross-Site Scripting"),
    "CWE-89": ("3.3; 8.3", "SI-10", "WSTG-INPV-05 SQL Injection"),
    "CWE-93": ("9.2; 9.3", "SI-10", "WSTG-INPV-13 CRLF Injection"),
    "CWE-94": ("8.3", "SC-7; SI-10", "WSTG-INPV-11 Code Injection"),
    "CWE-95": ("8.3", "SI-10", "WSTG-INPV-11 Code Injection"),
    "CWE-77": ("8.3", "SI-10", "WSTG-INPV-15 Command Injection"),
    "CWE-20": ("8.3; 8.4", "SI-10; SI-11", "WSTG-INPV-00 Input Validation"),
    "CWE-22": ("3.3; 3.4", "CM-6; SI-10", "WSTG-ATHN-01 Path Traversal"),
    "CWE-434": ("3.3", "SC-7; SI-10", "WSTG-BUSL-05 Unrestricted File Upload"),
    "CWE-502": ("8.3", "SC-7; SI-10", "WSTG-INPV-19 Deserialization"),
    "CWE-611": ("8.3", "SI-10", "WSTG-INPV-07 XXE"),
    "CWE-918": ("8.3", "SC-7; SI-10", "WSTG-INPV-09 SSRF"),
    "CWE-601": ("3.3", "SC-7; SI-10", "WSTG-CLNT-04 Open Redirect"),
    # Authentication / access control
    "CWE-269": ("6.8", "AC-6; AU-9", "WSTG-ATHZ-00 Access Control"),
    "CWE-287": ("6.1; 6.8", "IA-5; AC-7", "WSTG-AUTHN-00 Authentication"),
    "CWE-306": ("6.1; 6.8", "IA-2; IA-5", "WSTG-AUTHN-02 Bypass Authentication"),
    "CWE-307": ("6.1", "AC-7; IA-5", "WSTG-AUTHN-07 Weak Lockout"),
    "CWE-352": ("6.1; 8.3", "AC-4; SI-10", "WSTG-SESS-05 CSRF"),
    "CWE-521": ("6.1; 6.8", "IA-5", "WSTG-AUTHN-08 Weak Passwords"),
    "CWE-798": ("6.1; 6.8", "CM-6; IA-5", "WSTG-CONF-04 Hardcoded Credentials"),
    "CWE-862": ("6.8", "AC-6", "WSTG-ATHZ-02 Missing Authorization"),
    "CWE-863": ("6.8", "AC-6", "WSTG-ATHZ-03 Incorrect Authorization"),
    # Cryptography / transport security
    "CWE-295": ("3.10", "SC-8; SC-12", "WSTG-CRYP-01 TLS Configuration"),
    "CWE-310": ("3.10", "SC-8; SC-13", "WSTG-CRYP-00 Cryptographic Issues"),
    "CWE-311": ("3.10; 8.4", "SC-8; SC-28", "WSTG-CRYP-02 Data in Transit"),
    "CWE-319": ("3.10", "SC-8", "WSTG-CRYP-03 Cleartext Transmission"),
    "CWE-326": ("3.10", "SC-13", "WSTG-CRYP-01 Weak Cryptographic Keys"),
    "CWE-327": ("3.10", "SC-13", "WSTG-CRYP-04 Insecure Algorithms"),
    # Information disclosure / logging
    "CWE-200": ("3.3; 4.1", "AU-2; SC-7", "WSTG-INFO-05 Information Disclosure"),
    "CWE-209": ("4.1", "AU-2; SI-11", "WSTG-ERRH-01 Error Handling"),
    "CWE-522": ("4.1; 6.1", "IA-5; SC-28", "WSTG-AUTHN-04 Credentials in Logs"),
    "CWE-532": ("4.1", "AU-2; SI-11", "WSTG-INFO-07 Sensitive Data in Logs"),
    # Network / service hardening
    "CWE-284": ("6.8", "AC-6; CM-6", "WSTG-ATHZ-00 Improper Access Control"),
    "CWE-400": ("13.2", "SC-5; SI-10", "WSTG-DOS-00 Resource Exhaustion"),
    "CWE-770": ("13.2", "SC-5", "WSTG-DOS-01 Uncontrolled Resource Consumption"),
    "CWE-254": ("6.8", "CM-6; SI-3", "WSTG-SECP-00 Platform Hardening"),
}

# Keyword fallbacks applied when no CWE mapping exists.
_KEYWORD_MAP: list[tuple[str, str, str, str]] = [
    ("ssl", "3.10", "SC-8; SC-13", "WSTG-CRYP-01 TLS Configuration"),
    ("tls", "3.10", "SC-8; SC-13", "WSTG-CRYP-01 TLS Configuration"),
    ("http", "3.10", "SC-8", "WSTG-CRYP-03 Cleartext Transmission"),
    ("ftp", "3.10", "SC-8", "WSTG-CRYP-03 Cleartext Transmission"),
    ("telnet", "6.1", "AC-17; SC-8", "WSTG-CRYP-03 Cleartext Transmission"),
    ("rdp", "6.1", "AC-17; SC-8", "WSTG-CRYP-03 Cleartext Transmission"),
    ("snmp", "3.3; 3.4", "CM-6; IA-5", "WSTG-SECP-01 Default/Weak Community Strings"),
    ("ntp", "8.4", "CM-6; SC-7", "WSTG-SECP-00 NTP Hardening"),
    ("smb", "3.3; 6.8", "AC-6; CM-6", "WSTG-SECP-00 SMB Hardening"),
    ("cifs", "3.3; 6.8", "AC-6; CM-6", "WSTG-SECP-00 SMB/CIFS Hardening"),
    ("ssh", "3.4; 6.1", "CM-6; IA-5", "WSTG-SECP-00 SSH Hardening"),
    ("vnc", "6.1", "AC-17; IA-5", "WSTG-SECP-00 VNC Hardening"),
    ("brute", "6.1", "AC-7; IA-5", "WSTG-AUTHN-07 Brute Force"),
    ("default credential", "6.1; 6.8", "CM-6; IA-5", "WSTG-AUTHN-08 Default Credentials"),
    ("default password", "6.1; 6.8", "CM-6; IA-5", "WSTG-AUTHN-08 Default Credentials"),
    ("weak password", "6.1", "IA-5", "WSTG-AUTHN-08 Weak Passwords"),
    ("denial of service", "13.2", "SC-5", "WSTG-DOS-00 Denial of Service"),
    ("command injection", "8.3", "SI-10", "WSTG-INPV-15 Command Injection"),
    ("sql injection", "3.3; 8.3", "SI-10", "WSTG-INPV-05 SQL Injection"),
    ("path traversal", "3.3; 3.4", "CM-6; SI-10", "WSTG-ATHN-01 Path Traversal"),
    ("cross-site scripting", "9.2; 9.3", "SC-18; SI-10", "WSTG-INPV-01/02 Cross-Site Scripting"),
    ("remote code execution", "8.3", "SC-7; SI-10", "WSTG-INPV-11 Code Execution"),
    ("information disclosure", "3.3; 4.1", "AU-2; SC-7", "WSTG-INFO-05 Information Disclosure"),
    ("outdated", "7.4", "RA-5; SI-2", "WSTG-SECP-00 Patch Management"),
    ("obsolete", "7.4", "RA-5; SI-2", "WSTG-SECP-00 Patch Management"),
    ("end of life", "7.4", "RA-5; SI-2", "WSTG-SECP-00 Patch Management"),
    ("weak cipher", "3.10", "SC-8; SC-13", "WSTG-CRYP-04 Insecure Algorithms"),
]


def compliance_map_for(cwe_ids: Optional[list[str]], finding_name: str) -> Optional[dict]:
    """Return {'cis', 'nist', 'owasp'} mapping for a finding, or None if unmapped."""
    if cwe_ids:
        for cwe in cwe_ids:
            mapped = CWE_FRAMEWORK_MAP.get(cwe)
            if mapped:
                return {"cis": mapped[0], "nist": mapped[1], "owasp": mapped[2], "basis": cwe}
    name_lower = (finding_name or "").lower()
    for keyword, cis, nist, owasp in _KEYWORD_MAP:
        if keyword in name_lower:
            return {"cis": cis, "nist": nist, "owasp": owasp, "basis": f"keyword: {keyword}"}
    return None
