"""
PHISHIELD Cyber Risk Assessment — static data tables for the PDF generator.
Split out of pdf_report.py (pure move — no behaviour change).
"""

# Brief descriptions for common CVEs referenced in the protocol knowledge base
# review-by: 2026-12-02
CVE_DESCRIPTIONS = {
    # FTP
    "CVE-2015-3306": "ProFTPD mod_copy — unauthenticated remote file copy/write — UNDERWRITING: enables data exfiltration via unauthenticated file access",
    "CVE-2019-12815": "ProFTPD mod_copy — arbitrary file copy without auth — UNDERWRITING: enables data theft without credentials",
    "CVE-2010-4221": "ProFTPD — remote stack buffer overflow (RCE) — UNDERWRITING: enables full server takeover via file transfer service",
    # SSH
    "CVE-2024-6387": "regreSSHion — unauthenticated RCE in OpenSSH (critical) — UNDERWRITING: enables full server takeover; primary ransomware deployment vector",
    "CVE-2023-48795": "Terrapin — SSH prefix truncation attack — UNDERWRITING: degrades SSH encryption; facilitates data interception",
    "CVE-2016-20012": "OpenSSH — username enumeration via timing — UNDERWRITING: facilitates targeted brute-force attacks against valid accounts",
    # Telnet
    "CVE-2020-10188": "Telnetd — remote code execution via buffer overflow — UNDERWRITING: unencrypted protocol; enables full system compromise",
    "CVE-2011-4862": "FreeBSD telnetd — encryption key ID buffer overflow (RCE) — UNDERWRITING: legacy protocol RCE; indicates poor patch management",
    # SMTP
    "CVE-2021-3156": "Sudo heap overflow — local privilege escalation — UNDERWRITING: post-compromise privilege escalation to root access",
    "CVE-2020-28018": "Exim — use-after-free leading to RCE — UNDERWRITING: mail server compromise enables email interception and BEC attacks",
    "CVE-2011-1720": "Postfix — memory corruption via SASL — UNDERWRITING: mail server compromise enables data interception",
    # POP3/IMAP
    "CVE-2021-33515": "Dovecot — STARTTLS command injection — UNDERWRITING: enables email credential interception",
    "CVE-2019-11500": "Dovecot — buffer overflow in mail processing (RCE) — UNDERWRITING: mail server RCE enables full email system compromise",
    # MySQL
    "CVE-2012-2122": "MySQL — authentication bypass via timing attack — UNDERWRITING: enables immediate database access without credentials",
    "CVE-2016-6662": "MySQL — remote root code execution via config file — UNDERWRITING: enables full database and OS-level compromise",
    "CVE-2020-14812": "MySQL Server — denial of service via optimizer — UNDERWRITING: enables service disruption; business interruption risk",
    # RDP
    "CVE-2019-0708": "BlueKeep — unauthenticated RCE in RDP (wormable, critical) — UNDERWRITING: wormable; caused WannaCry/NotPetya global outbreaks",
    "CVE-2019-1181": "DejaBlue — RDP RCE affecting newer Windows versions — UNDERWRITING: wormable RDP exploit; lateral movement risk",
    "CVE-2019-1182": "DejaBlue — RDP RCE variant (wormable) — UNDERWRITING: wormable; enables rapid lateral spread across networks",
    # PostgreSQL
    "CVE-2023-5868": "PostgreSQL — privilege escalation via aggregate functions — UNDERWRITING: enables database privilege escalation to admin",
    "CVE-2019-9193": "PostgreSQL — authenticated RCE via COPY FROM PROGRAM — UNDERWRITING: enables OS command execution from database access",
    "CVE-2023-39417": "PostgreSQL — SQL injection in extension scripts — UNDERWRITING: enables database compromise via extension vulnerabilities",
    # VNC
    "CVE-2006-2369": "RealVNC — authentication bypass (no password required) — UNDERWRITING: enables unauthenticated remote desktop control",
    "CVE-2019-15681": "TightVNC — heap buffer overflow (RCE) — UNDERWRITING: enables remote desktop takeover; data exfiltration risk",
    # SMB
    "CVE-2017-0144": "EternalBlue — SMBv1 RCE (WannaCry, NotPetya) — UNDERWRITING: caused $10B+ in global losses via WannaCry/NotPetya",
    "CVE-2020-0796": "SMBGhost — SMBv3 RCE (wormable, critical) — UNDERWRITING: wormable; enables lateral movement across networks",
    "CVE-2017-0145": "EternalRomance — SMBv1 RCE variant — UNDERWRITING: used in NotPetya; enables ransomware lateral spread",
    # Redis
    "CVE-2022-0543": "Redis — Lua sandbox escape (RCE) — UNDERWRITING: enables remote code execution on cache/database servers",
    "CVE-2021-32761": "Redis — integer overflow in BITFIELD (heap corruption) — UNDERWRITING: enables cache server compromise and data manipulation",
    # Elasticsearch
    "CVE-2015-1427": "Elasticsearch — Groovy scripting RCE (unauthenticated) — UNDERWRITING: unauthenticated RCE; full data extraction possible",
    "CVE-2014-3120": "Elasticsearch — MVEL scripting RCE — UNDERWRITING: enables remote code execution on search/analytics infrastructure",
    # MongoDB
    "CVE-2015-7882": "MongoDB — authentication bypass — UNDERWRITING: enables unauthenticated database access; mass data theft risk",
    "CVE-2013-1892": "MongoDB — nativeHelper buffer overflow (RCE) — UNDERWRITING: enables full database server compromise",
    # MSSQL
    "CVE-2020-0618": "SQL Server — deserialization RCE — UNDERWRITING: enables remote code execution on enterprise database servers",
    "CVE-2019-1068": "SQL Server — remote code execution — UNDERWRITING: enables full compromise of enterprise database infrastructure",
    # CouchDB
    "CVE-2017-12635": "CouchDB — privilege escalation to admin — UNDERWRITING: enables unauthorized admin access to document databases",
    "CVE-2017-12636": "CouchDB — arbitrary command execution — UNDERWRITING: enables OS-level compromise via database service",
    # Docker
    "CVE-2019-5736": "runc — container escape to host (critical) — UNDERWRITING: container escape; compromises entire hosting infrastructure",
    # SNMP
    "CVE-2017-6736": "Cisco SNMP — remote code execution — UNDERWRITING: enables network infrastructure takeover",
    "CVE-2002-0012": "SNMP — community string brute-force / info disclosure — UNDERWRITING: enables network topology discovery and device enumeration",
}
