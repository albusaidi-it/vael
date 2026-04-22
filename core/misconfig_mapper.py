"""
VAEL – Stage 1 / Misconfig Mapper
Maps known software to common CWE weaknesses and CIS Benchmark flags.

This is a curated offline knowledge base — no network calls.
Extend by adding entries to SOFTWARE_CWE_MAP and CIS_FLAGS.
"""

from __future__ import annotations

from schemas.stage1 import MisconfigFlag, Severity


# ---------------------------------------------------------------------------
# Software → common CWE weaknesses
# Format: software_key → [(cwe_id, title, description, severity, remediation)]
# ---------------------------------------------------------------------------
SOFTWARE_CWE_MAP: dict[str, list[tuple]] = {
    "nginx": [
        ("CWE-16",  "Configuration",
         "Nginx default config may expose server version and unnecessary modules.",
         Severity.MEDIUM,
         "Set 'server_tokens off;' and disable unused modules."),
        ("CWE-200", "Information Exposure",
         "Default error pages may reveal stack info or version strings.",
         Severity.LOW,
         "Configure custom error pages."),
        ("CWE-400", "Resource Exhaustion",
         "Missing rate limiting can expose nginx to slow-loris DoS attacks.",
         Severity.HIGH,
         "Configure limit_req_zone and limit_conn directives."),
    ],
    "log4j": [
        ("CWE-917", "Expression Language Injection",
         "Log4j 2.x JNDI lookup feature allows remote code execution via crafted log messages.",
         Severity.CRITICAL,
         "Upgrade to >= 2.17.1 or set -Dlog4j2.formatMsgNoLookups=true."),
        ("CWE-611", "Improper Restriction of XML External Entity Reference",
         "Log4j XML configuration may be vulnerable to XXE if config is user-controlled.",
         Severity.HIGH,
         "Disable XML external entity processing in log4j config."),
    ],
    "apache": [
        ("CWE-16",  "Configuration",
         "Default Apache installation may enable directory listing and expose sensitive files.",
         Severity.MEDIUM,
         "Set 'Options -Indexes' and restrict access to sensitive directories."),
        ("CWE-200", "Information Exposure",
         "ServerSignature and ServerTokens may expose version info.",
         Severity.LOW,
         "Set ServerTokens Prod and ServerSignature Off."),
    ],
    "openssl": [
        ("CWE-326", "Inadequate Encryption Strength",
         "Older OpenSSL versions may negotiate weak cipher suites (SSLv3, RC4).",
         Severity.HIGH,
         "Disable SSLv2/SSLv3/TLS1.0 and configure strong cipher suites only."),
        ("CWE-310", "Cryptographic Issues",
         "Improper certificate validation or self-signed certs may be in use.",
         Severity.MEDIUM,
         "Enforce proper certificate chain validation."),
    ],
    "wordpress": [
        ("CWE-287", "Improper Authentication",
         "Default WordPress install may have weak admin credentials or XML-RPC enabled.",
         Severity.HIGH,
         "Disable XML-RPC if not needed, enforce strong passwords, limit login attempts."),
        ("CWE-79",  "Cross-Site Scripting",
         "Unpatched plugins frequently introduce stored/reflected XSS vulnerabilities.",
         Severity.HIGH,
         "Keep all plugins/themes updated, use a WAF."),
    ],
    "mysql": [
        ("CWE-521", "Weak Password Requirements",
         "MySQL may be configured with weak or default root credentials.",
         Severity.CRITICAL,
         "Set strong root password, remove anonymous users, disable remote root login."),
        ("CWE-16",  "Configuration",
         "MySQL may bind to all interfaces by default, exposing it externally.",
         Severity.HIGH,
         "Bind MySQL to localhost or specific trusted interface only."),
    ],
    "redis": [
        ("CWE-306", "Missing Authentication",
         "Redis default config has no authentication and listens on all interfaces.",
         Severity.CRITICAL,
         "Enable requirepass, bind to localhost, use TLS if exposing remotely."),
    ],
    "docker": [
        ("CWE-269", "Improper Privilege Management",
         "Running containers as root or with --privileged flag escalates attack surface.",
         Severity.HIGH,
         "Use non-root user in Dockerfile, avoid --privileged and --cap-add=SYS_ADMIN."),
        ("CWE-284", "Improper Access Control",
         "Docker socket exposure (/var/run/docker.sock) allows full host compromise.",
         Severity.CRITICAL,
         "Never expose docker socket to untrusted containers or web services."),
    ],
    "kubernetes": [
        ("CWE-269", "Improper Privilege Management",
         "Pods running as root or with hostPID/hostNetwork can escape to the host.",
         Severity.HIGH,
         "Enforce PodSecurityPolicy / PodSecurity admission, use non-root containers."),
        ("CWE-284", "Improper Access Control",
         "Default RBAC may be overly permissive. ClusterAdmin bindings are dangerous.",
         Severity.HIGH,
         "Audit RBAC bindings, apply least-privilege, enable audit logging."),
        ("CWE-16",  "Configuration",
         "etcd may be exposed without authentication, allowing full cluster takeover.",
         Severity.CRITICAL,
         "Enable etcd client cert auth and restrict access to control plane nodes only."),
    ],
}

# ---------------------------------------------------------------------------
# CIS Benchmark flags — high-signal reminders keyed by software
# ---------------------------------------------------------------------------
CIS_FLAGS: dict[str, list[tuple]] = {
    "nginx": [
        ("CIS-NGINX-1.1", "Ensure NGINX is updated to the latest stable release",
         Severity.HIGH, "Check nginx.org for current stable release."),
        ("CIS-NGINX-2.1", "Ensure HTTP is not served without TLS",
         Severity.HIGH, "Redirect all HTTP to HTTPS; configure HSTS."),
        ("CIS-NGINX-3.3", "Ensure keepalive_timeout is 10 seconds or less",
         Severity.MEDIUM, "Set keepalive_timeout 10; in nginx.conf."),
    ],
    "log4j": [
        ("CIS-LOG4J-1.1", "Ensure JNDI lookup is disabled",
         Severity.CRITICAL, "Set log4j2.formatMsgNoLookups=true or upgrade to 2.17.1+."),
    ],
    "docker": [
        ("CIS-DOCKER-2.1", "Ensure network traffic between containers is restricted",
         Severity.MEDIUM, "Use --icc=false in Docker daemon config."),
        ("CIS-DOCKER-4.1", "Ensure that a user for the container has been created",
         Severity.HIGH, "Add USER directive to Dockerfile."),
    ],
    "kubernetes": [
        ("CIS-K8S-1.2.1", "Ensure anonymous requests are not authorized",
         Severity.HIGH, "Set --anonymous-auth=false on API server."),
        ("CIS-K8S-4.2.6", "Ensure that the --protect-kernel-defaults argument is set",
         Severity.MEDIUM, "Set protectKernelDefaults: true in kubelet config."),
    ],
}


def get_misconfig_flags(software: str) -> list[MisconfigFlag]:
    """
    Return CWE + CIS misconfig flags for the given software.
    Matching is case-insensitive and checks if software name contains the key.
    """
    key = software.lower().strip()
    flags: list[MisconfigFlag] = []

    for sw_key, cwe_list in SOFTWARE_CWE_MAP.items():
        if sw_key in key or key in sw_key:
            for cwe_id, title, description, severity, remediation in cwe_list:
                flags.append(MisconfigFlag(
                    source="CWE",
                    rule_id=cwe_id,
                    title=title,
                    description=description,
                    severity=severity,
                    remediation=remediation,
                ))

    for sw_key, cis_list in CIS_FLAGS.items():
        if sw_key in key or key in sw_key:
            for rule_id, title, severity, remediation in cis_list:
                flags.append(MisconfigFlag(
                    source="CIS",
                    rule_id=rule_id,
                    title=title,
                    severity=severity,
                    remediation=remediation,
                ))

    return flags
