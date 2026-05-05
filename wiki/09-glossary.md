# Glossary

Plain-English definitions for every term used in VAEL documentation.

---

## Security Terms

**APT (Advanced Persistent Threat)**
A sophisticated hacker group, usually state-sponsored, that conducts long-term targeted attacks. Examples: APT41 (China), Lazarus Group (North Korea). When VulnCheck reports that an APT group uses a CVE, it means professional hackers are actively using that vulnerability in real attacks.

**CISA KEV (Known Exploited Vulnerabilities catalog)**
A public list maintained by the US Cybersecurity and Infrastructure Security Agency. Every CVE on this list has been confirmed as actively exploited in real-world attacks. Being on the KEV list is the strongest possible signal that a patch is urgent — this is not theoretical risk, it is confirmed ongoing exploitation. Updated frequently. [View the catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)

**CVE (Common Vulnerabilities and Exposures)**
A unique identifier for a publicly known security flaw in software. Format: `CVE-YEAR-NUMBER` (e.g., `CVE-2021-44228`). Every significant security vulnerability gets a CVE ID so that everyone — vendors, security teams, government agencies — is talking about the same specific flaw.

**CVSS (Common Vulnerability Scoring System)**
A numerical score from 0.0 to 10.0 that rates the *theoretical severity* of a vulnerability. 10.0 is the maximum. Labels: 0.1–3.9 = LOW, 4.0–6.9 = MEDIUM, 7.0–8.9 = HIGH, 9.0–10.0 = CRITICAL. Important: CVSS measures *maximum potential damage*, not *how likely you are to be attacked*. A CVSS 10.0 vulnerability with no known exploit is often less urgent than a CVSS 7.5 with an active Metasploit module.

**CWE (Common Weakness Enumeration)**
A categorized list of software weaknesses. Where a CVE is a specific flaw in a specific product, a CWE is a *type* of flaw (e.g., CWE-787 = buffer overflow, CWE-89 = SQL injection). VAEL uses CWEs to flag common misconfiguration patterns.

**EPSS (Exploit Prediction Scoring System)**
A probability score from 0% to 100% that estimates how likely a CVE is to be actively exploited in the wild *within the next 30 days*. Published by FIRST.org and updated daily. An EPSS of 97% means: based on historical patterns, there is a 97% chance this CVE will be exploited within a month. This is the most practical "urgency" signal available — more useful than CVSS for prioritization.

**Exploit**
Code or a technique that takes advantage of a vulnerability to do something unauthorized — run arbitrary commands, steal data, gain access, etc.

**Exploit-DB**
A public database of published exploit code, maintained by Offensive Security (the creators of Kali Linux). When a CVE has an Exploit-DB entry, working attack code has been formally published.

**Metasploit**
The most widely used penetration testing and hacking toolkit in the world. If a CVE has a Metasploit module, a ready-to-run, polished attack tool exists that anyone with basic technical skill can use. A Metasploit module is the highest-severity exploit signal VAEL can find.

**Nuclei**
An open-source vulnerability scanner. Nuclei "templates" are scripts that verify whether a specific CVE is exploitable on a target server. A Nuclei template means the vulnerability can be detected and confirmed automatically — strong evidence it is exploitable.

**PoC (Proof of Concept)**
Code or a demonstration that proves a vulnerability is real and can be exploited. A PoC may be a full attack (ready to use) or just a demonstration (shows the flaw exists but isn't a finished weapon). VAEL grades PoCs from WEAPONIZED (ready to attack) down to CONCEPTUAL (just a write-up).

**Ransomware**
Malicious software that encrypts a victim's files and demands payment to decrypt them. Many ransomware groups (Conti, LockBit, etc.) exploit known CVEs to get into networks. VulnCheck tracks which ransomware families use which CVEs.

---

## VAEL-Specific Terms

**DEFER**
One of VAEL's four verdict labels. Means: low priority, no known exploit, very low attack probability. Add it to your maintenance backlog and patch it when convenient. Does not mean "ignore."

**HIGH**
One of VAEL's four verdict labels. Means: working exploit code is publicly available. Not yet confirmed as being actively attacked, but it is only a matter of time. Fix within a few days.

**MONITOR**
One of VAEL's four verdict labels. Means: the vulnerability is real but there is no working public exploit yet. Patch on your normal schedule, but re-check regularly — this can change quickly when new PoC code is published.

**PATCH NOW**
One of VAEL's four verdict labels. Means: drop everything and fix this. Either confirmed active exploitation (on the CISA KEV list), or a finished, ready-to-run attack tool is already public. Every day of delay is real risk.

**Pipeline**
VAEL's term for the sequence of four automated stages (CVE discovery → exploitability scoring → exploit hunting → exposure check) that run one after another to build up the full picture before the final verdict.

**PoC Quality grades**
How VAEL classifies exploit code it finds:
- **WEAPONIZED** — finished attack tool, ready to run
- **FUNCTIONAL** — working code, needs some adaptation
- **CONCEPTUAL** — a write-up or partial code, not a finished attack
- **FAKE** — flagged as a honeypot or fake repository
- **UNKNOWN** — couldn't determine quality from available information

**VEP (Vulnerability Exploitation Probability) score**
VAEL's internal 0–100 score that combines EPSS, KEV presence, CVSS, and exploit maturity into a single number. Used internally to assign T0/T1/T2/T3 tiers. Not exposed directly in the UI — the tier labels and verdict are what you see.

**VEP Tiers**
Internal priority labels VAEL assigns to each CVE in Stage 2:
- T0 → `PATCH NOW`
- T1 → `HIGH`
- T2 → `MONITOR`
- T3 → `DEFER`

**Version compatibility**
Whether a found exploit is confirmed to work against your specific version:
- **CONFIRMED** — explicitly tested against your version
- **LIKELY** — targets a version range that includes yours
- **UNLIKELY** — targets a different version
- **UNKNOWN** — no version information available

---

## Data Sources

**Censys**
An internet scanning service that indexes publicly reachable servers and their certificates. Used in Stage 4 to estimate internet exposure. [censys.io](https://censys.io)

**GHSA (GitHub Security Advisories)**
GitHub's database of security advisories for open-source packages. Often has "first fixed in version X" information that the NVD database lacks.

**NVD (National Vulnerability Database)**
The US government's authoritative master database of all publicly known CVEs. Maintained by NIST. Every CVE that matters will be in the NVD. [nvd.nist.gov](https://nvd.nist.gov)

**OSV (Open Source Vulnerabilities)**
Google's open-source vulnerability database. Focuses on package ecosystems (Python/PyPI, JavaScript/npm, Java/Maven, Go, Rust, Ruby, etc.) with precise version range information.

**Shodan**
The most widely used internet scanning service. Continuously scans all public IP addresses and records what services they are running. Used in Stage 4 to count how many servers running the vulnerable software are publicly accessible. [shodan.io](https://shodan.io)

**VulnCheck**
A commercial threat intelligence service with a free community tier. Tracks which APT groups and ransomware families actively use specific CVEs. [vulncheck.com](https://vulncheck.com)

---

## Technical Terms

**API key**
A password-like token that identifies you to an external service and unlocks higher rate limits or additional data. All API keys in VAEL are optional.

**Cache**
A local copy of data from external sources, saved to speed up repeated queries. VAEL stores its cache in `feeds/vael_cache.db`. Data is re-fetched after it expires (TTL).

**CI/CD pipeline**
Continuous Integration / Continuous Deployment — automated systems that build, test, and deploy code. VAEL can be integrated into CI/CD to automatically analyze dependencies whenever code changes.

**Rate limit**
A restriction imposed by an API on how many requests you can make per time period (e.g., 10 requests per minute). When you hit a rate limit, requests are rejected until the window resets. VAEL tracks rate limits for all sources and warns you before you hit them.

**SBOM (Software Bill of Materials)**
A formal, machine-readable list of all the software components and dependencies in a project. Like a food ingredient label, but for software. Formats: CycloneDX, SPDX, or a simple `requirements.txt`. VAEL can analyze an entire SBOM file to check all components at once.

**TTL (Time To Live)**
How long a cached result is kept before being considered stale and re-fetched. VAEL uses different TTLs per source: NVD and EPSS are refreshed every 24 hours; CISA KEV every 6 hours (because active exploitations can be added at any time).
