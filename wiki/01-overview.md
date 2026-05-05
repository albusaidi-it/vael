# VAEL — What It Is and Why It Exists

## The Problem

Every week, development teams get back lists like this from their security scanner:

```
CVE-2021-44228   CRITICAL   log4j 2.14.1
CVE-2021-45046   CRITICAL   log4j 2.14.1
CVE-2021-4104    HIGH       log4j 2.14.1
CVE-2022-23302   HIGH       log4j 2.14.1
... 43 more
```

A **CVE** (Common Vulnerabilities and Exposures) is a publicly registered security flaw in a piece of software. Every CVE gets an ID like `CVE-2021-44228` and a severity label like CRITICAL or HIGH.

But the list above tells you almost nothing *actionable*. Knowing you have 47 CVEs doesn't tell you what to actually do. To decide, you need to answer questions the scanner cannot:

- **Is this CVE being attacked right now?** — Governments track confirmed attacks in a public list called the [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) (Known Exploited Vulnerabilities catalog).
- **How likely is an attack in the next 30 days?** — A scoring system called [EPSS](https://www.first.org/epss/) gives each CVE a probability from 0% to 100%.
- **Does working attack code already exist?** — Security researchers publish "proof-of-concept" (PoC) code on GitHub, Exploit-DB, and Metasploit. If someone already wrote the attack script, exploitation requires almost no skill.
- **Does the attack code work against my specific version?** — A PoC for version 2.0 may not work against version 2.14.
- **Are there attack scripts published in Chinese or Russian that English searches miss?** — Many exploits are published only on Chinese or Korean security platforms and never appear in Google results.
- **Is this software publicly visible on the internet?** — A vulnerability in software only accessible inside your private network is much less urgent than the same vulnerability on a public-facing server.
- **Are known hacker groups using this CVE?** — Some CVEs are actively used by state-sponsored hacker groups (called APT groups) or ransomware operations.

Answering all of that for 47 CVEs takes hours of manual research. Most teams either skip it (and carry hidden risk) or treat every CVE as critical (and waste time on things that don't matter).

**VAEL answers all of it automatically**, in seconds, and delivers one of four plain-English verdicts:

| Verdict | What it means |
|---------|--------------|
| 🚨 **PATCH NOW** | Fix this today — active attacks confirmed or a ready-to-use exploit is already public |
| ⚠️ **HIGH** | Fix this within a few days — working exploit code exists, attacks could start any time |
| 👁️ **MONITOR** | Fix on your normal schedule — real vulnerability but no working exploit yet |
| 📋 **DEFER** | Low priority — no known exploit, very unlikely to be attacked soon |

See [What the verdicts mean](#what-the-verdicts-mean) below for the full explanation.

---

## What VAEL Does

VAEL takes a software name and version number as input, then runs a 4-stage automated investigation:

1. **Finds every known CVE** for that software and version — by querying three major vulnerability databases at once and removing duplicates.
2. **Scores each CVE for real exploitability** — using live attack probability data, the government's confirmed-exploitation list, and hacker group intelligence.
3. **Hunts for actual attack code** — searching 12 sources globally (including non-English platforms) for proof-of-concept exploits and classifying each one by how dangerous it is.
4. **Checks internet exposure** — using internet scanning services to estimate how many servers running this software are publicly reachable.
5. **Produces a single AI-backed verdict** with a confidence score and a plain-English explanation of the evidence.
6. **Oman Internet Exposure** — a dedicated always-visible section that searches Shodan, FOFA, and Censys for publicly reachable hosts specifically inside Oman, using CVE IDs for targeted results. Runs independently — no pipeline analysis required first.

---

## Who It's For

| Role | How they use VAEL |
|------|------------------|
| **Developers and DevOps teams** | Find out which CVEs in their dependencies actually need urgent attention vs. which can wait |
| **Security engineers** | Replace hours of manual CVE triage with a seconds-long automated analysis |
| **CI/CD pipelines** | Automatically block or flag releases when a new critical CVE appears in a dependency |
| **Penetration testers** | Quickly find working public exploit code for a target software version |
| **Security researchers** | Cross-reference CVE data across all major databases in one query |
| **Security operations teams (SOC)** | Verify whether a CVE they were alerted about is confirmed as being actively attacked |
| **Offensive security teams (red teams)** | Discover PoCs on non-English platforms that standard tools miss |

---

## What Makes VAEL Different

### 1. It hunts for working exploits, not just lists CVEs

Most security scanners stop at "here are your CVEs." VAEL goes further and actually searches for exploit code — on GitHub, Exploit-DB, Metasploit Framework, Packet Storm, Nuclei, and international platforms. A CVE where someone already published a working attack script is categorically more urgent than one where no such code exists.

### 2. It searches where others don't look

Many PoCs and vulnerability write-ups are published only on Chinese, Russian, or Korean security platforms. These never appear in English Google searches. VAEL queries Gitee, Seebug, Naver, and Yandex using native-language security terms to surface exploits that English-only tools miss entirely.

### 3. What the verdicts mean

A CVSS severity score (the standard 0–10 number) tells you how bad a vulnerability *would be* if exploited. It does not tell you whether it *is being* exploited, or whether anyone has bothered to write an attack tool. VAEL's four verdicts answer the practical question — "what should I actually do right now?"

---

#### 🚨 `PATCH NOW` — Fix this today, even outside business hours

Someone is actively attacking this vulnerability right now, or a ready-to-use attack tool is already freely available. Every day you wait increases the risk of a real breach.

> **What triggers this:** The CVE appears on the government's confirmed-exploitation list (CISA KEV), a finished exploit module exists in Metasploit, or the statistical attack probability (EPSS) is above 50%.

---

#### ⚠️ `HIGH` — Fix this within the next few days

No confirmed active attacks yet, but a working proof-of-concept is already public. It is only a matter of time before attackers start using it. This is not a routine maintenance item.

> **What triggers this:** Working attack code exists on GitHub or Exploit-DB, or the attack probability (EPSS) is above 10%.

---

#### 👁️ `MONITOR` — Patch on your normal schedule, but keep watching

The vulnerability is real and confirmed, but there is no working public exploit and no evidence of attacks. Patch it in your next routine maintenance window. Check back in 2–4 weeks — this status can change quickly when new PoCs are published.

> **What triggers this:** Only a write-up or conceptual description exists with no working code, or attack probability is between 1% and 10%.

---

#### 📋 `DEFER` — Low priority; add to your maintenance backlog

No known attack tools, no threat actor interest, very low attack probability. This is the "fix it when you get around to it" category. It is still a real flaw — do not ignore it permanently — but it does not need to jump the queue ahead of more pressing issues.

> **What triggers this:** No exploit or PoC found anywhere across 12 sources, and attack probability is below 1%.

---

> **Important:** CVSS 9.8 does not automatically mean `PATCH NOW`. A CVE with CVSS 9.8 but a 0.001% attack probability and no known exploit code is often `DEFER`. A CVE with CVSS 6.5 that is already being used by ransomware groups and has a Metasploit module is always `PATCH NOW`. VAEL uses the full evidence picture, not just one number.

---

### 4. The AI explains its reasoning

When Gemini AI is available, it receives all the collected evidence and writes a plain-English explanation of *why* the verdict is what it is, and what specific signals drove it. The AI cannot invent data — it only reasons over facts VAEL collected. If Gemini is unavailable, a built-in rule engine produces the same verdict format automatically.

### 5. Everything works without API keys

Every API key is optional. Without keys the pipeline still works — it just runs at lower speed (public rate limits) and skips features that require credentials (Shodan exposure, VulnCheck threat intel). You get a useful result even with zero configuration.

---

## The Name

**V**ulnerability **A**nalysis **E**ngine **L**ite — built to be thorough but deployable anywhere, from a laptop to a Docker container.

---

## Relationship to Other Tools

| Tool | How VAEL relates to it |
|------|----------------------|
| **Trivy, Grype, Snyk** | These tools *find* CVEs in your code. VAEL takes their output and tells you *which ones actually matter and why*. |
| **CVSS calculators** | CVSS gives a severity score. VAEL uses CVSS as one of many inputs — not the final answer. |
| **CISA KEV** | The US government's list of CVEs confirmed as actively exploited. VAEL includes this list as a primary signal — any CVE on this list immediately becomes `PATCH NOW`. |
| **Metasploit** | A widely-used hacking toolkit. VAEL searches the Metasploit code repository for exploit modules targeting your CVEs. It does not *run* Metasploit. |
| **Vulhub** | A Chinese repository of vulnerable software environments for testing. VAEL can surface Vulhub-linked PoCs via its international search. |

---

## Key Terms Quick Reference

| Term | Plain meaning |
|------|--------------|
| **CVE** | A registered security flaw with a unique ID like `CVE-2021-44228` |
| **CVSS** | A severity score from 0.0 (harmless) to 10.0 (critical) |
| **EPSS** | Probability (0%–100%) that a CVE will be actively attacked in the next 30 days |
| **KEV** | CISA's official list of CVEs confirmed being actively exploited right now |
| **PoC** | Working code that demonstrates a vulnerability is real and exploitable |
| **APT** | Advanced Persistent Threat — a sophisticated, often state-sponsored hacker group |
| **Metasploit** | A widely-used attack toolkit; having a Metasploit module means the attack is easy to run |
| **Shodan / Censys** | Services that scan the internet and count publicly-visible servers |
| **NVD** | US government's master database of all known CVEs |
| **OSV** | Google's open-source vulnerability database |
| **GHSA** | GitHub's security advisory database |

See [Glossary](09-glossary.md) for a full reference.
