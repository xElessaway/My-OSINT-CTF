---
name: "Threat Cluster 150[.]241[.]65[.]250"
aliases: ["150241-889 Exposed Staging Node","Raul Multi-Architecture Cluster"]
status: "active"
origin: "Unknown / exposed Linux staging infrastructure"
motivation: "Multi-architecture Linux and IoT malware staging, payload delivery, operator workspace exposure, and possible botnet recruitment."
targets: ["Linux Servers and VPS Infrastructure","IoT and Embedded Devices","Internet-Exposed Edge Systems"]
firstSeen: "2026-08"
lastSeen: "2026-08"
tools: ["Python SimpleHTTP Server","wget / curl Payload Delivery","screen Session Management","Architecture-Specific Linux ELF Payloads","nc Listener","VPS Cleaner / Process-Killing Script"]
ttps: ["T1105 - Ingress Tool Transfer","T1059.004 - Unix Shell","T1204 - User Execution","T1071.001 - Web Protocols","T1070.004 - File and Directory Discovery / Indicator Removal on Host","T1562.001 - Impair Defenses"]
tags: ["threat-intelligence","dfir","malware-analysis","linux","iot-botnet","exposed-infrastructure"]
relatedPosts: []
featured: true
---

# Threat Cluster 150[.]241[.]65[.]250

> This dossier was generated from passive acquisition and static analysis. Retrieved artifacts were preserved as unexecuted evidence. No login, exploitation, modification, deletion, or active interaction with the endpoint was performed.

### Evidence Coverage

| Metric | Value |
| --- | --- |
| Root directory listing acquired | 1 |
| Root-level artifacts preserved | 7 |
| Text / configuration artifacts preserved | 5 |
| Linux ELF binaries preserved | 2 |
| Architecture-specific payloads listed but not fully acquired | 14 |
| Directory descendants acquired | 0 |
| PE candidates identified | 0 |
| Credential / secret exposure indicators | 2 high-risk exposure locations |
| Dynamic execution performed | No |
| Acquisition completed within bounded limits | No — larger transfers stalled and were stopped |

## Motivation & Objectives

### Strategic Motivation

The endpoint appears to be an exposed Linux staging workspace supporting multi-architecture payload delivery. Its directory listing contains binaries named for multiple CPU architectures, while the acquired shell history records the use of temporary HTTP servers, `wget`, `chmod +x`, and direct execution of downloaded payloads.[2]

### Operational Objectives

- **Multi-Architecture Payload Delivery:** Hosting `raul.*` binaries and related Linux ELF files for x86, ARM, MIPS, PowerPC, SPARC, and other architectures.

- **Botnet or IoT Recruitment:** Using architecture-specific binaries such as `pito.*`, `raul.*`, and `bot.i686` for possible deployment to heterogeneous Linux and embedded systems.

- **Staging Infrastructure:** Operating Python HTTP servers on ports `889` and `67` for file distribution.

- **Operator Workspace Management:** Retaining shell history, scripts, screen-session commands, and downloaded tooling in a web-accessible directory.

- **Defense Evasion and Cleanup:** Maintaining a VPS-cleaner script capable of killing processes and deleting artifacts from temporary directories and cron locations.

### Inferred Target Profile

- Linux servers and VPS instances

- IoT and embedded devices

- Internet-exposed edge systems

- Hosts vulnerable to unauthorized payload download and execution

### Key Operational Findings

- Unauthenticated Python `SimpleHTTP` directory listing on port `889`

- Multi-architecture `raul.*` payload set exposed in the web root

- `bot` and `dropper` Linux ELF binaries exposed and partially acquired

- Shell history showing `wget`, `curl`, `chmod +x`, and direct execution

- Historical retrieval and execution of `pito.arm7`, `pito.x86`, and `bot.i686`

- Historical use of `nc -nlvp 9001`, indicating listener setup

- VPS cleaner script capable of process termination and artifact deletion

- Strong tradecraft overlap with the supplied `194[.]238[.]57[.]124` cluster

- No direct evidence in this acquisition of successful victim compromise or current C2 activity

### Credentials, Keys & Tokens (Redacted )

| Risk | Type | Redacted Value | Source / Layer |
| --- | --- | --- | --- |
| **High** | SSH material exposure | `[NOT ACQUIRED — .ssh/ DIRECTORY PUBLICLY LISTED]` | Root directory listing / L0 |
| **High** | X11 authentication cookie | `[REDACTED_XAUTHORITY_COOKIE]` | `.Xauthority` / L0 |
| **Medium** | Shell-history credentials or operational secrets | `[NOT REPRODUCED]` | `.bash_history` / L0 |

### Verified Indicators

| Type | Defanged Value / Hash | Context | Confidence |
| --- | --- | --- | --- |
| **Investigated Host** | `150[.]241[.]65[.]250` | User-supplied investigated host | High (observed) |
| **Service Endpoint** | `150[.]241[.]65[.]250:889` | Unauthenticated HTTP directory listing | High (observed) |
| **Related Service Endpoint** | `150[.]241[.]65[.]250:67` | Historical HTTP server referenced in `.bash_history` | High (historical) |
| **Related IPv4** | `94[.]154[.]43[.]249` | Historical payload retrieval source | Medium-to-high (historical) |
| **Domain** | `node-32404[.]nodehost[.]ru` | Hostname found in acquired `.Xauthority` strings | Medium (context required) |
| **SHA-256** | `118be4b076806c3d426507fa11cc0fffc40c62be51343aef8e82cc04d91330b6` | Acquired `bot` Linux ELF | High (computed) |
| **SHA-256** | `79aebbbde524f8ec10d232ea48ed3c83068e5f96d8831c7f62820a36688e2550` | Acquired `dropper` Linux ELF | High (computed) |
| **Filename Pattern** | `raul.*` | Architecture-specific payload family listed at root | High (observed) |
| **Filename Pattern** | `pito.*` | Payload family referenced in shell history and related dossier | High (historical/correlated) |
| **Filename** | `bot.i686` | Historical download and execution target | High (historical) |
| **Filename** | `pito.arm7` | Historical download and execution target | High (historical) |
| **Filename** | `pito.x86` | Historical execution target | High (historical) |

### Windows LNK Findings

| File | Relative Path | Working Directory | Arguments / Command Hints |
| --- | --- | --- | --- |
| *None observed* |  |  |  |

### PE Candidates

| Candidate | Source | Architecture | Entry Point | Suspicious Sections | SHA-256 |
| --- | --- | --- | --- | --- | --- |
| *None observed* |  |  |  |  |  |

### Linux ELF Candidates

| Candidate | Source | Architecture | Static observations | SHA-256 |
| --- | --- | --- | --- | --- |
| `bot` | Root-level acquisition | x86-64 | Statically linked; debug information present; not stripped | `118be4b076806c3d426507fa11cc0fffc40c62be51343aef8e82cc04d91330b6` |
| `dropper` | Root-level acquisition | x86-64 | Dynamically linked; anomalous section-header offset reported by file parser; strings include `/proc/self/mountinfo` and Go runtime indicators | `79aebbbde524f8ec10d232ea48ed3c83068e5f96d8831c7f62820a36688e2550` |
| `raul.*` | Root directory listing | Multiple architectures | Listed but not fully acquired in bounded pass | Not available |

## Deep Technical Threat Analysis

### 1. Executive Technical Assessment

The endpoint is best assessed as **high-confidence hostile or malicious staging infrastructure**. The direct evidence is an unauthenticated directory listing containing operational files and multiple architecture-specific binaries, reinforced by shell-history records of payload retrieval and execution.[2]

The evidence supports a staging and distribution role. It does not prove that every file is malicious, that a victim was compromised, or that the service remained active after acquisition.

### 2. Artifact Inventory

| Artifact | Type | Size | SHA-256 | Notes |
| --- | --- | --- | --- | --- |
| `.bash_history` | Shell history | 24,794 bytes | Preserved in acquisition manifest | Contains payload retrieval, execution, listener, and cleanup commands. |
| `.bashrc` | Shell configuration | 3,106 bytes | Preserved in acquisition manifest | Standard configuration observed; retain for timeline analysis. |
| `.lesshst` | History file | 20 bytes | Preserved in acquisition manifest | No substantive command content observed. |
| `.profile` | Shell profile | 161 bytes | Preserved in acquisition manifest | Standard profile content observed. |
| `.Xauthority` | X11 authentication data | 204 bytes | Preserved in acquisition manifest | Contains X11 cookie marker and hostname; treat as sensitive. |
| `bot` | Linux ELF binary | 1,822,880 bytes | `118be4b076806c3d426507fa11cc0fffc40c62be51343aef8e82cc04d91330b6` | x86-64, statically linked, debug information present. |
| `dropper` | Linux ELF binary | 2,097,152 bytes acquired | `79aebbbde524f8ec10d232ea48ed3c83068e5f96d8831c7f62820a36688e2550` | x86-64, dynamically linked; parser reported malformed section-header offset. |
| `raul.*` | Linux ELF payload family | Not acquired | Not available | Fourteen architecture-labelled files listed in root index. |
| `exploit.py`, `test1.py`, `test2.py` | Python scripts | Not acquired | Not available | Listed in root index; require authorized static acquisition. |

### 3. Script Behaviors

#### 3.1 `.bash_history`

The history records the following operational behavior:

| Behavior | Evidence | Assessment |
| --- | --- | --- |
| Temporary HTTP staging | `screen python3 -m http.server 889` and port `67` | Deliberate file-serving activity. |
| Payload retrieval | `wget` and `curl` commands | Ingress tool transfer and staging. |
| Payload execution | `chmod +x` followed by `./pito.arm7`, `./pito.x86`, and `./bot.i686` | Historical execution attempts; success not established. |
| Listener setup | `nc -nlvp 9001` | Possible inbound control or transfer listener; intent unconfirmed. |
| Cleanup | VPS cleaner script | Process killing, temporary-file deletion, and crontab removal capability. |

#### 3.2 VPS Cleaner Script

The shell history contains a script labelled “VPS CLEANER (killer-based ).” Its documented logic scans processes, scores suspicious characteristics, issues `kill -9`, deletes executable or hidden files from `/tmp`, `/var/tmp`, `/dev/shm`, `/mnt`, and `/run`, and removes user crontabs and `/etc/cron.d/*`.[2]

This demonstrates **indicator-removal and defensive-disruption capability**. The current evidence does not establish whether the cleaner was executed, when it was executed, or what systems it affected.

### 4. Network Indicators

| Indicator ID | URL / Endpoint | Associated Evidence |
| --- | --- | --- |
| NI-001 | `hxxp://150[.]241[.]65[.]250:889/` | Direct passive acquisition. |
| NI-002 | `hxxp://150[.]241[.]65[.]250:67/pito.arm7` | Historical command in `.bash_history`. |
| NI-003 | `hxxp://94[.]154[.]43[.]249:233/gg11` | Historical command in `.bash_history`. |
| NI-004 | `hxxp://94[.]154[.]43[.]249:82/BORRARYA.zip` | Historical command in `.bash_history`. |
| NI-005 | `hxxp://94[.]154[.]43[.]249:33/bots/bot.i686` | Historical command in `.bash_history`. |
| NI-006 | `hxxp://94[.]154[.]43[.]249:98/bot` | Historical command in `.bash_history`. |
| NI-007 | `/raul.*` | Architecture-specific files listed in root directory. |
| NI-008 | `node-32404[.]nodehost[.]ru` | Hostname observed in `.Xauthority` strings. |

### 5. Cross-Cluster Correlation

The strongest correlation is with the supplied **Threat Cluster 194[.]238[.]57[.]124** dossier. That dossier documents a `pito.*` multi-architecture payload family, `gg11`, `dp.sh`, the contextual IP `94[.]154[.]43[.]249`, and port `889` staging.[3] The current endpoint independently exposes architecture-specific `raul.*` files and records historical use of `pito.arm7`, `pito.x86`, and `bot.i686`.[2]

| Correlation | Evidence | Confidence |
| --- | --- | --- |
| Shared multi-architecture staging model | `raul.*` root listing and `pito.*` / `bot.i686` history | High |
| Shared related infrastructure | `94[.]154[.]43[.]249` appears in current history and supplied dossier | Medium-to-high |
| Exact ownership or operator identity | No shared credentials, certificates, logs, or account evidence | Not established |
| Relationship to Windows Mythic/Adaptix clusters | No direct current-endpoint artifacts identified | Low / unconfirmed |

### 6. PE and LNK Assessment

No Windows PE candidates or LNK artifacts were identified in the bounded acquisition. The observed payload set is Linux ELF-oriented. This conclusion is limited because the listed Python scripts, `raul.*` files, directory descendants, and `.ssh/` contents were not fully acquired.

### 7. Secrets and Sensitive Material

The public listing exposes `.ssh/`, shell history, and `.Xauthority`. These are sensitive locations even where the acquisition does not reveal a usable private key or token. The `.Xauthority` file contains an X11 cookie marker, and its value is intentionally omitted from this dossier.[2]

If the infrastructure belongs to the organization, all SSH keys, cookies, cloud credentials, API tokens, and credentials appearing in shell history should be treated as compromised and rotated through a trusted administrative path.

### 8. Recommended Defensive Actions

1. Remove public access to the directory while preserving the host and web-server logs.

1. Acquire a forensic image, volatile memory, process/socket state, cron and systemd state, and the complete `.ssh/` directory under controlled evidence handling.

1. Hunt for `raul.*`, `pito.*`, `bot`, `dropper`, `gg11`, `dp.sh`, `wget`, `curl`, `chmod +x`, `screen`, and `nc -nlvp 9001` across Linux, IoT, and edge-device telemetry.

1. Block or monitor `150[.]241[.]65[.]250`, `94[.]154[.]43[.]249`, and the historical service ports after validating business ownership and avoiding disruption to legitimate investigations.

1. Rotate exposed SSH keys, X11 cookies, API tokens, passwords, and cloud credentials.

1. Reverse-engineer `bot`, `dropper`, and the uncollected `raul.*` payloads in an isolated environment; do not execute them on production systems.

1. Review historical authentication, firewall, DNS, proxy, and cloud-provider telemetry for connections to the listed infrastructure.

## Conclusion

The endpoint at `150[.]241[.]65[.]250:889` was publicly exposing an operational Linux staging workspace. The combination of directory exposure, architecture-specific payload names, historical download-and-execute commands, and cleanup tooling indicates a serious infrastructure-security incident and a likely relationship to the supplied multi-architecture `194[.]238[.]57[.]124` cluster.

The evidence supports high-confidence classification as hostile staging infrastructure. It does not independently establish victim compromise, current command-and-control activity, persistence, or attribution to a named threat actor. Those questions require server logs, disk and memory acquisition, network telemetry, and analysis of the uncollected payloads.