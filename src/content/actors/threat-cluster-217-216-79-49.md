---
name: "Threat Cluster 217[.]216[.]79[.]49"
aliases: ["217216-8085 Exposed Windows Staging Node","Beacon-Chisel Mixed Staging Cluster"]
status: "active"
origin: "Unknown / exposed Windows and web-oriented staging infrastructure"
motivation: "Exposed staging, C2 and beacon artifact hosting, tunneling or proxy support, credential and system collection, web-facing exploitation testing, and possible post-compromise operator workspace management."
targets: ["Enterprise Windows Workstations and Servers","Internet-Exposed Web and Application Infrastructure","Remote Access and Perimeter Systems","Cloud","Identity","and Authentication Infrastructure"]
firstSeen: "2026-08-26"
lastSeen: "2026-08-26"
tools: ["Beacon-named Windows payloads","Chisel tunneling artifacts","RDP proxy scripts","PowerShell token and registry collection scripts","PHP and ASP.NET request handlers","Java and .NET staging artifacts","SSRF/RFI and application probing utilities","Certificate and key-like material"]
ttps: ["T1071.001 - Application Layer Protocol: Web Protocols","T1090 - Proxy","T1105 - Ingress Tool Transfer","T1219 - Remote Access Software","T1505.003 - Server Software Component: Web Shell","T1552.001 - Credentials In Files","T1190 - Exploit Public-Facing Application"]
tags: ["threat-intelligence","dfir","malware-analysis","windows","c2-infrastructure","exposed-infrastructure","web-exploitation","credential-access"]
relatedPosts: []
featured: true
---

# Threat Cluster 217[.]216[.]79[.]49:8085

> This dossier was generated from passive HTTP observation and static filename correlation. The endpoint was not logged into, exploited, modified, or used to submit data. Listed artifacts were not opened, downloaded, hashed, or executed.

### Evidence Coverage

| Metric | Value |
| --- | --- |
| Root directory listing acquired | 2 captures |
| Unique root-level entries observed | 151 |
| Entries added between captures | 0 |
| Entries removed between captures | 0 |
| Current exposure | Unauthenticated HTTP directory listing |
| Text / configuration artifacts acquired | 0 |
| Windows PE binaries acquired | 0 |
| Linux ELF binaries acquired | 0 |
| Artifact hashes computed from target host | 0 |
| Dynamic execution performed | No |
| Login, exploitation, modification, or submission performed | No |
| Exact listing persistence | Confirmed across two captures |

### Motivation & Objectives

### Strategic Motivation

The host presents a persistent unauthenticated directory containing a heterogeneous collection of Windows, .NET, Java, PowerShell, PHP, ASP.NET, Python, and packaged artifacts. Filename semantics indicate a possible operator workspace or staging directory supporting beacon or C2 material, tunneling and proxying, credential or system collection, and public-facing application testing. These interpretations are triage hypotheses; artifact contents and runtime behavior were not acquired.

### Operational Objectives

- **C2 and Beacon Staging:** Hosting artifacts named `beacon-v8`, `beacon-v9f`, `beacon-v9f-agent`, `beacon-v9g`, `beacon-v9h`, and `beacon-v10`, alongside `wh_beacon.txt`.

- **Tunneling and Remote Access:** Maintaining Chisel-related files and `rdp_proxy.py`, `rdp_proxy2.py`, and `rdp_proxy3.py` for possible relay, pivot, or remote-access support.

- **Credential and System Collection:** Exposing files named `tok_steal.ps1`, `tok2.ps1`, `regsave.ps1`, `regsave.txt`, `recv_hive.php`, and `jwks.json`, which warrant controlled review for token, registry, hive, or authentication-material handling.

- **Web-Facing Collection and Proxying:** Hosting PHP and ASP.NET handlers including `api-proxy.php`, `collect.php`, `recv.php`, `recv_hive.php`, `proxy.php`, `redirect_ssrf.php`, `rfi_check.php`, and `relay.aspx`.

- **Exploit and Reconnaissance Testing:** Exposing `Exploit.class`, `cf_probe/`, `inet_probe.txt`, `probe-callao.txt`, `probe789`, and CORS-labelled proof-of-concept pages.

- **Windows/.NET and Java Payload Staging:** Maintaining `.exe`, `.dll`, `.cs`, `.ps1`, `.war`, `.aspx`, `.pkg`, and `.cab` artifacts in a publicly indexed location.

### Inferred Target Profile

- Enterprise Windows workstations and servers

- Internet-facing web and application infrastructure

- Remote access, RDP, and perimeter systems

- Cloud, identity, token, and authentication services

- Systems exposed to unauthorized payload staging or web-handler access

### Key Operational Findings

- Persistent unauthenticated directory listing on `217[.]216[.]79[.]49:8085`.

- Exactly 151 root entries were present in both the prior and current captures.

- No additions or removals were detected between the two captures.

- Beacon-like artifact families were publicly listed, including `beacon-v8`, `beacon-v9f`, `beacon-v9f-agent`, and `beacon-v10`.

- Chisel tunneling artifacts and multiple RDP proxy scripts were publicly listed.

- PowerShell and server-side files were named for token, registry, hive, proxy, SSRF, RFI, and collection functions.

- Java, .NET, Windows executable, DLL, package, and ASP.NET artifacts were present.

- Certificate/key-like files `sipro4.pem` and `sipro_script.pem` were publicly listed by name.

- The host most closely resembles a Windows-oriented staging node in the broad operational space of the supplied `93[.]152[.]223[.]39` and `101[.]42[.]255[.]92` dossiers.

- No direct hash, URL, certificate, credential, or artifact-content link to the supplied `150[.]241[.]65[.]250` or `194[.]238[.]57[.]124` clusters was established.

- No direct evidence of successful victim compromise, active C2, or execution of the listed artifacts was acquired.

### Credentials, Keys & Tokens (Redacted)

| Risk | Type | Redacted Value | Source / Layer |
| --- | --- | --- | --- |
| **High / Unconfirmed** | Potential private key or certificate material | `[NOT ACQUIRED — sipro4.pem AND sipro_script.pem WERE ONLY OBSERVED BY FILENAME]` | Root directory listing / L0 |
| **High / Unconfirmed** | Potential token or credential collection material | `[NOT ACQUIRED — tok_steal.ps1, tok2.ps1, regsave.ps1, recv_hive.php, AND jwks.json WERE ONLY OBSERVED BY FILENAME]` | Root directory listing / L0 |
| **Medium / Unconfirmed** | Potential authentication, database, or session material | `[NOT ACQUIRED — RELATED .txt, .dat, .json, AND SERVER-SIDE FILES REQUIRE AUTHORIZED REVIEW]` | Root directory listing / L0 |

### Verified Indicators

| Type | Defanged Value / Hash | Context | Confidence |
| --- | --- | --- | --- |
| **Investigated Host** | `217[.]216[.]79[.]49` | User-supplied investigated host | High (observed) |
| **Service Endpoint** | `217[.]216[.]79[.]49:8085` | Persistent unauthenticated HTTP directory listing | High (observed) |
| **HTTP Title** | `Directory listing for /` | Returned by the investigated endpoint | High (observed) |
| **Root Listing Size** | `151` entries | Exact count in prior and current captures | High (computed) |
| **Beacon Filename Pattern** | `beacon-v8`, `beacon-v9f`, `beacon-v9f-agent`, `beacon-v9g`, `beacon-v9h`, `beacon-v10` | Publicly listed root artifacts | High (filename observed) |
| **Tunneling Filename Pattern** | `chisel.exe`, `chisel_v1101.exe`, `chisel_1.10.1_windows_amd64.gz`, `chisel_packed.dat`, `chisel_win.dat` | Publicly listed root artifacts | High (filename observed) |
| **Proxy Filename Pattern** | `rdp_proxy.py`, `rdp_proxy2.py`, `rdp_proxy3.py`, `proxy.php`, `api-proxy.php` | Publicly listed root artifacts | High (filename observed) |
| **Credential/System Collection Pattern** | `tok_steal.ps1`, `tok2.ps1`, `regsave.ps1`, `regsave.txt`, `recv_hive.php`, `jwks.json` | Publicly listed root artifacts | High (filename observed) |
| **Web Handler Pattern** | `collect.php`, `recv.php`, `recv_hive.php`, `redirect_ssrf.php`, `rfi_check.php`, `relay.aspx` | Publicly listed root artifacts | High (filename observed) |
| **Exploit/Probe Pattern** | `Exploit.class`, `cf_probe/`, `inet_probe.txt`, `probe-callao.txt`, `probe789` | Publicly listed root artifacts | High (filename observed) |
| **Key/Certificate Filename Pattern** | `sipro4.pem`, `sipro_script.pem` | Publicly listed root artifacts; contents not acquired | High (filename observed) |
| **Related Cluster** | `150[.]241[.]65[.]250:889` | Supplied dossier describes separate Linux/IoT staging infrastructure | High (user-supplied evidence) |
| **Related Historical Infrastructure** | `94[.]154[.]43[.]249` | Present in supplied 150/194 cluster evidence; not observed on current host | Medium (user-supplied correlation) |

### Windows LNK Findings

| File | Relative Path | Working Directory | Arguments / Command Hints |
| --- | --- | --- | --- |
| *None observed in the directory listing* |  |  |  |

The absence of a visible `.lnk` filename is limited to the root listing. No descendants or file contents were acquired.

### PE Candidates

| Candidate | Source | Architecture | Entry Point | Suspicious Sections | SHA-256 |
| --- | --- | --- | --- | --- | --- |
| `Aplicativo.exe`, `c.exe`, `cs.exe`, `gp.exe`, `hook_fcc4.exe`, `mssync.exe`, `svcdiag.exe`, `tlu.exe`, `update.exe`, `winaux.exe`, and other `.exe` names | Root directory listing | Not determined | Not determined | Not determined | Not available |
| `DnsClient.dll`, `MongoDB.*.dll`, `r.dll`, `SharpCompress.dll`, `System.*.dll`, and other `.dll` names | Root directory listing | Not determined | Not determined | Not determined | Not available |

No PE file was acquired or statically parsed. The entries above are **PE candidates by filename extension only**, not confirmed malicious binaries.

### Deep Technical Threat Analysis

### 1. Executive Technical Assessment

The endpoint is best assessed as **high-priority suspicious exposed infrastructure with a Windows/.NET and web-oriented staging profile**. The direct evidence is a persistent unauthenticated directory listing containing beacon-like filenames, tunneling and proxy artifacts, credential/system-collection-labelled scripts, server-side request handlers, and exploit/probe-labelled files.

The evidence supports a public staging or operator-workspace role, but it does not prove that every file is malicious, that the host is compromised, that the listed files were executed, or that the host is controlled by the same operator as any supplied cluster.

### 2. Artifact Inventory

| Artifact Family | Type | Size | SHA-256 | Notes |
| --- | --- | --- | --- | --- |
| `beacon-v8`, `beacon-v9f`, `beacon-v9f-agent`, `beacon-v9g`, `beacon-v9h`, `beacon-v10` | Unknown executable or payload artifacts | Not acquired | Not available | Names suggest beacon or C2-related staging; framework identity unconfirmed. |
| `chisel.exe`, `chisel_v1101.exe`, `chisel_1.10.1_windows_amd64.gz` | Windows executable/archive candidates | Not acquired | Not available | Names suggest tunneling or relay tooling; behavior unverified. |
| `rdp_proxy.py`, `rdp_proxy2.py`, `rdp_proxy3.py` | Python scripts | Not acquired | Not available | Names suggest RDP proxy or relay functions. |
| `tok_steal.ps1`, `tok2.ps1`, `regsave.ps1` | PowerShell script candidates | Not acquired | Not available | Names suggest token or registry collection; no script content acquired. |
| `collect.php`, `recv.php`, `recv_hive.php`, `proxy.php`, `redirect_ssrf.php`, `rfi_check.php`, `relay.aspx` | Server-side script candidates | Not acquired | Not available | Could support collection, proxying, webshell, SSRF, or RFI testing. |
| `Exploit.class`, `hapi.war` | Java class/archive candidates | Not acquired | Not available | Java-related exploit or application staging is possible but unconfirmed. |
| `sipro4.pem`, `sipro_script.pem` | Certificate/private-key candidates | Not acquired | Not available | Treat as sensitive until contents and ownership are established. |
| `Aplicativo.exe`, `c.exe`, `cs.exe`, `gp.exe`, `hook_fcc4.exe`, `mssync.exe`, `svcdiag.exe`, `tlu.exe`, `update.exe`, `winaux.exe` | Windows PE candidates | Not acquired | Not available | Filename-based candidates only; no static analysis performed. |
| Remaining listed objects | Mixed text, data, package, archive, web, and directory entries | Not acquired | Not available | Root listing contained 151 total entries. |

### 3. Script and Artifact Behaviors

No script or binary content was acquired from the endpoint. The following behaviors are therefore **filename-based analytic hypotheses** rather than verified execution results:

| Behavior | Evidence | Assessment |
| --- | --- | --- |
| Beacon/C2 staging | Multiple `beacon-*` filenames and `wh_beacon.txt` | Possible payload or C2 artifact hosting; framework and activity unconfirmed. |
| Network tunneling | Chisel executable, compressed package, and packed data names | Possible tunneling, pivoting, or relay support; runtime behavior unverified. |
| RDP proxying | `rdp_proxy.py`, `rdp_proxy2.py`, `rdp_proxy3.py` | Possible remote-access relay capability; content not acquired. |
| Credential or token collection | `tok_steal.ps1`, `tok2.ps1`, `regsave.ps1`, `recv_hive.php`, `jwks.json` | Potential credential-access material; no secrets were observed because files were not acquired. |
| Server-side collection or proxying | `collect.php`, `recv.php`, `recv_hive.php`, `api-proxy.php`, `proxy.php` | Potential collection or relay endpoints; no requests were sent to these files. |
| SSRF/RFI or application testing | `redirect_ssrf.php`, `rfi_check.php`, `Exploit.class`, `cf_probe/`, CORS proof-of-concept names | Reconnaissance or testing theme; successful exploitation is not established. |
| Persistent public exposure | Identical 151-entry listings in two captures | Confirmed exposure persistence; no inference about process persistence. |

### 4. Network Indicators

| Indicator ID | URL / Endpoint | Associated Evidence |
| --- | --- | --- |
| NI-001 | `hxxp://217[.]216[.]79[.]49:8085/` | Direct passive acquisition; unauthenticated directory listing. |
| NI-002 | `hxxp://217[.]216[.]79[.]49:8085/beacon-v10` | Filename observed in root listing; artifact not acquired. |
| NI-003 | `hxxp://217[.]216[.]79[.]49:8085/chisel[.]exe` | Filename observed in root listing; artifact not acquired. |
| NI-004 | `hxxp://217[.]216[.]79[.]49:8085/rdp_proxy[.]py` | Filename observed in root listing; artifact not acquired. |
| NI-005 | `hxxp://217[.]216[.]79[.]49:8085/tok_steal[.]ps1` | Filename observed in root listing; artifact not acquired. |
| NI-006 | `hxxp://217[.]216[.]79[.]49:8085/recv_hive[.]php` | Filename observed in root listing; artifact not acquired. |
| NI-007 | `hxxp://217[.]216[.]79[.]49:8085/redirect_ssrf[.]php` | Filename observed in root listing; artifact not acquired. |
| NI-008 | `hxxp://217[.]216[.]79[.]49:8085/sipro4[.]pem` | Filename observed in root listing; contents not acquired. |
| NI-009 | `hxxp://217[.]216[.]79[.]49:8085/sipro_script[.]pem` | Filename observed in root listing; contents not acquired. |
| NI-010 | `hxxp://217[.]216[.]79[.]49:8085/cf_probe/` | Directory observed in root listing; descendants not acquired. |
| NI-011 | `hxxp://217[.]216[.]79[.]49:8085/data/` | Directory observed in root listing; descendants not acquired. |
| NI-012 | `hxxp://217[.]216[.]79[.]49:8085/dl/` | Directory observed in root listing; descendants not acquired. |

No additional remote IP, domain, callback, or C2 endpoint was established from the current host. The related `94[.]154[.]43[.]249` indicator belongs to supplied 150/194 cluster evidence and is not a current-host observation.

### 5. Cross-Cluster Correlation

The current host most closely resembles the supplied Windows-oriented staging context represented by the `93[.]152[.]223[.]39` and `101[.]42[.]255[.]92` dossiers. The overlap consists of beacon/C2 terminology, Windows payload or lure staging, proxying, credential-access themes, and exposure of operational infrastructure. This is thematic correlation only; the current host’s files were not acquired and no shared hashes, URLs, certificates, credentials, or artifact contents were identified.

The supplied `150[.]241[.]65[.]250` dossier documents a separate Linux/IoT staging node with `raul.*` payloads, historical `pito.*` execution, shell history, and a port-889 HTTP service. The current host does not visibly expose `raul.*`, `pito.*`, `bot.i686`, `gg11`, or `dp.sh` names. The relationship between the two hosts is therefore limited to a broad pattern of exposed operational staging infrastructure.

The supplied `194[.]238[.]57[.]124` dossier contains `pito.*`, `gg11`, `dp.sh`, and multi-architecture Linux payload evidence. None of those filename families was observed in the current root listing. No direct technical relationship is established.

| Correlation | Evidence | Confidence |
| --- | --- | --- |
| Shared Windows-oriented staging model with `93[.]152[.]223[.]39` | Beacon, exploit/probe, web-handler, and credential-access naming themes | Medium |
| Shared operational staging model with `150[.]241[.]65[.]250` | Public directory exposure and apparent tool workspace | Low-to-medium |
| Shared Linux multi-architecture payload family with `194[.]238[.]57[.]124` | No `pito.*`, `gg11`, or `dp.sh` names observed on current host | Low / not established |
| Exact ownership or operator identity | No shared hash, URL, certificate, credential, or artifact content | Not established |
| Active C2 relationship | No callback, traffic, execution, or runtime evidence | Not established |

### 6. PE and LNK Assessment

The root listing contains multiple `.exe`, `.dll`, `.cab`, `.pkg`, and related Windows-oriented filenames, but no PE file was downloaded or parsed. They remain **PE candidates by filename extension only**. No `.lnk` filename was observed in the root listing. This conclusion is limited because descendants and file contents were not acquired.

### 7. Secrets and Sensitive Material

The public listing exposes filenames that may represent private keys, certificates, tokens, registry material, authentication data, or collection endpoints. In particular, `sipro4.pem`, `sipro_script.pem`, `jwks.json`, `tok_steal.ps1`, `tok2.ps1`, `regsave.ps1`, and `recv_hive.php` should be treated as sensitive indicators. No actual key, token, password, cookie, or credential value was acquired or reproduced in this dossier.

If the infrastructure belongs to the organization, all credentials, keys, tokens, cookies, and certificates found during authorized acquisition should be rotated through a trusted administrative path, with sessions invalidated and recent use reviewed.

### 8. Recommended Defensive Actions

1. Restrict public access to `217[.]216[.]79[.]49:8085` if the host is organizationally controlled, while preserving web-server, reverse-proxy, firewall, authentication, process, and cloud logs.

1. Preserve a forensic image and volatile state before deleting or modifying individual artifacts; capture directory timestamps, process/socket state, scheduled tasks, services, web-server configuration, and access logs.

1. Hunt endpoint, proxy, DNS, firewall, and identity telemetry for `217[.]216[.]79[.]49`, port `8085`, Chisel process names, RDP proxy activity, beacon-like process trees, PowerShell token or registry access, and requests to the exposed server-side handlers.

1. Treat any private keys, tokens, cookies, database strings, cloud credentials, or authentication material discovered during authorized acquisition as compromised and rotate them.

1. Acquire and statically analyze the smallest authorized set of suspicious scripts, certificate/key files, PE candidates, PHP/ASP.NET handlers, and Chisel-related artifacts; compute SHA-256 hashes and compare them with the supplied cluster evidence.

1. Do not execute acquired binaries or scripts on production systems. Use an isolated analysis environment with no trusted credentials and controlled network access.

1. If the host is not owned by the organization, do not attempt login, exploitation, upload, execution, or bulk acquisition; report the persistent public exposure through the relevant provider, CERT, abuse desk, or authorized incident-response channel.

## Conclusion

The endpoint at `217[.]216[.]79[.]49:8085` continues to expose a persistent unauthenticated directory containing 151 mixed Windows, .NET, Java, PowerShell, PHP, ASP.NET, package, and data entries. The concentration of beacon-like names, Chisel artifacts, RDP proxy scripts, credential/system-collection-labelled files, web handlers, and exploit/probe names supports a **high-priority suspicious exposed-infrastructure** assessment.

The evidence is sufficient to justify containment, preservation, credential review, and targeted threat hunting if the host is organizationally controlled. It is not sufficient to confirm active C2, successful exploitation, victim compromise, maliciousness of every listed artifact, or common ownership with the supplied Linux/IoT `150[.]241[.]65[.]250` and `194[.]238[.]57[.]124` clusters.