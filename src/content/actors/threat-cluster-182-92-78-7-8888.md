---
name: "Threat Cluster 182[.]92[.]78[.]7:8888"
aliases: ["18292-8888 Exposed Linux Pivot and Java Webshell Node","GeoServer-SOCKS-Chisel Staging Cluster"]
status: "active"
origin: "Unknown / exposed Linux staging and post-compromise infrastructure"
motivation: "Webshell-enabled command execution, internal-network discovery through a local SOCKS proxy, database and host reconnaissance, screen and environment collection, dynamic Java payload loading, and tunneling or payload staging."
targets: ["Internet-Exposed Java Web Applications and Servlet Containers","GeoServer and Geospatial Application Infrastructure","Internal SSH","MySQL","and Redis Services","Linux VPS and Cloud-Hosted Application Hosts"]
firstSeen: "2026-08-29"
lastSeen: "2026-08-29"
tools: ["JSP command-execution handlers","Decompiled Java memory-resident webshell payload","Chisel-labelled tunneling artifact","Local SOCKS5 pivot probe","GeoServer REST request-monitor harvesting script","Java/JDK and Kali Linux operational artifacts","Screen-capture and database-query modules"]
ttps: ["T1059.004 - Command and Scripting Interpreter: Unix Shell","T1505.003 - Server Software Component: Web Shell","T1021.004 - Remote Services: SSH","T1046 - Network Service Scanning","T1090 - Proxy","T1105 - Ingress Tool Transfer","T1083 - File and Directory Discovery","T1082 - System Information Discovery","T1057 - Process Discovery","T1113 - Screen Capture","T1213 - Data from Information Repositories","T1552.001 - Credentials In Files"]
tags: ["threat-intelligence","dfir","malware-analysis","linux","java","webshell","pivoting","geoserver","exposed-infrastructure"]
relatedPosts: []
featured: true
---

# Threat Cluster 182[.]92[.]78[.]7:8888

> This dossier was generated from passive HTTP observation and bounded static acquisition. The endpoint was not logged into, exploited, modified, or used to submit data. Exposed command handlers and payloads were not invoked. Acquired artifacts were preserved for analysis and were not executed.

### Evidence Coverage

| Metric | Value |
| --- | --- |
| Root directory listing acquired | 1 |
| Visible root-level entries observed | 29 |
| Selected subdirectory indexes acquired | 3 |
| Text / source artifacts acquired | 10 |
| ELF binaries acquired | 1 |
| ZIP archives acquired | 1 |
| Empty or zero-length artefacts acquired | 2 |
| Artifact hashes computed | 13 |
| Dynamic execution performed | No |
| Login, exploitation, modification, or submission performed | No |
| Recursive acquisition completed | No — bounded collection only |

### Motivation & Objectives

### Strategic Motivation

The host presents a publicly accessible Python `SimpleHTTP/0.6` directory listing containing Linux runtime paths, shell and Python tooling, JSP command handlers, a Chisel-labelled executable, a Java payload, a local SOCKS5 probing utility, GeoServer-related material, SSH temporary material, and a file explicitly named `webshell.jsp`.[1] Static review provides stronger evidence than filename semantics alone: both JSP handlers invoke `Runtime.getRuntime().exec()` on attacker-supplied request parameters, while the Java payload implements dynamic class loading, command execution, host and environment collection, screen capture, file access, and database operations.[2] [3] [4]

These findings support assessment of the endpoint as **high-confidence suspicious infrastructure with probable webshell and pivoting capability**. They do not, by themselves, prove when the handlers were installed, whether an external operator currently controls the host, whether commands were successfully executed, or whether any listed data belonged to victims.

### Operational Objectives

- **Webshell-Based Command Execution:** Exposing `cmd.jsp` and `webshell.jsp`, both of which accept a `cmd` parameter and execute it through the Java runtime.[2] [3]

- **In-Memory Java Payload Loading:** Maintaining a decompiled `basic.payload` class loader that accepts bytecode, defines classes, stores modules in an HTTP-session map, and dispatches methods dynamically.[4]

- **Host and Environment Discovery:** Collecting operating-system properties, local IP addresses, filesystem roots, current user, servlet paths, Java properties, and environment variables.[4]

- **Screen and Data Collection:** Implementing full-screen capture and file-read functionality through Java AWT and filesystem APIs.[4]

- **Database Access:** Supporting JDBC connections to MySQL, Oracle, SQL Server, and PostgreSQL and executing supplied SQL statements.[4]

- **Internal Pivoting and Service Discovery:** Using a local SOCKS5 proxy at `127.0.0.1:1080` to probe internal addresses on SSH, MySQL, and Redis ports.[5]

- **Tunneling and Payload Staging:** Exposing `chx` as a statically linked x86-64 Go executable and `chisel.gz` as an empty file named after the Chisel tunneling utility.[1] [6]

- **GeoServer Credential and Request Collection:** Hosting a script containing the literal credential pair `admin:geoserver` and querying GeoServer monitor request IDs from an external domain.[7]

### Inferred Target Profile

- Internet-facing Java application servers and servlet containers.

- GeoServer deployments and geospatial service backends.

- Linux VPS instances hosting Java, GeoServer, or proxy services.

- Internal SSH, MySQL, and Redis services reachable from a compromised application host.

- Applications and data stores whose credentials or environment variables are available to the Java process.

### Key Operational Findings

- Unauthenticated directory listing on `182[.]92[.]78[.]7:8888` with the title `Directory listing for /`.[1]

- The server identifies as `SimpleHTTP/0.6 Python/3.11.4` and exposes a root containing 29 visible entries.[1]

- `cmd.jsp` and `webshell.jsp` are direct command-execution handlers accepting request parameters.[2] [3]

- `payload.java` is decompiled Java source for a servlet-context-aware, session-persistent dynamic payload loader.[4]

- The payload contains methods for command execution, environment/system discovery, screen capture, file access, class inclusion, and SQL execution.[4]

- `sp.py` performs SOCKS5 negotiation against a local proxy and attempts connections to `192[.]18[.]1[.]1:22`, `192[.]18[.]1[.]2:3306`, and `192[.]18[.]1[.]4:6379`.[5]

- `chx` is an 8,654,848-byte, statically linked x86-64 Go ELF executable; its filename and context suggest tunneling or auxiliary staging, but its runtime behavior was not tested.[6]

- `1.sh` contains hardcoded HTTP Basic credentials `admin:geoserver` and retrieves GeoServer monitor request records from `www.hlxdtdl.com`.[7]

- The host exposes Unix/X11 sockets, systemd-private paths, SSH temporary material, GeoServer-labelled content, and Java installation/update logs, suggesting that the directory may map to an active or recently used Linux workspace.[1]

### Credentials, Keys & Tokens (Redacted)

| Risk | Type | Redacted Value | Source / Layer |
| --- | --- | --- | --- |
| **High / Exposed in Source** | GeoServer HTTP Basic credential | `admin:[REDACTED]` | `1.sh` / L0 acquired source |
| **High / Capability-Based** | Arbitrary OS command execution | `[REQUEST PARAMETER: cmd OR cmdLine]` | `cmd.jsp`, `webshell.jsp`, `payload.java` / L0 acquired source |
| **High / Capability-Based** | Database credentials accepted by payload | `[dbUsername / dbPassword PARAMETERS]` | `payload.java` / L0 acquired source |
| **High / Capability-Based** | Environment variables and Java system properties | `[COLLECTED AT RUNTIME — NOT ACQUIRED]` | `payload.java` / L0 acquired source |
| **Medium / Potentially Sensitive** | GeoServer request history and request bodies | `[REMOTE REQUEST IDS 632815–632914]` | `1.sh` / L0 acquired source |
| **Medium / Potentially Sensitive** | SSH temporary material | `[DIRECTORY OBSERVED; CONTENT NOT ACQUIRED]` | `ssh-b0Lv1r4VfNpp/` / L0 listing |

No private key, password database, session token, or victim data was acquired from the endpoint during this bounded pass. The presence of the named locations and code paths warrants treating any credentials available to the exposed service as potentially compromised until ownership and host integrity are established.

### Verified Indicators

| Type | Defanged Value / Hash | Context | Confidence |
| --- | --- | --- | --- |
| **Investigated Host** | `182[.]92[.]78[.]7` | User-supplied investigated host | High (observed) |
| **Service Endpoint** | `hxxp://182[.]92[.]78[.]7:8888/` | Unauthenticated directory listing | High (observed) |
| **HTTP Server** | `SimpleHTTP/0.6 Python/3.11.4` | Server response header | High (observed) |
| **HTTP Title** | `Directory listing for /` | Returned by endpoint | High (observed) |
| **Command Handler** | `hxxp://182[.]92[.]78[.]7:8888/cmd.jsp` | JSP invokes `Runtime.getRuntime().exec(cmd)` | High (static source) |
| **Webshell Handler** | `hxxp://182[.]92[.]78[.]7:8888/webshell.jsp` | JSP invokes `Runtime.getRuntime().exec(request.getParameter("cmd"))` | High (static source) |
| **Java Payload Source** | `hxxp://182[.]92[.]78[.]7:8888/basic/payload.java` | Decompiled dynamic servlet payload | High (static source) |
| **SOCKS Probe** | `hxxp://182[.]92[.]78[.]7:8888/sp.py` | Local SOCKS5 pivot probe | High (static source) |
| **GeoServer Script** | `hxxp://182[.]92[.]78[.]7:8888/1.sh` | Queries GeoServer monitor API with hardcoded Basic Auth | High (static source) |
| **Tunneling Candidate** | `hxxp://182[.]92[.]78[.]7:8888/chx` | 64-bit statically linked Go ELF | High (file type); medium (purpose) |
| **Tunneling Filename** | `hxxp://182[.]92[.]78[.]7:8888/chisel.gz` | Chisel-labelled file; zero-byte content acquired | High (filename); low (function) |
| **Internal Target** | `192[.]18[.]1[.]1:22` | SOCKS probe target | High (static source) |
| **Internal Target** | `192[.]18[.]1[.]2:3306` | SOCKS probe target | High (static source) |
| **Internal Target** | `192[.]18[.]1[.]4:6379` | SOCKS probe target | High (static source) |
| **External Host** | `www[.]hlxdtdl[.]com` | GeoServer monitor request source in `1.sh` | High (static source); not independently validated |
| **SHA-256** | `75fc431ce030047e6dafc6c5d787ef5d8a4a23c9da3ba8fb239d869d46784dc7` | Acquired `chx` | High (computed) |
| **SHA-256** | `c5b6c33c0b07f827e6cd65176a6c4aa7a4aca2ad10e1d56286ae416b639b89a4` | Acquired `payload.java` | High (computed) |
| **SHA-256** | `d72952242e213853bc04fba44ea7c8cb2ea4bea22eabf07e293543379480853e` | Acquired `cmd.jsp` | High (computed) |
| **SHA-256** | `9f7e13edc3365ee1c06f58e95fbb51077b5bb0556cbd3bb49ac8c8216a1a4901` | Acquired `webshell.jsp` | High (computed) |
| **SHA-256** | `edd9227f6ffbca2a42fb4aaa44afdab9631df9b1ffae71474fa9eeef9ee92430` | Acquired `sp.py` | High (computed) |
| **SHA-256** | `60b93d61103e1163ed935ee4a447a1e2f17a5817cf188b3f5512149e21a3db26` | Acquired `1.sh` | High (computed) |
| **SHA-256** | `8e03090fee16f6e0ee2e436af8e51d0c3deed6d9f0db80dec048e668fc009a48` | Acquired `tmpaddon` ZIP archive | High (computed) |

### Windows LNK Findings

| File | Relative Path | Working Directory | Arguments / Command Hints |
| --- | --- | --- | --- |
| *None observed in the bounded listing or acquisition* |  |  |  |

The absence of a visible LNK file is limited to the acquired root and selected descendants. It does not exclude unlisted or inaccessible content.

### PE Candidates

| Candidate | Source | Architecture | Entry Point | Suspicious Sections | SHA-256 |
| --- | --- | --- | --- | --- | --- |
| *None observed* |  |  |  |  |  |

`chx` is an ELF executable, not a PE. No Windows PE was acquired in the bounded pass.

### Linux ELF Candidates

| Candidate | Source | Architecture | Static observations | SHA-256 |
| --- | --- | --- | --- | --- |
| `chx` | Root-level acquisition | x86-64 | Statically linked Go executable; stripped; Go BuildID present; runtime not executed | `75fc431ce030047e6dafc6c5d787ef5d8a4a23c9da3ba8fb239d869d46784dc7` |

The file name `chx` and co-location with `chisel.gz` are consistent with a tunneling or pivoting theme, but the exact tool identity and behavior remain unconfirmed without safe reverse engineering.

## Deep Technical Threat Analysis

### 1. Executive Technical Assessment

The endpoint at `182[.]92[.]78[.]7:8888` is assessed as **high-confidence suspicious and likely compromised or intentionally operated as a post-compromise Linux staging node**. Unlike a simple exposed directory, this host exposes working command-execution handlers and a Java payload with a broad remote-administration feature set. The local SOCKS probe provides concrete evidence of intended internal-network reachability testing against SSH, MySQL, and Redis services.[2] [3] [4] [5]

The most likely operational role is a **Java application or servlet-container compromise combined with Linux pivoting and data-access activity**. The host may also be an operator workspace or test node rather than a victim server; attribution, persistence, and successful use remain unproven.

### 2. Artifact Inventory

| Artifact | Type | Size | SHA-256 | Notes |
| --- | --- | --- | --- | --- |
| `cmd.jsp` | JSP command handler | 568 bytes | `d72952242e213853bc04fba44ea7c8cb2ea4bea22eabf07e293543379480853e` | Executes `cmd` through Java `Runtime` and returns stdout/stderr. |
| `webshell.jsp` | JSP webshell | 347 bytes | `9f7e13edc3365ee1c06f58e95fbb51077b5bb0556cbd3bb49ac8c8216a1a4901` | Executes request-supplied `cmd` and returns stdout. |
| `payload.java` | Decompiled Java payload | 64,042 bytes | `c5b6c33c0b07f827e6cd65176a6c4aa7a4aca2ad10e1d56286ae416b639b89a4` | Session-backed dynamic loader; command, screen, file, system, environment, and JDBC methods. |
| `sp.py` | Python SOCKS5 probe | 785 bytes | `edd9227f6ffbca2a42fb4aaa44afdab9631df9b1ffae71474fa9eeef9ee92430` | Tests internal SSH, MySQL, and Redis endpoints through `127.0.0.1:1080`. |
| `1.sh` | Shell request-harvesting script | 1,321 bytes | `60b93d61103e1163ed935ee4a447a1e2f17a5817cf188b3f5512149e21a3db26` | Calls GeoServer monitor REST endpoints with hardcoded credentials. |
| `chx` | ELF executable | 8,654,848 bytes | `75fc431ce030047e6dafc6c5d787ef5d8a4a23c9da3ba8fb239d869d46784dc7` | Statically linked x86-64 Go binary; execution and reverse engineering not performed. |
| `chisel.gz` | Gzip-labelled file | 0 bytes | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | Empty despite tunneling-oriented filename. |
| `tmpaddon` | ZIP archive | 511,815 bytes | `8e03090fee16f6e0ee2e436af8e51d0c3deed6d9f0db80dec048e668fc009a48` | Contains `gmpopenh264.info` and `libgmpopenh264.so`; contents not executed or extracted. |
| `payload.java` | Java source | 1,556 lines | Same as above | File is decompiled CFR output and should be treated as source evidence, not proof of runtime deployment. |
| `workspaces.json` | JSON | 0 bytes | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | Empty file in GeoServer-labelled directory. |

The `payload.java` byte count is not reproduced in this dossier because the acquisition record used line-count and hash validation; the hash is the authoritative artifact identifier.

### 3. Script and Payload Behaviors

| Behavior | Evidence | Assessment |
| --- | --- | --- |
| Direct OS command execution | `cmd.jsp`, `webshell.jsp`, and `payload.java` call Java runtime execution APIs | Confirmed capability; execution against the host was not attempted. |
| Dynamic class loading | `include()` calls `defineClass()` on supplied bytecode and stores the resulting class in an HTTP-session map | Strongly supports modular in-memory payload execution. |
| Session persistence | Payload maintains `sessionMap`, `httpSession`, and loaded classes | Supports persistence across requests within an application session; host-level persistence not established. |
| Host discovery | `getBasicsInfo( )` returns OS, architecture, user, paths, properties, local IPs, and environment variables | Confirmed collection capability. |
| Screen capture | `screen()` uses `java.awt.Robot` and writes a PNG image | Confirmed screen-capture capability; no image was collected. |
| File read/write | Payload contains file listing, read, and copy operations | Confirmed file-manipulation capability; no target files were accessed. |
| Database access | `execSql()` supports MySQL, Oracle, SQL Server, and PostgreSQL JDBC drivers | Confirmed database-query capability; no connection was attempted. |
| Internal service probing | `sp.py` negotiates SOCKS5 through localhost and targets ports 22, 3306, and 6379 | Confirmed probe logic; no probe was run. |
| GeoServer request harvesting | `1.sh` loops over request IDs and prints path, query, method, status, service, operation, remote address, user, and body prefix | Confirmed collection logic; the external GeoServer was not queried. |
| Tunneling candidate | `chx` ELF plus `chisel.gz` filename | Suspicious contextual indicator; exact behavior unverified. |

### 4. Network Indicators

| Indicator ID | URL / Endpoint | Associated Evidence |
| --- | --- | --- |
| NI-001 | `hxxp://182[.]92[.]78[.]7:8888/` | Public Python directory listing. |
| NI-002 | `hxxp://182[.]92[.]78[.]7:8888/cmd.jsp` | JSP arbitrary command handler. |
| NI-003 | `hxxp://182[.]92[.]78[.]7:8888/webshell.jsp` | JSP webshell with `cmd` parameter. |
| NI-004 | `hxxp://182[.]92[.]78[.]7:8888/basic/payload.java` | Dynamic Java payload source. |
| NI-005 | `hxxp://182[.]92[.]78[.]7:8888/sp.py` | Local SOCKS5 internal-service probe. |
| NI-006 | `hxxp://182[.]92[.]78[.]7:8888/1.sh` | GeoServer request-monitor harvesting script. |
| NI-007 | `hxxp://182[.]92[.]78[.]7:8888/chx` | Acquired x86-64 ELF candidate. |
| NI-008 | `hxxp://182[.]92[.]78[.]7:8888/chisel.gz` | Empty Chisel-labelled object. |
| NI-009 | `hxxp://www[.]hlxdtdl[.]com/geoserver/rest/monitor/requests/` | External GeoServer API base path embedded in `1.sh`; not contacted. |
| NI-010 | `192[.]18[.]1[.]1:22` | Internal SSH target encoded in `sp.py`. |
| NI-011 | `192[.]18[.]1[.]2:3306` | Internal MySQL target encoded in `sp.py`. |
| NI-012 | `192[.]18[.]1[.]4:6379` | Internal Redis target encoded in `sp.py`. |
| NI-013 | `127[.]0[.]0[.]1:1080` | Local SOCKS5 proxy endpoint encoded in `sp.py`. |

No live C2 callback, victim IP, authentication token, or successful internal connection was established from this bounded acquisition.

### 5. Cross-Cluster Correlation

The strongest relationship is **tradecraft-level overlap** with the supplied `217[.]216[.]79[.]49:8085` cluster: both expose Chisel-labelled tunneling material, web-facing handlers, and Windows/Linux-adjacent staging artifacts. The current endpoint differs in that it presents concrete Java webshell and Linux pivot evidence rather than primarily filename-based indicators.[1] [8]

A secondary relationship exists with the supplied `93[.]152[.]223[.]39:8089` cluster through web exploitation, exposed server-side code, credential-oriented collection, and C2/staging themes. However, the current endpoint contains no directly observed shared hash, certificate, wallet, domain ownership, or payload family.[9]

The supplied `150[.]241[.]65[.]250:889` and `2[.]27[.]63[.]244:9999` clusters show broader staging and operator-workspace similarities, but no direct current-host indicator links were established.[10] [11]

| Correlation | Evidence | Confidence |
| --- | --- | --- |
| Shared tunneling/staging tradecraft with `217[.]216[.]79[.]49` | Chisel-labelled artifacts and exposed server-side handlers | Medium |
| Shared web exploitation / credential-access theme with `93[.]152[.]223[.]39` | Webshell-style code, server-side collection, exposed keys/credential capability | Medium |
| Shared Linux staging model with `150[.]241[.]65[.]250` | Linux workspace artefacts and operational scripts | Low-to-medium |
| Shared operator identity | No shared hashes, certificates, credentials, or exact payload family | Not established |
| Direct malware-family attribution | No C2 configuration or runtime telemetry acquired | Not established |

### 6. Secrets and Sensitive Material

The most important exposure is not a recovered secret value but **service-side access capability**. The JSP handlers and Java payload could expose files, process output, environment variables, screen data, servlet context, and database contents if reachable in a live servlet-container context.[2] [3] [4] The literal `admin:geoserver` credential in `1.sh` should be treated as compromised if it was valid for any owned GeoServer deployment.[7]

The publicly indexed `ssh-b0Lv1r4VfNpp/` directory and the host’s Unix/X11 runtime paths are sensitive locations. Their presence does not prove that private keys, active sockets, or usable session material were downloadable, because descendants were not fully acquired.

### 7. Recommended Defensive Actions

1. Remove unauthenticated public access to port `8888` while preserving web-server, servlet-container, authentication, process, firewall, and network-flow logs.

1. Treat the host as potentially compromised. Isolate it from production networks using an approved containment procedure, preserving volatile state before eradication where operationally safe.

1. Acquire a forensic image, process and socket state, memory, cron/systemd state, Java/Tomcat/Jetty configuration, deployed web applications, web-access logs, and the complete exposed directory under controlled evidence handling.

1. Search application and proxy logs for requests to `cmd.jsp`, `webshell.jsp`, `payload.java`, `sp.py`, `chx`, and requests containing `cmd`, `cmdLine`, `evalClassName`, `methodName`, `binCode`, `dbHost`, or `execSql` parameters.

1. Hunt for outbound or proxied connections from the affected host to internal ports `22`, `3306`, and `6379`, especially through local SOCKS listeners on `127.0.0.1:1080`.

1. Rotate or revoke the GeoServer credential represented by `admin:geoserver` after validating ownership, and review GeoServer monitor logs for request IDs in the range `632815–632914` and for access from the exposed host or related infrastructure.

1. Rotate credentials available to the Java process, including database passwords, cloud tokens, SSH keys, application secrets, and environment-based credentials. Do this through a trusted administrative path rather than through the exposed service.

1. Reverse-engineer `chx` and inspect `tmpaddon` in an isolated analysis environment. Do not execute either artifact on production systems; preserve originals and work from copies.

1. Review the supplied `217[.]216[.]79[.]49`, `93[.]152[.]223[.]39`, `150[.]241[.]65[.]250`, and `2[.]27[.]63[.]244` indicators in enterprise telemetry for temporal or infrastructure overlap, while treating correlation as unconfirmed unless shared content-level evidence is found.

1. Examine the Java deployment path for unauthorized JSPs, session attributes, class-loading hooks, scheduled tasks, shell history, SSH keys, and persistence mechanisms. Rebuild the host from trusted media if integrity cannot be established.

## Conclusion

The endpoint at `182[.]92[.]78[.]7:8888` is not merely an exposed file repository. Passive acquisition confirmed two JSP command-execution handlers, a modular Java payload with broad post-compromise capabilities, an internal SOCKS5 service-probing utility, GeoServer request-harvesting logic, and a Chisel-labelled ELF candidate.[1] [2] [3] [4] [5] The host should therefore be prioritized as **probable compromised or deliberately operated post-compromise infrastructure**.

The evidence supports high-priority containment and forensic preservation. It does not establish attribution, successful victim access, current operator control, or the runtime execution of any artifact. All artifacts in this assessment were handled as untrusted evidence and were not executed.