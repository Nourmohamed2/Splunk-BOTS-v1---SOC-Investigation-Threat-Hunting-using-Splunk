# 🔍 Splunk BOTS v1 — SOC Investigation & Threat Hunting Lab

> **Boss of the SOC (BOTS) v1** is a real-world blue team challenge developed by Splunk. This lab documents a full SOC investigation of a web defacement attack and APT intrusion against Wayne Enterprises, using Splunk as the primary SIEM platform.

---

## 📌 Lab Overview

| Field | Details |
|---|---|
| **Platform** | Splunk Enterprise (BOTSv1 Dataset) |
| **Scenario** | Web defacement + APT intrusion (Po1s0n1vy group) |
| **Target** | `imreallynotbatman.com` — Wayne Enterprises CEO blog |
| **Log Sources** | Suricata IDS, Sysmon, Windows Event Logs, FortiGate Firewall, stream:http |
| **Framework** | MITRE ATT&CK |

---

## 🎯 Objectives

- Identify the attacker's IP address and tools used for reconnaissance
- Trace the full attack chain from scanning to defacement
- Detect brute-force login attempts and identify compromised credentials
- Analyze uploaded malware and extract forensic indicators (MD5, SHA256)
- Map all attacker behavior to MITRE ATT&CK TTPs

---

## 🔗 Attack Chain Summary

```
Reconnaissance → Initial Access → Delivery → Installation → Actions on Objective
```

| Phase | Details | MITRE TTP |
|---|---|---|
| **Reconnaissance** | `40.80.148.42` scanned the site using **Acunetix** vulnerability scanner | T1595.002 — Vulnerability Scanning |
| **Brute Force** | `23.22.63.114` attempted 412 passwords against Joomla admin panel | T1110.001 — Password Guessing |
| **Initial Access** | Correct admin password `batman` found; login within 92.17 seconds | T1078 — Valid Accounts |
| **Delivery** | Malicious JPEG downloaded from `prankglassinebracket.jumpingcrab.com` via Dynamic DNS | T1105, T1568 |
| **Installation** | `3791.exe` uploaded and executed (confirmed via Sysmon EventCode 1) | T1059, T1547 |
| **Spear Phishing** | Secondary malware `MirandaTateScreensaver.scr.exe` linked to APT infrastructure | T1566.001 |
| **Actions on Objective** | Site defaced with `poisonivy-is-coming-for-you-batman.jpeg` | — |

---

## 🧩 Key Findings

### Threat Actor Infrastructure
| IOC | Type | Notes |
|---|---|---|
| `40.80.148.42` | IP | Acunetix scanner — reconnaissance |
| `23.22.63.114` | IP | Brute-force attacker |
| `prankglassinebracket.jumpingcrab.com` | FQDN | Dynamic DNS — malware delivery (port 1337) |
| `po1s0n1vy.com` | Domain | APT group infrastructure |

### Malware Indicators
| File | Hash Type | Value |
|---|---|---|
| `3791.exe` | MD5 | `AAE3F5A29935E6ABCC2C2754D12A9AF0` |
| `MirandaTateScreensaver.scr.exe` | SHA256 | `9709473ab351387aab9e816eff3910b9f28a7a70202e250ed46dba8f820f34a8` |

### Brute-Force Statistics
- **Total unique passwords attempted:** 412
- **First password tried:** `12345678`
- **Correct admin password:** `batman`
- **Average password length:** 6 characters
- **Time between discovery and compromise:** 92.17 seconds

---

## 🛠️ Tools & Technologies Used

| Tool | Purpose |
|---|---|
| **Splunk Enterprise** | Primary SIEM — log search, correlation, SPL queries |
| **Suricata IDS** | Network intrusion detection — file and traffic alerts |
| **Sysmon (EventCode 1)** | Process creation detection — confirmed malware execution |
| **Windows Event Logs** | Authentication and system activity analysis |
| **FortiGate Firewall** | Identified malicious domain category (`Malicious Websites`) |
| **VirusTotal** | Hash verification — identified trojan/cryptz malware family |
| **ThreatMiner** | Pivoted from IP `23.22.63.114` to associated malware hashes |
| **stream:http** | HTTP POST log analysis for brute-force and file upload detection |

---

## 🔎 Key SPL Queries

### Identify Scanning IP
```spl
imreallynotbatman.com
| stats count by src_ip
| sort -count
```

### Detect Brute-Force Attempts
```spl
index=botsv1 sourcetype="stream:http" http_method=POST form_data="*username*passwd*"
| rex field=form_data "passwd=(?<Password>[^&\r\n]+)"
| table _time src dest host uri form_data password user_agent status
| sort - _time
```

### Find Unique Passwords Used
```spl
index=botsv1 sourcetype="stream:http" http_method=POST form_data="*username*passwd*"
| rex field=form_data "passwd=(?<Password>[^&\s]+)"
| stats count values(src) by Password
| sort count
```

### Average Password Length
```spl
index=botsv1 sourcetype="stream:http" http_method=POST form_data="*username*passwd*"
| rex field=form_data "passwd=(?<Password>[^&\s]+)"
| search Password=*
| eval mylen=len(Password)
| stats avg(mylen) as avg_len_http
| eval avg_len_http=round(avg_len_http,0)
```

### Time Between Discovery and Compromise
```spl
index=botsv1 sourcetype=stream:http
| rex field=form_data "passwd=(?<Password>\w+)"
| search Password=batman
| transaction Password
| table duration
```

### Detect Malicious Domain via FortiGate
```spl
index="botsv1" sourcetype=fgt_utm category="Malicious Websites"
```

### Confirm Malware Execution via Sysmon
```spl
index=botsv1 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1 3791.exe
```

---

## 🗺️ MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Reconnaissance | Vulnerability Scanning | T1595.002 |
| Credential Access | Brute Force — Password Guessing | T1110.001 |
| Defense Evasion | Valid Accounts | T1078 |
| Command & Control | Dynamic Resolution | T1568 |
| Lateral Movement | Ingress Tool Transfer | T1105 |
| Initial Access | Spearphishing Attachment | T1566.001 |
| Execution | Command and Scripting Interpreter | T1059 |
| Persistence | Boot or Logon Autostart Execution | T1547 |

---

## 📁 Questions Solved

| # | Question | Answer |
|---|---|---|
| 101 | Scanning IP from Po1s0n1vy group | `40.80.148.42` |
| 102 | Vulnerability scanner used | Acunetix |
| 103 | CMS running on target | Joomla |
| 104 | Defacement file name | `poisonivy-is-coming-for-you-batman.jpeg` |
| 105 | Malicious FQDN (Dynamic DNS) | `prankglassinebracket.jumpingcrab.com` |
| 106 | Pre-staged attack IP | `23.22.63.114` |
| 108 | Brute-force source IP | `23.22.63.114` |
| 109 | Uploaded malicious executable | `3791.exe` |
| 110 | MD5 hash of executable | `AAE3F5A29935E6ABCC2C2754D12A9AF0` |
| 111 | SHA256 of spear-phishing malware | `9709473ab351387aab9e816eff3910b9f28a7a70202e250ed46dba8f820f34a8` |
| 112 | Special hex code in malware | (found via VirusTotal community) |
| 114 | First brute-force password | `12345678` |
| 115 | Coldplay song password (6 chars) | `yellow` |
| 116 | Correct admin password | `batman` |
| 117 | Average password length | `6` |
| 118 | Seconds to compromised login | `92.17` |
| 119 | Total unique passwords attempted | `412` |

---

## 📚 References

- [Splunk BOTS v1 — Official Dataset](https://github.com/splunk/botsv1)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [VirusTotal](https://www.virustotal.com/)
- [ThreatMiner](https://www.threatminer.org/)
- [Acunetix Web Vulnerability Scanner](https://www.acunetix.com/)
