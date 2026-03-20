# LOLLATERAL

> **Living Off the Land — Lateral Movement Complete Reference**  
> MITRE ATT&CK TA0008 · All techniques, APT intelligence, detection rules, telemetry & D3FEND countermeasures

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![ATT&CK Version](https://img.shields.io/badge/ATT%26CK-v16-red)](https://attack.mitre.org/tactics/TA0008/)
[![D3FEND](https://img.shields.io/badge/D3FEND-mapped-teal)](https://d3fend.mitre.org)
[![Single File](https://img.shields.io/badge/deployment-single%20HTML-blue)]()

---

##  Overview

**LOLLATERAL** is a single-file, offline-capable interactive reference for MITRE ATT&CK **TA0008 Lateral Movement**. It is inspired by [LOLEXFIL](https://lolexfil.github.io/), [LOLBAS](https://lolbas-project.github.io/), and [LOLC2](https://lolc2.github.io/), extending the "Living Off the Land" reference format to cover every lateral movement technique with:

- Red team simulation commands
- APT threat actor intelligence with DFIR report links
- Threat intelligence source mapping (GreyNoise, Shodan, VirusTotal, MISP, etc.)
- Detection rules from SigmaHQ, Elastic, Splunk, Microsoft Sentinel, MITRE CAR
- Telemetry source mapping (Event IDs, Sysmon, CloudTrail, auditd, EDR)
- Interactive D3FEND defensive technique diagrams per ATT&CK technique

**No server, no dependencies, no internet required.** Open `lollateral.html` in any modern browser.

---

##  Quick Start

```bash
git clone https://github.com/lolmitre/lollateral.git
cd lollateral
open lollateral.html        # macOS
xdg-open lollateral.html    # Linux
start lollateral.html       # Windows
```
---

## Coverage

| Category | Count |
|---|---|
| Lateral Movement Techniques | **38** unique techniques |
| ATT&CK (Sub-)Technique IDs | **49** mapped IDs |
| APT / Threat Actor Entries | **146** across all techniques |
| Detection Patterns | **220+** telemetry-merged patterns |
| SigmaHQ Detection Rules | **27** direct search links |
| Elastic Detection Rules | **34** direct search links |
| Splunk ESCU Analytics | **33** direct search links |
| Microsoft Sentinel KQL | **10** detection links |
| MITRE CAR Analytics | **9** analytics linked |
| D3FEND Countermeasure Maps | **49** techniques mapped |
| Threat Intelligence Sources | **37** MISP Galaxy + GreyNoise/Shodan/OTX |

---

## Techniques Covered

### Remote Services
`T1021.001` RDP · `T1021.002` SMB/Admin Shares · `T1021.003` DCOM · `T1021.004` SSH · `T1021.005` VNC · `T1021.006` WinRM · `T1021.007` Cloud Services · `T1021.008` Direct Cloud VM

### Credential & Token Abuse
`T1550.001` App Access Token · `T1550.002` Pass-the-Hash · `T1550.003` Pass-the-Ticket · `T1550.004` Web Session Cookie · `T1134.001/002` Token Impersonation

### Kerberos Attacks
`T1558.001` Golden Ticket · `T1558.002` Silver Ticket · `T1558.003` Kerberoasting · `T1558.004` AS-REP Roasting · `T1550.002+overpass` Overpass-the-Hash · Kerberos Delegation Abuse · Kerbrute

### Session Hijacking
`T1563.001` SSH Hijacking · `T1563.002` RDP Session Hijacking

### Credential Harvesting
`T1003.006` DCSync · Mimikatz · LAPS Abuse · ACL/ACE Abuse

### LOLBin Execution
PsExec · WMI Remote Exec · Remote Scheduled Tasks · Process Injection · dcomexec/smbexec

### Protocol Abuse & Tooling
CrackMapExec · Impacket Suite · BloodHound/SharpHound · NTLM Relay/Responder · MSSQL Linked Servers · Cobalt Strike · Sliver/Havoc/Metasploit · Chisel/Ligolo Pivoting

### Exploitation
`T1210` Remote Service Exploitation · PrintNightmare (CVE-2021-1675) · Zerologon (CVE-2020-1472)

### Supply Chain & Persistence-Adjacent
GPO Abuse · SCCM/Software Deployment Tools · Taint Shared Content

### Phishing & Transfer
Internal Spearphishing · Lateral Tool Transfer · Removable Media

---

##  Features

### Interactive Card Interface
- **Expand/collapse** individual cards or all at once
- **Search** across technique names, IDs, APT group names, tools, platforms
- **Filter** by platform (Windows/Linux/macOS/Cloud/Cross-platform)
- **Filter** by category (Remote Services, Kerberos, LOLBin, etc.)
- **Filter by APT group** — dropdown with all 140+ threat actor entries
- **Filter by origin nation** — Russia, China, Iran, North Korea, Criminal, etc.
- **Filter by target sector** — Healthcare, Government, Financial, etc.
- Active filter chips displayed with one-click removal

### Per-Technique Data
Each card contains:

1. **Simulation Command** — ready-to-run red team commands (tools: Mimikatz, Impacket, CrackMapExec, Rubeus, evil-winrm, etc.)
2. **Simulation References** — Atomic Red Team link, MITRE ATT&CK page, D3FEND link
3. **IOC Artifacts** — file paths, registry keys, event IDs, process names, network indicators
4. **APT / Threat Actor Intelligence** — actor name, alias, origin nation, active period, target sectors, victim organizations, DFIR reports (CISA advisories, DOJ indictments, vendor reports)
5. **Threat Intelligence Sources** — GreyNoise tags, Shodan queries, OTX pulses, MISP galaxy links, VirusTotal hunts, Microsoft TI
6. **Detection Rules** — linked rules from SigmaHQ, Elastic, Splunk, Sentinel, MITRE CAR
7. **Telemetry + Detection Patterns** — merged table: log source → event IDs → detection context → severity
8. **D3FEND Defensive Technique Map** — interactive SVG diagram showing applicable D3FEND countermeasures for the technique's artifact type (UserAccount / NetworkTraffic / ProcessImage / KerberosTicket)

### D3FEND Diagrams
Four artifact-mapped interactive diagrams (expand per-card):
- **UserAccount** — credential/token abuse techniques (9 D3FEND techniques, 5 tactics)
- **NetworkTraffic** — network lateral movement (8 D3FEND techniques, 4 tactics)
- **ProcessImage** — LOLBin/process injection (7 D3FEND techniques, 4 tactics)
- **KerberosTicket** — Kerberos attacks (6 D3FEND techniques, 3 tactics)

Nodes are colour-coded by tactic (Eviction/Hardening/Detection/Restore/Policy), hover for descriptions, click to open D3FEND.

---

##  Architecture

```
lollateral.html          ← Single self-contained file (266 KB)
│
├── CSS                  ← Dark theme, IBM Plex Sans + Fira Code fonts
│
└── JavaScript
    ├── const tools[]       ← 38 technique objects (simulation, detections, IOCs)
    ├── const telData{}     ← Telemetry source mappings per technique
    ├── const extData{}     ← APT intel, TI sources, detection rule links
    ├── const aptExtra{}    ← APT enrichment (timeline, victims, DFIR reports, countries)
    ├── const D3G           ← D3FEND grid layout constants
    ├── const d3Diagrams{}  ← 4 interactive defensive technique diagrams
    ├── const d3TechMap{}   ← Technique → diagram type mapping
    ├── buildSections()     ← Renders APT table, TI, rules, teldetect, D3FEND
    ├── buildD3fendDiagram()← Generates responsive SVG diagram
    ├── render()            ← Main render with multi-filter logic
    └── Filter engine       ← APT/nation/sector multi-select dropdowns
```

---

##  Customization

### Adding a Technique

Add an object to the `tools` array:

```javascript
{
  id: "T1234.001",
  name: "My Technique",
  category: "Remote Services",   // see catBadgeMap for valid values
  platform: "Windows",
  desc: "Technique description.",
  attck: ["T1234.001"],
  signed: true,
  refs: 5,
  sim: `# simulation commands here`,
  detections: [
    {type: "EventLog", text: "Event 4624 ...", sev: "high"}
  ],
  iocs: [
    {type: "Port", val: "TCP 445"}
  ]
}
```

### Adding APT Intelligence

Add to `extData["T1234.001"]`:

```javascript
"T1234.001": {
  apt: [
    {
      name: "APT28 (Fancy Bear)", alias: "G0007", nation: "Russia 🇷🇺",
      sectors: "Government, Military",
      campaigns: "Campaign description",
      ref: "https://attack.mitre.org/groups/G0007/"
    }
  ],
  ti:    [ {src: "GreyNoise", text: "Description", link: "https://..."} ],
  rules: [ {src: "SigmaHQ", name: "Rule Name", link: "https://...", note: "Note"} ]
}
```

### Adding Telemetry

Add to `telData["T1234.001"]`:

```javascript
"T1234.001": [
  {src: "Windows Security Log", ids: "4624, 4625", note: "Detection context"}
]
```

---

##  Data Sources

| Source | Usage |
|---|---|
| [MITRE ATT&CK](https://attack.mitre.org/tactics/TA0008/) | Technique definitions, APT group procedures |
| [MITRE D3FEND](https://d3fend.mitre.org/) | Defensive countermeasure mapping |
| [MITRE CAR](https://car.mitre.org/) | Cyber Analytics Repository |
| [SigmaHQ](https://github.com/SigmaHQ/sigma) | Detection rule library |
| [Elastic Detection Rules](https://github.com/elastic/detection-rules) | SIEM detection content |
| [Splunk Security Content](https://github.com/splunk/security_content) | ESCU analytics |
| [Azure Sentinel](https://github.com/Azure/Azure-Sentinel) | KQL detection rules |
| [MISP Galaxy](https://www.misp-galaxy.org/) | Threat intel sharing |
| [GreyNoise](https://viz.greynoise.io/) | Internet-scale scanning intel |
| [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) | Simulation references |
| CISA Advisories | APT DFIR reports and IOCs |
| Mandiant / CrowdStrike / Microsoft MSTIC | APT campaign reports |

---

##  Related Projects

- [LOLEXFIL](https://lolexfil.github.io/) — Data exfiltration techniques reference
- [LOLBAS](https://lolbas-project.github.io/) — Living Off The Land Binaries
- [LOLC2](https://lolc2.github.io/) — C2 frameworks reference
- [GTFOBins](https://gtfobins.github.io/) — Unix binary exploitation
- [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) — ATT&CK coverage mapping

---

##  Disclaimer

This tool is intended for **authorized security testing, red team operations, detection engineering, and defensive research** only. All simulation commands and techniques documented here should only be used in environments where you have explicit written authorization. The authors assume no liability for misuse.

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

*Built with ❤️ for detection engineers, threat hunters, red teamers, and SOC analysts.*
