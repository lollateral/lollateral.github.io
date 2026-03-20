# LOLLATERAL — Technical Documentation

## Table of Contents

1. [What is LOLLATERAL?](#1-what-is-lollateral)
2. [Architecture & Data Model](#2-architecture--data-model)
3. [Core Functions Reference](#3-core-functions-reference)
4. [Card Sections Explained](#4-card-sections-explained)
5. [Filter System](#5-filter-system)
6. [D3FEND Diagram System](#6-d3fend-diagram-system)
7. [Detection & Telemetry Merge Engine](#7-detection--telemetry-merge-engine)
8. [APT Intelligence System](#8-apt-intelligence-system)
9. [Link Conventions](#9-link-conventions)
10. [Usage Examples](#10-usage-examples)
11. [Extending LOLLATERAL](#11-extending-lollateral)
12. [Design Decisions](#12-design-decisions)

---

## 1. What is LOLLATERAL?

LOLLATERAL is a self-contained HTML reference page for **MITRE ATT&CK TA0008 — Lateral Movement**. It bridges four disciplines in a single interface:

| Audience | Value |
|---|---|
| **Red Teamers** | Copy-paste simulation commands, know what indicators you'll leave |
| **Detection Engineers** | Pre-linked Sigma/Elastic/Splunk rules, telemetry sources, event IDs |
| **Threat Hunters** | APT actor intelligence, campaign context, IOC artifacts |
| **SOC Analysts** | D3FEND countermeasure maps, severity-labelled detection patterns |
| **Threat Intel Analysts** | Per-technique APT timelines, DFIR report links, target country mapping |

The guiding principle: **one technique, one card, everything you need**.

---

## 2. Architecture & Data Model

The file is structured as: `HTML/CSS → <script>` with five data layers followed by the rendering engine.

### Data Layer Stack

```
Layer 1  const tools[]       — Technique definitions
Layer 2  const telData{}     — Telemetry sources per technique
Layer 3  const extData{}     — External intel (APT, TI, rules)
Layer 4  const aptExtra{}    — APT enrichment (timeline, victims, DFIR)
Layer 5  const d3Diagrams{}  — D3FEND SVG diagram definitions
         const d3TechMap{}   — Technique → diagram mapping
```

### `tools` Object Schema

```javascript
{
  id:         string,     // Primary ID used as key across all data layers
  name:       string,     // Display name
  category:   string,     // One of: Remote Services, Credential Abuse, Session
                          //   Hijacking, LOLBin, Protocol Abuse, Exploitation,
                          //   Phishing, Replication, Cloud, Tool Transfer,
                          //   Supply Chain, Kerberos
  platform:   string,     // Comma-separated: Windows,Linux,macOS,Cloud,Cross-platform
  desc:       string,     // Full technique description
  attck:      string[],   // ATT&CK technique IDs (may include parent + sub)
  signed:     boolean,    // Whether primary binary is Microsoft-signed
  refs:       number,     // Approximate reference count (informational)
  sim:        string,     // Simulation commands (template literal, multi-line)
  detections: [{          // Detection patterns array
    type:  string,        // Log source type key (EventLog, Network, EDR, etc.)
    text:  string,        // Detection description
    sev:   string         // critical | high | med | low
  }],
  iocs: [{                // IOC artifacts array
    type:  string,        // IOC category (Port, EventID, Process, File, etc.)
    val:   string         // IOC value or description
  }]
}
```

### `extData` Object Schema

```javascript
{
  [technique_id]: {
    apt: [{
      name:      string,  // Actor display name with common alias
      alias:     string,  // ATT&CK Group ID (G0007) or label
      nation:    string,  // Country + emoji flag
      sectors:   string,  // Target sector list
      campaigns: string,  // Campaign/operation descriptions
      ref:       string   // URL to ATT&CK group page
    }],
    ti: [{
      src:  string,       // TI platform name (GreyNoise, Shodan, etc.)
      text: string,       // Description of the intel value
      link: string        // Direct URL to relevant search/tag/pulse
    }],
    rules: [{
      src:  string,       // Rule source (SigmaHQ, Elastic, Splunk, Sentinel, CAR, D3FEND)
      name: string,       // Rule/analytic name
      link: string,       // Direct URL to rule or search
      note: string        // Brief context note
    }]
  }
}
```

### `aptExtra` Object Schema

Keyed by ATT&CK Group ID (`G0007`, `G0016`, etc.):

```javascript
{
  [group_id]: {
    first_seen:       string,    // Year active since (e.g. "2004")
    last_seen:        string,    // Last confirmed year (e.g. "2024")
    targets:          string,    // Victim organization descriptions
    postmortem:       [{         // DFIR reports and advisories
      name: string,              // Report/advisory name
      url:  string               // Direct URL
    }],
    target_countries: string[]   // List of targeted country names
  }
}
```

### `telData` Object Schema

```javascript
{
  [technique_id]: [{
    src:  string,   // Log source (Windows Security Log, Sysmon, CloudTrail, etc.)
    ids:  string,   // Event IDs or identifiers (4624, 4625, TCP 445)
    note: string,   // Detection context / hunting pivot description
    sev?: string    // Optional: critical | high | med | low
  }]
}
```

---

## 3. Core Functions Reference

### `render()`
Main render function. Reads filter state, applies all active filters, sorts results, updates stats bar, and builds the card HTML list.

```
Filters applied (in order):
  1. Text search  — id + name + desc + platform + category + attck[] + APT names
  2. Platform     — exact match against tool.platform CSV
  3. Category     — exact match against tool.category
  4. APT filter   — any APT name in extData[t.id].apt matches selectedApts
  5. Nation filter — any APT nation in extData[t.id].apt matches selectedNations
  6. Sector filter — any APT sector substring matches selectedSectors
```

### `buildSections(t)`
Renders all intel sections for a technique card. Called once per visible card during render. Returns HTML string. Sections rendered (if data present):

1. **APT Intelligence table** — 7-column table with timeline, victims, DFIR links, target countries
2. **Intel Grid** — 2-column: Threat Intelligence Sources | Detection Rules
3. **Telemetry + Detection table** — merged, deduplicated, severity-ranked
4. **D3FEND Countermeasures** — D3FEND-sourced rules rendered as detect/harden rows
5. **D3FEND Diagram** — calls `buildD3fendDiagram(t.id)`

### `buildD3fendDiagram(techId)`
Looks up `d3TechMap[techId]` → diagram type → `d3Diagrams[type]`. Generates a unique instance ID (`d3vN`), builds SVG from slot coordinates, renders connector paths, artifact center node, colour-coded technique nodes. Returns the full toggle wrapper HTML. Returns `''` if no mapping exists.

### `toggleD3Viz(uid)`
Toggles open/closed state of a D3FEND diagram by toggling CSS classes on the toggle button and body div.

### `toggleFilter(type, val)`
Adds or removes a value from `selectedApts`, `selectedNations`, or `selectedSectors`. Calls `renderActiveTags()` and `render()`.

### `renderActiveTags()`
Rebuilds the active filter chip bar. Each chip is a `<span>` that calls `toggleFilter()` on click.

### `buildAptDropdown()` / `buildMsDropdown(type)`
Rebuild dropdown option lists from `extData` APT entries, filtered by the search input value. Options are marked `.sel` if currently selected.

---

## 4. Card Sections Explained

### Header (always visible)
- Technique name + ATT&CK ID
- Truncated description (130 chars)
- Platform badges (colour-coded)
- Category badge
- ATT&CK ID links (clickable, open MITRE page)
- Signed/unsigned indicator
- Detection count badge
- APT group count badge (if > 0)
- Chevron toggle

### Body (expanded)

**Simulation Command** (left column)
Monospace code block with multi-line commands. Covers: native Windows/Linux tools, common attacker frameworks (Impacket, CrackMapExec, Mimikatz, Rubeus, evil-winrm, etc.), and variations (password, hash, kerberos).

**Simulation References + IOC Artifacts** (right column)
Top: direct links to Atomic Red Team test file, MITRE ATT&CK page, D3FEND countermeasures.
Below: IOC table with type (Port, EventID, File, Process, Registry, etc.) and value.

**APT / Threat Actor Intelligence**
7-column table:
- **Actor** — name + ATT&CK alias + activity timeline bar (▶ first ⬛ last)
- **Nation** — origin country with flag emoji
- **Active** — `YYYY–YYYY` span
- **Target Sectors & Victims** — sector list + italic victim org names
- **Campaigns & DFIR Reports** — campaign description + purple badges linking to CISA advisories, DOJ indictments, Mandiant/CrowdStrike reports
- **Target Countries** — blue chip list
- **Ref** — ATT&CK group page link

**Threat Intelligence Sources** (left of Intel Grid)
Each row: `TI Platform` → linked description pointing to the relevant search, tag, or pulse.

**Detection Rules** (right of Intel Grid)
Each row: `[SOURCE BADGE]` → rule name (linked) → short note.
Source badge colours: SigmaHQ=purple, Elastic=blue, Splunk=amber, Sentinel=green, CAR=pink, D3FEND=teal.

**Required Telemetry Sources and Detection Patterns**
Merged table from both `telData[id]` and `tool.detections[]`. Grouped by normalised source key, deduplicates notes, shows highest severity per source group.
Columns: Source | Event IDs / Identifiers | Detection Pattern | Sev

**D3FEND Countermeasures**
D3FEND-sourced rules rendered as typed rows (detect=blue / harden=teal). Each links to the D3FEND technique page.

**D3FEND Diagram** (collapsible)
Toggle reveals artifact-specific SVG diagram. See Section 6.

---

## 5. Filter System

### Text Search
Searches: `id + name + desc + platform + category + attck[].join(' ') + APT names from extData`

Examples:
- `mimikatz` — finds all techniques where Mimikatz appears
- `T1558` — finds all Kerberos sub-techniques
- `APT29` — finds all techniques where APT29 is listed
- `golden ticket` — description match
- `russia` — matches APT nation field via description or name

### APT Group Dropdown
Multi-select. Populated from all `extData[*].apt[].name` values. Shows check mark for selected. Technique matches if **any** of its APT entries includes the selected name (substring match both ways).

### Nation Dropdown
Populated from `extData[*].apt[].nation`. Matches techniques with **any** APT from that nation. Useful for: `Russia 🇷🇺`, `China 🇨🇳`, `North Korea 🇰🇵`, `Iran 🇮🇷`, `Criminal`.

### Sector Dropdown
Populated from all APT `sectors` field values (comma-split). Matches techniques where **any** APT targets that sector. Examples: `Healthcare`, `Government`, `Financial`, `Energy`, `Defense`.

### Combining Filters
All filters are AND-combined. Text + APT + Nation simultaneously narrows to exact intersection.

### Active Tag Chips
All selected filters appear as coloured chips below the controls bar:
- Purple chips = APT group filters
- Blue chips = Nation filters
- Teal chips = Sector filters

Click any chip to remove that filter.

---

## 6. D3FEND Diagram System

### Grid Layout
All diagrams use the `D3G` constant for collision-free grid layout:

```javascript
const D3G = {
  NW: 150,          // Node width
  NH: 62,           // Node height
  C: [10, 178, 346], // Column X positions (3 columns)
  R: [14, 100, 186, 272, 358], // Row Y positions (5 rows)
  VBW: 506          // SVG viewBox width
}
```

Nodes are placed at grid slots `{ci: 0-2, ri: 0-4}`. The central artifact always occupies `{ci:1, ri:1}`. Extra bottom-row nodes use explicit `x` positions for centred layouts.

### Node Colour Classes
| Class | Colour | D3FEND Tactic |
|---|---|---|
| `d3n-evict` | Red `#f87171` | Credential Eviction / Network Isolation (Evict) |
| `d3n-harden` | Amber `#fbbf24` | Credential Hardening / Platform Hardening |
| `d3n-detect` | Blue `#60a5fa` | User Behavior Analysis / Traffic Analysis / Process Analysis |
| `d3n-model` | Purple `#a78bfa` | Access Policy / Network Isolation / Execution Isolation |
| `d3n-restore` | Green `#86efac` | Restore Access |
| `d3n-art` | Indigo `#818cf8` | Digital Artifact (center node) |

### Connector Paths
Connectors are computed at render time from node center coordinates to artifact center. The algorithm picks the nearest facing edge (horizontal vs vertical dominant) and adds a slight quadratic Bézier curve for readability.

### Technique-to-Diagram Mapping (`d3TechMap`)
| Diagram Type | Mapped Techniques |
|---|---|
| `userAccount` | PtH, PtT, token impersonation, DCSync, LAPS, ACL abuse, GPO abuse, BloodHound, cookie theft, session hijacking |
| `networkTraffic` | All RDP/SMB/SSH/WinRM/DCOM/Cloud, NTLM relay, CME, Impacket, pivoting tools, Cobalt Strike, internal phishing |
| `processImage` | PsExec, WMI, schtasks, process injection, PrintNightmare, Zerologon, dcomexec/smbexec, SCCM, taint shared content |
| `kerberosTicket` | Golden/Silver ticket, Kerberoasting, AS-REP roasting, overpass-the-hash, delegation abuse, Kerbrute |

---

## 7. Detection & Telemetry Merge Engine

The `buildSections()` function merges `telData[id]` and `tool.detections[]` into a single table using source normalisation.

### Source Normalisation (`normSrc`)
Maps raw source strings to canonical keys:

| Input variations | Canonical key |
|---|---|
| `Windows Security Log`, `EventLog`, `event log` | `WS-LOG` |
| `Sysmon` | `Sysmon` |
| `Sysmon for Linux` | `SysmonLinux` |
| `Linux Auditd`, `auditd`, `linux` | `Auditd` |
| `CloudTrail`, `cloudtrail`, `aws` | `CloudTrail` |
| `Azure AD`, `azuread` | `AzureAD` |
| `EDR` | `EDR` |
| `Network`, `Firewall`, `network` | `Network` |
| `UEBA`, `ueba`, `honeypot` | `UEBA` |

### Merge Logic
1. `telData` entries populate groups first (establishing order)
2. `detections[]` entries are looked up by their `type` field via `detTypeKey()`
3. If the detection's source key matches an existing group: the detection text is added to notes **only if** its first word isn't already present (deduplication)
4. If no matching group: a new orphan row is created

### Deduplication
Notes within each group are deduplicated on first-45-chars normalised key. The final `mergedNote` joins surviving notes with ` · `.

### Severity
Each group tracks the **maximum** severity seen across all telemetry and detection entries. Final value: `critical` > `high` > `med` > `low`.

---

## 8. APT Intelligence System

### Data Flow

```
extData[technique_id].apt[]
    ↓ alias (G0007, G0016, etc.)
aptExtra[alias]
    → first_seen, last_seen  → "Active" column + timeline bar
    → targets                → "Target Sectors & Victims" bottom text
    → postmortem[]           → "Campaigns & DFIR Reports" purple links
    → target_countries[]     → "Target Countries" blue chips
```

### DFIR Report Links
`postmortem` entries link directly to:
- CISA Advisories (`www.cisa.gov/news-events/cybersecurity-advisories/...`)
- DOJ Press Releases (`www.justice.gov/...`)
- Mandiant Blog Posts (`www.mandiant.com/resources/blog/...`)
- Microsoft MSRC / Security Blog
- CrowdStrike Blog
- NCSC Advisories
- FBI Flash Alerts

### Non-G alias handling
Entries with `alias: "Criminal"`, `"Various"`, or `"Multiple"` resolve to generic `aptExtra` entries that show `—` for timeline and empty countries/postmortem.

---

## 9. Link Conventions

All external links in `extData` rules follow working URL patterns:

| Source | URL Pattern |
|---|---|
| SigmaHQ | `https://github.com/SigmaHQ/sigma/search?q=KEYWORD&type=code` |
| Elastic | `https://github.com/elastic/detection-rules/search?q=KEYWORD&type=code` |
| Splunk | `https://github.com/splunk/security_content/search?q=KEYWORD&type=code` |
| Sentinel | `https://github.com/Azure/Azure-Sentinel/blob/master/Detections/...` |
| MITRE CAR | `https://car.mitre.org/analytics/CAR-YYYY-MM-NNN/` |
| D3FEND | `https://d3fend.mitre.org/offensive-technique/attack/TXXXX.XXX/` |
| MISP Galaxy | `https://www.misp-galaxy.org/mitre-attack-pattern/` |
| ATT&CK Group | `https://attack.mitre.org/groups/GXXXX/` |
| ATT&CK Technique | `https://attack.mitre.org/techniques/TXXXX/XXX/` |

> **Note on rule links**: SigmaHQ, Elastic, and Splunk links point to **search results** rather than specific files. This ensures links remain valid as repos evolve. Search for the rule name to find the current file.

---

## 10. Usage Examples

### Example 1: Hunt Prep for Pass-the-Hash Campaign

1. Open `lollateral.html`
2. Search: `pass the hash` or `T1550.002`
3. Expand the **Pass the Hash (PtH)** card
4. In **APT Intelligence**: see APT28, APT38, Wizard Spider, FIN6 with CISA advisory links
5. In **Telemetry + Detection Patterns**: note `Event 4624 LogonType 3 NtLmSsp` → build SIEM rule
6. Click **SigmaHQ** rule link → copy rule to your SIEM
7. In **D3FEND Diagram**: expand → see **UserAccount** defensive map → click `D3-CDP` (Change Default Password) for hardening guidance

---

### Example 2: Filter to Russian APT Techniques

1. Click the **"Filter APT group..."** dropdown
2. Type `APT28` → select it
3. Purple chip appears: `APT28 (Fancy Bear) ×`
4. Results narrow to all techniques where APT28 is documented
5. Add **Nation** filter: `Russia 🇷🇺` → now shows ALL Russian-attributed techniques
6. Cross-reference with your organisation's industry sector using the **Sector** filter

---

### Example 3: Detection Engineering for Kerberos Attacks

1. Filter by **Category**: `Kerberos`
2. Expand **Kerberoasting (T1558.003)**
3. In **Detection Rules**: click the SigmaHQ link → `win_security_kerberoasting.yml`
4. In **Telemetry**: note `Event 4769 etype 23 (RC4)` bulk from single source
5. In **D3FEND Diagram**: expand → `KerberosTicket` diagram → note `D3-AES` (Strong Cryptographic Algorithm) → click to open D3FEND for implementation guidance
6. Repeat for T1558.001 (Golden Ticket), T1558.004 (AS-REP Roasting), T1550.002+overpass

---

### Example 4: Red Team Pre-Op Checklist

1. Expand all cards: click **"Expand all"**
2. Use browser's Ctrl+F to find specific tool names (e.g., `evil-winrm`)
3. For each planned technique, review **IOC Artifacts** to understand what traces you'll leave
4. Check **Signed** badge — `signed` techniques (mstsc, schtasks, wmic) blend better than `unsigned`
5. Review **Simulation References** → Atomic Red Team link to run detection validation tests

---

### Example 5: Cloud Incident Response

1. Filter **Platform**: `Cloud`
2. Three cloud techniques shown: T1021.007, T1021.008, T1550.001
3. For **Application Access Token (T1550.001)**:
   - **APT**: Midnight Blizzard (2023 Microsoft breach), Scattered Spider (MGM 2023)
   - **DFIR Reports**: Click CISA AA24-057a, Microsoft MSRC blog links
   - **Telemetry**: CloudTrail `AssumeRoleWithWebIdentity`, Azure AD sign-in logs
   - **TI**: Microsoft TI blog for AiTM phishing IOCs, AlienVault OTX OAuth pulses

---

### Example 6: SOC Alert Triage — "WMI Execution" Alert

1. Search: `WMI`
2. Find **WMI Remote Execution** card
3. In **APT Intelligence**: APT29, APT32, APT41, FIN7, MuddyWater — assess threat actor fit
4. In **Telemetry**: confirm you have `WMI Activity Log (Evt 5857, 5861)` enabled
5. In **Detection Patterns**: look for `wmiprvse.exe spawning cmd.exe` — is this your alert?
6. Check **IOC Artifacts**: `wmiprvse.exe + child spawn` — correlate with your endpoint telemetry

---

## 11. Extending LOLLATERAL

### Adding a New Technique

**Step 1**: Add to `tools[]` array (follow the schema in Section 2).

**Step 2**: Add to `extData{}`:
```javascript
"YOUR_ID": {
  apt:   [ /* APT entries */ ],
  ti:    [ /* TI sources */ ],
  rules: [ /* detection rule links */ ]
}
```

**Step 3**: Add to `telData{}`:
```javascript
"YOUR_ID": [
  {src: "Windows Security Log", ids: "4624", note: "LogonType X anomaly", sev: "high"}
]
```

**Step 4**: Add `aptExtra` entries for any new Group IDs not already present.

**Step 5**: Map to a D3FEND diagram in `d3TechMap`:
```javascript
"YOUR_ID": "userAccount"  // or networkTraffic / processImage / kerberosTicket
```

### Adding a New D3FEND Diagram Type

1. Add a new entry to `d3Diagrams{}` with `label`, `artifact`, `stats`, `slots[]`, `extra[]`
2. Add the new type key to `D3_TACTIC_COLORS` for legend rendering
3. Map techniques to it in `d3TechMap{}`

---

## 12. Design Decisions

**Why a single HTML file?**  
Zero friction deployment. No server, no build pipeline, no npm. Share via email, USB, or GitHub Pages. Works on air-gapped networks.

**Why inline SVG for D3FEND diagrams?**  
SVG scales perfectly on any screen size and doesn't require a D3.js dependency. Grid-based layout (D3G) eliminates collision detection complexity while keeping diagrams readable.

**Why merge telemetry and detection patterns?**  
Telemetry data (`telData`) says *what to collect*. Detection data (`tool.detections[]`) says *what to look for*. Merging them by source gives a single actionable table: "Collect X from source Y, look for pattern Z."

**Why GitHub search links instead of direct file links?**  
Detection rule repositories change directory structures frequently. GitHub search links are stable and always return current results. Searching `SigmaHQ/sigma` for `kerberoasting` will always find the current rule, even if it's been moved or renamed.

**Why no frameworks (Vue, React, etc.)?**  
A cybersecurity reference tool must be auditable. No CDN dependencies, no external JS, no hidden network calls. Everything visible in the source.
