# Detection Engineering & Validation Pipeline

## 1. The Vision: "Evidence-Based Detection"
In modern SOC environments, "Hope" is not a strategy. Writing rules without testing them against real attack data leads to False Negatives and Alert Fatigue.

This repository implements a **Telemetry Replay Architecture** that treats detection logic as code. By leveraging **Infrastructure-as-Code (IaC)** principles, I validate every detection rule against immutable, high-fidelity attack datasets (OTRF/Mordor) before they ever touch a production sensor.

### 🔭 The Framework
* **Methodology:** Telemetry Replay (Offline Validation).
* **Engine:** Azure Data Explorer (ADX) / Kusto Emulator.
* **Data Source:** [OTRF Security Datasets](https://github.com/OTRF/Security-Datasets) (Empire, Atomic Red Team, Cobalt Strike).
* **Schema Standard:** Microsoft Defender for Endpoint (MDE).

---

## 2. Architecture: The "Schema Bridge"
A core challenge in Detection Engineering is the schema mismatch between open-source datasets (often Sysmon) and enterprise EDRs (CrowdStrike/MDE).

To solve this, I architected a **KQL Schema Bridge** that dynamically ingests raw JSON telemetry, parses the Sysmon event structure, and normalizes it into the `DeviceProcessEvents` schema used by Microsoft Sentinel and CrowdStrike Raptor.

### The Data Flow
1.  **Ingest:** Pull raw JSON attack data from a "Golden Artifact" repository (Self-Hosted Gist).
2.  **Normalize:** Map `Image` $\to$ `FileName`, `ParentImage` $\to$ `InitiatingProcessFileName`.
3.  **Execute:** Run Composite Risk Scoring logic against the normalized memory stream.
4.  **Verify:** Confirm the **Risk Score** exceeds the Critical Threshold (50+).

---

## 3. Standard Operating Procedures (SOP)
*How we maintain the integrity of the validation pipeline.*

### SOP-01: Artifact Supply Chain
We do not rely on volatile upstream URLs. All datasets are validated and hosted internally to ensure pipeline resilience.
1.  **Acquire:** Download validated PCAP/JSON from OTRF Security Datasets.
2.  **Sanitize:** Bypass "Mark of the Web" via secure local environments (`Lab_Data` exclusions).
3.  **Slice:** Extract relevant event frames (First ~5k events) to optimize ingestion performance.
4.  **Host:** Upload to the internal "Golden Artifacts" Gist/Repo for stable raw access.

### SOP-02: The Validation Loop
Every rule in this portfolio must pass the **"True Positive"** test:
1.  Load the `Schema Bridge` with the target attack dataset (e.g., `Empire_WMI_Lateral_Movement`).
2.  Inject the candidate KQL/LQL logic.
3.  **PASS CRITERIA:**
    * Logic returns > 0 results.
    * **Risk Score** is calculated correctly (e.g., Logic correctly identifies `WMI Spawning PowerShell`).
    * No False Positives observed in the dataset window.

---

## 4. The Code: KQL Schema Bridge
*This logic allows any Sysmon-based dataset to be replayed as MDE telemetry.*

```kql
// ============================================================================
// THE MORDOR SCHEMA BRIDGE (Sysmon -> MDE)
// Author: Ala Dabat
// Purpose: Normalizes external datasets for Risk Rule Validation
// ============================================================================
let MordorData = externaldata(RawData:dynamic)
[
    // Pointer to "Golden Artifact" (Hosted Gist)
    @"[https://gist.githubusercontent.com/adabat/hunting-lab/raw/wmi_lateral_sample.json](https://gist.githubusercontent.com/adabat/hunting-lab/raw/wmi_lateral_sample.json)"
]
with(format="json");

let DeviceProcessEvents = 
    MordorData
    | extend EventID = toint(RawData.EventID)
    | where EventID == 1 // Filter for Process Creation
    | extend 
        Timestamp = todatetime(RawData.TimeCreated),
        DeviceName = tostring(RawData.Computer),
        // Normalization: Sysmon Image -> MDE FileName
        FileName = tostring(split(RawData.Image, "\\")[-1]),
        FolderPath = tostring(RawData.Image),
        ProcessCommandLine = tostring(RawData.CommandLine),
        // Normalization: Sysmon ParentImage -> MDE InitiatingProcess
        InitiatingProcessFileName = tostring(split(RawData.ParentImage, "\\")[-1]),
        InitiatingProcessFolderPath = tostring(RawData.ParentImage),
        InitiatingProcessCommandLine = tostring(RawData.ParentCommandLine),
        InitiatingProcessId = toint(RawData.ParentProcessId),
        ProcessId = toint(RawData.ProcessId)
    | project Timestamp, DeviceName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessId, ProcessId;

// [INSERT COMPOSITE RULE LOGIC BELOW FOR VALIDATION]

```
