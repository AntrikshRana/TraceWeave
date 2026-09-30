# TraceWeave

> **Unified Network Log Normalization & Verification Workspace**

[![Live Demo](https://img.shields.io/badge/Live%20Demo-traceweave.onrender.com-success?style=for-the-badge&logo=render)](https://traceweave.onrender.com)
[![Tests & Verification](https://img.shields.io/github/actions/workflow/status/Ixotic27/TraceWeave/test.yml?branch=main&style=for-the-badge&label=Tests%20Passing)](https://github.com/Ixotic27/TraceWeave/actions/workflows/test.yml)
[![Zero Dependency Runtime](https://img.shields.io/badge/Runtime-Python%20Standard%20Library-blue?style=for-the-badge)](https://www.python.org/)

---

### 🌐 Try the Live Online Workspace
👉 **[https://traceweave.onrender.com](https://traceweave.onrender.com)**

Create an account or sign in to open your private cloud-backed workspace. All records, field mappings, and audit history persist securely to your personal Supabase account. *(Note: Render free instances sleep after inactivity and may take ~30–45 seconds to spin up on first load).*

---

## 💡 What Are We Doing? (The Problem)

Every security team and network engineer faces the same headache: **log format chaos**.

- A **Cisco firewall** outputs logs with `src`, `dst`, and `act`.
- A **Fortinet gateway** uses `srcip`, `dstip`, and `action`.
- A **Palo Alto appliance** exports comma-separated positional fields.
- A **Linux iptables server** outputs kernel syslog key-values (`SRC=... DST=... PROTO=...`).
- A **Cloud WAF** sends nested JSON objects or tab-separated LEEF/CEF attributes.

When these logs reach security analysts, SIEM pipelines (Splunk, Elastic, Microsoft Sentinel), or incident response teams, analysts waste hours writing, maintaining, and debugging brittle regex parsers. Whenever a vendor pushes a firmware upgrade, field names change subtly, breaking the pipeline silently.

**TraceWeave solves this.** We turn chaotic, vendor-specific device logs into clean, unified, cryptographically verified security records—instantly, intelligently, and with human oversight.

---

## 🛠️ What Have We Made? (The Solution)

**TraceWeave** is an end-to-end log ingestion, field normalization, and verification workspace. It works both as a **hosted cloud platform on Render** and as a **100% offline local desktop application** requiring zero external dependencies.

### Key Capabilities

- **Automatic Format & Structure Detection**: Drop any log file or paste raw text. TraceWeave detects record boundaries, parses delimiters, and extracts individual keys and values automatically.
- **AI-Assisted Field Mapping**: Unfamiliar vendor fields are analyzed by our built-in Machine Learning classifier, which suggests their standard security meaning (e.g., predicting that `orig_host` means `src_ip`).
- **Human-in-the-Loop Review**: The AI proposes suggestions, but **you** stay in control. One click confirms or adjusts the field mapping, locking it in as an approved template for that device.
- **Instant Historic Replay**: When you approve a field mapping for a device, all matching logs in your workspace are immediately reprocessed and updated automatically.
- **Drift & Structural Change Alerts**: If a device upgrades its firmware and introduces unexpected fields, TraceWeave flags them as `Format changed` so unvetted data never pollutes your downstream SIEM.
- **Cryptographic Tamper-Proof Audit**: Every log retains its exact original raw bytes. A SHA-256 integrity hash is computed at ingestion, guaranteeing complete chain-of-custody verification.
- **Standardized NDJSON Export**: Export clean, validated records ready for ingestion into any SIEM, data lake, or analytics pipeline.

---

## 🧠 What Is the Machine Learning Model?

TraceWeave includes an embedded, purpose-built **Machine Learning Field Classifier** designed specifically for network security telemetry.

### How It Works

1. **Feature Extraction & Character N-Grams**:
   Rather than relying on exact dictionary matches, the model inspects sub-word character patterns (n-grams) across field keys and sample values. It recognizes structural clues like `ip`, `addr`, `host`, `port`, `proto`, and action keywords (`permit`, `drop`, `deny`, `allow`).
2. **TF-IDF & Logistic Classifier**:
   Extracted features pass through a calibrated multi-class classifier trained across thousands of real-world firewall, router, proxy, and IDS logs.
3. **Probability & Confidence Scoring**:
   The model assigns confidence probabilities to candidate target fields (`src_ip`, `dst_ip`, `action`, `src_port`, `dst_port`, `protocol`, `timestamp`). Only high-confidence matches are presented as suggestions; uncertain fields are left unassigned for manual review.
4. **Zero-API, 100% CPU-Native Inference**:
   The model was trained on GPU using AMD DirectML / PyTorch and exported to pure Python/NumPy weight matrices.
   - ⚡ **Runs in milliseconds directly on CPU**.
   - 🔒 **Zero external API calls**: No data ever leaves your server. No OpenAI or Anthropic API keys required.
   - 💰 **Zero cost**: Completely free to run forever.

*For complete training methodology, metrics, and held-out validation benchmarks, see the [Model Card](docs/MODEL_CARD.md).*

---

## 📂 Supported Formats & File Types

TraceWeave accepts practically any common format generated by firewalls, security gateways, and operating systems:

### 1. File Formats Accepted (up to 2 MB / 2,000 records per upload)
- `.log` — Standard server and firewall output logs
- `.txt` — Exported text files or raw diagnostic dumps
- `.json` — Structured JSON objects
- `.ndjson` / `.jsonl` — Newline-delimited JSON streams
- `.csv` — Delimited tabular logs (header + records)
- `.xml` — Flat XML event records
- **Direct Paste** — Paste raw logs directly into the browser from your clipboard

### 2. Device & Vendor Log Syntaxes Handled
| Format | Example Source / Vendor | Sample Raw Syntax |
| :--- | :--- | :--- |
| **Key-Value Pairs** | Fortinet FortiGate, Linux iptables, Check Point | `src=192.168.1.50 dst=10.0.0.1 action=allow proto=TCP` |
| **Cisco Syslog** | Cisco ASA 5500, Firepower, PIX | `%ASA-6-302013: Built inbound TCP connection ...` |
| **Palo Alto Networks** | PAN-OS Traffic / Threat Logs | `1,2026/09/29,001801...,TRAFFIC,drop,...,192.168.1.10,10.0.0.5...` |
| **CEF (ArcSight)** | Micro Focus ArcSight, Imperva, Trend Micro | `CEF:0\|Vendor\|Product\|Version\|EventID\|Name\|Severity\|src=...` |
| **LEEF (QRadar)** | IBM QRadar, F5 BIG-IP | `LEEF:1.0\|Vendor\|Product\|Version\|EventID\|src=...\|dst=...` |
| **Standard Syslog** | RFC 3164 (BSD) & RFC 5424 (IETF) | `<134>1 2026-09-29T12:00:00Z gateway firewall - - - src=...` |
| **Snort / Suricata** | Open-source NIDS / NIPS | `[**] [1:1000001:1] Alert [**] [Priority: 1] {TCP} 192.168.1.1 -> 10.0.0.1` |
| **Structured JSON** | AWS CloudWatch, Azure Monitor, GCP Cloud Logging | `{"source_ip": "1.2.3.4", "destination_ip": "5.6.7.8", "status": "DENY"}` |

---

## 🔄 Into What Does It Convert?

TraceWeave normalizes all input variations into **NDJSON (Newline Delimited JSON)** adhering to the canonical `traceweave.network/0.1` security schema:

```json
{
  "timestamp": "2026-09-29T12:00:00Z",
  "src_ip": "192.168.1.50",
  "dst_ip": "10.0.0.1",
  "src_port": 54321,
  "dst_port": 443,
  "protocol": "TCP",
  "action": "allow",
  "source": "Office Firewall",
  "status": "normalized",
  "raw_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
}
```

### Why This Output Format Matters:
1. **Universal Compatibility**: NDJSON is directly ingestible by Elasticsearch, OpenSearch, Splunk, ClickHouse, BigQuery, Snowflake, and pandas.
2. **Validated & Type-Enforced**: IP addresses are checked against strict IPv4/IPv6 parsers; port numbers are validated in `[0, 65535]`; actions are canonicalized to `allow`, `deny`, `drop`, or `reject`.
3. **Forensic Integrity**: Each record includes `raw_sha256` matching the original raw log bytes. If ever challenged during an audit, you can prove the transformed log was never tampered with.

---

## 🚀 How to Run Locally (Offline Mode)

You can run the full TraceWeave application locally on your computer with **zero third-party dependencies**—no Docker, no `pip install`, and no internet connection required.

### Quick Start with PowerShell (Windows)

```powershell
.\run.ps1
```

Then open **[http://127.0.0.1:8765](http://127.0.0.1:8765)** in your browser.

### Cross-Platform (macOS / Linux / Windows with Python 3.11+)

```bash
python -m traceweave.server
```

Open **[http://127.0.0.1:8765](http://127.0.0.1:8765)**.

To run a separate isolated workspace on another port:
```bash
python -m traceweave.server --db data/incident-response.sqlite3 --port 8766
```

---

## 🧪 Testing & Verification

TraceWeave comes with a comprehensive test suite covering log parsing, schema normalization, replay mechanics, cryptographic hashing, and hosted security boundaries:

```powershell
python -m unittest discover tests
```

To run the reproducibility benchmark:
```powershell
python scripts/benchmark.py
```

---

## 📚 Deep-Dive Architecture & Documentation

- 🧭 **[Easy Guide & Step-by-Step Walkthrough](docs/EASY_GUIDE.md)**
- 📐 **[System Architecture & Design Decisions](docs/ARCHITECTURE.md)**
- 🤖 **[ML Model Card & Training Methodology](docs/MODEL_CARD.md)**
- ☁️ **[Render & Cloud Hosting Guide](docs/HOSTING.md)**
- 🗄️ **[Supabase Cloud Database Schema & Security](docs/SUPABASE.md)**
- 🔬 **[Verification & Benchmark Report](docs/VERIFICATION.md)**
- 📋 **[Problem Statement & Competitor Analysis](docs/PROBLEM_STATEMENT.md)**

---

## 📄 License & Integrity Notice

TraceWeave is built for SIH 2026. Local data is kept exclusively in your local SQLite database (`data/traceweave.sqlite3`). Hosted data is account-scoped through Supabase Row Level Security. All original log content remains accessible and exportable at all times.
