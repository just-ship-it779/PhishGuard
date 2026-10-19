# 🛡️ PhishGuard — Malicious URL Checker

A web-based cybersecurity tool that analyses URLs for phishing and suspicious indicators using rule-based heuristic detection. Built with Python and Streamlit.

> ⚠️ **Disclaimer:** PhishGuard is a heuristic assessment tool based on URL structure only. It does **not** visit, fetch, or render the submitted URL. A low score does not guarantee a URL is safe. A high score does not guarantee it is malicious. For educational use and initial triage only.

---

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Project Structure](#project-structure)
- [Technology Stack](#technology-stack)
- [Installation](#installation)
- [How to Run](#how-to-run)
- [How to Use](#how-to-use)
- [Optional: Threat Intelligence APIs](#optional-threat-intelligence-apis)
- [Running the Tests](#running-the-tests)
- [Detection Rules](#detection-rules)
- [Risk Scoring](#risk-scoring)
- [Known Limitations](#known-limitations)

---

## Overview

PhishGuard analyses the **structure** of a URL to identify characteristics commonly associated with phishing attacks — such as raw IP addresses as hostnames, misleading credentials syntax, suspicious keywords, deep subdomain nesting, and more.

It produces:
- A **risk score** from 0 to 100
- A **risk category**: Low / Moderate / High / Critical
- A **list of findings** explaining exactly what was detected and why it matters
- A **URL structure breakdown** showing every parsed component
- Downloadable **CSV and Markdown reports**

The application **never opens or visits the submitted URL** at any point.

---

## Features

| Feature | Description |
|---|---|
| 🔍 Single URL Analysis | Analyse any URL with a full breakdown of findings |
| 📋 Bulk CSV Analysis | Upload a CSV file to analyse multiple URLs at once |
| 🕒 Session History | View and export all URLs analysed in the current session |
| 📊 Risk Score | Transparent 0–100 score with 4 risk categories |
| 🧩 10 Detection Rules | Named, weighted rules covering the most common phishing URL patterns |
| 🌐 Threat Intelligence | Optional Google Safe Browsing and VirusTotal lookups (requires API key) |
| ⬇️ Report Export | Download results as CSV or Markdown report |
| 🔒 Secure by Design | Never visits URLs, blocks dangerous schemes, no persistent storage |

---

## Project Structure

```
phishguard/
│
├── app.py                      ← Main Streamlit application (run this)
├── requirements.txt            ← Python dependencies
├── README.md                   ← This file
│
├── src/                        ← Analysis engine modules
│   ├── __init__.py
│   ├── validators.py           ← Input validation and URL normalisation
│   ├── url_parser.py           ← Structural URL parsing
│   ├── feature_extractor.py    ← Security feature derivation
│   ├── detection_rules.py      ← 10 named detection rules
│   ├── risk_scoring.py         ← Risk score calculation [0–100]
│   ├── threat_intelligence.py  ← Optional Google Safe Browsing / VirusTotal
│   ├── analysis_engine.py      ← Pipeline orchestrator
│   └── report_generator.py     ← CSV and Markdown report generation
│
├── data/
│   └── sample_urls.csv         ← Sample URLs for testing bulk analysis
│
└── tests/                      ← Automated tests (126 tests, all passing)
    ├── test_validators.py
    ├── test_url_parser.py
    ├── test_feature_extractor.py
    ├── test_detection_rules.py
    ├── test_risk_scoring.py
    ├── test_analysis_engine.py
    └── test_report_generator.py
```

---

## Technology Stack

| Package | Version | Purpose |
|---|---|---|
| Python | 3.11+ | Core language |
| Streamlit | ≥1.35 | Web interface |
| pandas | ≥2.0 | Bulk CSV processing |
| requests | ≥2.28 | Optional TI API calls |
| tldextract | ≥5.0 | Public Suffix List domain parsing |
| python-dotenv | ≥1.0 | API key management |
| pytest | ≥9.0 | Automated testing |

---

## Installation

### Step 1 — Make sure Python is installed

```bash
python --version
```

If Python is not installed, download it from [python.org](https://www.python.org/downloads/). During installation, check **"Add Python to PATH"**.

### Step 2 — Install dependencies

Navigate to the project folder and run:

```bash
pip install -r requirements.txt
```

Or install manually:

```bash
pip install streamlit pandas requests tldextract python-dotenv pytest
```

---

## How to Run

From inside the project folder:

```bash
streamlit run app.py
```

The app will open automatically in your browser at `http://localhost:8501`.

---

## How to Use

### Single URL Analysis

1. Open the **🔍 Single URL Analysis** tab.
2. Type or paste a URL into the input field.
3. Click **Analyse URL**.
4. View the risk score, category, findings, and URL breakdown.
5. Download the CSV or Markdown report using the buttons at the bottom.

### Bulk Analysis

1. Open the **📋 Bulk Analysis** tab.
2. Prepare a CSV file with a column named `url`. Example:

```csv
url
https://example.com
http://192.0.2.1/login
bit.ly/abc123
```

3. Click **Browse files** and upload your CSV.
4. View the summary metrics and results table.
5. Filter by risk category and download the full report.

You can download the included `sample_urls.csv` from the **Expected CSV format** section in the app to try it out immediately.

### Session History

The **🕒 Session History** tab shows all URLs analysed during the current session. Use **Clear History** to reset it. History is never saved to disk — it disappears when you close the browser tab.

---

## Optional: Threat Intelligence APIs

PhishGuard works fully in offline mode without any API keys. To enable optional threat intelligence lookups:

### 1. Get free API keys

- **Google Safe Browsing:** [console.cloud.google.com](https://console.cloud.google.com) → Enable the Safe Browsing API → Create an API key
- **VirusTotal:** [virustotal.com/gui/join-us](https://www.virustotal.com/gui/join-us) → Register for a free account → Get your API key

### 2. Set environment variables

**Windows (Command Prompt):**
```cmd
set GOOGLE_SAFE_BROWSING_API_KEY=your_key_here
set VIRUSTOTAL_API_KEY=your_key_here
streamlit run app.py
```

**Windows (PowerShell):**
```powershell
$env:GOOGLE_SAFE_BROWSING_API_KEY="your_key_here"
$env:VIRUSTOTAL_API_KEY="your_key_here"
streamlit run app.py
```

**Or create a `.env` file** in the project folder:
```
GOOGLE_SAFE_BROWSING_API_KEY=your_key_here
VIRUSTOTAL_API_KEY=your_key_here
```

> 🔒 **Privacy:** When TI lookups are enabled, the submitted URL is sent to Google and/or VirusTotal. The app shows a privacy notice and requires you to tick a checkbox before any URL is sent externally.

---

## Running the Tests

```bash
python -m pytest tests/ -v
```

Expected output:
```
126 passed in 0.51s
```

All external API calls are mocked in tests — no real network requests are made and no API keys are needed to run the test suite.

---

## Detection Rules

| Rule ID | Name | Severity | Weight | What it detects |
|---|---|---|---|---|
| URL001 | IP-Address Hostname | High | 20 | Hostname is a raw IPv4 or IPv6 address |
| URL002 | HTTP Instead of HTTPS | Medium | 10 | URL uses unencrypted HTTP scheme |
| URL003 | Misleading User-Info Syntax | High | 25 | `trusted@evil.com` credential deception |
| URL004 | Unusually Long URL | Low | 5 | URL exceeds 75 characters |
| URL005 | Suspicious Keyword Pattern | Low | 8 | Keywords like login, verify, password |
| URL006 | Unusual Subdomain Depth | Medium | 12 | Three or more subdomain labels |
| URL007 | Internationalized Domain Name | Medium | 12 | Non-ASCII or Punycode (xn--) hostname |
| URL008 | Nonstandard Port | Low | 6 | Port other than 80 (HTTP) or 443 (HTTPS) |
| URL009 | Known URL-Shortening Service | Low | 7 | bit.ly, tinyurl.com, t.co, etc. |
| URL010 | Excessive Percent-Encoding | Low | 6 | Five or more `%XX` encoded sequences |

---

## Risk Scoring

The risk score is calculated as:

```
raw_score = sum of all triggered rule weights
score     = round(raw_score / 104 × 100), capped at 100
```

| Score Range | Category |
|---|---|
| 0 – 24 | 🟢 Low |
| 25 – 49 | 🟡 Moderate |
| 50 – 74 | 🔴 High |
| 75 – 100 | 🟣 Critical |

A confirmed malicious result from a threat-intelligence provider overrides the category to **Critical** and raises the score to at least 90, regardless of the heuristic findings.

---

## Known Limitations

- **Keywords cause false positives** — Words like "login" appear in many legitimate URLs (e.g. `github.com/login`). The keyword rule is weighted low to reduce its impact.
- **Shortened URLs** — The destination of `bit.ly` or `tinyurl.com` links cannot be assessed without following the redirect, which the app intentionally avoids.
- **No domain-age check** — Newly registered domains are a strong phishing signal but require WHOIS lookups (not implemented).
- **No TLS certificate inspection** — HTTPS protects the connection but does not prove a site is legitimate. Certificate details are not checked.
- **No page content analysis** — The app only analyses URL structure. It does not inspect the web page, forms, or scripts at the destination.
- **Score is not a probability** — The risk score is a transparent heuristic index, not a statistically calibrated probability.
