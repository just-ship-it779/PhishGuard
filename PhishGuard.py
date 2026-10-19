"""
PhishGuard — Malicious URL Checker
====================================
Single-file version for submission.
All logic is contained in this one file.

Run with:  streamlit run phishguard_single.py
Install:   pip install streamlit pandas requests tldextract python-dotenv
"""

from __future__ import annotations

import csv
import io
import ipaddress
import re
import datetime
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse, parse_qs

import pandas as pd
import streamlit as st

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 1 — URL VALIDATION
# ══════════════════════════════════════════════════════════════════════════════

BLOCKED_SCHEMES = {"javascript","file","data","vbscript","about","blob","ftp","mailto","tel","sms"}
ALLOWED_SCHEMES = {"http","https"}
MAX_INPUT_LENGTH = 2048

@dataclass
class ValidationResult:
    is_valid: bool
    normalised_url: str = ""
    original_input: str = ""
    normalisation_applied: bool = False
    error_message: str = ""

def validate_url(raw_input: str) -> ValidationResult:
    """Validate and normalise raw user input. Never raises."""
    original = raw_input
    stripped = raw_input.strip()

    if not stripped:
        return ValidationResult(is_valid=False, original_input=original,
                                error_message="Input is empty. Please enter a URL.")
    if len(stripped) > MAX_INPUT_LENGTH:
        return ValidationResult(is_valid=False, original_input=original,
                                error_message=f"Input exceeds {MAX_INPUT_LENGTH} characters.")

    # Block dangerous schemes before parsing
    scheme_match = re.match(r"^([a-zA-Z][a-zA-Z0-9+\-.]*)\s*:", stripped)
    if scheme_match:
        detected = scheme_match.group(1).lower()
        if detected in BLOCKED_SCHEMES:
            return ValidationResult(is_valid=False, original_input=original,
                                    error_message=f"The scheme '{detected}:' is not supported. Only http:// and https:// are accepted.")

    # Add https:// if no scheme present
    normalisation_applied = False
    working_url = stripped
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", stripped):
        working_url = "https://" + stripped
        normalisation_applied = True

    try:
        parsed = urlparse(working_url)
    except Exception:
        return ValidationResult(is_valid=False, original_input=original,
                                error_message="The URL could not be parsed. Please check the format.")

    if parsed.scheme not in ALLOWED_SCHEMES:
        return ValidationResult(is_valid=False, original_input=original,
                                error_message=f"The scheme '{parsed.scheme}:' is not supported.")

    hostname = parsed.hostname
    if not hostname:
        return ValidationResult(is_valid=False, original_input=original,
                                error_message="No hostname found. Please include a valid domain or IP address.")

    if hostname in {".",".."} or hostname.startswith(".") or hostname.endswith("."):
        return ValidationResult(is_valid=False, original_input=original,
                                error_message=f"The hostname '{hostname}' is not valid.")

    try:
        port = parsed.port
    except ValueError:
        return ValidationResult(is_valid=False, original_input=original,
                                error_message="Port is outside the valid range (1–65535).")

    if port is not None and not (0 < port <= 65535):
        return ValidationResult(is_valid=False, original_input=original,
                                error_message=f"Port {port} is outside the valid range (1–65535).")

    return ValidationResult(is_valid=True, normalised_url=working_url,
                            original_input=original, normalisation_applied=normalisation_applied)


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 2 — URL PARSING
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class ParsedURL:
    original_input: str = ""
    normalised_url: str = ""
    normalisation_applied: bool = False
    scheme: str = ""
    is_https: bool = False
    username: str = ""
    password: str = ""
    has_credentials: bool = False
    hostname: str = ""
    port: Optional[int] = None
    has_nonstandard_port: bool = False
    subdomain: str = ""
    domain: str = ""
    suffix: str = ""
    registered_domain: str = ""
    is_ip_address: bool = False
    ip_version: Optional[int] = None
    path: str = ""
    path_depth: int = 0
    query_string: str = ""
    query_params: dict = field(default_factory=dict)
    query_param_count: int = 0
    fragment: str = ""
    has_fragment: bool = False
    total_length: int = 0
    has_percent_encoding: bool = False
    percent_encoded_count: int = 0

_STANDARD_PORTS = {("http", 80), ("https", 443)}

def parse_url(normalised_url: str, original_input: str = "",
              normalisation_applied: bool = False) -> ParsedURL:
    """Parse a validated URL into structured components."""
    result = ParsedURL(original_input=original_input, normalised_url=normalised_url,
                       normalisation_applied=normalisation_applied, total_length=len(normalised_url))
    parsed = urlparse(normalised_url)
    result.scheme = parsed.scheme.lower()
    result.is_https = result.scheme == "https"
    result.username = parsed.username or ""
    result.password = parsed.password or ""
    result.has_credentials = bool(result.username or result.password)
    result.hostname = parsed.hostname or ""

    try:
        result.port = parsed.port
    except ValueError:
        result.port = None

    if result.port is not None:
        result.has_nonstandard_port = (result.scheme, result.port) not in _STANDARD_PORTS

    # Detect IP address hostnames using the ipaddress module
    if result.hostname:
        try:
            ip_obj = ipaddress.ip_address(result.hostname)
            result.is_ip_address = True
            result.ip_version = ip_obj.version
        except ValueError:
            result.is_ip_address = False

    # Domain extraction using tldextract (Public Suffix List)
    if not result.is_ip_address and result.hostname:
        try:
            import tldextract
            ext = tldextract.extract(normalised_url)
            result.subdomain = ext.subdomain
            result.domain = ext.domain
            result.suffix = ext.suffix
            if hasattr(ext, "top_domain_under_public_suffix"):
                result.registered_domain = ext.top_domain_under_public_suffix
            else:
                result.registered_domain = ext.registered_domain
        except ImportError:
            # Fallback if tldextract is not installed
            parts = result.hostname.rsplit(".", 2)
            result.registered_domain = ".".join(parts[-2:]) if len(parts) >= 2 else result.hostname
            result.domain = parts[-2] if len(parts) >= 2 else result.hostname
            result.suffix = parts[-1] if len(parts) >= 1 else ""
            result.subdomain = ".".join(parts[:-2]) if len(parts) > 2 else ""

    result.path = parsed.path
    result.path_depth = len([s for s in parsed.path.split("/") if s])
    result.query_string = parsed.query
    if parsed.query:
        result.query_params = parse_qs(parsed.query, keep_blank_values=True)
        result.query_param_count = len(result.query_params)
    result.fragment = parsed.fragment
    result.has_fragment = bool(parsed.fragment)

    encoded_hits = re.findall(r"%[0-9A-Fa-f]{2}", normalised_url)
    result.percent_encoded_count = len(encoded_hits)
    result.has_percent_encoding = result.percent_encoded_count > 0
    return result


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 3 — FEATURE EXTRACTION
# ══════════════════════════════════════════════════════════════════════════════

LONG_URL_THRESHOLD = 75
SUSPICIOUS_SUBDOMAIN_DEPTH = 3
EXCESSIVE_ENCODING_THRESHOLD = 5

SUSPICIOUS_KEYWORDS = [
    "login","verify","account","password","update","secure","urgent",
    "wallet","payment","recover","signin","banking","confirm","credential",
    "authenticate","webscr","ebayisapi","paypal",
]

URL_SHORTENER_DOMAINS = {
    "bit.ly","tinyurl.com","t.co","goo.gl","ow.ly","is.gd",
    "buff.ly","adf.ly","shorte.st","tiny.cc","lnkd.in",
}

@dataclass
class URLFeatures:
    uses_https: bool = False
    uses_http: bool = False
    is_ip_hostname: bool = False
    ip_version: Optional[int] = None
    has_credentials: bool = False
    credential_username: str = ""
    actual_hostname: str = ""
    url_length: int = 0
    is_long_url: bool = False
    found_keywords: list = field(default_factory=list)
    has_suspicious_keywords: bool = False
    subdomain_depth: int = 0
    has_deep_subdomains: bool = False
    registered_domain: str = ""
    subdomain: str = ""
    has_nonstandard_port: bool = False
    port: Optional[int] = None
    is_url_shortener: bool = False
    shortener_domain: str = ""
    has_excessive_encoding: bool = False
    percent_encoded_count: int = 0
    has_idn_hostname: bool = False
    idn_punycode: str = ""
    path_depth: int = 0
    has_query: bool = False
    query_param_count: int = 0
    has_fragment: bool = False
    has_percent_encoding: bool = False

def extract_features(parsed: ParsedURL) -> URLFeatures:
    """Derive security-relevant features from a ParsedURL."""
    f = URLFeatures()
    f.uses_https = parsed.is_https
    f.uses_http = parsed.scheme == "http"
    f.is_ip_hostname = parsed.is_ip_address
    f.ip_version = parsed.ip_version
    f.has_credentials = parsed.has_credentials
    f.credential_username = parsed.username
    f.actual_hostname = parsed.hostname
    f.url_length = parsed.total_length
    f.is_long_url = parsed.total_length > LONG_URL_THRESHOLD
    lower_url = parsed.normalised_url.lower()
    f.found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in lower_url]
    f.has_suspicious_keywords = bool(f.found_keywords)
    f.registered_domain = parsed.registered_domain
    f.subdomain = parsed.subdomain
    if parsed.subdomain:
        f.subdomain_depth = len(parsed.subdomain.split("."))
    f.has_deep_subdomains = f.subdomain_depth >= SUSPICIOUS_SUBDOMAIN_DEPTH
    f.has_nonstandard_port = parsed.has_nonstandard_port
    f.port = parsed.port
    if parsed.registered_domain.lower() in URL_SHORTENER_DOMAINS:
        f.is_url_shortener = True
        f.shortener_domain = parsed.registered_domain.lower()
    f.percent_encoded_count = parsed.percent_encoded_count
    f.has_percent_encoding = parsed.has_percent_encoding
    f.has_excessive_encoding = parsed.percent_encoded_count >= EXCESSIVE_ENCODING_THRESHOLD
    if parsed.hostname:
        try:
            parsed.hostname.encode("ascii")
        except UnicodeEncodeError:
            f.has_idn_hostname = True
            try:
                f.idn_punycode = parsed.hostname.encode("idna").decode("ascii")
            except (UnicodeError, UnicodeDecodeError):
                f.idn_punycode = "(encoding error)"
        else:
            if "xn--" in parsed.hostname.lower():
                f.has_idn_hostname = True
                f.idn_punycode = parsed.hostname
    f.path_depth = parsed.path_depth
    f.has_query = bool(parsed.query_string)
    f.query_param_count = parsed.query_param_count
    f.has_fragment = parsed.has_fragment
    return f


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 4 — DETECTION RULES
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class Finding:
    rule_id: str
    rule_name: str
    severity: str
    weight: int
    description: str
    rationale: str
    limitation: str
    evidence: str = ""

def evaluate_rules(f: URLFeatures) -> list[Finding]:
    """Evaluate all detection rules and return triggered findings."""
    findings = []

    # URL001 — IP-Address Hostname
    if f.is_ip_hostname:
        findings.append(Finding("URL001", "IP-Address Hostname", "high", 20,
            f"The hostname is a raw IP address ({f.actual_hostname}) rather than a domain name.",
            "Legitimate services almost always use domain names. A raw IP address can evade domain-based reputation checks.",
            "Some legitimate internal tools and development environments use IP addresses.",
            f.actual_hostname))

    # URL002 — HTTP Instead of HTTPS
    if f.uses_http:
        findings.append(Finding("URL002", "HTTP Instead of HTTPS", "medium", 10,
            "The URL uses HTTP, which means the connection is not encrypted.",
            "HTTPS encrypts data in transit and verifies server identity. Most legitimate websites use HTTPS.",
            "HTTP alone does not prove malicious intent. HTTPS does not guarantee a site is safe.",
            "http://"))

    # URL003 — Misleading User-Information Syntax
    if f.has_credentials:
        findings.append(Finding("URL003", "Misleading User-Info Syntax", "high", 25,
            f"The URL contains '{f.credential_username}@{f.actual_hostname}'. The real destination is '{f.actual_hostname}'.",
            "Attackers use https://trusted-bank.com@evil.com/ to make victims believe they visit a trusted domain.",
            "Embedded credentials are extremely rare in legitimate web URLs.",
            f"{f.credential_username}@{f.actual_hostname}"))

    # URL004 — Unusually Long URL
    if f.is_long_url:
        findings.append(Finding("URL004", "Unusually Long URL", "low", 5,
            f"The URL is {f.url_length} characters long. Phishing URLs are often long to obscure the real destination.",
            "Phishing URLs tend to be longer than legitimate ones, often to hide the real domain.",
            "Many legitimate URLs are long — tracking parameters, deep paths, encoded data.",
            f"{f.url_length} characters"))

    # URL005 — Suspicious Keyword Pattern
    if f.has_suspicious_keywords:
        kw_list = ", ".join(f.found_keywords)
        findings.append(Finding("URL005", "Suspicious Keyword Pattern", "low", 8,
            f"The URL contains keyword(s) frequently seen in phishing links: {kw_list}.",
            "Phishing URLs frequently include terms like 'login', 'verify', 'account' to create false urgency.",
            "These words also appear in many legitimate URLs. This is a weak indicator on its own.",
            kw_list))

    # URL006 — Unusual Subdomain Depth
    if f.has_deep_subdomains:
        findings.append(Finding("URL006", "Unusual Subdomain Depth", "medium", 12,
            f"The hostname has {f.subdomain_depth} subdomain labels: '{f.subdomain}'.",
            "Attackers use deep subdomains to embed trusted brand names before the real registered domain.",
            "Some legitimate cloud services use multi-level subdomains.",
            f"{f.subdomain}.{f.registered_domain}"))

    # URL007 — Internationalized Domain Name
    if f.has_idn_hostname:
        findings.append(Finding("URL007", "Internationalized Domain Name", "medium", 12,
            f"The hostname contains non-ASCII or Punycode characters. ACE: '{f.idn_punycode}'.",
            "Characters from other scripts can look identical to Latin letters, enabling homograph attacks.",
            "Many legitimate international websites use IDN domains.",
            f.idn_punycode or f.actual_hostname))

    # URL008 — Nonstandard Port
    if f.has_nonstandard_port:
        findings.append(Finding("URL008", "Nonstandard Port", "low", 6,
            f"The URL specifies port {f.port}, which is not standard for its scheme.",
            "Phishing infrastructure sometimes runs on unusual ports to evade network filters.",
            "Nonstandard ports are common for development servers, APIs, and internal tools.",
            str(f.port)))

    # URL009 — Known URL-Shortening Service
    if f.is_url_shortener:
        findings.append(Finding("URL009", "Known URL-Shortening Service", "low", 7,
            f"The URL uses the shortening service '{f.shortener_domain}'. The final destination is concealed.",
            "URL shorteners hide the real destination, making it impossible to assess the target without following the link.",
            "URL shorteners are widely used for legitimate social media and marketing purposes.",
            f.shortener_domain))

    # URL010 — Excessive Percent-Encoding
    if f.has_excessive_encoding:
        findings.append(Finding("URL010", "Excessive Percent-Encoding", "low", 6,
            f"The URL contains {f.percent_encoded_count} percent-encoded sequences.",
            "Excessive encoding can be used to bypass URL filters or hide suspicious keywords.",
            "Legitimate URLs with non-ASCII paths may have many percent-encoded characters.",
            f"{f.percent_encoded_count} encoded sequences"))

    return findings


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 5 — RISK SCORING
# ══════════════════════════════════════════════════════════════════════════════

RAW_SCORE_CEILING = 104  # Sum of all 10 rule weights

CATEGORY_COLOURS = {
    "Low":      "#22c55e",
    "Moderate": "#f59e0b",
    "High":     "#ef4444",
    "Critical": "#7c3aed",
}

@dataclass
class RiskScore:
    raw_score: int = 0
    score: int = 0
    category: str = "Low"
    findings: list = field(default_factory=list)
    ti_status: str = "not_checked"
    ti_details: str = ""

    @property
    def category_colour(self) -> str:
        return CATEGORY_COLOURS.get(self.category, "#6b7280")

    @property
    def finding_count(self) -> int:
        return len(self.findings)

def calculate_score(findings: list[Finding]) -> RiskScore:
    """Calculate bounded [0–100] risk score from triggered findings."""
    raw = sum(f.weight for f in findings)
    score = min(round((raw / RAW_SCORE_CEILING) * 100), 100) if RAW_SCORE_CEILING > 0 else 0
    thresholds = [("Low",0,24),("Moderate",25,49),("High",50,74),("Critical",75,100)]
    category = next((label for label, lo, hi in thresholds if lo <= score <= hi), "Critical")
    return RiskScore(raw_score=raw, score=score, category=category, findings=findings)

def apply_ti_result(risk: RiskScore, ti_status: str, ti_details: str = "") -> RiskScore:
    """Incorporate a TI result. Malicious → Critical. Unavailable ≠ clean."""
    risk.ti_status = ti_status
    risk.ti_details = ti_details
    if ti_status == "malicious":
        risk.category = "Critical"
        risk.score = max(risk.score, 90)
    return risk


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 6 — ANALYSIS ENGINE
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class AnalysisResult:
    raw_input: str = ""
    timestamp: str = ""
    validation: ValidationResult = field(default_factory=lambda: ValidationResult(is_valid=False))
    parsed: Optional[ParsedURL] = None
    features: Optional[URLFeatures] = None
    findings: list = field(default_factory=list)
    risk: Optional[RiskScore] = None
    ti_results: list = field(default_factory=list)

    @property
    def is_valid(self) -> bool: return self.validation.is_valid
    @property
    def score(self) -> int: return self.risk.score if self.risk else 0
    @property
    def category(self) -> str: return self.risk.category if self.risk else "Unknown"

def analyse(raw_input: str, run_ti: bool = False) -> AnalysisResult:
    """
    Full analysis pipeline. Never visits the submitted URL.
    1. Validate  2. Parse  3. Extract features  4. Evaluate rules  5. Score
    """
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    result = AnalysisResult(raw_input=raw_input, timestamp=ts)
    result.validation = validate_url(raw_input)
    if not result.validation.is_valid:
        return result
    result.parsed = parse_url(result.validation.normalised_url,
                               result.validation.original_input,
                               result.validation.normalisation_applied)
    result.features = extract_features(result.parsed)
    result.findings = evaluate_rules(result.features)
    result.risk = calculate_score(result.findings)

    if run_ti:
        ti_results = _run_ti_checks(result.validation.normalised_url)
        result.ti_results = ti_results
        statuses = {r["status"] for r in ti_results}
        if "malicious" in statuses:
            details = next(r["details"] for r in ti_results if r["status"] == "malicious")
            result.risk = apply_ti_result(result.risk, "malicious", details)
        elif "error" in statuses or "unavailable" in statuses:
            result.risk = apply_ti_result(result.risk, "unavailable", "One or more TI providers were unavailable.")
        elif all(s == "not_checked" for s in statuses):
            result.risk = apply_ti_result(result.risk, "not_checked", "No API keys configured.")
        else:
            result.risk = apply_ti_result(result.risk, "clean", "No threats detected by configured providers.")
    return result


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 7 — THREAT INTELLIGENCE (OPTIONAL)
# ══════════════════════════════════════════════════════════════════════════════

def _run_ti_checks(url: str) -> list[dict]:
    """Run all configured TI checks. Requires explicit user opt-in."""
    import os
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except ImportError:
        pass

    results = []
    results.append(_check_gsb(url, os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY")))
    results.append(_check_virustotal(url, os.environ.get("VIRUSTOTAL_API_KEY")))
    return results

def _utc_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

def _check_gsb(url: str, api_key: str | None) -> dict:
    provider = "Google Safe Browsing"
    if not api_key:
        return {"provider": provider, "status": "not_checked", "details": "API key not configured (GOOGLE_SAFE_BROWSING_API_KEY).", "timestamp": _utc_now()}
    try:
        import requests as req
        endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
        payload = {"client": {"clientId": "phishguard", "clientVersion": "1.0.0"},
                   "threatInfo": {"threatTypes": ["MALWARE","SOCIAL_ENGINEERING","UNWANTED_SOFTWARE","POTENTIALLY_HARMFUL_APPLICATION"],
                                  "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"],
                                  "threatEntries": [{"url": url}]}}
        r = req.post(endpoint, json=payload, timeout=10)
        if r.status_code == 429: return {"provider": provider, "status": "unavailable", "details": "Rate limit exceeded.", "timestamp": _utc_now()}
        if r.status_code != 200: return {"provider": provider, "status": "error", "details": f"HTTP {r.status_code}.", "timestamp": _utc_now()}
        data = r.json()
        if not data or "matches" not in data:
            return {"provider": provider, "status": "clean", "details": "No threats detected.", "timestamp": _utc_now()}
        types = {m.get("threatType","UNKNOWN") for m in data["matches"]}
        return {"provider": provider, "status": "malicious", "details": f"Threat: {', '.join(sorted(types))}.", "timestamp": _utc_now()}
    except Exception as e:
        return {"provider": provider, "status": "unavailable", "details": str(e), "timestamp": _utc_now()}

def _check_virustotal(url: str, api_key: str | None) -> dict:
    provider = "VirusTotal"
    if not api_key:
        return {"provider": provider, "status": "not_checked", "details": "API key not configured (VIRUSTOTAL_API_KEY).", "timestamp": _utc_now()}
    try:
        import base64, requests as req
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        r = req.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers={"x-apikey": api_key}, timeout=10)
        if r.status_code == 401: return {"provider": provider, "status": "error", "details": "Invalid API key.", "timestamp": _utc_now()}
        if r.status_code == 429: return {"provider": provider, "status": "unavailable", "details": "Rate limit exceeded.", "timestamp": _utc_now()}
        if r.status_code == 404: return {"provider": provider, "status": "unavailable", "details": "No existing report. URL submitted for scanning.", "timestamp": _utc_now()}
        if r.status_code != 200: return {"provider": provider, "status": "error", "details": f"HTTP {r.status_code}.", "timestamp": _utc_now()}
        stats = r.json().get("data",{}).get("attributes",{}).get("last_analysis_stats",{})
        mal = stats.get("malicious",0); sus = stats.get("suspicious",0); total = sum(stats.values()) if stats else 0
        if mal > 0: return {"provider": provider, "status": "malicious", "details": f"{mal}/{total} vendors flagged as malicious.", "timestamp": _utc_now()}
        if sus > 0: return {"provider": provider, "status": "malicious", "details": f"{sus}/{total} vendors flagged as suspicious.", "timestamp": _utc_now()}
        return {"provider": provider, "status": "clean", "details": f"0/{total} vendors flagged.", "timestamp": _utc_now()}
    except Exception as e:
        return {"provider": provider, "status": "unavailable", "details": str(e), "timestamp": _utc_now()}


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 8 — REPORT GENERATION
# ══════════════════════════════════════════════════════════════════════════════

_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")

def _safe_cell(value: str) -> str:
    """Prevent CSV formula injection by prefixing dangerous characters."""
    value = str(value)
    return ("'" + value) if value.startswith(_FORMULA_PREFIXES) else value

def generate_csv(results: list[AnalysisResult]) -> str:
    """Generate a CSV string from a list of AnalysisResults."""
    columns = ["timestamp","original_input","normalised_url","is_valid","validation_error",
               "hostname","scheme","is_ip","risk_score","risk_category",
               "finding_count","finding_ids","ti_status","ti_details"]
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=columns, extrasaction="ignore", lineterminator="\n")
    writer.writeheader()
    for r in results:
        if not r.is_valid:
            writer.writerow({"timestamp":r.timestamp,"original_input":_safe_cell(r.raw_input),
                             "is_valid":"No","validation_error":_safe_cell(r.validation.error_message),
                             "normalised_url":"","hostname":"","scheme":"","is_ip":"",
                             "risk_score":"","risk_category":"","finding_count":"","finding_ids":"","ti_status":"","ti_details":""})
        else:
            finding_ids = "; ".join(f.rule_id for f in r.findings)
            ti_status = r.risk.ti_status if r.risk else "not_checked"
            ti_details = r.risk.ti_details if r.risk else ""
            writer.writerow({"timestamp":r.timestamp,"original_input":_safe_cell(r.raw_input),
                             "normalised_url":_safe_cell(r.validation.normalised_url),
                             "is_valid":"Yes","validation_error":"",
                             "hostname":_safe_cell(r.parsed.hostname if r.parsed else ""),
                             "scheme":r.parsed.scheme if r.parsed else "",
                             "is_ip":str(r.parsed.is_ip_address) if r.parsed else "",
                             "risk_score":str(r.score),"risk_category":r.category,
                             "finding_count":str(len(r.findings)),"finding_ids":_safe_cell(finding_ids),
                             "ti_status":ti_status,"ti_details":_safe_cell(ti_details)})
    return output.getvalue()

def generate_markdown(result: AnalysisResult) -> str:
    """Generate a Markdown report for a single AnalysisResult."""
    lines = ["# PhishGuard — URL Analysis Report",
             f"\n**Timestamp:** {result.timestamp}",
             f"**Input:** `{result.raw_input}`"]
    if not result.is_valid:
        lines.append(f"\n**Validation failed:** {result.validation.error_message}")
    else:
        lines.append(f"**Normalised URL:** `{result.validation.normalised_url}`")
        if result.validation.normalisation_applied:
            lines.append("*(https:// was added automatically)*")
        lines += ["\n## Risk Assessment",
                  f"- **Score:** {result.score} / 100",
                  f"- **Category:** {result.category}",
                  f"- **Findings:** {len(result.findings)}"]
        if result.findings:
            lines.append("\n## Findings")
            for f in result.findings:
                lines += [f"\n### [{f.rule_id}] {f.rule_name} *(Severity: {f.severity})*",
                          f"**What was found:** {f.description}",
                          f"**Why it matters:** {f.rationale}",
                          f"**Limitation:** {f.limitation}",
                          f"**Evidence:** `{f.evidence}`"]
        else:
            lines.append("\nNo suspicious indicators detected.")
    lines.append("\n---\n> **Disclaimer:** Heuristic assessment based on URL structure only. Does not visit the URL. A low score does not guarantee safety. For educational use only.")
    return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 9 — STREAMLIT DASHBOARD
# ══════════════════════════════════════════════════════════════════════════════

st.set_page_config(page_title="PhishGuard", page_icon="🛡️", layout="wide", initial_sidebar_state="collapsed")

st.markdown("""<style>
html,body,[data-testid="stAppViewContainer"]{background:#0d1117;color:#e6edf3;font-family:-apple-system,"Segoe UI",system-ui,sans-serif;}
.pg-header{background:linear-gradient(135deg,#161b22,#1c2128);border:1px solid #30363d;border-radius:8px;padding:1.2rem 1.5rem;margin-bottom:1.5rem;}
.pg-header h1{color:#58a6ff;margin:0;font-size:1.8rem;}
.pg-header p{color:#8b949e;margin:0.3rem 0 0;font-size:0.95rem;}
.pg-card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:1.2rem 1.5rem;margin-bottom:1rem;}
.risk-badge{display:inline-block;padding:0.4rem 1.2rem;border-radius:6px;font-size:1.1rem;font-weight:700;}
.risk-low{background:#0d2b1a;color:#3fb950;border:1px solid #3fb950;}
.risk-moderate{background:#2b1f0a;color:#d29922;border:1px solid #d29922;}
.risk-high{background:#2b0d0d;color:#f85149;border:1px solid #f85149;}
.risk-critical{background:#1f0d2b;color:#a371f7;border:1px solid #a371f7;}
.url-table{width:100%;border-collapse:collapse;}
.url-table td{padding:0.4rem 0.7rem;border-bottom:1px solid #21262d;font-size:0.9rem;}
.url-table td:first-child{color:#8b949e;width:40%;}
.url-table tr:last-child td{border-bottom:none;}
.score-number{font-size:2.8rem;font-weight:800;line-height:1;}
.pg-disclaimer{background:#1c2128;border-left:3px solid #3b82f6;padding:0.8rem 1rem;border-radius:0 6px 6px 0;font-size:0.85rem;color:#8b949e;margin-top:1rem;}
.pg-footer{text-align:center;color:#484f58;font-size:0.75rem;border-top:1px solid #21262d;padding-top:1rem;margin-top:2rem;}
div.stButton>button{background-color:#238636 !important;color:#fff !important;border:1px solid #2ea043 !important;border-radius:6px !important;font-weight:600 !important;}
</style>""", unsafe_allow_html=True)

if "history" not in st.session_state:
    st.session_state.history: list[AnalysisResult] = []

def _risk_class(cat):
    return {"Low":"risk-low","Moderate":"risk-moderate","High":"risk-high","Critical":"risk-critical"}.get(cat,"risk-low")

def render_result(result: AnalysisResult):
    if not result.is_valid:
        st.error(f"❌ {result.validation.error_message}"); return

    risk = result.risk; parsed = result.parsed
    col_score, col_meta = st.columns([1, 3])

    with col_score:
        st.markdown(f"""<div class="pg-card" style="text-align:center">
          <div style="color:#8b949e;font-size:0.8rem;text-transform:uppercase">Risk Score</div>
          <div class="score-number" style="color:{risk.category_colour}">{risk.score}</div>
          <div style="color:#8b949e;font-size:0.8rem">out of 100</div>
          <div style="margin-top:0.6rem"><span class="risk-badge {_risk_class(risk.category)}">{risk.category}</span></div>
        </div>""", unsafe_allow_html=True)

    with col_meta:
        ti_icons = {"not_checked":"⬜ Not Checked","clean":"✅ No Threats","malicious":"🚨 THREAT DETECTED","unavailable":"⚠️ Unavailable","error":"❌ Error"}
        ti_label = ti_icons.get(risk.ti_status, "—")
        norm_note = "<tr><td>Note</td><td style='color:#d29922'>⚠ https:// added automatically</td></tr>" if result.validation.normalisation_applied else ""
        st.markdown(f"""<div class="pg-card"><table class="url-table">
          <tr><td>Findings</td><td>{risk.finding_count} indicator(s)</td></tr>
          <tr><td>Mode</td><td>Local heuristic — URL not visited</td></tr>
          <tr><td>Threat intelligence</td><td>{ti_label}</td></tr>
          <tr><td>Analysed at</td><td>{result.timestamp}</td></tr>
          <tr><td>URL</td><td><code style="font-size:0.82rem">{result.validation.normalised_url}</code></td></tr>
          {norm_note}</table></div>""", unsafe_allow_html=True)

    if result.findings:
        st.markdown("<div class='pg-card'><b style='color:#58a6ff'>⚠ SUSPICIOUS INDICATORS</b></div>", unsafe_allow_html=True)
        for f in result.findings:
            with st.expander(f"[{f.rule_id}] {f.rule_name}  —  {f.severity.upper()}", expanded=True):
                c1, c2 = st.columns(2)
                with c1:
                    st.markdown("**What was found**"); st.markdown(f.description)
                    st.markdown(f"**Evidence:** `{f.evidence}`")
                with c2:
                    st.markdown("**Why it matters**"); st.markdown(f.rationale)
                    st.caption(f"⚠ Limitation: {f.limitation}")
    else:
        st.markdown("<div class='pg-card' style='border-left:3px solid #3fb950'><b style='color:#3fb950'>✅ No suspicious indicators detected</b><br><span style='color:#8b949e;font-size:0.9rem'>This does not guarantee the URL is safe.</span></div>", unsafe_allow_html=True)

    actions = {
        "Low":      "💡 **No major concerns found.** Always verify unexpected links before entering credentials.",
        "Moderate": "⚠️ **Proceed with caution.** Verify the domain through an independently obtained official source before entering any personal information.",
        "High":     "🚨 **Significant caution advised.** Multiple suspicious indicators detected. Do not enter credentials. Verify through an official source.",
        "Critical": "🛑 **Do not interact with this URL.** Flagged by threat-intelligence or high-severity indicators. Report to your security team.",
    }
    st.info(actions.get(risk.category, actions["Low"]))

    with st.expander("🔍 URL Structure Breakdown", expanded=False):
        if parsed:
            rows = [("Scheme",parsed.scheme),("Hostname",parsed.hostname),
                    ("Is IP address","Yes ⚠" if parsed.is_ip_address else "No"),
                    ("Registered domain",parsed.registered_domain or "N/A"),
                    ("Subdomain",parsed.subdomain or "None"),("TLD",parsed.suffix or "N/A"),
                    ("User credentials","Yes ⚠" if parsed.has_credentials else "No"),
                    ("Port",str(parsed.port) if parsed.port else "Default"),
                    ("Nonstandard port","Yes ⚠" if parsed.has_nonstandard_port else "No"),
                    ("Path",parsed.path or "/"),("Path depth",str(parsed.path_depth)),
                    ("Query parameters",str(parsed.query_param_count)),
                    ("Fragment","Yes" if parsed.has_fragment else "No"),
                    ("Percent-encoded",str(parsed.percent_encoded_count)),
                    ("Total length",f"{parsed.total_length} chars"),
                    ("HTTPS","Yes" if parsed.is_https else "No ⚠")]
            st.markdown(f"<table class='url-table'>{''.join(f'<tr><td>{k}</td><td>{v}</td></tr>' for k,v in rows)}</table>", unsafe_allow_html=True)

    if result.ti_results:
        with st.expander("🌐 Threat Intelligence Details", expanded=False):
            for ti in result.ti_results:
                icon = {"clean":"✅","malicious":"🚨","unavailable":"⚠️","error":"❌","not_checked":"⬜"}.get(ti["status"],"—")
                st.markdown(f"**{icon} {ti['provider']}** — *{ti['status'].upper()}*\n\n> {ti['details']}")
                if ti.get("timestamp"): st.caption(f"Checked at: {ti['timestamp']}")
                st.divider()

    c1, c2 = st.columns(2)
    with c1: st.download_button("⬇ Download CSV", data=generate_csv([result]), file_name="phishguard_report.csv", mime="text/csv")
    with c2: st.download_button("⬇ Download Markdown", data=generate_markdown(result), file_name="phishguard_report.md", mime="text/markdown")

    st.markdown("<div class='pg-disclaimer'>⚠ <strong>Disclaimer:</strong> Heuristic assessment based on URL structure only. Does not visit the URL. A low score does not guarantee safety. A high score does not guarantee malice. For educational use and initial triage only.</div>", unsafe_allow_html=True)


# ── Header ─────────────────────────────────────────────────────────────────────
st.markdown("""<div class="pg-header"><h1>🛡️ PhishGuard</h1><p>Malicious URL Analysis &amp; Threat Intelligence — Heuristic Mode</p></div>""", unsafe_allow_html=True)

tab_single, tab_bulk, tab_history = st.tabs(["🔍 Single URL", "📋 Bulk CSV", "🕒 History"])

# ── Tab 1: Single URL ──────────────────────────────────────────────────────────
with tab_single:
    st.markdown("#### Enter a URL to analyse")
    st.caption("PhishGuard analyses the **structure** of the URL only. It will **not** open or visit the destination.")
    url_input = st.text_input("URL", placeholder="https://example.com/path", label_visibility="collapsed")
    col_btn, col_ti = st.columns([1, 3])
    with col_btn: clicked = st.button("🔍 Analyse URL", use_container_width=True)
    with col_ti: run_ti = st.checkbox("Enable Threat Intelligence lookup (requires API key — sends URL to external provider)", value=False)
    if run_ti:
        st.warning("⚠️ **Privacy:** Enabling TI will send the URL to Google Safe Browsing and/or VirusTotal. Set `GOOGLE_SAFE_BROWSING_API_KEY` and `VIRUSTOTAL_API_KEY` environment variables.")
    if clicked:
        if not url_input.strip():
            st.warning("Please enter a URL.")
        else:
            with st.spinner("Analysing…"):
                result = analyse(url_input, run_ti=run_ti)
            st.session_state.history.insert(0, result)
            st.session_state.history = st.session_state.history[:20]
            st.divider()
            render_result(result)

# ── Tab 2: Bulk CSV ────────────────────────────────────────────────────────────
with tab_bulk:
    st.markdown("#### Upload a CSV file for bulk analysis")
    st.markdown("The CSV must have a column named **`url`**. Each row is analysed independently.")
    with st.expander("📄 Expected format"):
        st.code("url\nhttps://example.com\nhttp://192.0.2.1/login\nbit.ly/abc123", language="csv")
    uploaded = st.file_uploader("Upload CSV", type=["csv"])
    if uploaded:
        try:
            df = pd.read_csv(uploaded)
        except Exception as e:
            st.error(f"Could not read CSV: {e}"); df = None
        if df is not None:
            url_col = next((c for c in df.columns if c.strip().lower() == "url"), None)
            if not url_col:
                st.error(f"No 'url' column found. Columns: {list(df.columns)}")
            else:
                urls = df[url_col].fillna("").astype(str).tolist()
                st.info(f"Found {len(urls)} row(s). Analysing…")
                results: list[AnalysisResult] = []
                progress = st.progress(0)
                for i, u in enumerate(urls):
                    results.append(analyse(u))
                    progress.progress((i+1)/len(urls))
                progress.empty()
                valid = [r for r in results if r.is_valid]
                cats = [r.category for r in valid]
                st.success(f"Done — {len(results)} URL(s) processed.")
                m1,m2,m3,m4,m5 = st.columns(5)
                m1.metric("Total",len(results)); m2.metric("Valid",len(valid))
                m3.metric("🟢 Low",cats.count("Low")); m4.metric("🟡 Moderate",cats.count("Moderate"))
                m5.metric("🔴 High/Critical", cats.count("High")+cats.count("Critical"))
                table_data = [{"URL":r.validation.normalised_url if r.is_valid else r.raw_input,
                               "Score":r.score if r.is_valid else "—",
                               "Category":r.category if r.is_valid else "Invalid",
                               "Findings":r.risk.finding_count if r.risk else "—"} for r in results]
                result_df = pd.DataFrame(table_data)
                sel = st.selectbox("Filter by category", ["All"] + sorted(set(result_df["Category"].tolist())))
                if sel != "All": result_df = result_df[result_df["Category"]==sel]
                st.dataframe(result_df, use_container_width=True)
                st.download_button("⬇ Download Full CSV", data=generate_csv(results), file_name="phishguard_bulk.csv", mime="text/csv")

# ── Tab 3: History ─────────────────────────────────────────────────────────────
with tab_history:
    if not st.session_state.history:
        st.info("No URLs analysed yet in this session.")
    else:
        c1, c2 = st.columns([4,1])
        with c1: st.markdown(f"**{len(st.session_state.history)} URL(s) analysed this session**")
        with c2:
            if st.button("🗑 Clear"):
                st.session_state.history = []; st.rerun()
        hist = [{"Time":r.timestamp,
                 "URL":r.validation.normalised_url if r.is_valid else r.raw_input,
                 "Valid":"✅" if r.is_valid else "❌",
                 "Score":r.score if r.is_valid else "—",
                 "Category":r.category if r.is_valid else "Invalid"} for r in st.session_state.history]
        st.dataframe(pd.DataFrame(hist), use_container_width=True)
        st.download_button("⬇ Download History CSV", data=generate_csv(st.session_state.history), file_name="phishguard_history.csv", mime="text/csv")

st.markdown("<div class='pg-footer'>PhishGuard v1.0.0 &nbsp;·&nbsp; Heuristic analysis only — does not visit URLs &nbsp;·&nbsp; For educational use only</div>", unsafe_allow_html=True)
