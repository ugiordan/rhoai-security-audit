#!/usr/bin/env python3
"""Normalize security tool outputs to a common finding format."""
import json
import os
import re
import sys
from pathlib import Path

SEVERITY_MAP = {
    "CRITICAL": "critical", "critical": "critical", "ERROR": "critical",
    "HIGH": "high", "high": "high", "WARNING": "high",
    "MEDIUM": "medium", "medium": "medium", "INFO": "medium",
    "LOW": "low", "low": "low",
    "NOTE": "info", "info": "info", "style": "info", "warning": "high", "error": "critical",
}

TOOL_PREFIX = {
    "semgrep": "SEM", "gitleaks": "GLK", "trufflehog": "THG",
    "trivy": "TRV", "grype": "GRP", "kube-linter": "KBL",
    "hadolint": "HDL", "actionlint": "ACT", "zizmor": "ZIZ",
    "govulncheck": "GVC", "shellcheck": "SHC", "gosec": "GSC",
    "pip-audit": "PIP", "osv-scanner": "OSV", "yamllint": "YML",
}


def norm_sev(s):
    return SEVERITY_MAP.get(s, "info")


def make_id(tool, n):
    return f"{TOOL_PREFIX.get(tool, 'UNK')}-{n:03d}"


def parse_semgrep(path):
    data = json.loads(path.read_text())
    results = data.get("results", [])
    findings = []
    for i, r in enumerate(results, 1):
        findings.append({
            "id": make_id("semgrep", i), "source": "semgrep",
            "severity": norm_sev(r.get("extra", {}).get("severity", "INFO")),
            "category": "other", "file": r.get("path", ""),
            "line_start": r.get("start", {}).get("line", 0),
            "line_end": r.get("end", {}).get("line", 0),
            "title": r.get("check_id", "").split(".")[-1],
            "description": r.get("extra", {}).get("message", ""),
            "confidence": 0.8, "rule_id": r.get("check_id", ""),
            "detected_by": ["semgrep"], "recommendation": "",
        })
    return findings


def parse_gitleaks(path):
    data = json.loads(path.read_text())
    if not isinstance(data, list):
        return []
    findings = []
    for i, r in enumerate(data, 1):
        findings.append({
            "id": make_id("gitleaks", i), "source": "gitleaks",
            "severity": "high", "category": "secrets",
            "file": r.get("File", ""), "line_start": r.get("StartLine", 0),
            "line_end": r.get("EndLine", 0),
            "title": r.get("Description", "Secret detected"),
            "description": r.get("Description", ""),
            "confidence": 0.9, "rule_id": r.get("RuleID", ""),
            "detected_by": ["gitleaks"], "recommendation": "Remove secret and rotate credentials",
        })
    return findings


def parse_trivy(path):
    data = json.loads(path.read_text())
    findings = []
    n = 0
    for result in data.get("Results", []):
        for v in result.get("Vulnerabilities", []):
            n += 1
            findings.append({
                "id": make_id("trivy", n), "source": "trivy",
                "severity": norm_sev(v.get("Severity", "UNKNOWN")),
                "category": "sca", "file": result.get("Target", ""),
                "line_start": 0, "line_end": 0,
                "title": f"{v.get('VulnerabilityID', '')}: {v.get('PkgName', '')}",
                "description": v.get("Description", "")[:500],
                "confidence": 0.9, "rule_id": v.get("VulnerabilityID", ""),
                "detected_by": ["trivy"], "recommendation": f"Update to {v.get('FixedVersion', 'latest')}",
            })
    return findings


def parse_grype(path):
    data = json.loads(path.read_text())
    findings = []
    for i, m in enumerate(data.get("matches", []), 1):
        vuln = m.get("vulnerability", {})
        art = m.get("artifact", {})
        findings.append({
            "id": make_id("grype", i), "source": "grype",
            "severity": norm_sev(vuln.get("severity", "Unknown")),
            "category": "sca", "file": art.get("locations", [{}])[0].get("path", "") if art.get("locations") else "",
            "line_start": 0, "line_end": 0,
            "title": f"{vuln.get('id', '')}: {art.get('name', '')}",
            "description": vuln.get("description", "")[:500],
            "confidence": 0.85, "rule_id": vuln.get("id", ""),
            "detected_by": ["grype"], "recommendation": f"Update {art.get('name', '')}",
        })
    return findings


def parse_kube_linter(path):
    data = json.loads(path.read_text())
    findings = []
    for i, r in enumerate(data.get("Reports", []), 1):
        diag = r.get("Diagnostic", {})
        obj = r.get("Object", {}).get("K8sObject", {}).get("GroupVersionKind", {})
        findings.append({
            "id": make_id("kube-linter", i), "source": "kube-linter",
            "severity": "medium", "category": "k8s",
            "file": r.get("Object", {}).get("Metadata", {}).get("FilePath", ""),
            "line_start": 0, "line_end": 0,
            "title": diag.get("Message", "")[:100],
            "description": diag.get("Message", ""),
            "confidence": 0.8, "rule_id": r.get("Check", ""),
            "detected_by": ["kube-linter"], "recommendation": diag.get("Remediation", ""),
        })
    return findings


def parse_sarif(path, tool):
    data = json.loads(path.read_text())
    findings = []
    for run in data.get("runs", []):
        for i, r in enumerate(run.get("results", []), 1):
            loc = r.get("locations", [{}])[0].get("physicalLocation", {})
            region = loc.get("region", {})
            findings.append({
                "id": make_id(tool, i), "source": tool,
                "severity": norm_sev(r.get("level", "note")),
                "category": "cicd" if tool in ("actionlint", "zizmor") else "config",
                "file": loc.get("artifactLocation", {}).get("uri", ""),
                "line_start": region.get("startLine", 0),
                "line_end": region.get("endLine", region.get("startLine", 0)),
                "title": r.get("message", {}).get("text", "")[:100],
                "description": r.get("message", {}).get("text", ""),
                "confidence": 0.7, "rule_id": r.get("ruleId", ""),
                "detected_by": [tool], "recommendation": "",
            })
    return findings


def parse_shellcheck(path):
    data = json.loads(path.read_text())
    if not isinstance(data, list):
        return []
    findings = []
    for i, r in enumerate(data, 1):
        findings.append({
            "id": make_id("shellcheck", i), "source": "shellcheck",
            "severity": norm_sev(r.get("level", "info")),
            "category": "config", "file": r.get("file", ""),
            "line_start": r.get("line", 0), "line_end": r.get("endLine", r.get("line", 0)),
            "title": f"SC{r.get('code', '')}: {r.get('message', '')[:80]}",
            "description": r.get("message", ""),
            "confidence": 0.7, "rule_id": f"SC{r.get('code', '')}",
            "detected_by": ["shellcheck"], "recommendation": r.get("fix", {}).get("replacements", [{}])[0].get("replacement", "") if r.get("fix") else "",
        })
    return findings


def parse_gosec(path):
    data = json.loads(path.read_text())
    findings = []
    for i, r in enumerate(data.get("Issues", []), 1):
        findings.append({
            "id": make_id("gosec", i), "source": "gosec",
            "severity": norm_sev(r.get("severity", "MEDIUM")),
            "category": "other", "file": r.get("file", ""),
            "line_start": int(r.get("line", "0")),
            "line_end": int(r.get("line", "0")),
            "title": r.get("details", "")[:100],
            "description": r.get("details", ""),
            "confidence": float({"HIGH": 0.9, "MEDIUM": 0.7, "LOW": 0.5}.get(r.get("confidence", "MEDIUM"), 0.7)),
            "rule_id": r.get("rule_id", ""),
            "detected_by": ["gosec"], "recommendation": "",
        })
    return findings


def parse_trufflehog(path):
    data = json.loads(path.read_text())
    if not isinstance(data, list):
        return []
    findings = []
    for i, r in enumerate(data, 1):
        meta = r.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {})
        findings.append({
            "id": make_id("trufflehog", i), "source": "trufflehog",
            "severity": "high", "category": "secrets",
            "file": meta.get("file", ""), "line_start": meta.get("line", 0),
            "line_end": meta.get("line", 0),
            "title": f"Secret: {r.get('DetectorName', 'unknown')}",
            "description": f"Verified: {r.get('Verified', False)}",
            "confidence": 0.95 if r.get("Verified") else 0.6,
            "rule_id": r.get("DetectorName", ""),
            "detected_by": ["trufflehog"], "recommendation": "Remove secret and rotate credentials",
        })
    return findings


def parse_govulncheck(path):
    data = json.loads(path.read_text())
    if not isinstance(data, list):
        return []
    findings = []
    n = 0
    for entry in data:
        finding = entry.get("finding", {})
        if not finding:
            continue
        osv_id = finding.get("osv", "")
        if not osv_id:
            continue
        n += 1
        trace = finding.get("trace", [{}])
        pkg = trace[0].get("module", "") if trace else ""
        findings.append({
            "id": make_id("govulncheck", n), "source": "govulncheck",
            "severity": "high", "category": "sca",
            "file": trace[0].get("position", {}).get("filename", "") if trace else "",
            "line_start": trace[0].get("position", {}).get("line", 0) if trace else 0,
            "line_end": 0,
            "title": f"{osv_id}: {pkg}",
            "description": f"Vulnerability in {pkg}",
            "confidence": 0.9, "rule_id": osv_id,
            "detected_by": ["govulncheck"], "recommendation": f"Update {pkg}",
        })
    return findings


def parse_pip_audit(path):
    data = json.loads(path.read_text())
    deps = data.get("dependencies", [])
    findings = []
    n = 0
    for dep in deps:
        for vuln in dep.get("vulns", []):
            n += 1
            findings.append({
                "id": make_id("pip-audit", n), "source": "pip-audit",
                "severity": "high", "category": "sca",
                "file": "requirements.txt", "line_start": 0, "line_end": 0,
                "title": f"{vuln.get('id', '')}: {dep.get('name', '')} {dep.get('version', '')}",
                "description": vuln.get("description", "")[:500],
                "confidence": 0.9, "rule_id": vuln.get("id", ""),
                "detected_by": ["pip-audit"],
                "recommendation": f"Update to {vuln.get('fix_versions', ['latest'])[0]}" if vuln.get("fix_versions") else "Update package",
            })
    return findings


def parse_osv_scanner(path):
    data = json.loads(path.read_text())
    findings = []
    n = 0
    for result in data.get("results", []):
        source_path = result.get("source", {}).get("path", "")
        for pkg in result.get("packages", []):
            pkg_info = pkg.get("package", {})
            for v in pkg.get("vulnerabilities", []):
                n += 1
                sev = "medium"
                for s in v.get("severity", []):
                    score = s.get("score", "")
                    if isinstance(score, str) and ":" in score:
                        try:
                            base = float(score.split("/")[0].split(":")[-1])
                            if base >= 9.0: sev = "critical"
                            elif base >= 7.0: sev = "high"
                            elif base >= 4.0: sev = "medium"
                            else: sev = "low"
                        except (ValueError, IndexError):
                            pass
                findings.append({
                    "id": make_id("osv-scanner", n), "source": "osv-scanner",
                    "severity": sev, "category": "sca",
                    "file": source_path, "line_start": 0, "line_end": 0,
                    "title": f"{v.get('id', '')}: {pkg_info.get('name', '')}",
                    "description": v.get("summary", "")[:500],
                    "confidence": 0.85, "rule_id": v.get("id", ""),
                    "detected_by": ["osv-scanner"],
                    "recommendation": f"Update {pkg_info.get('name', '')}",
                })
    return findings


PARSERS = {
    "semgrep.json": ("semgrep", parse_semgrep),
    "gitleaks-report.json": ("gitleaks", parse_gitleaks),
    "trufflehog-report.json": ("trufflehog", parse_trufflehog),
    "trivy-report.json": ("trivy", parse_trivy),
    "grype-report.json": ("grype", parse_grype),
    "kube-linter.json": ("kube-linter", parse_kube_linter),
    "hadolint.sarif": ("hadolint", lambda p: parse_sarif(p, "hadolint")),
    "zizmor.sarif": ("zizmor", lambda p: parse_sarif(p, "zizmor")),
    "shellcheck-report.json": ("shellcheck", parse_shellcheck),
    "gosec-report.json": ("gosec", parse_gosec),
    "govulncheck-report.json": ("govulncheck", parse_govulncheck),
    "pip-audit-report.json": ("pip-audit", parse_pip_audit),
    "osv-scanner-report.json": ("osv-scanner", parse_osv_scanner),
}


def main():
    if len(sys.argv) < 2:
        print("Usage: normalize.py <results-dir>", file=sys.stderr)
        sys.exit(1)

    results_dir = Path(sys.argv[1])
    if not results_dir.is_dir():
        print(f"Not a directory: {results_dir}", file=sys.stderr)
        sys.exit(1)

    all_findings = []
    for filename, (tool, parser) in PARSERS.items():
        filepath = results_dir / filename
        if not filepath.exists():
            for sub in results_dir.iterdir():
                if sub.is_dir():
                    candidate = sub / filename
                    if candidate.exists():
                        filepath = candidate
                        break
        if not filepath.exists():
            continue
        try:
            findings = parser(filepath)
            all_findings.extend(findings)
        except Exception as e:
            print(f"Warning: failed to parse {filepath}: {e}", file=sys.stderr)

    json.dump(all_findings, sys.stdout, indent=2)


if __name__ == "__main__":
    main()
