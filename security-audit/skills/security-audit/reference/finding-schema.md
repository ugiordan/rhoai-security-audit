# Normalized Finding Schema

All tools output findings in this format after normalization.

```json
{
  "id": "SEM-001",
  "source": "semgrep",
  "severity": "critical|high|medium|low|info",
  "category": "injection|auth|crypto|config|secrets|k8s|cicd|sca|data-exposure|other",
  "file": "path/to/file.go",
  "line_start": 42,
  "line_end": 55,
  "title": "Short description",
  "description": "Full message from the tool",
  "confidence": 0.85,
  "rule_id": "original-rule-id",
  "detected_by": ["semgrep"],
  "recommendation": ""
}
```

## ID Prefixes

| Prefix | Tool |
|--------|------|
| SEM | semgrep |
| GLK | gitleaks |
| THG | trufflehog |
| TRV | trivy |
| GRP | grype |
| KBL | kube-linter |
| HDL | hadolint |
| ACT | actionlint |
| ZIZ | zizmor |
| GVC | govulncheck |
| SHC | shellcheck |
| GSC | gosec |
| PIP | pip-audit |
| OSV | osv-scanner |
| YML | yamllint |
| ADV | adversarial-reviewing |
| SSC | semantic-scan |

## Categories

| Category | Description |
|----------|-------------|
| injection | SQL, command, template, header injection |
| auth | Authentication, authorization, session, RBAC |
| crypto | Weak algorithms, hardcoded keys, TLS bypass |
| config | Misconfigurations, debug mode, defaults |
| secrets | Hardcoded credentials, exposed tokens |
| k8s | Kubernetes/container security (SCC, network, RBAC) |
| cicd | CI/CD pipeline security (actions, workflows) |
| sca | Vulnerable dependencies (CVEs) |
| data-exposure | Sensitive data in logs, errors, responses |
| other | Anything not fitting above categories |
