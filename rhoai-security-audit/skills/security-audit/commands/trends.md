# Trends Command

Show security finding trends across previous scan runs.

## Usage

```
/security-audit:trends [--repo <name>] [--last <n>] [--output <dir>]
```

## Steps

1. **Load trends data**:
   ```bash
   python3 "${SKILL_DIR}/scripts/trends.py" \
     --show \
     --trends-file "output/security-trends.json" \
     [--repo <name>] \
     [--last <n>]
   ```

2. **Present to user**: Display the markdown trends table.

## Output Format

Markdown table with columns:

| Date | Repo | Branch | Commit | Critical | High | Medium | Low | Total | Delta |
|------|------|--------|--------|----------|------|--------|-----|-------|-------|

Delta column shows change from previous run:
- Green down arrow for decrease (improvement)
- Red up arrow for increase (regression)
- Dash for first run (no comparison)

## Interpretation Guide

- **Consistent decrease**: security posture improving
- **Sudden spike**: new code or tool added, investigate
- **Same numbers**: no change, check if scans are running
- **Tool count change**: different tools run, not comparable
