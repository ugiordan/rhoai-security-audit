# Report Command

Generate consolidated security reports from existing scan data.

## Usage

```
/security-audit:report [--repo <name>] [--full] [--format md|docx] [--date <YYYY-MM-DD>]
```

## Steps

1. **Find scan data**: Look in `output/<repo>/` for the latest dated
   directory (or specific `--date`). If `--repo` not specified, find
   all repos with scan data.

2. **Load findings**: Read `deduplicated-findings.json` (preferred) or
   `normalized-findings.json` (fallback) from the scan directory.

3. **Generate report**:
   ```bash
   python3 "${SKILL_DIR}/scripts/report.py" "$SCAN_DIR" [--full]
   ```

4. **Present to user**: Display the report and save to the scan directory.

## Report Types

**Executive Report** (default):
- Critical + High findings only
- Deduplicated, with tool attribution
- Top 5 actionable recommendations
- Concise, shareable

**Full Report** (`--full`):
- All severities including medium, low, info
- Complete tool coverage matrix
- Cross-tool overlap analysis
- Detailed per-tool breakdown
