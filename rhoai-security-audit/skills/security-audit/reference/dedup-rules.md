# Deduplication Rules

## What constitutes a duplicate

Two findings are duplicates when ALL of these match:
1. Same `file` path
2. Overlapping line range (within 5 lines of each other)
3. Same or compatible `category`

## Merge strategy

When merging duplicates:
- **severity**: keep the highest (critical > high > medium > low > info)
- **detected_by**: combine all tool names into a list
- **description**: keep the longest description
- **recommendation**: keep the first non-empty recommendation
- **confidence**: keep the highest
- **id**: use the first finding's ID
- **source**: use the first finding's source

## Category compatibility

Findings in these categories are considered compatible for dedup:
- injection + injection
- auth + auth
- secrets + secrets + crypto (overlapping concern)
- config + k8s (k8s misconfigs are configs)
- sca + sca
- cicd + cicd

Different categories are NOT deduplicated even if same file+line.
