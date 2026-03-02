# StartStak Healthcheck - v1

Simple health check script for **page routes** on [startstak.ai](https://startstak.ai), dynamically fetching slugs from Directus CMS.

## What it does

- Fetches all slugs from the `pages` collection in Directus
- Tests each route with a `GET` request and reports the HTTP status
- Classifies results: `OK` (2xx), `WARN` (3xx redirect), `FAIL` (4xx/5xx), `TIMEOUT`, `ERROR`
- Displays a summary with counts for each status
- Returns exit code `1` if any failures occur

## Requirements

- Python >= 3.10
- No external dependencies (stdlib only)

## Usage

```bash
python3 healthcheck_routes_v1.py
```

## Example output

```
Found 12 routes. Starting health check...

----------------------------------------------------------------------
[OK]      200     412ms  https://startstak.ai/about
[OK]      200     389ms  https://startstak.ai/contact
[FAIL]    404     350ms  https://startstak.ai/old-page
----------------------------------------------------------------------

============================== SUMMARY ==============================
Total:            12
OK (2xx):         11
Redirect (3xx):   0
Error (4xx/5xx):  1
Timeout:          0
Conn error:       0
=====================================================================
```

## Configuration

URLs are defined as constants in the script:

```python
DIRECTUS_URL = "https://directus.startstak.ai/items/pages?limit=-1&fields=slug"
BASE_URL = "https://startstak.ai"
TIMEOUT = 10
```

Edit the file directly to change them.
