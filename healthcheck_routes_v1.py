# /// script
# requires-python = ">=3.10"
# ///

import sys
import time
import json
import urllib.request
import urllib.error

DIRECTUS_URL = "https://directus.startstak.ai/items/pages?limit=-1&fields=slug"
BASE_URL = "https://startstak.ai"
TIMEOUT = 10


def fetch_slugs():
    print(f'$ curl -s "{DIRECTUS_URL}"')
    req = urllib.request.Request(DIRECTUS_URL)
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        raw = resp.read().decode()
    print(raw, flush=True)
    data = json.loads(raw)
    slugs = [item["slug"] for item in data.get("data", []) if item.get("slug")]
    print(f"\nFound {len(slugs)} routes. Starting health check...\n")
    return slugs


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


no_redirect_opener = urllib.request.build_opener(NoRedirectHandler)


def check_route(url):
    req = urllib.request.Request(url, method="GET")
    try:
        start = time.time()
        with no_redirect_opener.open(req, timeout=TIMEOUT) as resp:
            elapsed_ms = int((time.time() - start) * 1000)
            return resp.status, elapsed_ms, None
    except urllib.error.HTTPError as e:
        elapsed_ms = int((time.time() - start) * 1000)
        return e.code, elapsed_ms, None
    except TimeoutError:
        return None, None, "TIMEOUT"
    except Exception as e:
        return None, None, str(e)


def main():
    slugs = fetch_slugs()

    counts = {"ok": 0, "redirect": 0, "error": 0, "timeout": 0, "conn_error": 0}
    print("-" * 70)

    for slug in sorted(slugs):
        url = f"{BASE_URL}{slug}"
        status, ms, err = check_route(url)

        if err:
            if "TIMEOUT" in err:
                counts["timeout"] += 1
                print(f"[TIMEOUT] ---   >10s   {url}", flush=True)
            else:
                counts["conn_error"] += 1
                print(f"[ERROR]   ---   ---    {url}  ({err})", flush=True)
        elif 200 <= status < 300:
            counts["ok"] += 1
            print(f"[OK]      {status}   {ms:>5}ms  {url}", flush=True)
        elif 300 <= status < 400:
            counts["redirect"] += 1
            print(f"[WARN]    {status}   {ms:>5}ms  {url}", flush=True)
        else:
            counts["error"] += 1
            print(f"[FAIL]    {status}   {ms:>5}ms  {url}", flush=True)

    total = len(slugs)
    print("-" * 70)
    print(f"\n{'=' * 30} SUMMARY {'=' * 30}")
    print(f"Total:            {total}")
    print(f"OK (2xx):         {counts['ok']}")
    print(f"Redirect (3xx):   {counts['redirect']}")
    print(f"Error (4xx/5xx):  {counts['error']}")
    print(f"Timeout:          {counts['timeout']}")
    print(f"Conn error:       {counts['conn_error']}")
    print("=" * 69)

    if counts["error"] or counts["timeout"] or counts["conn_error"]:
        sys.exit(1)


if __name__ == "__main__":
    main()
