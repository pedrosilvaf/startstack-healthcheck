# /// script
# requires-python = ">=3.10"
# ///

import sys
import os
import time
import json
import ssl
import argparse
import urllib.request
import urllib.error
import urllib.parse
from http.cookiejar import CookieJar
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


# ── .env Loader ──────────────────────────────────────────────────────


def load_dotenv(path: str | Path | None = None) -> None:
    """Load variables from a .env file into os.environ (no third-party deps)."""
    candidates = [Path(path)] if path else [
        Path(__file__).resolve().parent / ".env",
        Path(__file__).resolve().parent.parent / ".env",
    ]
    for env_path in candidates:
        if env_path.is_file():
            print(f"  Loading env from: {env_path}")
            with open(env_path) as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    key, _, value = line.partition("=")
                    key = key.strip()
                    value = value.strip()
                    # Strip surrounding quotes
                    if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
                        value = value[1:-1]
                    os.environ.setdefault(key, value)
            return
    print("  No .env file found, using existing environment variables")


# ── Defaults ─────────────────────────────────────────────────────────

DEFAULT_BASE_URL = "https://startstak.ai"
DEFAULT_DIRECTUS_URL = "https://directus.startstak.ai"
TIMEOUT = 10
DIRECTUS_STATUS_FILTER = "filter[status][_eq]=published"

# ── SSL Setup ────────────────────────────────────────────────────────

try:
    import certifi
    SSL_CTX = ssl.create_default_context(cafile=certifi.where())
except ImportError:
    SSL_CTX = ssl.create_default_context()
    SSL_CTX.check_hostname = False
    SSL_CTX.verify_mode = ssl.CERT_NONE

# ── Enums & Data Classes ────────────────────────────────────────────


class UserType(Enum):
    UNAUTHENTICATED = "unauthenticated"
    FREE_TRIAL = "free-trial"
    AUTH_NO_PLAN = "auth-no-plan"
    AUTH_WITH_PLAN = "auth-with-plan"


USER_TYPE_LABELS = {
    UserType.UNAUTHENTICATED: "Unauthenticated User",
    UserType.FREE_TRIAL: "Authenticated User (Free Trial)",
    UserType.AUTH_NO_PLAN: "Authenticated User (No Plan)",
    UserType.AUTH_WITH_PLAN: "Authenticated User (With Plan)",
}


class ExpectedResult(Enum):
    OK = "ok"
    REDIRECT = "redirect"


@dataclass
class RouteSpec:
    path: str
    category: str
    expected: dict  # UserType -> ExpectedResult


@dataclass
class CheckResult:
    route: RouteSpec
    user_type: UserType
    status: int | None
    elapsed_ms: int | None
    error: str | None
    passed: bool


# ── Route Builders ───────────────────────────────────────────────────

ALL_USER_TYPES = list(UserType)


def public_route(path: str, category: str) -> RouteSpec:
    return RouteSpec(
        path=path,
        category=category,
        expected={ut: ExpectedResult.OK for ut in ALL_USER_TYPES},
    )


def protected_route(path: str, category: str) -> RouteSpec:
    expected = {ut: ExpectedResult.OK for ut in ALL_USER_TYPES}
    expected[UserType.UNAUTHENTICATED] = ExpectedResult.REDIRECT
    return RouteSpec(path=path, category=category, expected=expected)


# ── HTTP Helpers ─────────────────────────────────────────────────────


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def build_opener(cookie_jar: CookieJar | None = None):
    handlers = [
        NoRedirectHandler,
        urllib.request.HTTPSHandler(context=SSL_CTX),
    ]
    if cookie_jar is not None:
        handlers.append(urllib.request.HTTPCookieProcessor(cookie_jar))
    return urllib.request.build_opener(*handlers)


# ── Authentication ───────────────────────────────────────────────────

USER_TYPE_ENV_MAP = {
    UserType.FREE_TRIAL: ("HC_FREE_TRIAL_EMAIL", "HC_FREE_TRIAL_PASSWORD"),
    UserType.AUTH_NO_PLAN: ("HC_AUTH_NO_PLAN_EMAIL", "HC_AUTH_NO_PLAN_PASSWORD"),
    UserType.AUTH_WITH_PLAN: ("HC_AUTH_WITH_PLAN_EMAIL", "HC_AUTH_WITH_PLAN_PASSWORD"),
}


def authenticate_via_nextauth(base_url: str, email: str, password: str) -> CookieJar:
    cookie_jar = CookieJar()
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(cookie_jar),
        urllib.request.HTTPSHandler(context=SSL_CTX),
    )

    # Step 1: Get CSRF token
    csrf_url = f"{base_url}/api/auth/csrf"
    csrf_req = urllib.request.Request(csrf_url)
    with opener.open(csrf_req, timeout=TIMEOUT) as resp:
        csrf_data = json.loads(resp.read().decode())
        csrf_token = csrf_data["csrfToken"]

    # Step 2: POST credentials
    form_data = urllib.parse.urlencode({
        "email": email,
        "password": password,
        "csrfToken": csrf_token,
        "json": "true",
    }).encode()

    login_url = f"{base_url}/api/auth/callback/credentials"
    login_req = urllib.request.Request(login_url, data=form_data, method="POST")
    login_req.add_header("Content-Type", "application/x-www-form-urlencoded")

    try:
        with opener.open(login_req, timeout=TIMEOUT) as resp:
            pass
    except urllib.error.HTTPError:
        # NextAuth may redirect after login, which is expected
        pass

    # Verify we got a session cookie
    session_cookie = None
    for cookie in cookie_jar:
        if "session-token" in cookie.name:
            session_cookie = cookie
            break

    if not session_cookie:
        raise RuntimeError("Authentication failed: no session cookie received")

    return cookie_jar


def authenticate_user_types(
    base_url: str, requested_types: list[UserType]
) -> dict[UserType, CookieJar | None]:
    sessions: dict[UserType, CookieJar | None] = {}
    sessions[UserType.UNAUTHENTICATED] = None

    for ut in requested_types:
        if ut == UserType.UNAUTHENTICATED:
            continue

        env_email, env_pass = USER_TYPE_ENV_MAP[ut]
        email = os.environ.get(env_email)
        password = os.environ.get(env_pass)

        if not email or not password:
            print(f"  [SKIP] {ut.value}: missing env vars {env_email} / {env_pass}")
            continue

        try:
            print(f"  Authenticating {ut.value}...", end=" ", flush=True)
            cookie_jar = authenticate_via_nextauth(base_url, email, password)
            sessions[ut] = cookie_jar
            print("OK")
        except Exception as e:
            print(f"FAILED ({e})")

    return sessions


# ── Directus Fetchers ────────────────────────────────────────────────


def fetch_directus_items(directus_url: str, endpoint: str) -> list[str]:
    url = f"{directus_url}/items/{endpoint}"
    req = urllib.request.Request(url)
    with urllib.request.urlopen(req, timeout=TIMEOUT, context=SSL_CTX) as resp:
        data = json.loads(resp.read().decode())
    return [item["slug"] for item in data.get("data", []) if item.get("slug")]


def normalize_path(slug: str, prefix: str = "") -> str:
    slug = slug.strip("/")
    if prefix:
        return f"{prefix}/{slug}"
    return f"/{slug}"


def fetch_page_routes(directus_url: str) -> list[RouteSpec]:
    slugs = fetch_directus_items(directus_url, f"pages?limit=-1&fields=slug&{DIRECTUS_STATUS_FILTER}")
    return [public_route(s, "pages") for s in slugs]


def fetch_academy_static_routes(directus_url: str) -> list[RouteSpec]:
    slugs = fetch_directus_items(directus_url, "static_pages?limit=-1&fields=slug")
    return [public_route(s, "academy-static") for s in slugs]


def fetch_article_routes(directus_url: str) -> list[RouteSpec]:
    slugs = fetch_directus_items(
        directus_url,
        "articles?limit=-1&fields=slug&filter[status][_eq]=published",
    )
    return [public_route(normalize_path(s, "/academy/articles"), "articles") for s in slugs]


def fetch_event_routes(directus_url: str) -> list[RouteSpec]:
    slugs = fetch_directus_items(
        directus_url,
        "events?limit=-1&fields=slug&filter[status][_eq]=published",
    )
    return [public_route(normalize_path(s, "/academy/events"), "events") for s in slugs]


def fetch_qa_routes(directus_url: str) -> list[RouteSpec]:
    slugs = fetch_directus_items(
        directus_url,
        "q_and_a?limit=-1&fields=slug&filter[status][_eq]=published",
    )
    return [public_route(normalize_path(s, "/academy/q-and-a"), "q-and-a") for s in slugs]


def fetch_course_routes(directus_url: str) -> list[RouteSpec]:
    slugs = fetch_directus_items(
        directus_url,
        "courses?limit=-1&fields=slug&filter[status][_eq]=published",
    )
    return [public_route(normalize_path(s, "/academy/on-demand-learning"), "courses") for s in slugs]


def get_profile_routes() -> list[RouteSpec]:
    paths = [
        "/academy/profile/dashboard",
        "/academy/profile/account",
        "/academy/profile/account/profile",
        "/academy/profile/account/subscription",
        "/academy/profile/account/change-email",
        "/academy/profile/account/change-password",
        "/academy/profile/notifications",
        "/academy/profile/events",
        "/academy/profile/activity",
    ]
    return [protected_route(p, "profile") for p in paths]


CATEGORY_FETCHERS = {
    "academy-static": fetch_academy_static_routes,
    "articles": fetch_article_routes,
    "events": fetch_event_routes,
    "q-and-a": fetch_qa_routes,
    "courses": fetch_course_routes,
}


def collect_academy_routes(
    directus_url: str, categories: list[str] | None = None
) -> list[RouteSpec]:
    all_categories = ["academy-static", "articles", "events", "q-and-a", "courses", "profile"]
    selected = categories if categories else all_categories

    routes: list[RouteSpec] = []
    for cat in selected:
        if cat == "profile":
            items = get_profile_routes()
        elif cat in CATEGORY_FETCHERS:
            items = CATEGORY_FETCHERS[cat](directus_url)
        else:
            continue
        print(f"  {cat}: {len(items)} routes")
        routes.extend(items)

    return routes


# ── Check Engine ─────────────────────────────────────────────────────


def check_route(url: str, opener) -> tuple[int | None, int | None, str | None]:
    req = urllib.request.Request(url, method="GET")
    req.add_header("User-Agent", "StartStak-HealthCheck/2.0")
    timeout_ms = int(TIMEOUT * 1000)
    try:
        start = time.time()
        with opener.open(req, timeout=TIMEOUT + 5) as resp:
            elapsed_ms = int((time.time() - start) * 1000)
            if elapsed_ms > timeout_ms:
                return resp.status, elapsed_ms, "SOFT_TIMEOUT"
            return resp.status, elapsed_ms, None
    except urllib.error.HTTPError as e:
        elapsed_ms = int((time.time() - start) * 1000)
        if elapsed_ms > timeout_ms:
            return e.code, elapsed_ms, "SOFT_TIMEOUT"
        return e.code, elapsed_ms, None
    except TimeoutError:
        elapsed_ms = int((time.time() - start) * 1000)
        return None, elapsed_ms, "TIMEOUT"
    except Exception as e:
        return None, None, str(e)


def check_final_destination(url: str) -> tuple[int | None, int | None, str | None, str | None]:
    """Follow redirects and return (final_status, elapsed_ms, error, final_url)."""
    follow_opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=SSL_CTX),
    )
    req = urllib.request.Request(url, method="GET")
    req.add_header("User-Agent", "StartStak-HealthCheck/2.0")
    try:
        start = time.time()
        with follow_opener.open(req, timeout=TIMEOUT + 5) as resp:
            elapsed_ms = int((time.time() - start) * 1000)
            return resp.status, elapsed_ms, None, resp.url
    except urllib.error.HTTPError as e:
        elapsed_ms = int((time.time() - start) * 1000)
        return e.code, elapsed_ms, None, None
    except TimeoutError:
        elapsed_ms = int((time.time() - start) * 1000)
        return None, elapsed_ms, "TIMEOUT", None
    except Exception as e:
        return None, None, str(e), None


def evaluate_result(
    status: int | None, error: str | None, expected: ExpectedResult
) -> bool:
    if error:
        return False
    if expected == ExpectedResult.OK:
        # 308 is a trailing-slash redirect from Next.js, treat as OK
        return 200 <= status < 300 or status == 308
    if expected == ExpectedResult.REDIRECT:
        return 300 <= status < 400
    return False


# ── Pages Check (backward compatible) ───────────────────────────────


def run_pages_check(base_url: str, directus_url: str) -> dict:
    print(f"\n{'=' * 28} PAGES {'=' * 28}")
    slugs = fetch_directus_items(directus_url, f"pages?limit=-1&fields=slug&{DIRECTUS_STATUS_FILTER}")
    print(f"  Found {len(slugs)} page routes\n")

    opener = build_opener()
    counts = {"total": 0, "pass": 0, "fail": 0, "timeout": 0, "error": 0}

    print("-" * 62)
    for slug in sorted(slugs):
        url = f"{base_url}{slug}"
        status, ms, err = check_route(url, opener)
        counts["total"] += 1

        if err:
            if "TIMEOUT" in err:
                counts["timeout"] += 1
                ms_str = f"{ms}ms" if ms else ">timeout"
                print(f"  [TIMEOUT] {status or '---'}   {ms_str:>7}  {url}", flush=True)
            else:
                counts["error"] += 1
                print(f"  [ERROR]   ---   ---    {url}  ({err})", flush=True)
        elif 200 <= status < 300:
            counts["pass"] += 1
            print(f"  [OK]      {status}   {ms:>5}ms  {url}", flush=True)
        elif 300 <= status < 400:
            # Follow redirect and check final destination
            final_status, final_ms, final_err, final_url = check_final_destination(url)
            if not final_err and final_status and 200 <= final_status < 300:
                counts["pass"] += 1
                print(f"  [REDIR]   {status}→{final_status}   {ms:>5}ms  {url} → {final_url}", flush=True)
            else:
                counts["fail"] += 1
                dest = f" → {final_url}" if final_url else ""
                print(f"  [FAIL]    {status}→{final_status or '---'}   {ms:>5}ms  {url}{dest}", flush=True)
        else:
            counts["fail"] += 1
            print(f"  [FAIL]    {status}   {ms:>5}ms  {url}", flush=True)

    print("-" * 62)
    return counts


# ── Academy Check ────────────────────────────────────────────────────


def run_academy_check(
    base_url: str,
    routes: list[RouteSpec],
    user_type: UserType,
    cookie_jar: CookieJar | None,
) -> dict:
    label = USER_TYPE_LABELS[user_type]
    header = f" ACADEMY ROUTES: {label} "
    print(f"\n{header:=^62}")

    opener = build_opener(cookie_jar)
    counts = {"total": 0, "pass": 0, "fail": 0, "timeout": 0, "error": 0}
    current_category = None

    for route in routes:
        if route.category != current_category:
            current_category = route.category
            print(f"\n  --- {current_category} ---")

        url = f"{base_url}{route.path}"
        expected = route.expected.get(user_type, ExpectedResult.OK)
        status, ms, err = check_route(url, opener)
        counts["total"] += 1

        passed = evaluate_result(status, err, expected)

        # If redirect received but expected OK, follow redirect to check destination
        if not err and not passed and expected == ExpectedResult.OK and status and 300 <= status < 400:
            url = f"{base_url}{route.path}"
            final_status, final_ms, final_err, final_url = check_final_destination(url)
            if not final_err and final_status and 200 <= final_status < 300:
                counts["pass"] += 1
                print(f"  [REDIR]   {status}→{final_status}   {ms:>5}ms  {route.path} → {final_url}", flush=True)
                continue
            else:
                counts["fail"] += 1
                dest = f" → {final_url}" if final_url else ""
                print(
                    f"  [FAIL]    {status}→{final_status or '---'}   {ms:>5}ms  {route.path}{dest}"
                    f"  (expected: {expected.value})",
                    flush=True,
                )
                continue

        if err:
            if "TIMEOUT" in err:
                counts["timeout"] += 1
                ms_str = f"{ms}ms" if ms else ">timeout"
                print(f"  [TIMEOUT] {status or '---'}   {ms_str:>7}  {route.path}", flush=True)
            else:
                counts["error"] += 1
                print(f"  [ERROR]   ---   ---    {route.path}  ({err})", flush=True)
        elif passed:
            counts["pass"] += 1
            hint = f"  (expected: {expected.value})" if expected != ExpectedResult.OK else ""
            print(f"  [PASS]    {status}   {ms:>5}ms  {route.path}{hint}", flush=True)
        else:
            counts["fail"] += 1
            print(
                f"  [FAIL]    {status}   {ms:>5}ms  {route.path}"
                f"  (expected: {expected.value})",
                flush=True,
            )

    return counts


# ── Summary ──────────────────────────────────────────────────────────


def print_summary(all_counts: dict[str, dict]):
    print(f"\n{'=' * 30} SUMMARY {'=' * 30}")

    headers = list(all_counts.keys())
    col_w = max(14, *(len(h) + 2 for h in headers))

    # Header row
    print(f"  {'':>14}", end="")
    for h in headers:
        print(f"{h:>{col_w}}", end="")
    print()

    # Data rows
    for metric in ["total", "pass", "fail", "timeout", "error"]:
        label = f"{metric.capitalize()}:"
        print(f"  {label:>14}", end="")
        for h in headers:
            val = all_counts[h].get(metric, 0)
            print(f"{val:>{col_w}}", end="")
        print()

    print("=" * 61)


# ── CLI ──────────────────────────────────────────────────────────────


def parse_args():
    parser = argparse.ArgumentParser(
        description="Health check for startstak.ai routes"
    )
    parser.add_argument(
        "--academy-only",
        action="store_true",
        help="Only test academy routes (skip pages)",
    )
    parser.add_argument(
        "--pages-only",
        action="store_true",
        help="Only test page routes (original behavior)",
    )
    parser.add_argument(
        "--user-type",
        choices=["unauthenticated", "free-trial", "auth-no-plan", "auth-with-plan"],
        action="append",
        dest="user_types",
        help="Test only specific user type(s). Can be repeated.",
    )
    parser.add_argument(
        "--category",
        choices=["academy-static", "articles", "events", "q-and-a", "courses", "profile"],
        action="append",
        dest="categories",
        help="Test only specific route category(s). Can be repeated.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=TIMEOUT,
        help=f"Request timeout in seconds (default: {TIMEOUT})",
    )
    parser.add_argument(
        "--base-url",
        default=DEFAULT_BASE_URL,
        help=f"Base URL to test (default: {DEFAULT_BASE_URL})",
    )
    parser.add_argument(
        "--directus-url",
        default=DEFAULT_DIRECTUS_URL,
        help=f"Directus API URL (default: {DEFAULT_DIRECTUS_URL})",
    )
    parser.add_argument(
        "--env-file",
        default=None,
        help="Path to .env file with credentials (default: auto-detect)",
    )
    return parser.parse_args()


# ── Main ─────────────────────────────────────────────────────────────


def main():
    global TIMEOUT
    args = parse_args()

    # Load .env before anything else
    load_dotenv(args.env_file)

    TIMEOUT = args.timeout

    all_counts: dict[str, dict] = {}
    has_failures = False

    print(f"Base URL:     {args.base_url}")
    print(f"Directus URL: {args.directus_url}")
    print(f"Timeout:      {TIMEOUT}s")

    # ── Pages ────────────────────────────────────────────────────────
    if not args.academy_only:
        counts = run_pages_check(args.base_url, args.directus_url)
        all_counts["pages"] = counts
        if counts["fail"] or counts["timeout"] or counts["error"]:
            has_failures = True

    # ── Academy ──────────────────────────────────────────────────────
    if not args.pages_only:
        # Determine user types
        if args.user_types:
            user_types = [UserType(ut) for ut in args.user_types]
        else:
            user_types = list(UserType)

        # Fetch routes
        print(f"\n{'=' * 22} FETCHING ACADEMY ROUTES {'=' * 22}")
        academy_routes = collect_academy_routes(args.directus_url, args.categories)
        print(f"\n  Total: {len(academy_routes)} academy routes")

        # Authenticate
        print(f"\n{'=' * 24} AUTHENTICATION {'=' * 24}")
        sessions = authenticate_user_types(args.base_url, user_types)

        # Run checks per user type
        for ut in user_types:
            if ut not in sessions and ut != UserType.UNAUTHENTICATED:
                continue

            cookie_jar = sessions.get(ut)
            counts = run_academy_check(args.base_url, academy_routes, ut, cookie_jar)
            all_counts[ut.value] = counts
            if counts["fail"] or counts["timeout"] or counts["error"]:
                has_failures = True

    # ── Summary ──────────────────────────────────────────────────────
    if all_counts:
        print_summary(all_counts)

    if has_failures:
        sys.exit(1)


if __name__ == "__main__":
    main()
