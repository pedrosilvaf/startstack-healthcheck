# /// script
# requires-python = ">=3.9"
# ///

from __future__ import annotations

import sys
import os
import time
import json
import ssl
import argparse
import urllib.request
import urllib.error
import urllib.parse
import statistics
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from http.cookiejar import CookieJar
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Optional

try:
    import boto3
except ImportError:
    boto3 = None

# ── .env Loader ──────────────────────────────────────────────────────


def load_dotenv(path: str | Path | None = None) -> None:
    """Load variables from a .env file into os.environ (no third-party deps)."""
    candidates = [Path(path)] if path else [
        Path(__file__).resolve().parent / ".env",
        Path(__file__).resolve().parent.parent / ".env",
    ]
    for env_path in candidates:
        if env_path.is_file():
            _log(f"Loading env from: {env_path}")
            with open(env_path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    key, _, value = line.partition("=")
                    key = key.strip()
                    value = value.strip()
                    if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
                        value = value[1:-1]
                    os.environ.setdefault(key, value)
            return
    _log("No .env file found, using existing environment variables")


# ── Terminal Colors ──────────────────────────────────────────────────

_USE_COLOR = sys.stdout.isatty()


def _c(code: str, text: str) -> str:
    if not _USE_COLOR:
        return text
    return f"\033[{code}m{text}\033[0m"


def _green(t: str) -> str: return _c("32", t)
def _red(t: str) -> str: return _c("31", t)
def _yellow(t: str) -> str: return _c("33", t)
def _cyan(t: str) -> str: return _c("36", t)
def _bold(t: str) -> str: return _c("1", t)
def _dim(t: str) -> str: return _c("2", t)


def _log(msg: str) -> None:
    print(f"  {msg}", flush=True)


# ── Defaults ─────────────────────────────────────────────────────────

DEFAULT_BASE_URL = "https://startstak.ai"
DEFAULT_DIRECTUS_URL = "https://directus.startstak.ai"
TIMEOUT = 10
DEFAULT_CONCURRENCY = 8
DIRECTUS_STATUS_FILTER = "filter[status][_eq]=published"
USER_AGENT = "StartStak-HealthCheck/3.0"

DEFAULT_SNS_SUBJECT = "Endpoint Health Check"
RETRY_DELAYS = [10, 20]


# ── SSL Setup ────────────────────────────────────────────────────────

try:
    import certifi  # type: ignore
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
    url: str
    path: str
    category: str
    status: int | None
    elapsed_ms: int | None
    error: str | None
    expected: str
    passed: bool
    redirect_to: str | None = None
    final_status: int | None = None
    final_error: str | None = None
    retries: int = 0


@dataclass
class SuiteStats:
    latencies: list[int] = field(default_factory=list)

    def add(self, ms: int | None) -> None:
        if ms is not None:
            self.latencies.append(ms)

    def to_dict(self) -> dict[str, Any]:
        if not self.latencies:
            return {"min_ms": None, "max_ms": None, "avg_ms": None, "p95_ms": None, "median_ms": None}
        s = sorted(self.latencies)
        p95_idx = max(0, int(len(s) * 0.95) - 1)
        return {
            "min_ms": s[0],
            "max_ms": s[-1],
            "avg_ms": int(statistics.mean(s)),
            "p95_ms": s[p95_idx],
            "median_ms": int(statistics.median(s)),
        }


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

    csrf_url = f"{base_url}/api/auth/csrf"
    csrf_req = urllib.request.Request(csrf_url)
    csrf_req.add_header("User-Agent", USER_AGENT)

    with opener.open(csrf_req, timeout=TIMEOUT) as resp:
        csrf_data = json.loads(resp.read().decode())
        csrf_token = csrf_data["csrfToken"]

    form_data = urllib.parse.urlencode({
        "email": email,
        "password": password,
        "csrfToken": csrf_token,
        "json": "true",
    }).encode()

    login_url = f"{base_url}/api/auth/callback/credentials"
    login_req = urllib.request.Request(login_url, data=form_data, method="POST")
    login_req.add_header("Content-Type", "application/x-www-form-urlencoded")
    login_req.add_header("User-Agent", USER_AGENT)

    try:
        with opener.open(login_req, timeout=TIMEOUT) as _:
            pass
    except urllib.error.HTTPError:
        pass

    for cookie in cookie_jar:
        if "session-token" in cookie.name:
            return cookie_jar

    raise RuntimeError("Authentication failed: no session cookie received")


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
            _log(f"{_yellow('[SKIP]')} {ut.value}: missing env vars {env_email} / {env_pass}")
            continue

        try:
            print(f"  Authenticating {ut.value}...", end=" ", flush=True)
            cookie_jar = authenticate_via_nextauth(base_url, email, password)
            sessions[ut] = cookie_jar
            print(_green("OK"))
        except Exception as e:
            print(_red(f"FAILED ({e})"))

    return sessions


# ── Directus Fetchers ────────────────────────────────────────────────


def fetch_directus_items(directus_url: str, endpoint: str) -> list[str]:
    url = f"{directus_url}/items/{endpoint}"
    req = urllib.request.Request(url)
    req.add_header("User-Agent", USER_AGENT)
    with urllib.request.urlopen(req, timeout=TIMEOUT, context=SSL_CTX) as resp:
        data = json.loads(resp.read().decode())
    return [
        item["slug"] for item in data.get("data", [])
        if item.get("slug") and _is_valid_slug(item["slug"])
    ]


def _is_valid_slug(slug: str) -> bool:
    if not slug or not slug.strip():
        return False
    if slug.startswith("[") or slug.startswith("{"):
        return False
    if any(ch in slug for ch in (" ", "#", "?", "%", "\t", "\n")):
        return False
    return True


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
        _log(f"{cat}: {len(items)} routes")
        routes.extend(items)

    return routes


# ── Check Engine ─────────────────────────────────────────────────────


def _check_route_once(url: str, opener) -> tuple[int | None, int | None, str | None]:
    try:
        req = urllib.request.Request(url, method="GET")
    except ValueError as e:
        return None, None, f"Invalid URL: {e}"
    req.add_header("User-Agent", USER_AGENT)
    timeout_ms = int(TIMEOUT * 1000)
    start = time.time()
    try:
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
        elapsed_ms = int((time.time() - start) * 1000)
        return None, elapsed_ms, str(e)


def _is_check_error(status: int | None, error: str | None) -> bool:
    if error is not None:
        return True
    if status is None:
        return True
    if status >= 500:
        return True
    return False


def check_route(url: str, opener) -> tuple[int | None, int | None, str | None, int]:
    """Returns (status, ms, error, retries)."""
    status, ms, err = _check_route_once(url, opener)
    retries = 0
    if _is_check_error(status, err):
        for attempt, delay in enumerate(RETRY_DELAYS, start=1):
            _log(f"{_dim(f'[RETRY] Attempt {attempt}/{len(RETRY_DELAYS)} for {url} in {delay}s...')}")
            time.sleep(delay)
            status, ms, err = _check_route_once(url, opener)
            retries += 1
            if not _is_check_error(status, err):
                break
    return status, ms, err, retries


def check_final_destination(url: str) -> tuple[int | None, int | None, str | None, str | None]:
    """Follow redirects and return (final_status, elapsed_ms, error, final_url).

    Uses a manual redirect loop instead of urllib's built-in redirect handler
    to preserve SSL context across hops and capture the final URL reliably.
    """
    current_url = url
    max_redirects = 10

    # Build opener once outside the loop
    hop_opener = urllib.request.build_opener(
        NoRedirectHandler,
        urllib.request.HTTPSHandler(context=SSL_CTX),
    )

    start = time.time()
    for _ in range(max_redirects):
        req = urllib.request.Request(current_url, method="GET")
        req.add_header("User-Agent", USER_AGENT)

        try:
            with hop_opener.open(req, timeout=TIMEOUT + 5) as resp:
                status = resp.status
                if 300 <= status < 400:
                    location = resp.headers.get("Location")
                    if location:
                        current_url = urllib.parse.urljoin(current_url, location)
                        continue
                elapsed_ms = int((time.time() - start) * 1000)
                return status, elapsed_ms, None, current_url
        except urllib.error.HTTPError as e:
            if 300 <= e.code < 400:
                location = e.headers.get("Location")
                if location:
                    current_url = urllib.parse.urljoin(current_url, location)
                    continue
            elapsed_ms = int((time.time() - start) * 1000)
            return e.code, elapsed_ms, None, current_url
        except TimeoutError:
            elapsed_ms = int((time.time() - start) * 1000)
            return None, elapsed_ms, "TIMEOUT", current_url
        except Exception as e:
            return None, None, str(e), current_url

    elapsed_ms = int((time.time() - start) * 1000)
    return None, elapsed_ms, "TOO_MANY_REDIRECTS", current_url


def evaluate_result(
    status: int | None, error: str | None, expected: ExpectedResult
) -> bool:
    if error:
        return False
    if status is None:
        return False
    if expected == ExpectedResult.OK:
        return 200 <= status < 300 or status == 308
    if expected == ExpectedResult.REDIRECT:
        return 300 <= status < 400
    return False


# ── Result Formatting ────────────────────────────────────────────────


def _format_result_line(result: CheckResult) -> str:
    ms_str = f"{result.elapsed_ms:>5}ms" if result.elapsed_ms is not None else "  ---  "
    status_str = str(result.status) if result.status is not None else "---"
    retry_hint = f" {_dim(f'(r:{result.retries})')}" if result.retries > 0 else ""
    display_path = result.path or result.url

    if result.error:
        if result.error == "TIMEOUT":
            tag = _red("[TIMEOUT]")
            ms_str = f"{result.elapsed_ms}ms" if result.elapsed_ms else ">timeout"
            return f"  {tag} {status_str:>3}   {ms_str:>7}  {display_path}{retry_hint}"
        elif result.error == "SOFT_TIMEOUT":
            tag = _yellow("[ SLOW ]")
            return f"  {tag} {status_str:>3}   {ms_str}  {display_path}{retry_hint}"
        else:
            tag = _red("[ERROR ]")
            return f"  {tag} ---     ---  {display_path}  ({result.error}){retry_hint}"

    if result.passed:
        if result.redirect_to:
            tag = _cyan("[REDIR ]")
            return f"  {tag} {status_str}->{result.final_status}   {ms_str}  {display_path} -> {result.redirect_to}{retry_hint}"
        tag = _green("[ PASS ]")
        hint = f"  {_dim(f'(expected: {result.expected})')}" if result.expected != "ok" else ""
        return f"  {tag} {status_str:>3}   {ms_str}  {display_path}{hint}{retry_hint}"
    else:
        tag = _red("[ FAIL ]")
        if result.redirect_to:
            dest = f" -> {result.redirect_to}"
            return f"  {tag} {status_str}->{result.final_status or '---'}   {ms_str}  {display_path}{dest}  {_dim(f'(expected: {result.expected})')}{retry_hint}"
        return f"  {tag} {status_str:>3}   {ms_str}  {display_path}  {_dim(f'(expected: {result.expected})')}{retry_hint}"


# ── Progress Counter ─────────────────────────────────────────────────

_progress_lock = threading.Lock()
_progress_current = 0
_progress_total = 0


def _reset_progress(total: int) -> None:
    global _progress_current, _progress_total
    with _progress_lock:
        _progress_current = 0
        _progress_total = total


def _tick_progress() -> str:
    global _progress_current
    with _progress_lock:
        _progress_current += 1
        return f"[{_progress_current}/{_progress_total}]"


# ── Concurrent Check Workers ────────────────────────────────────────


def _check_single_page(slug: str, base_url: str, opener) -> CheckResult:
    url = f"{base_url}{slug}"
    status, ms, err, retries = check_route(url, opener)

    # 308 is Next.js trailing-slash redirect — treat as pass
    if not err and status == 308:
        final_status, final_ms, final_err, final_url = check_final_destination(url)
        return CheckResult(
            url=url, path=slug, category="pages", status=status,
            elapsed_ms=ms, error=None, expected="ok", passed=True,
            redirect_to=final_url, final_status=final_status, retries=retries,
        )

    # Handle other redirects -> follow destination
    if not err and status and 300 <= status < 400:
        final_status, final_ms, final_err, final_url = check_final_destination(url)
        if not final_err and final_status and 200 <= final_status < 300:
            return CheckResult(
                url=url, path=slug, category="pages", status=status,
                elapsed_ms=ms, error=None, expected="ok", passed=True,
                redirect_to=final_url, final_status=final_status, retries=retries,
            )
        else:
            return CheckResult(
                url=url, path=slug, category="pages", status=status,
                elapsed_ms=ms, error=None, expected="ok", passed=False,
                redirect_to=final_url, final_status=final_status,
                final_error=final_err, retries=retries,
            )

    passed = not err and status is not None and (200 <= status < 300 or status == 308)
    return CheckResult(
        url=url, path=slug, category="pages", status=status,
        elapsed_ms=ms, error=err, expected="ok", passed=passed, retries=retries,
    )


def _check_single_academy(
    route: RouteSpec, base_url: str, user_type: UserType, opener
) -> CheckResult:
    url = f"{base_url}{route.path}"
    expected = route.expected.get(user_type, ExpectedResult.OK)
    status, ms, err, retries = check_route(url, opener)

    passed = evaluate_result(status, err, expected)

    # 308 is Next.js trailing-slash redirect — treat as pass when expecting OK
    if not err and status == 308 and expected == ExpectedResult.OK:
        final_status, final_ms, final_err, final_url = check_final_destination(url)
        return CheckResult(
            url=url, path=route.path, category=route.category, status=status,
            elapsed_ms=ms, error=None, expected=expected.value, passed=True,
            redirect_to=final_url, final_status=final_status, retries=retries,
        )

    # Other redirects received but expected OK -> follow
    if not err and not passed and expected == ExpectedResult.OK and status and 300 <= status < 400:
        final_status, final_ms, final_err, final_url = check_final_destination(url)
        if not final_err and final_status and 200 <= final_status < 300:
            return CheckResult(
                url=url, path=route.path, category=route.category, status=status,
                elapsed_ms=ms, error=None, expected=expected.value, passed=True,
                redirect_to=final_url, final_status=final_status, retries=retries,
            )
        else:
            return CheckResult(
                url=url, path=route.path, category=route.category, status=status,
                elapsed_ms=ms, error=None, expected=expected.value, passed=False,
                redirect_to=final_url, final_status=final_status,
                final_error=final_err, retries=retries,
            )

    return CheckResult(
        url=url, path=route.path, category=route.category, status=status,
        elapsed_ms=ms, error=err, expected=expected.value, passed=passed, retries=retries,
    )


# ── Pages Check ──────────────────────────────────────────────────────


def run_pages_check(base_url: str, directus_url: str, concurrency: int) -> dict[str, Any]:
    print(f"\n{_bold('=' * 28 + ' PAGES ' + '=' * 28)}")
    slugs = fetch_directus_items(directus_url, f"pages?limit=-1&fields=slug&{DIRECTUS_STATUS_FILTER}")
    _log(f"Found {_bold(str(len(slugs)))} page routes (concurrency: {concurrency})\n")

    opener = build_opener()
    counts = {"total": 0, "pass": 0, "fail": 0, "timeout": 0, "soft_timeout": 0, "error": 0}
    failures: list[dict[str, Any]] = []
    stats = SuiteStats()

    sorted_slugs = sorted(slugs)
    _reset_progress(len(sorted_slugs))

    print("-" * 62)

    results: list[CheckResult] = []
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        future_map = {
            pool.submit(_check_single_page, slug, base_url, opener): slug
            for slug in sorted_slugs
        }
        for future in as_completed(future_map):
            result = future.result()
            progress = _tick_progress()
            results.append(result)
            print(f"  {_dim(progress)} {_format_result_line(result).strip()}", flush=True)

    # Aggregate counts
    for r in results:
        counts["total"] += 1
        stats.add(r.elapsed_ms)

        if r.error:
            if r.error == "TIMEOUT":
                counts["timeout"] += 1
            elif r.error == "SOFT_TIMEOUT":
                counts["soft_timeout"] += 1
            else:
                counts["error"] += 1
            failures.append(_result_to_failure(r, "pages"))
        elif r.passed:
            counts["pass"] += 1
        else:
            counts["fail"] += 1
            failures.append(_result_to_failure(r, "pages"))

    print("-" * 62)
    _print_suite_stats(stats)
    return {"counts": counts, "failures": failures, "stats": stats.to_dict()}


# ── Academy Check ────────────────────────────────────────────────────


def run_academy_check(
    base_url: str,
    routes: list[RouteSpec],
    user_type: UserType,
    cookie_jar: CookieJar | None,
    concurrency: int,
) -> dict[str, Any]:
    label = USER_TYPE_LABELS[user_type]
    header = f" ACADEMY: {label} "
    print(f"\n{_bold(f'{header:=^62}')}")

    opener = build_opener(cookie_jar)
    counts = {"total": 0, "pass": 0, "fail": 0, "timeout": 0, "soft_timeout": 0, "error": 0}
    failures: list[dict[str, Any]] = []
    stats = SuiteStats()

    _reset_progress(len(routes))

    # Group by category for display
    results_by_category: dict[str, list[tuple[str, CheckResult]]] = {}

    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        future_map = {
            pool.submit(_check_single_academy, route, base_url, user_type, opener): route
            for route in routes
        }
        for future in as_completed(future_map):
            route = future_map[future]
            result = future.result()
            progress = _tick_progress()

            cat = route.category
            if cat not in results_by_category:
                results_by_category[cat] = []
            results_by_category[cat].append((progress, result))

            print(f"  {_dim(progress)} {_dim(f'[{cat}]')} {_format_result_line(result).strip()}", flush=True)

    # Aggregate
    for r_list in results_by_category.values():
        for _, r in r_list:
            counts["total"] += 1
            stats.add(r.elapsed_ms)

            if r.error:
                if r.error == "TIMEOUT":
                    counts["timeout"] += 1
                elif r.error == "SOFT_TIMEOUT":
                    counts["soft_timeout"] += 1
                else:
                    counts["error"] += 1
                failures.append(_result_to_failure(r, "academy", user_type.value))
            elif r.passed:
                counts["pass"] += 1
            else:
                counts["fail"] += 1
                failures.append(_result_to_failure(r, "academy", user_type.value))

    _print_suite_stats(stats)
    return {"counts": counts, "failures": failures, "stats": stats.to_dict()}


def _result_to_failure(r: CheckResult, suite: str, user_type: str | None = None) -> dict[str, Any]:
    d: dict[str, Any] = {
        "suite": suite,
        "url": r.url,
        "path": r.path,
        "category": r.category,
        "status": r.status,
        "elapsed_ms": r.elapsed_ms,
        "error": r.error,
        "expected": r.expected,
        "retries": r.retries,
    }
    if user_type:
        d["user_type"] = user_type
    if r.redirect_to:
        d["redirect_to"] = r.redirect_to
        d["final_status"] = r.final_status
        d["final_error"] = r.final_error
    return d


def _print_suite_stats(stats: SuiteStats) -> None:
    s = stats.to_dict()
    if s["min_ms"] is None:
        return
    _log(
        f"{_dim('Latency:')} min={s['min_ms']}ms  "
        f"avg={s['avg_ms']}ms  "
        f"median={s['median_ms']}ms  "
        f"p95={s['p95_ms']}ms  "
        f"max={s['max_ms']}ms"
    )


# ── Summary Payload ──────────────────────────────────────────────────


def healthcheck_run(
    base_url: str,
    directus_url: str,
    do_pages: bool = True,
    do_academy: bool = True,
    user_types: Optional[list[UserType]] = None,
    categories: Optional[list[str]] = None,
    concurrency: int = DEFAULT_CONCURRENCY,
) -> dict[str, Any]:
    if user_types is None:
        user_types = list(UserType)

    run_start = time.time()
    run_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    suites: dict[str, dict[str, int]] = {}
    suite_stats: dict[str, dict[str, Any]] = {}
    failures: list[dict[str, Any]] = []

    # Pages
    if do_pages:
        pages = run_pages_check(base_url, directus_url, concurrency)
        suites["pages"] = pages["counts"]
        suite_stats["pages"] = pages["stats"]
        failures.extend(pages["failures"])

    # Academy
    if do_academy:
        print(f"\n{_bold('=' * 22 + ' FETCHING ACADEMY ROUTES ' + '=' * 22)}")
        academy_routes = collect_academy_routes(directus_url, categories)
        _log(f"Total academy routes: {_bold(str(len(academy_routes)))}")

        print(f"\n{_bold('=' * 24 + ' AUTHENTICATION ' + '=' * 24)}")
        sessions = authenticate_user_types(base_url, user_types)

        for ut in user_types:
            if ut != UserType.UNAUTHENTICATED and ut not in sessions:
                continue
            cookie_jar = sessions.get(ut)
            res = run_academy_check(base_url, academy_routes, ut, cookie_jar, concurrency)
            key = f"academy:{ut.value}"
            suites[key] = res["counts"]
            suite_stats[key] = res["stats"]
            failures.extend(res["failures"])

    def _sum(metric: str) -> int:
        return sum(v.get(metric, 0) for v in suites.values())

    total = _sum("total")
    passed = _sum("pass")
    elapsed_total = round(time.time() - run_start, 2)
    health_score = round((passed / total) * 100, 1) if total > 0 else 0.0

    summary = {
        "run_at_utc": run_at,
        "base_url": base_url,
        "directus_url": directus_url,
        "timeout_s": float(TIMEOUT),
        "concurrency": concurrency,
        "elapsed_total_s": elapsed_total,
        "health_score_pct": health_score,
        "suites": list(suites.keys()),
        "total": total,
        "pass": passed,
        "fail": _sum("fail"),
        "timeout": _sum("timeout"),
        "soft_timeout": _sum("soft_timeout"),
        "error": _sum("error"),
        "failures_count": len(failures),
    }

    return {
        "summary": summary,
        "suites": suites,
        "suite_stats": suite_stats,
        "failures": failures,
    }


# ── Slack Message Formatter ──────────────────────────────────────────


def _error_label(f: dict[str, Any]) -> str:
    err = f.get("error")
    if err == "TIMEOUT":
        return "Timeout"
    if err == "SOFT_TIMEOUT":
        return "Slow response"
    if err and err not in (None, ""):
        return f"Error: {err}"
    status = f.get("status")
    final_status = f.get("final_status")
    if final_status is not None:
        return f"HTTP {status} -> {final_status}"
    if status is not None:
        return f"HTTP {status}"
    return "Unknown error"


def format_slack_message(payload: dict[str, Any]) -> str:
    summary = payload["summary"]
    failures = payload.get("failures", [])

    if not failures:
        run_at = summary.get("run_at_utc", "N/A")
        total = summary.get("total", 0)
        base_url = summary.get("base_url", "")
        score = summary.get("health_score_pct", 100.0)
        elapsed = summary.get("elapsed_total_s", "?")
        return (
            f"All systems operational! "
            f"Health check completed successfully — "
            f"{total} routes checked, all passing. "
            f"Score: {score}% | {elapsed}s elapsed | "
            f"Run at {run_at} | {base_url}"
        )

    return json.dumps(payload, default=str, ensure_ascii=False)


# ── SNS Publisher ────────────────────────────────────────────────────


def publish_summary_to_sns(
    topic_arn: str,
    payload: dict[str, Any],
    subject: str = DEFAULT_SNS_SUBJECT,
    region: Optional[str] = None,
    max_failures: int = 200,
) -> str:
    safe = dict(payload)
    failures = safe.get("failures", [])
    has_failures = len(failures) > 0

    if isinstance(failures, list) and len(failures) > max_failures:
        safe["failures"] = failures[:max_failures]
        safe["failures_truncated"] = True
        safe["failures_total"] = len(failures)

    message_str = format_slack_message(safe)
    subject = "Health Check FAILED" if has_failures else "Health Check PASSED"

    if len(message_str.encode("utf-8")) > 240_000:
        slim = {
            "summary": safe.get("summary", {}),
            "failures_truncated": True,
            "failures_removed_due_to_size": True,
        }
        message_str = json.dumps(slim, default=str, ensure_ascii=False)

    if boto3 is None:
        raise RuntimeError("boto3 is required for SNS publishing (pip install boto3)")
    sns = boto3.client("sns", region_name=region or os.getenv("AWS_REGION"))
    resp = sns.publish(
        TopicArn=topic_arn,
        Subject=subject[:100],
        Message=message_str,
    )
    return resp["MessageId"]


def is_critical_failure(f: dict[str, Any]) -> bool:
    err = f.get("error")
    if err in ("TIMEOUT", "SOFT_TIMEOUT"):
        return True
    if err and err not in (None, ""):
        return True

    status = f.get("status")
    try:
        if status is not None and int(status) >= 400:
            return True
    except Exception:
        pass

    final_status = f.get("final_status")
    try:
        if final_status is not None and int(final_status) >= 400:
            return True
    except Exception:
        pass

    return False


# ── CLI ──────────────────────────────────────────────────────────────


def parse_args():
    parser = argparse.ArgumentParser(
        description="Health check for startstak.ai routes (v3 — concurrent)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  python3 healthcheck_routes_v3.py --pages-only
  python3 healthcheck_routes_v3.py --concurrency 16 --output report.json
  python3 healthcheck_routes_v3.py --category articles --category events
  python3 healthcheck_routes_v3.py --user-type unauthenticated --dry-run
  python3 healthcheck_routes_v3.py --no-color
        """,
    )
    parser.add_argument("--academy-only", action="store_true", help="Only test academy routes (skip pages)")
    parser.add_argument("--pages-only", action="store_true", help="Only test page routes (skip academy)")
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
    parser.add_argument("--timeout", type=float, default=TIMEOUT, help=f"Request timeout in seconds (default: {TIMEOUT})")
    parser.add_argument("--concurrency", "-c", type=int, default=DEFAULT_CONCURRENCY,
                        help=f"Max concurrent requests (default: {DEFAULT_CONCURRENCY})")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL, help=f"Base URL to test (default: {DEFAULT_BASE_URL})")
    parser.add_argument("--directus-url", default=DEFAULT_DIRECTUS_URL, help=f"Directus API URL (default: {DEFAULT_DIRECTUS_URL})")
    parser.add_argument("--env-file", default=None, help="Path to .env file with credentials (default: auto-detect)")
    parser.add_argument("--output", "-o", default=None, help="Write full JSON report to file")
    parser.add_argument("--dry-run", action="store_true", help="Run checks but only print the Slack message (don't publish to SNS)")
    parser.add_argument("--preview", action="store_true", help="Preview Slack messages using sample data (no real checks)")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    return parser.parse_args()


def _build_preview_payloads() -> tuple[dict[str, Any], dict[str, Any]]:
    run_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    base_url = DEFAULT_BASE_URL

    ok_payload = {
        "summary": {
            "run_at_utc": run_at,
            "base_url": base_url,
            "total": 142,
            "pass": 142,
            "fail": 0,
            "timeout": 0,
            "soft_timeout": 0,
            "error": 0,
            "failures_count": 0,
            "health_score_pct": 100.0,
            "elapsed_total_s": 18.5,
            "concurrency": DEFAULT_CONCURRENCY,
        },
        "failures": [],
    }

    fail_payload = {
        "summary": {
            "run_at_utc": run_at,
            "base_url": base_url,
            "total": 142,
            "pass": 138,
            "fail": 2,
            "timeout": 1,
            "soft_timeout": 1,
            "error": 0,
            "failures_count": 4,
            "health_score_pct": 97.2,
            "elapsed_total_s": 45.3,
            "concurrency": DEFAULT_CONCURRENCY,
        },
        "failures": [
            {
                "suite": "pages",
                "url": f"{base_url}/pricing",
                "status": 404,
                "elapsed_ms": 230,
                "error": None,
            },
            {
                "suite": "academy",
                "user_type": "unauthenticated",
                "category": "articles",
                "path": "/academy/articles/getting-started",
                "url": f"{base_url}/academy/articles/getting-started",
                "status": None,
                "elapsed_ms": 10200,
                "error": "TIMEOUT",
                "expected": "ok",
            },
            {
                "suite": "academy",
                "user_type": "auth-with-plan",
                "category": "profile",
                "path": "/academy/profile/dashboard",
                "url": f"{base_url}/academy/profile/dashboard",
                "status": 302,
                "elapsed_ms": 450,
                "error": None,
                "expected": "ok",
                "redirect_to": f"{base_url}/error",
                "final_status": 500,
                "final_error": None,
            },
            {
                "suite": "academy",
                "user_type": "free-trial",
                "category": "courses",
                "path": "/academy/on-demand-learning/intro-course",
                "url": f"{base_url}/academy/on-demand-learning/intro-course",
                "status": 200,
                "elapsed_ms": 12500,
                "error": "SOFT_TIMEOUT",
                "expected": "ok",
            },
        ],
    }

    return ok_payload, fail_payload


def _print_final_summary(payload: dict[str, Any]) -> None:
    s = payload["summary"]
    total = s["total"]
    passed = s["pass"]
    failed = s["fail"]
    timeout = s["timeout"]
    soft_timeout = s["soft_timeout"]
    error = s["error"]
    score = s["health_score_pct"]
    elapsed = s["elapsed_total_s"]
    concurrency = s.get("concurrency", DEFAULT_CONCURRENCY)

    print(f"\n{'=' * 30} {_bold('SUMMARY')} {'=' * 30}")

    # Health score with color
    if score == 100.0:
        score_str = _green(f"{score}%")
    elif score >= 95.0:
        score_str = _yellow(f"{score}%")
    else:
        score_str = _red(f"{score}%")

    print(f"  Health Score:     {score_str}")
    print(f"  Total routes:     {total}")
    print(f"  Passed:           {_green(str(passed))}")

    if failed > 0:
        print(f"  Failed:           {_red(str(failed))}")
    else:
        print(f"  Failed:           {failed}")

    if timeout > 0:
        print(f"  Timeout:          {_red(str(timeout))}")
    else:
        print(f"  Timeout:          {timeout}")

    if soft_timeout > 0:
        print(f"  Slow (soft TO):   {_yellow(str(soft_timeout))}")
    else:
        print(f"  Slow (soft TO):   {soft_timeout}")

    if error > 0:
        print(f"  Conn error:       {_red(str(error))}")
    else:
        print(f"  Conn error:       {error}")

    print(f"  Concurrency:      {concurrency}")
    print(f"  Elapsed:          {elapsed}s")
    print(f"  Run at:           {s['run_at_utc']}")
    print("=" * 69)


def main_cli():
    global TIMEOUT, _USE_COLOR
    args = parse_args()

    if args.no_color:
        _USE_COLOR = False

    # ── Preview mode ─────────────────────────────────────────────
    if args.preview:
        ok_payload, fail_payload = _build_preview_payloads()
        print("=" * 60)
        print(f"  {_bold('PREVIEW: Slack message when everything is OK')}")
        print("=" * 60)
        print(format_slack_message(ok_payload))
        print()
        print("=" * 60)
        print(f"  {_bold('PREVIEW: Slack message when there are failures')}")
        print("=" * 60)
        print(format_slack_message(fail_payload))
        return

    load_dotenv(args.env_file)
    TIMEOUT = args.timeout

    do_pages = not args.academy_only
    do_academy = not args.pages_only

    if args.user_types:
        user_types = [UserType(ut) for ut in args.user_types]
    else:
        user_types = list(UserType)

    print(f"\n  {_bold('StartStak HealthCheck v3.0')}")
    print(f"  {_dim(f'concurrency={args.concurrency}  timeout={args.timeout}s')}\n")

    payload = healthcheck_run(
        base_url=args.base_url,
        directus_url=args.directus_url,
        do_pages=do_pages,
        do_academy=do_academy,
        user_types=user_types,
        categories=args.categories,
        concurrency=args.concurrency,
    )

    # ── Print summary ────────────────────────────────────────────
    _print_final_summary(payload)

    # ── Dry-run ──────────────────────────────────────────────────
    if args.dry_run:
        print(f"\n{'=' * 25} {_bold('SLACK MESSAGE')} {'=' * 25}")
        print(format_slack_message(payload))
        print("=" * 65)

    # ── Output JSON to file ──────────────────────────────────────
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, default=str, ensure_ascii=False)
        _log(f"Report written to {_bold(args.output)}")

    # Exit non-zero if any failures
    if payload["summary"]["failures_count"] > 0:
        sys.exit(1)


# ── Lambda handler ───────────────────────────────────────────────────

def lambda_handler(event, context):
    """
    Env knobs (optional):
      HC_BASE_URL, HC_DIRECTUS_URL, HC_TIMEOUT, HC_CONCURRENCY
      HC_DO_PAGES=true/false, HC_DO_ACADEMY=true/false
      HC_CATEGORIES=csv   e.g. "articles,events,profile"
      HC_USER_TYPES=csv   e.g. "unauthenticated,auth-with-plan"
      HC_SNS_TOPIC_ARN, HC_SNS_SUBJECT

    Credentials:
      HC_FREE_TRIAL_EMAIL / HC_FREE_TRIAL_PASSWORD
      HC_AUTH_NO_PLAN_EMAIL / HC_AUTH_NO_PLAN_PASSWORD
      HC_AUTH_WITH_PLAN_EMAIL / HC_AUTH_WITH_PLAN_PASSWORD
    """
    global TIMEOUT, _USE_COLOR
    _USE_COLOR = False  # Lambda doesn't support ANSI

    env_file = os.getenv("HC_ENV_FILE")
    if env_file:
        load_dotenv(env_file)

    base_url = os.getenv("HC_BASE_URL", DEFAULT_BASE_URL)
    directus_url = os.getenv("HC_DIRECTUS_URL", DEFAULT_DIRECTUS_URL)
    TIMEOUT = float(os.getenv("HC_TIMEOUT", str(TIMEOUT)))
    concurrency = int(os.getenv("HC_CONCURRENCY", str(DEFAULT_CONCURRENCY)))

    do_pages = os.getenv("HC_DO_PAGES", "true").lower() != "false"
    do_academy = os.getenv("HC_DO_ACADEMY", "true").lower() != "false"

    categories = os.getenv("HC_CATEGORIES")
    categories_list = [c.strip() for c in categories.split(",") if c.strip()] if categories else None

    user_types_env = os.getenv("HC_USER_TYPES")
    user_types_list = [UserType(u.strip()) for u in user_types_env.split(",") if u.strip()] if user_types_env else None

    topic_arn = os.getenv("HC_SNS_TOPIC_ARN", "arn:aws:sns:us-east-1:612703023085:production-error")
    sns_region = os.getenv("AWS_REGION")
    sns_subject = os.getenv("HC_SNS_SUBJECT", DEFAULT_SNS_SUBJECT)

    try:
        payload = healthcheck_run(
            base_url=base_url,
            directus_url=directus_url,
            do_pages=do_pages,
            do_academy=do_academy,
            user_types=user_types_list,
            categories=categories_list,
            concurrency=concurrency,
        )
    except Exception as e:
        import traceback
        error_trace = traceback.format_exc()
        print(f"[CRASH] Health check failed: {e}\n{error_trace}")

        crash_payload = {
            "summary": {
                "run_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "base_url": base_url,
                "directus_url": directus_url,
                "status": "CRASHED",
                "error": str(e),
                "error_type": type(e).__name__,
            },
            "failures": [],
        }

        try:
            if boto3 is None:
                print("[CRASH] boto3 not available, cannot send SNS notification")
            else:
                sns = boto3.client("sns", region_name=sns_region)
                sns.publish(
                    TopicArn=topic_arn,
                    Subject="Health Check CRASHED",
                    Message=json.dumps(crash_payload, default=str, ensure_ascii=False),
                )
                print("[CRASH] SNS crash notification sent.")
        except Exception as sns_err:
            print(f"[CRASH] Failed to send SNS crash notification: {sns_err}")

        return {
            "statusCode": 500,
            "body": crash_payload,
        }

    try:
        msg_id = publish_summary_to_sns(
            topic_arn=topic_arn,
            payload=payload,
            subject=sns_subject,
            region=sns_region,
        )
        print(f"SNS MessageId: {msg_id}")
    except Exception as sns_err:
        print(f"[ERROR] Failed to publish to SNS: {sns_err}")

    critical = any(is_critical_failure(f) for f in payload.get("failures", []))

    return {
        "statusCode": 500 if critical else 200,
        "body": payload,
    }


if __name__ == "__main__":
    main_cli()
