# StartStack Healthcheck - v2

Comprehensive health check script for [startstak.ai](https://startstak.ai) that tests **page routes** and **academy routes** across multiple user types, with authentication via NextAuth and dynamic route fetching from Directus CMS.

## What it does

- Fetches routes dynamically from Directus CMS (pages, articles, Q&A, courses, events, static pages)
- Tests routes across 4 user types: unauthenticated, free-trial, auth-no-plan, auth-with-plan
- Authenticates via NextAuth (CSRF token + credentials flow)
- Validates expected behavior per user type (e.g., profile routes redirect unauthenticated users)
- Built-in `.env` loader — no external dependencies
- Displays a detailed summary table per user type

## Requirements

- Python >= 3.10
- No external dependencies (stdlib only)

## Environment variables

Create a `.env` file in the same directory as the script:

```env
# Free trial user (registered, Trial plan)
HC_FREE_TRIAL_EMAIL=your-freetrial-user@example.com
HC_FREE_TRIAL_PASSWORD=your-password

# Authenticated user without a paid plan (registered, Public Users plan)
HC_AUTH_NO_PLAN_EMAIL=your-noplan-user@example.com
HC_AUTH_NO_PLAN_PASSWORD=your-password

# Authenticated user with an active plan (registered, Monthly/Quarterly/Annually plan)
HC_AUTH_WITH_PLAN_EMAIL=your-withplan-user@example.com
HC_AUTH_WITH_PLAN_PASSWORD=your-password
```

### Creating test users in Directus

Create 3 users via the Directus admin panel (`/admin/users`) with role **Registered User** and status **Active**:

| User type | Plan field | Subscription Plan Validity |
|-----------|-----------|---------------------------|
| Free Trial | Trial | *(empty)* |
| No Plan | Public Users | *(empty)* |
| With Plan | Monthly (or Quarterly/Annually) | A future date (e.g., `2027-01-01`) |

## Usage

```bash
# Run all checks (pages + academy, all user types)
python3 healthcheck_routes.py

# Academy routes only
python3 healthcheck_routes.py --academy-only

# Pages only
python3 healthcheck_routes.py --pages-only

# Specific user type(s)
python3 healthcheck_routes.py --academy-only --user-type free-trial
python3 healthcheck_routes.py --academy-only --user-type unauthenticated --user-type auth-with-plan

# Specific route category(s)
python3 healthcheck_routes.py --academy-only --category profile --category courses

# Custom .env file path
python3 healthcheck_routes.py --env-file /path/to/.env

# Custom timeout (default: 10s)
python3 healthcheck_routes.py --timeout 15

# Custom URLs
python3 healthcheck_routes.py --base-url https://staging.startstak.ai --directus-url https://directus-staging.startstak.ai
```

### Available options

| Flag | Description |
|------|-------------|
| `--academy-only` | Skip page routes, test only academy |
| `--pages-only` | Skip academy routes, test only pages |
| `--user-type` | Filter by user type. Repeatable. Values: `unauthenticated`, `free-trial`, `auth-no-plan`, `auth-with-plan` |
| `--category` | Filter by route category. Repeatable. Values: `academy-static`, `articles`, `events`, `q-and-a`, `courses`, `profile` |
| `--timeout` | Request timeout in seconds (default: 10) |
| `--base-url` | Base URL to test (default: `https://startstak.ai`) |
| `--directus-url` | Directus API URL (default: `https://directus.startstak.ai`) |
| `--env-file` | Path to `.env` file (default: auto-detect) |

## Route categories

| Category | Source | Directus collection | Example path |
|----------|--------|-------------------|-------------|
| `academy-static` | Directus | `static_pages` | `/academy`, `/academy/pricing` |
| `articles` | Directus | `articles` (published) | `/academy/articles/my-article` |
| `events` | Directus | `events` (published) | `/academy/events/my-event` |
| `q-and-a` | Directus | `q_and_a` (published) | `/academy/q-and-a/my-question` |
| `courses` | Directus | `courses` (published) | `/academy/on-demand-learning/my-course` |
| `profile` | Hardcoded | — | `/academy/profile/dashboard` |

## Example output

```
  Loading env from: /path/to/.env
Base URL:     https://startstak.ai
Directus URL: https://directus.startstak.ai
Timeout:      10s

====================== FETCHING ACADEMY ROUTES ======================
  academy-static: 7 routes
  articles: 15 routes
  courses: 4 routes
  profile: 9 routes

  Total: 35 academy routes

======================== AUTHENTICATION ========================
  Authenticating free-trial... OK
  Authenticating auth-no-plan... OK
  Authenticating auth-with-plan... OK

============ ACADEMY ROUTES: Unauthenticated User ============

  --- profile ---
  [PASS]    307     403ms  /academy/profile/dashboard  (expected: redirect)

============================== SUMMARY ==============================
                  unauthenticated       free-trial     auth-no-plan   auth-with-plan
          Total:               35               35               35               35
           Pass:               35               35               35               35
           Fail:                0                0                0                0
        Timeout:                0                0                0                0
          Error:                0                0                0                0
=============================================================
```
