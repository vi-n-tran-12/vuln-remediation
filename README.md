# 🛡️ Automated Vulnerability Remediation with Devin

**3 critical security vulnerabilities identified, filed, and fixed — automatically — in under 15 minutes each, with zero human intervention.**

This system watches a GitHub repository for security issues and uses [Devin](https://devin.ai) as an autonomous software engineer to remediate them. Devin clones the repo, reads the vulnerability report, writes the fix, runs tests, and opens a pull request. The orchestrator manages the lifecycle and reports results on a live dashboard.

## Results

| Issue | Severity | Time to PR | Pull Request |
|-------|----------|-----------|--------------|
| [#1 SQL Injection via guest token RLS](https://github.com/vi-n-tran-12/superset/issues/1) | Critical | 13 min | [PR #5](https://github.com/vi-n-tran-12/superset/pull/5) |
| [#2 Default JWT secret — no startup validation](https://github.com/vi-n-tran-12/superset/issues/2) | Critical | 8 min | [PR #4](https://github.com/vi-n-tran-12/superset/pull/4) |
| [#3 SSRF via database validation endpoint](https://github.com/vi-n-tran-12/superset/issues/3) | High | 14 min | [PR #6](https://github.com/vi-n-tran-12/superset/pull/6) |

- **3/3** issues remediated automatically
- **100%** success rate
- **~12 min** average time from issue creation to pull request
- **0** human interventions required

### The Attack Chain

Issues #1 and #2 chain together into an unauthenticated data breach:

1. **Forge a guest token** using the default JWT secret (public in source code, no startup check)
2. **Inject SQL** via the unsanitized RLS clause in the forged token
3. **Exfiltrate any data** from any connected database

Issue #3 is independent: any authenticated user can port-scan internal networks and probe cloud metadata endpoints through the database validation API.

These were found through manual code audit of [Apache Superset](https://github.com/apache/superset), a widely-deployed data platform.

## How It Works

```
GitHub Issue (labeled "security")
        │
        ├── Webhook ── real-time trigger
        └── Poller ── periodic trigger (every 30s)
                │
                ▼
        ┌──────────────┐
        │  Orchestrator │  discover → dispatch → poll → report
        └──────┬───────┘
               │
               ▼
        ┌──────────────┐
        │  Devin API   │  session created with playbook + issue context
        │              │
        │  Phase 1: Validate
        │  • Spin up sandbox environment
        │  • Attempt to reproduce the attack scenario
        │  • If NOT reproducible → comment on issue, finish
        │              │
        │  Phase 2: Fix (only if validated)
        │  • Implement the fix
        │  • Write tests proving the vuln is closed
        │  • Open PR with reproduction steps + fix explanation
        └──────┬───────┘
               │
               ▼
        ┌──────────────┐
        │  GitHub      │  🤖 "Devin is working on this"
        │              │  ✅ "PR opened" + audit log
        │              │  ⚠️ "Could not reproduce" (if validation fails)
        └──────────────┘
```

### Devin API Features Used

| Feature | Purpose |
|---------|---------|
| **Create Session** | Launch a Devin agent for each vulnerability |
| **Playbook** | Reusable remediation instructions (clone, fix, test, PR) — attached to every session |
| **Knowledge Note** | Superset codebase context (directory structure, testing patterns) — auto-applied by Devin |
| **Get Session** | Poll status + detect PRs via `pull_requests` field |
| **Get Messages** | Download full conversation for audit trail |
| **Send Message** | Notify Devin to finish after PR is submitted |
| **Close Session** | End session after grace period to free resources |
| **Get Attachments** | Download artifacts (test output, screenshots) for audit |
| **List Playbooks** | Idempotent setup — reuse existing playbook on restart |

### Task Lifecycle

```
PENDING → SESSION_CREATED → RUNNING → COMPLETED (PR opened, session closed)
                                    → NEEDS_INPUT (Devin suspended, waiting for human)
                                    → FAILED (with error details)
```

When a PR is detected, the orchestrator waits a 5-minute grace period (Devin may iterate — push fixes, open a new PR) before saving the audit log, closing the session, and posting the completion comment.

## Quick Start

```bash
git clone <this-repo>
cd vuln-remediation
cp .env.example .env     # fill in credentials
docker compose up --build
```

Open http://localhost:8000/dashboard to monitor.

### Configuration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DEVIN_API_KEY` | Yes | — | Service user key (`cog_...`) from Settings → Service Users |
| `DEVIN_ORG_ID` | Yes | — | Organization ID from the same page |
| `GITHUB_TOKEN` | Yes | — | PAT with `repo` scope |
| `GITHUB_REPO` | Yes | — | Target repo (`owner/name`) |
| `GITHUB_WEBHOOK_SECRET` | No | — | Webhook HMAC secret |
| `POLL_INTERVAL_SECONDS` | No | 30 | Polling frequency |
| `MAX_CONCURRENT_SESSIONS` | No | 3 | Max parallel Devin sessions |

### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/dashboard` | Live dashboard with metrics, filtering, audit links |
| `GET` | `/api/metrics` | JSON metrics |
| `GET` | `/api/tasks` | Task details |
| `POST` | `/api/trigger` | Force a scan cycle |
| `POST` | `/webhook/github` | GitHub webhook receiver |
| `GET` | `/api/logs/{N}` | Session audit log |
| `GET` | `/api/logs/{N}/attachments/{file}` | Download artifact |

## Dashboard

The dashboard provides:
- **Metric cards** — running, needs input (clickable → filters to blocked tasks), completed, failed (clickable → filters to failed tasks), success rate, avg time
- **Task table** — issue link, status badge, Devin session link, PR link, artifacts (PR diff or downloaded files), audit log
- **Alert banner** — appears when any task is waiting for human input, with direct links to respond in Devin
- **Auto-refresh** every 10 seconds

## Project Structure

```
src/vuln_remediation/
├── main.py              # FastAPI app, webhook, API endpoints
├── orchestrator.py      # Core state machine
├── devin_client.py      # Devin API v3 client (retry, rate limiting)
├── github_client.py     # GitHub API client
├── notifier.py          # GitHub comment service
├── persistence.py       # Task storage + audit log saving
├── models.py            # Pydantic domain models
├── config.py            # Type-safe settings (pydantic-settings)
├── logging.py           # Structured logging (structlog)
└── static/
    └── dashboard.html   # Dashboard UI
```

## Limitations & What We Learned About Devin

### Observed Devin Behaviors

- **Sessions don't self-terminate after opening a PR.** Devin continued running post-PR — attempting end-to-end testing, waiting for CI that didn't exist on the fork. We built a grace period + `DELETE` session mechanism to handle this. The `DELETE /sessions/{id}` endpoint isn't documented; we discovered it through experimentation.
- **API response schemas differ from what you'd expect.** Session messages use `source`/`message` fields, not `role`/`content`. The attachments endpoint returns a raw list, not a `{"items": [...]}` wrapper. The `pull_requests` field on the session object was the most reliable way to detect PRs — more reliable than parsing message content.
- **Devin works best with specific, scoped prompts.** Our issue descriptions included exact file paths, line numbers, attack scenarios, and proposed fixes. This is why all 3 succeeded on the first attempt. A vague issue like "fix the security bug" would likely fail or produce an incomplete fix.
- **Playbooks and Knowledge Notes serve different roles.** Playbooks are explicit instructions attached per-session (the "how"). Knowledge Notes are background context Devin recalls automatically based on trigger matching (the "what"). Conflating them would bloat every session prompt.

### System Limitations

- **No retry on failure.** If Devin's session errors out, the task is marked failed. A production system should retry with additional context from the failed session's messages.
- **No fix verification.** The orchestrator confirms a PR was opened but doesn't verify the fix is correct. A second Devin session could review the PR, or we could run the test suite independently.
- **Single-repo scope.** Hardcoded to one repository. Extending to org-wide scanning would require mapping issues to repos and managing playbooks per-codebase.
- **Prompt engineering is the bottleneck.** The system is only as good as the issue descriptions. Integrating with a vulnerability scanner (e.g., Snyk, CodeQL) that produces structured output would remove the dependency on hand-written issues.

## Future Improvements

- **PR review loop** — after Devin opens a PR, create a second session to review it
- **Retry with feedback** — when a Devin session fails, automatically create a new session with the original prompt plus the failed session's error messages as additional context. Cap at 3 retries with exponentially increasing context (first retry gets the error, second retry gets the error + Devin's last attempted approach). Track retry count on the task and surface it on the dashboard so engineering leads can spot issues that Devin consistently struggles with.
- **Slack/Teams notifications** — alert the security team when remediation completes
- **Multi-repo support** — monitor an organization's repos, not just one
- **Proactive rate limiting** — the Devin client currently retries on 429s (reactive), but at scale with hundreds of issues, we'd want a token bucket rate limiter that throttles outbound requests before hitting Devin's API limits. Combined with `MAX_CONCURRENT_SESSIONS`, this would let the orchestrator queue issues gracefully instead of flooding the API and relying on backoff.
- **Auto-merge** — merge PRs automatically if tests pass and the fix is low-risk
- **Proactive security scanning with Devin as a security engineer** — currently the system is reactive (issue filed → fix). The next evolution is proactive: use the Devin Schedules API to run a recurring "Security Audit" session (e.g., weekly) with a penetration testing playbook. The playbook would encode industry-standard pen test methodology (OWASP Top 10, CWE/SANS Top 25) and instruct Devin to: audit the codebase for vulnerabilities, attempt to reproduce them in a sandbox, and for each confirmed finding, automatically create a GitHub issue with the vulnerability details, severity, and reproduction steps. Those issues then feed back into this remediation system — closing the loop from detection to fix with no human in the critical path.
- **Multi-purpose Devin instances with a playbook library** — this system uses a single playbook for security remediation, but the same orchestration pattern applies to other engineering workflows: dependency upgrades, test coverage gaps, documentation generation, migration tasks. Each purpose would need its own playbook with domain-specific instructions and a corresponding knowledge note with the right codebase context. A playbook library (stored in Devin via the API, versioned, tagged by purpose) would let the orchestrator route different issue types to the right Devin configuration — effectively running specialized Devin agents in parallel, each with the correct context for their task.

## Production Considerations

- **Artifact storage** — attachments and audit logs are currently stored on local disk. Swap to S3 or a managed object store for durability and access control.
- **Task persistence** — JSON file works for a demo. Use PostgreSQL or DynamoDB for concurrent access, querying, and backup.
- **Authentication** — the dashboard and API endpoints are currently unauthenticated. Add OAuth or API key auth before exposing to a network.
- **Secrets rotation** — Devin API keys and GitHub tokens should be rotated periodically and stored in a vault (e.g., AWS Secrets Manager), not `.env` files.
- **Rate limiting** — the Devin client retries on 429s, but the GitHub client does not. At scale, the GitHub API's 5000 req/hr limit could be hit during frequent polling. Add the same retry-with-backoff pattern to the GitHub client, and consider caching issue data to reduce API calls.
- **Horizontal scaling** — the asyncio.Lock prevents races within a single process. For multiple replicas, use distributed locking (e.g., Redis) or a task queue (e.g., Celery).
