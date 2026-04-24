"""FastAPI application: webhook receiver, dashboard, and metrics API.

Endpoints:
    POST /webhook/github     — GitHub webhook receiver (issue events)
    GET  /dashboard          — HTML dashboard showing task status
    GET  /api/metrics        — JSON metrics for programmatic access
    GET  /api/tasks          — Full task list as JSON
    POST /api/trigger        — Manually trigger a scan + dispatch cycle
    GET  /api/logs/{number}  — Session audit log for an issue
    GET  /health             — Health check
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncGenerator

import structlog
from fastapi import BackgroundTasks, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse

from vuln_remediation.agents.devin import DevinClient
from vuln_remediation.config import Settings
from vuln_remediation.logging import setup_logging
from vuln_remediation.notifications.github import GitHubNotifier
from vuln_remediation.orchestrator import Orchestrator
from vuln_remediation.persistence.json_file import JsonFilePersistence
from vuln_remediation.sources.github import GitHubClient

logger = structlog.get_logger()

DASHBOARD_PATH = Path(__file__).parent / "static" / "dashboard.html"


# ---------------------------------------------------------------------------
# Devin-specific provisioning (extracted from orchestrator)
# ---------------------------------------------------------------------------

async def _ensure_devin_playbook(devin: DevinClient) -> str | None:
    """Create or reuse the remediation playbook. Returns playbook_id."""
    try:
        existing = await devin.list_playbooks()
        for pb in existing:
            if pb.get("title") == "Security Vulnerability Remediation":
                playbook_id = pb.get("playbook_id")
                logger.info("playbook_reused", playbook_id=playbook_id)
                return playbook_id  # type: ignore[return-value]

        playbook_id = await devin.create_playbook(
            name="Security Vulnerability Remediation",
            instructions=(
                "You are triaging and remediating a security vulnerability.\n\n"
                "## Phase 1: Validate the vulnerability\n"
                "1. Clone the repository\n"
                "2. Read the GitHub issue carefully — it describes the vulnerability, "
                "affected code, and an attack scenario\n"
                "3. Set up a local environment to reproduce the issue:\n"
                "   - Install dependencies\n"
                "   - Spin up the application (or the relevant subsystem) in a sandbox\n"
                "4. Attempt to reproduce the attack scenario described in the issue\n"
                "5. Document your findings:\n"
                "   - Could you reproduce the vulnerability? What did you observe?\n"
                "   - If you could NOT reproduce it, stop here. Post a comment on the "
                "GitHub issue explaining what you tried, what you observed, and why "
                "the vulnerability may not be exploitable as described. Then finish.\n\n"
                "## Phase 2: Fix the vulnerability (only if validated)\n"
                "6. Implement the fix described in the issue\n"
                "7. Write unit tests that verify the vulnerability is closed:\n"
                "   - Write a test that reproduces the attack scenario\n"
                "   - Confirm the test fails without your fix and passes with it\n"
                "   - Test edge cases (e.g. malformed input, boundary values)\n"
                "8. Run the existing test suite to ensure nothing is broken\n"
                "9. Open a pull request that references the issue "
                '(use "Fixes #N" in the PR body)\n'
                "10. In the PR description, include:\n"
                "   - Reproduction steps you used to validate the vulnerability\n"
                "   - What the fix does and why\n"
                "   - How the tests verify the fix\n\n"
                "Constraints:\n"
                "- Only modify files directly related to the fix\n"
                "- Follow the existing code style and conventions\n"
                "- Do not refactor unrelated code\n"
                "- Keep the PR focused and reviewable\n"
                "- After opening the PR (or posting the comment), finish the session"
            ),
        )

        # Also create knowledge note
        existing_notes = await devin.list_knowledge_notes()
        has_note = any(n.get("name") == "Apache Superset Codebase" for n in existing_notes)
        if not has_note:
            await devin.create_knowledge_note(
                name="Apache Superset Codebase",
                trigger="When working on the Apache Superset repository",
                body=(
                    "Apache Superset is a data exploration and visualization platform.\n\n"
                    "Key directories:\n"
                    "- superset/security/ — authentication, authorization, RLS, guest tokens\n"
                    "- superset/connectors/sqla/ — SQLAlchemy connector, query building\n"
                    "- superset/db_engine_specs/ — database engine specifications\n"
                    "- superset/utils/network.py — hostname/port validation utilities\n"
                    "- superset/sql/parse.py — SQL parsing and sanitize_clause()\n"
                    "- superset/config.py — all configuration defaults\n"
                    "- superset/initialization/__init__.py — startup checks\n\n"
                    "Testing:\n"
                    "- Tests are in tests/unit_tests/ and tests/integration_tests/\n"
                    "- Run with: pytest tests/unit_tests/\n"
                    "- The fork has no CI workflows — run tests locally before opening PRs"
                ),
            )

        return playbook_id
    except Exception:
        logger.exception("devin_provisioning_failed")
        return None


# ---------------------------------------------------------------------------
# App lifecycle
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    settings = Settings()  # type: ignore[call-arg]
    setup_logging(settings.log_level)
    logger.info("app_starting", repo=settings.github_repo)

    # Build concrete implementations
    devin = DevinClient(settings)
    github = GitHubClient(settings)
    notifier = GitHubNotifier(github)
    persistence = JsonFilePersistence()

    # Devin-specific provisioning
    playbook_id = await _ensure_devin_playbook(devin)

    # Wire the orchestrator
    app.state.settings = settings
    app.state.orchestrator = Orchestrator(
        agent=devin,
        source=github,
        notifier=notifier,
        persistence=persistence,
        repo=settings.github_repo,
        max_concurrent_sessions=settings.max_concurrent_sessions,
        playbook_id=playbook_id,
    )
    app.state.dashboard_html = DASHBOARD_PATH.read_text()

    async def poll_loop() -> None:
        while True:
            try:
                await app.state.orchestrator.run_once()
            except Exception:
                logger.exception("background_poll_error")
            await asyncio.sleep(settings.poll_interval_seconds)

    app.state.poll_task = asyncio.create_task(poll_loop())
    yield

    app.state.poll_task.cancel()
    try:
        await app.state.poll_task
    except asyncio.CancelledError:
        pass
    await app.state.orchestrator.close()
    logger.info("app_stopped")


app = FastAPI(
    title="Vulnerability Remediation System",
    description="Event-driven security remediation powered by Devin",
    version="0.1.0",
    lifespan=lifespan,
)


def _get_orchestrator(request: Request) -> Orchestrator:
    orch = request.app.state.orchestrator
    if not orch:
        raise HTTPException(status_code=503, detail="Orchestrator not ready")
    return orch


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.exception("unhandled_error", path=request.url.path)
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})


# ---------------------------------------------------------------------------
# Webhook
# ---------------------------------------------------------------------------

def _verify_signature(payload: bytes, signature: str, secret: str) -> bool:
    if not secret:
        return True
    expected = "sha256=" + hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


@app.post("/webhook/github")
async def github_webhook(request: Request, background_tasks: BackgroundTasks) -> JSONResponse:
    body = await request.body()
    settings = request.app.state.settings

    if settings.github_webhook_secret and not _verify_signature(
        body,
        request.headers.get("X-Hub-Signature-256", ""),
        settings.github_webhook_secret,
    ):
        raise HTTPException(status_code=401, detail="Invalid signature")

    if request.headers.get("X-GitHub-Event", "") != "issues":
        return JSONResponse({"status": "ignored"})

    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    if payload.get("action") not in ("opened", "labeled"):
        return JSONResponse({"status": "ignored"})

    issue = payload.get("issue", {})
    logger.info("webhook_received", issue=issue.get("number"), title=issue.get("title"))

    orch = _get_orchestrator(request)
    background_tasks.add_task(orch.run_once)
    return JSONResponse({"status": "accepted", "issue": issue.get("number")})


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------

@app.get("/api/metrics")
async def get_metrics(request: Request) -> dict[str, Any]:
    return _get_orchestrator(request).get_metrics()


@app.get("/api/tasks")
async def get_tasks(request: Request) -> list[dict[str, Any]]:
    return [t.model_dump(mode="json") for t in _get_orchestrator(request).get_tasks()]


@app.post("/api/trigger")
async def trigger_scan(request: Request, background_tasks: BackgroundTasks) -> JSONResponse:
    background_tasks.add_task(_get_orchestrator(request).run_once)
    return JSONResponse({"status": "triggered"})


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()}


@app.get("/api/logs/{issue_number}")
async def get_log(issue_number: int) -> HTMLResponse:
    log_path = Path(f"data/logs/issue-{issue_number}.md")
    if not log_path.exists():
        raise HTTPException(status_code=404, detail="Log not found")
    content = log_path.read_text()

    attach_dir = Path(f"data/logs/issue-{issue_number}-attachments")
    attachment_links = ""
    if attach_dir.exists():
        files = sorted(attach_dir.iterdir())
        if files:
            attachment_links = "\n\n## Attachments\n\n" + "\n".join(
                f"- <a href='/api/logs/{issue_number}/attachments/{f.name}'>{f.name}</a>"
                for f in files
            )

    escaped = content.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return HTMLResponse(
        f"<html><head><title>Log: Issue #{issue_number}</title>"
        f"<style>body{{background:#0d1117;color:#c9d1d9;font-family:monospace;padding:2rem;"
        f"white-space:pre-wrap}}a{{color:#58a6ff}}</style></head>"
        f"<body><a href='/dashboard'>← Dashboard</a>\n\n{escaped}"
        f"{attachment_links}</body></html>"
    )


@app.get("/api/logs/{issue_number}/attachments/{filename}")
async def get_attachment(issue_number: int, filename: str) -> Any:
    from fastapi.responses import FileResponse
    path = Path(f"data/logs/issue-{issue_number}-attachments/{filename}")
    if not path.exists() or ".." in filename:
        raise HTTPException(status_code=404, detail="Attachment not found")
    return FileResponse(path)


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request) -> str:
    return request.app.state.dashboard_html
