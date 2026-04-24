"""Async client for the Devin API v3.

Encapsulates all Devin interactions behind a clean interface so the
orchestrator never deals with raw HTTP. Uses httpx for async requests
with proper timeout, retry, and error handling.
"""

from __future__ import annotations

import asyncio

import httpx
import structlog

from vuln_remediation.config import Settings
from vuln_remediation.models import DevinMessage, DevinSession, DevinSessionStatus

logger = structlog.get_logger()


class DevinAPIError(Exception):
    """Raised when the Devin API returns an unexpected response."""

    def __init__(self, status_code: int, detail: str) -> None:
        self.status_code = status_code
        self.detail = detail
        super().__init__(f"Devin API error {status_code}: {detail}")


class DevinClient:
    """Thin async wrapper around Devin API v3.

    Usage:
        async with DevinClient(settings) as client:
            session = await client.create_session("Fix the bug")
            status = await client.get_session(session.session_id)
    """

    def __init__(self, settings: Settings) -> None:
        self._base_url = f"{settings.devin_base_url}/organizations/{settings.devin_org_id}"
        self._client = httpx.AsyncClient(
            headers={
                "Authorization": f"Bearer {settings.devin_api_key}",
                "Content-Type": "application/json",
            },
            timeout=httpx.Timeout(30.0, connect=10.0),
        )

    async def __aenter__(self) -> DevinClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.close()

    async def close(self) -> None:
        await self._client.aclose()

    # ------------------------------------------------------------------
    # Sessions
    # ------------------------------------------------------------------

    async def create_session(
        self,
        prompt: str,
        *,
        playbook_id: str | None = None,
    ) -> DevinSession:
        """Create a new Devin session with the given prompt."""
        payload: dict[str, object] = {"prompt": prompt}
        if playbook_id:
            payload["playbook_id"] = playbook_id

        data = await self._post("/sessions", payload)
        session = DevinSession(
            session_id=data["session_id"],
            url=data["url"],
            status=data.get("status", "running"),
        )
        logger.info(
            "devin_session_created",
            session_id=session.session_id,
            url=session.url,
        )
        return session

    async def get_session(self, session_id: str) -> DevinSessionStatus:
        """Get the current status of a session."""
        data = await self._get(f"/sessions/{session_id}")
        pr_urls = [
            pr["pr_url"]
            for pr in (data.get("pull_requests") or [])
            if pr.get("pr_url")
        ]
        return DevinSessionStatus(
            session_id=data["session_id"],
            status=data["status"],
            title=data.get("title"),
            pull_requests=pr_urls,
        )

    async def list_sessions(
        self,
        *,
        limit: int = 50,
        offset: int = 0,
    ) -> list[DevinSessionStatus]:
        """List sessions in the organization."""
        data = await self._get(f"/sessions?limit={limit}&offset={offset}")
        return [
            DevinSessionStatus(
                session_id=s["session_id"],
                status=s["status"],
                title=s.get("title"),
            )
            for s in data.get("items", data.get("sessions", []))
        ]

    async def send_message(self, session_id: str, message: str) -> None:
        """Send a follow-up message to a running session."""
        await self._post(f"/sessions/{session_id}/messages", {"message": message})
        logger.info("devin_message_sent", session_id=session_id)

    async def get_attachments(self, session_id: str) -> list[dict[str, str]]:
        """List attachments (files, screenshots, logs) produced by a session."""
        resp = await self._client.get(f"{self._base_url}/sessions/{session_id}/attachments")
        data = self._handle_response(resp)
        # API may return a raw list or a dict with items
        if isinstance(data, list):
            return data  # type: ignore[return-value]
        return data.get("items", data.get("attachments", []))  # type: ignore[return-value]

    async def download_attachment(self, url: str) -> bytes:
        """Download an attachment by its URL."""
        resp = await self._client.get(url)
        if resp.status_code >= 400:
            raise DevinAPIError(resp.status_code, f"Failed to download attachment: {url}")
        return resp.content

    async def close_session(self, session_id: str) -> None:
        """Close a running session. Transitions status to 'exit'.
        Silently succeeds if the session is already closed."""
        try:
            resp = await self._client.delete(f"{self._base_url}/sessions/{session_id}")
            if resp.status_code < 400:
                logger.info("devin_session_closed", session_id=session_id)
            else:
                logger.warning("devin_session_close_ignored", session_id=session_id, status=resp.status_code)
        except Exception:
            logger.warning("devin_session_close_failed", session_id=session_id)

    async def get_messages(self, session_id: str) -> list[DevinMessage]:
        """Retrieve messages from a session."""
        data = await self._get(f"/sessions/{session_id}/messages")
        return [
            DevinMessage(
                role=m.get("source") or m.get("role"),
                content=m.get("message") or m.get("content"),
            )
            for m in data.get("items", data.get("messages", []))
        ]

    # ------------------------------------------------------------------
    # Playbooks
    # ------------------------------------------------------------------

    async def create_playbook(self, name: str, instructions: str) -> str:
        """Create a playbook and return its ID."""
        data = await self._post("/playbooks", {"title": name, "body": instructions})
        playbook_id = data["playbook_id"]
        logger.info("devin_playbook_created", playbook_id=playbook_id, name=name)
        return playbook_id

    async def list_playbooks(self) -> list[dict[str, object]]:
        """List all playbooks in the organization."""
        data = await self._get("/playbooks")
        return data.get("items", data.get("playbooks", []))  # type: ignore[return-value]

    # ------------------------------------------------------------------
    # Knowledge Notes
    # ------------------------------------------------------------------

    async def create_knowledge_note(
        self,
        name: str,
        trigger: str,
        body: str,
    ) -> str:
        """Create a knowledge note and return its ID."""
        data = await self._post(
            "/knowledge/notes",
            {"name": name, "trigger": trigger, "body": body},
        )
        note_id = data["note_id"]
        logger.info("devin_knowledge_note_created", note_id=note_id, name=name)
        return note_id

    async def list_knowledge_notes(self) -> list[dict[str, object]]:
        """List all knowledge notes in the organization."""
        data = await self._get("/knowledge/notes")
        return data.get("items", data.get("notes", []))  # type: ignore[return-value]

    # ------------------------------------------------------------------
    # Schedules
    # ------------------------------------------------------------------

    async def create_schedule(
        self,
        prompt: str,
        cron_schedule: str,
        *,
        timezone: str = "UTC",
    ) -> str:
        """Create a recurring schedule and return its ID."""
        data = await self._post(
            "/schedules",
            {
                "prompt": prompt,
                "cron_schedule": cron_schedule,
                "timezone": timezone,
            },
        )
        schedule_id = data["schedule_id"]
        logger.info(
            "devin_schedule_created",
            schedule_id=schedule_id,
            cron=cron_schedule,
        )
        return schedule_id

    # ------------------------------------------------------------------
    # HTTP helpers
    # ------------------------------------------------------------------

    async def _get(self, path: str) -> dict[str, object]:
        return await self._request("GET", path)

    async def _post(self, path: str, payload: dict[str, object]) -> dict[str, object]:
        return await self._request("POST", path, json=payload)

    async def _request(
        self,
        method: str,
        path: str,
        max_retries: int = 3,
        **kwargs: object,
    ) -> dict[str, object]:
        """Make an HTTP request with retry on transient failures."""
        last_error: Exception | None = None
        for attempt in range(max_retries):
            try:
                resp = await self._client.request(method, f"{self._base_url}{path}", **kwargs)  # type: ignore[arg-type]
                if resp.status_code == 429:
                    # Rate limited — back off and retry
                    wait = min(2 ** attempt * 2, 30)
                    logger.warning("devin_rate_limited", attempt=attempt, wait=wait)
                    await asyncio.sleep(wait)
                    continue
                return self._handle_response(resp)
            except httpx.TimeoutException as exc:
                last_error = exc
                wait = min(2 ** attempt * 2, 30)
                logger.warning("devin_timeout", attempt=attempt, wait=wait)
                await asyncio.sleep(wait)
            except httpx.ConnectError as exc:
                last_error = exc
                wait = min(2 ** attempt * 2, 30)
                logger.warning("devin_connect_error", attempt=attempt, wait=wait)
                await asyncio.sleep(wait)
        raise DevinAPIError(0, f"Request failed after {max_retries} retries: {last_error}")

    @staticmethod
    def _handle_response(resp: httpx.Response) -> dict[str, object]:
        if resp.status_code >= 400:
            detail = resp.text
            try:
                detail = resp.json().get("detail", resp.text)
            except Exception:
                pass
            raise DevinAPIError(resp.status_code, str(detail))
        return resp.json()  # type: ignore[no-any-return]
