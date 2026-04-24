"""Protocol for notification backends (GitHub comments, Slack, etc.)."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from vuln_remediation.models import RemediationTask


@runtime_checkable
class NotificationSink(Protocol):
    """Interface for posting remediation lifecycle updates."""

    async def on_dispatched(self, task: RemediationTask) -> None: ...
    async def on_completed(self, task: RemediationTask) -> None: ...
    async def on_needs_input(self, task: RemediationTask) -> None: ...
    async def on_failed(self, task: RemediationTask) -> None: ...
