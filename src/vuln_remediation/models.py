"""Domain models shared across the application."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, List, Optional

from pydantic import BaseModel, Field

try:
    from enum import StrEnum
except ImportError:
    from enum import Enum

    class StrEnum(str, Enum):  # type: ignore[no-redef]
        pass


# ---------------------------------------------------------------------------
# Task lifecycle
# ---------------------------------------------------------------------------

class TaskStatus(StrEnum):
    PENDING = "pending"
    SESSION_CREATED = "session_created"
    RUNNING = "running"
    NEEDS_INPUT = "needs_input"
    COMPLETED = "completed"
    FAILED = "failed"


class RemediationTask(BaseModel):
    """Tracks a single issue → Devin session → PR lifecycle."""

    issue_number: int
    issue_title: str
    issue_url: str
    status: TaskStatus = TaskStatus.PENDING
    session_id: Optional[str] = None
    session_url: Optional[str] = None
    pr_url: Optional[str] = None
    error: Optional[str] = None
    log_file: Optional[str] = None  # path to saved session log
    attachments: List[str] = Field(default_factory=list)  # saved attachment filenames
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def transition(self, status: TaskStatus, **kwargs: Any) -> None:
        self.status = status
        self.updated_at = datetime.now(timezone.utc)
        for key, value in kwargs.items():
            setattr(self, key, value)


# ---------------------------------------------------------------------------
# Devin API response models
# ---------------------------------------------------------------------------

class DevinSession(BaseModel):
    session_id: str
    url: str
    status: str


class DevinSessionStatus(BaseModel):
    session_id: str
    status: str  # running, exit, error, suspended
    title: Optional[str] = None
    pull_requests: List[str] = Field(default_factory=list)  # PR URLs from Devin


class DevinMessage(BaseModel):
    role: Optional[str] = None
    content: Optional[str] = None


# ---------------------------------------------------------------------------
# GitHub models
# ---------------------------------------------------------------------------

class GitHubIssue(BaseModel):
    number: int
    title: str
    body: Optional[str] = None
    html_url: str
    labels: List[str] = Field(default_factory=list)
    state: str = "open"
