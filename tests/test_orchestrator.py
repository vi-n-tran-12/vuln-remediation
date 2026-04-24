"""Tests for core orchestrator logic."""

import pytest

from vuln_remediation.models import GitHubIssue, RemediationTask, TaskStatus
from vuln_remediation.orchestrator import _detect_priority, build_prompt


# ---------------------------------------------------------------------------
# Priority detection
# ---------------------------------------------------------------------------

class TestDetectPriority:
    def test_critical_in_body(self):
        assert _detect_priority("Some title", "Severity: Critical") == "critical"

    def test_critical_in_title(self):
        assert _detect_priority("Critical bug found", "") == "critical"

    def test_high_in_body(self):
        assert _detect_priority("SSRF issue", "Severity: High") == "high"

    def test_low_in_body(self):
        assert _detect_priority("Minor issue", "Severity: Low") == "low"

    def test_defaults_to_medium(self):
        assert _detect_priority("Some issue", "No severity mentioned") == "medium"

    def test_case_insensitive(self):
        assert _detect_priority("", "CRITICAL vulnerability") == "critical"

    def test_critical_takes_precedence_over_high(self):
        assert _detect_priority("", "Critical and High severity") == "critical"


# ---------------------------------------------------------------------------
# Prompt builder
# ---------------------------------------------------------------------------

class TestBuildPrompt:
    def test_includes_repo(self):
        issue = GitHubIssue(number=1, title="Bug", body="Fix it", html_url="https://x.com")
        prompt = build_prompt(issue, "owner/repo")
        assert "owner/repo" in prompt

    def test_includes_issue_number(self):
        issue = GitHubIssue(number=42, title="Bug", body="Fix it", html_url="https://x.com")
        prompt = build_prompt(issue, "owner/repo")
        assert "#42" in prompt
        assert "Fixes #42" in prompt

    def test_includes_title_and_body(self):
        issue = GitHubIssue(
            number=1, title="SQL Injection", body="The clause is injected", html_url="https://x.com"
        )
        prompt = build_prompt(issue, "owner/repo")
        assert "SQL Injection" in prompt
        assert "The clause is injected" in prompt

    def test_handles_empty_body(self):
        issue = GitHubIssue(number=1, title="Bug", body=None, html_url="https://x.com")
        prompt = build_prompt(issue, "owner/repo")
        assert "No description provided" in prompt


# ---------------------------------------------------------------------------
# Task state machine
# ---------------------------------------------------------------------------

class TestTaskStateMachine:
    def test_initial_state(self):
        task = RemediationTask(issue_number=1, issue_title="Test", issue_url="https://x.com")
        assert task.status == TaskStatus.PENDING
        assert task.session_id is None
        assert task.pr_url is None

    def test_transition_to_running(self):
        task = RemediationTask(issue_number=1, issue_title="Test", issue_url="https://x.com")
        task.transition(TaskStatus.RUNNING)
        assert task.status == TaskStatus.RUNNING

    def test_transition_with_kwargs(self):
        task = RemediationTask(issue_number=1, issue_title="Test", issue_url="https://x.com")
        task.transition(TaskStatus.COMPLETED, pr_url="https://github.com/test/pull/1")
        assert task.status == TaskStatus.COMPLETED
        assert task.pr_url == "https://github.com/test/pull/1"

    def test_transition_updates_timestamp(self):
        task = RemediationTask(issue_number=1, issue_title="Test", issue_url="https://x.com")
        original = task.updated_at
        task.transition(TaskStatus.RUNNING)
        assert task.updated_at >= original

    def test_failed_with_error(self):
        task = RemediationTask(issue_number=1, issue_title="Test", issue_url="https://x.com")
        task.transition(TaskStatus.FAILED, error="Rate limited")
        assert task.status == TaskStatus.FAILED
        assert task.error == "Rate limited"

    def test_needs_input(self):
        task = RemediationTask(issue_number=1, issue_title="Test", issue_url="https://x.com")
        task.transition(TaskStatus.NEEDS_INPUT)
        assert task.status == TaskStatus.NEEDS_INPUT

    def test_priority_default(self):
        task = RemediationTask(issue_number=1, issue_title="Test", issue_url="https://x.com")
        assert task.priority == "medium"

    def test_priority_set(self):
        task = RemediationTask(
            issue_number=1, issue_title="Test", issue_url="https://x.com", priority="critical"
        )
        assert task.priority == "critical"
