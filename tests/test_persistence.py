"""Tests for task persistence."""

import json
from pathlib import Path

from vuln_remediation.models import RemediationTask, TaskStatus
from vuln_remediation.persistence.json_file import JsonFilePersistence


class TestPersistence:
    def test_save_and_load(self, tmp_path):
        store = JsonFilePersistence(data_dir=tmp_path)

        tasks = {
            1: RemediationTask(issue_number=1, issue_title="Bug", issue_url="https://x.com"),
            2: RemediationTask(
                issue_number=2, issue_title="Fix", issue_url="https://x.com", priority="critical"
            ),
        }
        tasks[1].transition(TaskStatus.COMPLETED, pr_url="https://github.com/test/pull/1")

        store.save_tasks(tasks)
        loaded = store.load_tasks()

        assert len(loaded) == 2
        assert loaded[1].status == TaskStatus.COMPLETED
        assert loaded[1].pr_url == "https://github.com/test/pull/1"
        assert loaded[2].status == TaskStatus.PENDING
        assert loaded[2].priority == "critical"

    def test_load_empty(self, tmp_path):
        store = JsonFilePersistence(data_dir=tmp_path)
        assert store.load_tasks() == {}
