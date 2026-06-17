# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Deprecation + strict mode for unsafe legacy approval behaviors (ADR-0030 step 5)."""

import json
import time
import urllib.request
import warnings

import pytest

from agentmesh.governance.approval import (
    ApprovalDecision,
    ApprovalRequest,
    CallbackApproval,
    WebhookApproval,
)


def _req():
    return ApprovalRequest(action="transfer", rule_name="r", policy_name="p", agent_id="a")


def _cb(approved=True):
    return lambda request: ApprovalDecision(approved=approved, approver="alice")


# --------------------------------------------------------------------------- #
# CallbackApproval: timeout auto-approval is deprecated / rejected
# --------------------------------------------------------------------------- #


class TestCallbackTimeoutDeprecation:
    def test_default_emits_no_warning(self):
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            CallbackApproval(_cb())  # on_timeout defaults to "deny"

    def test_non_deny_on_timeout_is_deprecated(self):
        with pytest.warns(DeprecationWarning, match="on_timeout"):
            CallbackApproval(_cb(), on_timeout="allow")

    def test_strict_rejects_non_deny_on_timeout(self):
        with pytest.raises(ValueError, match="on_timeout"):
            CallbackApproval(_cb(), on_timeout="allow", strict=True)

    def test_env_strict_rejects_non_deny_on_timeout(self, monkeypatch):
        monkeypatch.setenv("AGT_APPROVAL_STRICT", "1")
        with pytest.raises(ValueError):
            CallbackApproval(_cb(), on_timeout="allow")

    def test_timeout_always_denies(self):
        # Behavior unchanged: a timeout denies regardless of on_timeout.
        handler = CallbackApproval(
            lambda r: (time.sleep(0.005) or ApprovalDecision(approved=True, approver="x")),
            timeout_seconds=0,
        )
        decision = handler.request_approval(_req())
        assert not decision.approved
        assert decision.approver == "system:timeout"


# --------------------------------------------------------------------------- #
# WebhookApproval: unverified body-supplied identity is deprecated / rejected
# --------------------------------------------------------------------------- #


class _FakeResp:
    def __init__(self, body):
        self._b = json.dumps(body).encode("utf-8")

    def read(self):
        return self._b

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


@pytest.fixture
def mock_urlopen(monkeypatch):
    def _set(body):
        monkeypatch.setattr(
            urllib.request, "urlopen", lambda req, timeout=None: _FakeResp(body)
        )

    return _set


def _webhook(strict=None):
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        return WebhookApproval("https://example.com/approve", strict=strict)


class TestWebhookIdentityDeprecation:
    def test_construction_is_deprecated(self):
        with pytest.warns(DeprecationWarning, match="VersionedWebhookApproval"):
            WebhookApproval("https://example.com/approve")

    def test_non_strict_trusts_body_identity(self, mock_urlopen):
        mock_urlopen({"approved": True, "approver": "alice", "reason": "ok"})
        decision = _webhook().request_approval(_req())
        assert decision.approved
        assert decision.approver == "alice"

    def test_strict_rejects_body_identity(self, mock_urlopen):
        mock_urlopen({"approved": True, "approver": "alice"})
        decision = _webhook(strict=True).request_approval(_req())
        assert not decision.approved
        assert decision.approver == "webhook:unverified"

    def test_strict_deny_passes_through(self, mock_urlopen):
        # Denial is the safe direction and needs no identity verification.
        mock_urlopen({"approved": False, "approver": "alice", "reason": "no"})
        decision = _webhook(strict=True).request_approval(_req())
        assert not decision.approved
        assert decision.approver != "webhook:unverified"
