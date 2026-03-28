import pytest

from core.approval_identity import (
    ApprovalIdentityPolicy,
    InvalidApprovalTokenError,
    MissingReviewerIdentityError,
    ReviewerIdentityNotAllowedError,
    normalize_identity_list,
)


def test_normalize_identity_list_deduplicates_and_strips():
    assert normalize_identity_list(["  Analyst1 ", "analyst1", "", "  Lead  "]) == ("Analyst1", "Lead")


def test_validate_reviewer_identity_accepts_allowlisted_user():
    policy = ApprovalIdentityPolicy(allowed_reviewers=("analyst1", "lead"))

    assert policy.validate_reviewer("  Analyst1 ") == "Analyst1"


def test_validate_reviewer_identity_rejects_missing_identity():
    policy = ApprovalIdentityPolicy(allowed_reviewers=("analyst1",))

    with pytest.raises(MissingReviewerIdentityError):
        policy.validate_reviewer(None)

    with pytest.raises(MissingReviewerIdentityError):
        policy.validate_reviewer("   ")


def test_validate_reviewer_identity_rejects_non_allowlisted_user():
    policy = ApprovalIdentityPolicy(allowed_reviewers=("analyst1",))

    with pytest.raises(ReviewerIdentityNotAllowedError):
        policy.validate_reviewer("outsider")


def test_authorize_uses_approval_token_for_approval_routes():
    policy = ApprovalIdentityPolicy(general_token="general", approval_token="approval")

    with pytest.raises(InvalidApprovalTokenError):
        policy.authorize({"Authorization": "Bearer general"}, approval_route=True)

    policy.authorize({"Authorization": "Bearer approval"}, approval_route=True)
    policy.authorize({"Authorization": "Bearer general"}, approval_route=False)


def test_policy_from_config_uses_configured_values():
    config = type(
        "Config",
        (),
        {
            "api_token": "general",
            "api_approver_token": "approval",
            "approver_identities": ("analyst1", "lead"),
        },
    )()

    policy = ApprovalIdentityPolicy.from_config(config)

    assert policy.general_token == "general"
    assert policy.approval_token == "approval"
    assert policy.allowed_reviewers == ("analyst1", "lead")
