import json
from datetime import datetime, timedelta, timezone, UTC
from pathlib import Path

import pytest

from core.verification.authorization import (
    issue_verification_authorization,
    load_verification_authorization,
)


def test_authorization_is_signed_project_bound_and_outside_repository(tmp_path):
    project = tmp_path / "project"
    state = tmp_path / "state"
    project.mkdir()
    issued = issue_verification_authorization(
        str(project), state_root=str(state), allow_service_start=True,
    )

    trusted = load_verification_authorization(
        issued["path"], str(project), state_root=str(state),
    )

    assert trusted["_trusted_authorization_verified"] is True
    assert trusted["allow_poc_execution"] is True
    assert trusted["allow_service_start"] is True
    assert not Path(issued["path"]).is_relative_to(project)


def test_authorization_rejects_tampering_wrong_project_expiry_and_repository_path(tmp_path):
    project = tmp_path / "project"
    other = tmp_path / "other"
    state = tmp_path / "state"
    project.mkdir()
    other.mkdir()
    issued = issue_verification_authorization(str(project), state_root=str(state))
    source = Path(issued["path"])

    with pytest.raises(ValueError, match="different project"):
        load_verification_authorization(issued["path"], str(other), state_root=str(state))
    expired = datetime.now(UTC) + timedelta(days=1)
    with pytest.raises(ValueError, match="expired"):
        load_verification_authorization(
            issued["path"], str(project), state_root=str(state), now=expired,
        )

    payload = json.loads(source.read_text(encoding="utf-8"))
    payload["policy"]["allow_network"] = True
    source.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="signature"):
        load_verification_authorization(issued["path"], str(project), state_root=str(state))

    with pytest.raises(ValueError, match="outside"):
        issue_verification_authorization(
            str(project), output_path=str(project / "authorization.json"), state_root=str(state),
        )
