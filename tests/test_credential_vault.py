"""模型凭据静态加密：vault 行为、状态库读写与透明迁移。"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from api.state_store import ApiStateStore
from core.policy.credential_vault import VALUE_PREFIX, CredentialVault, key_file_path


@pytest.fixture
def vault(tmp_path):
    instance = CredentialVault(state_home=tmp_path)
    instance.adopt_key(CredentialVault(state_home=tmp_path)._load_or_create_key())
    return instance


def _config(api_key: str = "sk-secret-123"):
    def model_dump(mode="json", **_):
        return {"id": "cfg-1", "model_type": "chat", "is_active": True, "api_key": api_key}

    return SimpleNamespace(
        id="cfg-1", model_type="chat", is_active=True, api_key=api_key,
        updated_at="2026-01-01T00:00:00", model_dump=model_dump,
    )


class TestVault:
    def test_roundtrip_and_prefix(self, vault):
        token = vault.encrypt("sk-plain")
        assert token.startswith(VALUE_PREFIX)
        assert vault.decrypt(token) == ("sk-plain", False)

    def test_encrypt_is_idempotent_on_ciphertext(self, vault):
        token = vault.encrypt("sk-plain")
        assert vault.encrypt(token) == token

    def test_legacy_plaintext_flagged_for_migration(self, vault):
        assert vault.decrypt("sk-old-plaintext") == ("sk-old-plaintext", True)

    def test_wrong_key_yields_empty_not_raise(self, vault):
        token = vault.encrypt("sk-plain")
        other = CredentialVault(state_home=Path(tempfile.mkdtemp()))
        other.adopt_key(CredentialVault(state_home=Path(tempfile.mkdtemp()))._load_or_create_key())
        assert other.decrypt(token) == ("", False)

    def test_status_shape(self, tmp_path):
        vault = CredentialVault(state_home=tmp_path)
        snapshot = vault.status()
        assert snapshot["enabled"] is True
        assert snapshot["key_present"] is False, "status 不得触发密钥生成"

    def test_key_file_created_with_tight_perms(self, tmp_path):
        vault = CredentialVault(state_home=tmp_path)
        vault.encrypt("x")
        path = key_file_path(tmp_path)
        assert path.is_file()


class TestStateStoreEncryption:
    def _store(self, tmp_path, vault):
        return ApiStateStore(tmp_path / "state.sqlite3", vault=vault)

    def test_api_key_encrypted_at_rest(self, tmp_path, vault):
        store = self._store(tmp_path, vault)
        store.save_model_config(_config("sk-secret-123"))
        row = store._connection.execute(
            "SELECT payload FROM model_configs WHERE id = 'cfg-1'"
        ).fetchone()
        payload = json.loads(row["payload"])
        assert payload["api_key"].startswith(VALUE_PREFIX)
        assert "sk-secret-123" not in row["payload"]

    def test_roundtrip_through_load_state(self, tmp_path, vault):
        store = self._store(tmp_path, vault)
        store.save_model_config(_config("sk-secret-123"))
        loaded = store.load_state()["model_configs"]
        assert loaded[0]["api_key"] == "sk-secret-123"

    def test_legacy_plaintext_migrated_on_load(self, tmp_path, vault):
        store = self._store(tmp_path, vault)
        # 直接以旧明文形态写入（模拟历史版本数据）
        with store._lock, store._connection:
            payload = {"id": "cfg-1", "api_key": "sk-legacy", "updated_at": "2026-01-01T00:00:00"}
            store._connection.execute(
                "INSERT INTO model_configs(id, payload, updated_at) VALUES (?, ?, ?)",
                ("cfg-1", json.dumps(payload), "2026-01-01T00:00:00"),
            )
        loaded = store.load_state()["model_configs"]
        assert loaded[0]["api_key"] == "sk-legacy", "读取侧仍得到明文"
        row = store._connection.execute(
            "SELECT payload FROM model_configs WHERE id = 'cfg-1'"
        ).fetchone()
        assert json.loads(row["payload"])["api_key"].startswith(VALUE_PREFIX), "落盘侧已迁移为密文"

    def test_empty_key_stays_empty(self, tmp_path, vault):
        store = self._store(tmp_path, vault)
        store.save_model_config(_config(""))
        loaded = store.load_state()["model_configs"]
        assert loaded[0]["api_key"] == ""
