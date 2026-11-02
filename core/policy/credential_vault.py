"""模型凭据的静态加密（at-rest encryption）。

设计（诚实边界）：Fernet 对称加密，密钥文件位于用户本地状态目录
（``VIBE_SEC_STATE_HOME`` 或 ``~/.vibe-sec``），写盘时 0600 权限。
防止 SQLite 状态文件被单独泄露（备份/同步/误提交）时凭据随之外泄；
**不防御攻击者已控制整机**的情形（可读到密钥文件本身）。

- 加密值格式：``enc:v1:<fernet token>``（前缀区分旧明文，读时自动迁移）
- 密钥文件缺失时自动生成；损坏时新值照常加密写入，旧密文值解密失败
  返回空串并在 doctor 的 ``credential_vault`` 段可见（见 status()）
- 仅用于 ``model_configs`` 表的 ``api_key`` 字段；其余状态不加密
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

VALUE_PREFIX = "enc:v1:"


def _state_home() -> Path:
    override = os.getenv("VIBE_SEC_STATE_HOME")
    if override:
        return Path(override).expanduser().resolve()
    return Path.home() / ".vibe-sec"


def key_file_path(state_home: Path | None = None) -> Path:
    return (state_home or _state_home()) / "secret.key"


class CredentialVault:
    """Fernet 封装：懒加载/生成密钥，加密与解密均为进程内单例语义。"""

    def __init__(self, state_home: Path | None = None):
        self._state_home = state_home or _state_home()
        self._fernet: object | None = None
        self.key_error: str | None = None
        self.key_generated = False

    # -- 密钥管理 -----------------------------------------------------

    def _load_or_create_key(self) -> bytes:
        path = key_file_path(self._state_home)
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.is_file():
            try:
                return path.read_bytes().strip()
            except OSError as exc:
                self.key_error = f"unreadable:{type(exc).__name__}"
                raise
        from cryptography.fernet import Fernet

        key = Fernet.generate_key()
        path.write_bytes(key)
        self.key_generated = True
        try:
            path.chmod(stat.S_IRUSR | stat.S_IWUSR)  # 0600（Windows 上尽力而为）
        except OSError:
            pass
        return key

    def _fernet_instance(self):
        if self._fernet is None:
            from cryptography.fernet import Fernet, InvalidToken

            self._InvalidToken = InvalidToken
            self._fernet = Fernet(self._load_or_create_key())
        return self._fernet

    # -- 供依赖注入/测试 ------------------------------------------------

    def adopt_key(self, key: bytes) -> None:
        """测试与密钥轮换：直接采用给定密钥（不落盘）。"""
        from cryptography.fernet import Fernet, InvalidToken

        self._InvalidToken = InvalidToken
        self._fernet = Fernet(key)

    # -- 加解密 ---------------------------------------------------------

    def encrypt(self, plaintext: str) -> str:
        """加密明文凭据。已是密文格式则原样返回（幂等）。"""
        if not plaintext:
            return plaintext
        if plaintext.startswith(VALUE_PREFIX):
            return plaintext
        token = self._fernet_instance().encrypt(plaintext.encode("utf-8"))
        return VALUE_PREFIX + token.decode("ascii")

    def decrypt(self, value: str) -> tuple[str, bool]:
        """解密凭据，返回 (明文, 是否为旧明文待迁移)。

        - 密文格式且解密成功 → (明文, False)
        - 密文格式但解密失败（密钥更换/损坏）→ ("", False)——调用方按
          凭据缺失处理，doctor 的 vault 段会暴露此状态
        - 无前缀（旧明文）→ (原值, True)，调用方应触发一次加密回写迁移
        """
        if not value:
            return value, False
        if not value.startswith(VALUE_PREFIX):
            return value, True
        from cryptography.fernet import InvalidToken

        try:
            token = value[len(VALUE_PREFIX):].encode("ascii")
            return self._fernet_instance().decrypt(token).decode("utf-8"), False
        except (InvalidToken, ValueError, UnicodeError):
            return "", False

    # -- 自检 -----------------------------------------------------------

    def status(self) -> dict[str, object]:
        """doctor 报告用的 vault 状态（不触发密钥生成）。"""
        path = key_file_path(self._state_home)
        return {
            "enabled": True,
            "key_file": str(path),
            "key_present": path.is_file(),
            "key_error": self.key_error,
            "note": "防状态文件单独泄露；不防已控制整机的攻击者",
        }


_DEFAULT_VAULT: CredentialVault | None = None


def default_vault() -> CredentialVault:
    global _DEFAULT_VAULT
    if _DEFAULT_VAULT is None:
        _DEFAULT_VAULT = CredentialVault()
    return _DEFAULT_VAULT


def set_default_vault(vault: CredentialVault | None) -> None:
    """依赖注入（测试隔离用）。"""
    global _DEFAULT_VAULT
    _DEFAULT_VAULT = vault
