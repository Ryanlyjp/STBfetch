from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


class SecureStore:
    def __init__(self, path: Path, bootstrap_password: str):
        if not bootstrap_password:
            raise RuntimeError("SBEANS_ADMIN_PASSWORD 未设置")
        self.path = path
        if not path.exists():
            self._write_state(bootstrap_password, [])

    @staticmethod
    def _encode(value: bytes) -> str:
        return base64.b64encode(value).decode("ascii")

    @staticmethod
    def _decode(value: str) -> bytes:
        return base64.b64decode(value.encode("ascii"))

    @staticmethod
    def _derive(password: str, salt: bytes) -> bytes:
        return Scrypt(salt=salt, length=32, n=2**14, r=8, p=1).derive(password.encode("utf-8"))

    def _read_state(self) -> dict[str, str | int]:
        return json.loads(self.path.read_text(encoding="utf-8"))

    def _build_state(
        self,
        password: str,
        records: list[dict[str, object]],
        code_library: list[dict[str, object]] | None = None,
    ) -> dict[str, str | int]:
        auth_salt = os.urandom(16)
        records_salt = os.urandom(16)
        nonce = os.urandom(12)
        auth_key = self._derive(password, auth_salt)
        records_key = self._derive(password, records_salt)
        plaintext = json.dumps(
            {"records": records, "code_library": code_library or []},
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        ciphertext = AESGCM(records_key).encrypt(nonce, plaintext, b"sbeans-records-v1")
        return {
            "version": 1,
            "auth_salt": self._encode(auth_salt),
            "auth_hash": self._encode(hashlib.sha256(auth_key + b"sbeans-auth-v1").digest()),
            "records_salt": self._encode(records_salt),
            "records_nonce": self._encode(nonce),
            "records_ciphertext": self._encode(ciphertext),
        }

    def _write_state(
        self,
        password: str,
        records: list[dict[str, object]],
        code_library: list[dict[str, object]] | None = None,
    ) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        state = self._build_state(password, records, code_library)
        fd, temporary = tempfile.mkstemp(prefix=f".{self.path.name}.", dir=self.path.parent)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(state, handle, ensure_ascii=False, separators=(",", ":"))
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.path)
        except Exception:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
            raise

    def authenticate(self, password: str | None) -> bool:
        if not password:
            return False
        state = self._read_state()
        auth_key = self._derive(password, self._decode(str(state["auth_salt"])))
        actual = hashlib.sha256(auth_key + b"sbeans-auth-v1").digest()
        return hmac.compare_digest(actual, self._decode(str(state["auth_hash"])))

    def _payload(self, password: str) -> dict[str, list[dict[str, object]]]:
        if not self.authenticate(password):
            raise ValueError("面板密码错误")
        state = self._read_state()
        key = self._derive(password, self._decode(str(state["records_salt"])))
        plaintext = AESGCM(key).decrypt(
            self._decode(str(state["records_nonce"])),
            self._decode(str(state["records_ciphertext"])),
            b"sbeans-records-v1",
        )
        decoded = json.loads(plaintext.decode("utf-8"))
        if isinstance(decoded, list):
            return {"records": decoded, "code_library": []}
        if not isinstance(decoded, dict):
            raise ValueError("安全存储内容格式无效")
        records = decoded.get("records")
        code_library = decoded.get("code_library")
        return {
            "records": records if isinstance(records, list) else [],
            "code_library": code_library if isinstance(code_library, list) else [],
        }

    def _records(self, password: str) -> list[dict[str, object]]:
        return self._payload(password)["records"]

    def list_records(self, password: str) -> list[dict[str, str]]:
        return [
            {"id": record["id"], "email": record["email"], "time": record["time"]}
            for record in self._records(password)
        ]

    def add_record(self, password: str, email: str, account_password: str, time: str) -> dict[str, str]:
        payload = self._payload(password)
        records = payload["records"]
        record = {"id": uuid.uuid4().hex, "email": email, "password": account_password, "time": time}
        records.append(record)
        self._write_state(password, records, payload["code_library"])
        return {"id": record["id"], "email": email, "time": time}

    def delete_record(self, password: str, record_id: str) -> bool:
        payload = self._payload(password)
        records = payload["records"]
        remaining = [record for record in records if record["id"] != record_id]
        if len(remaining) == len(records):
            return False
        self._write_state(password, remaining, payload["code_library"])
        return True

    def update_record_time(self, password: str, email: str, record_time: str) -> int:
        payload = self._payload(password)
        target_email = email.strip().casefold()
        updated = 0
        for record in payload["records"]:
            if str(record.get("email") or "").strip().casefold() != target_email:
                continue
            if record.get("time") == record_time:
                continue
            record["time"] = record_time
            updated += 1
        if updated:
            self._write_state(password, payload["records"], payload["code_library"])
        return updated

    def selected_accounts(self, password: str, record_ids: list[str]) -> list[tuple[str, str]]:
        records = self._records(password)
        by_id = {record["id"]: record for record in records}
        if any(record_id not in by_id for record_id in record_ids):
            raise ValueError("所选账号记录不存在")
        return [(by_id[record_id]["email"], by_id[record_id]["password"]) for record_id in record_ids]

    def change_password(self, current_password: str, new_password: str) -> None:
        if not new_password:
            raise ValueError("新密码不能为空")
        payload = self._payload(current_password)
        self._write_state(new_password, payload["records"], payload["code_library"])

    def add_code_library(
        self,
        password: str,
        email: str,
        codes: list[dict[str, object]],
        next_date: str,
    ) -> dict[str, object]:
        payload = self._payload(password)
        stored_codes = [
            {
                "planId": str(item.get("planId") or ""),
                "code": str(item.get("code") or ""),
                "endDate": str(item.get("endDate") or ""),
            }
            for item in codes
            if isinstance(item, dict)
            and item.get("ok")
            and item.get("code")
            and item.get("endDate")
        ]
        if not email or len(stored_codes) != 4:
            raise ValueError("优惠码库只接受完整的四组优惠码")
        entry: dict[str, object] = {
            "id": uuid.uuid4().hex,
            "email": email,
            "next_date": next_date or stored_codes[0]["endDate"],
            "captured_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "codes": stored_codes,
        }
        payload["code_library"].append(entry)
        self._write_state(password, payload["records"], payload["code_library"])
        return entry

    def list_code_library(self, password: str) -> list[dict[str, object]]:
        entries = self._payload(password)["code_library"]
        return list(reversed(entries))
