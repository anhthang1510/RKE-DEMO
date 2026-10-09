"""Two persistent endpoints and an atomic, directory-based local transport."""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import threading
import time
from typing import Callable

from .crypto import (MAX_SEQUENCE, PROTOCOL, ProtocolError, b64, canonical,
                     generate_identity, hexbytes, make_data, open_handshake,
                     read_data, rs, seal_handshake, unb64, validate_filename, xor_bytes)

DEFAULT_CONFIG = {
    "protocol": PROTOCOL, "key_bits": 128, "hash_algorithm": "sha256", "cipher": "AES-CBC",
    "rotate_right_bits": 1, "max_file_bytes": 5 * 1024 * 1024, "poll_interval_seconds": 0.3,
}


def atomic_bytes(path: Path, data: bytes, private: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + "." + secrets.token_hex(8) + ".tmp")
    try:
        with temporary.open("xb") as stream:
            if private and os.name != "nt":
                os.chmod(temporary, 0o600)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def atomic_json(path: Path, value: dict, private: bool = False) -> None:
    atomic_bytes(path, (json.dumps(value, ensure_ascii=True, indent=2, allow_nan=False) + "\n").encode(), private)


def unique_fields(pairs: list) -> dict:
    value = {}
    for key, item in pairs:
        if key in value:
            raise ProtocolError("FORMAT", "JSON có tên trường trùng lặp.")
        value[key] = item
    return value


def load_json(path: Path, maximum: int = 16 * 1024 * 1024) -> dict:
    if path.is_symlink() or path.stat().st_size > maximum:
        raise ProtocolError("SIZE", "File JSON quá lớn hoặc là liên kết.")
    # Read with a bound even if another local program changes the file during stat().
    with path.open("rb") as stream:
        raw = stream.read(maximum + 1)
    if len(raw) > maximum:
        raise ProtocolError("SIZE", "File JSON vượt giới hạn.")
    try:
        value = json.loads(raw, object_pairs_hook=unique_fields,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (ValueError, UnicodeError, RecursionError) as exc:
        if isinstance(exc, ProtocolError):
            raise
        raise ProtocolError("FORMAT", "Không đọc được JSON hợp lệ.") from None
    if not isinstance(value, dict):
        raise ProtocolError("FORMAT", "Nội dung JSON phải là một object.")
    return value


def load_config(root: Path) -> dict:
    config = load_json(root / "config.json", 8192)
    if set(config) != set(DEFAULT_CONFIG):
        raise ProtocolError("CONFIG", "config.json thiếu trường hoặc có trường không hỗ trợ.")
    for field in ("protocol", "hash_algorithm", "cipher", "rotate_right_bits"):
        if config[field] != DEFAULT_CONFIG[field]:
            raise ProtocolError("CONFIG", f"Không hỗ trợ giá trị của {field}.")
    if type(config["key_bits"]) is not int or config["key_bits"] not in (128, 256):
        raise ProtocolError("CONFIG", "key_bits chỉ có thể là 128 hoặc 256.")
    if type(config["max_file_bytes"]) is not int or not 1 <= config["max_file_bytes"] <= 5 * 1024 * 1024:
        raise ProtocolError("CONFIG", "max_file_bytes phải từ 1 đến 5242880.")
    if (type(config["poll_interval_seconds"]) not in (int, float)
            or not 0.05 <= config["poll_interval_seconds"] <= 5):
        raise ProtocolError("CONFIG", "poll_interval_seconds phải từ 0.05 đến 5.")
    return config


def profile_digest(config: dict) -> bytes:
    # Polling interval is a local preference, not a cryptographic parameter.
    return hashlib.sha256(canonical({k: v for k, v in config.items()
                                     if k != "poll_interval_seconds"})).digest()


def initialize(root: Path) -> bool:
    """Provision pinned public keys locally. Never overwrite an existing runtime."""
    root = root.resolve()
    config = load_config(root)
    runtime = root / "runtime"
    if runtime.exists():
        if not (runtime / "READY").exists():
            raise ProtocolError("SETUP", "Thư mục runtime chưa hoàn tất; dùng một bản giải nén mới.")
        for role in ("alice", "bob"):
            existing = load_json(runtime / role / "config.json")
            if existing["profile_digest"] != profile_digest(config).hex():
                raise ProtocolError("CONFIG", "Cấu hình đã đổi sau khởi tạo. Hãy dùng một bản giải nén mới.")
        return False
    staging = root / (".initializing-" + secrets.token_hex(8))
    staging.mkdir(mode=0o700)
    try:
        identities = {role: generate_identity() for role in ("alice", "bob")}
        for role in ("alice", "bob"):
            other = "bob" if role == "alice" else "alice"
            directory = staging / role
            directory.mkdir(mode=0o700)
            private, public = identities[role]
            atomic_bytes(directory / "private_key.pem", private, True)
            atomic_bytes(directory / "public_key.pem", public)
            atomic_bytes(directory / "peer_public_key.pem", identities[other][1])
            atomic_json(directory / "config.json", {
                "role": role, "profile_digest": profile_digest(config).hex(),
                "session": None, "pending": None, "last_sent_sequence": None,
                "last_sent_hash": None, "last_wrapped_key": None,
                "used_key_fingerprints": [], "last_incoming_hello_digest": None,
                "cached_welcome": None,
            }, True)
            for name in ("sent", "processed", "rejected"):
                (directory / name).mkdir()
        (staging / "READY").write_text("Local trusted setup complete.\n", encoding="utf-8")
        os.rename(staging, runtime)
    finally:
        if staging.exists():
            shutil.rmtree(staging)
    for role in ("alice", "bob"):
        (root / "wire" / ("to_" + role)).mkdir(parents=True, exist_ok=True)
        (root / "received" / role).mkdir(parents=True, exist_ok=True)
    return True


class ProcessLock:
    """One CLI process per endpoint; locks are released by the OS on exit."""

    def __init__(self, path: Path):
        self.path = path
        self.stream = None

    def __enter__(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.stream = self.path.open("a+b")
        self.stream.seek(0, os.SEEK_END)
        if self.stream.tell() == 0:
            self.stream.write(b"0")
            self.stream.flush()
        self.stream.seek(0)
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(self.stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self.stream.close()
            self.stream = None
            raise ProtocolError("LOCKED", "Bên này đang chạy trong cửa sổ khác. Hãy đóng cửa sổ đó trước.") from None
        return self

    def __exit__(self, *_):
        if self.stream is not None:
            if os.name == "nt":
                import msvcrt
                self.stream.seek(0)
                msvcrt.locking(self.stream.fileno(), msvcrt.LK_UNLCK, 1)
            self.stream.close()


class Endpoint:
    """Endpoint methods are serialized within one process with an RLock.

    CLI callers must also hold ProcessLock to prevent concurrent processes from
    overwriting the same role's state. Alice and Bob have separate state files.
    """

    def __init__(self, root: Path, role: str, logger: Callable[[dict], None] | None = None):
        if role not in ("alice", "bob"):
            raise ValueError("Role must be alice or bob")
        self.root, self.role = root.resolve(), role
        self.other = "bob" if role == "alice" else "alice"
        self.directory = self.root / "runtime" / role
        if not (self.root / "runtime" / "READY").exists():
            raise ProtocolError("SETUP", "Chạy 0_CAI_DAT.cmd hoặc python setup_demo.py trước.")
        self.config = load_config(self.root)
        self.state = load_json(self.directory / "config.json")
        if self.state["profile_digest"] != profile_digest(self.config).hex():
            raise ProtocolError("CONFIG", "Cấu hình đã đổi sau khởi tạo; hãy dùng bản giải nén mới.")
        self.key_bytes = self.config["key_bits"] // 8
        self.private = (self.directory / "private_key.pem").read_bytes()
        self.peer_public = (self.directory / "peer_public_key.pem").read_bytes()
        self.lock = threading.RLock()
        self.logger = logger
        self.events: list[dict] = []

    def _save(self):
        atomic_json(self.directory / "config.json", self.state, True)

    def _event(self, event: str, **fields) -> dict:
        record = {"time": time.strftime("%Y-%m-%d %H:%M:%S"), "role": self.role,
                  "event": event, **fields}
        self.events.append(record)
        with (self.directory / "events.jsonl").open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(record, ensure_ascii=True) + "\n")
        if self.logger:
            self.logger(record)
        return record

    def _queue(self, packet: dict) -> Path:
        inbox = self.root / "wire" / ("to_" + self.other)
        inbox.mkdir(parents=True, exist_ok=True)
        name = f"{time.time_ns():020d}_{secrets.token_hex(8)}"
        temporary = inbox / ("." + name + ".tmp")
        destination = inbox / (name + ".packet")
        temporary.mkdir()
        try:
            atomic_json(temporary / "config.json", packet)
            os.replace(temporary, destination)
        finally:
            if temporary.exists():
                shutil.rmtree(temporary)
        return destination / "config.json"

    def connect(self) -> Path | None:
        with self.lock:
            if self.role != "alice":
                raise ProtocolError("ROLE", "Alice là bên bắt đầu thiết lập phiên.")
            if self.state["session"] is not None:
                self._event("INFO", detail="Phiên đã được thiết lập.")
                return None
            if self.state["pending"] is None:
                sid = secrets.token_hex(16)
                word = secrets.token_bytes(self.key_bytes)
                iv = secrets.token_bytes(self.key_bytes)
                body = bytes.fromhex(sid) + bytes([self.key_bytes]) + iv + word + profile_digest(self.config)
                hello = seal_handshake("hello", self.role, self.other, sid, body, self.private, self.peer_public)
                self.state["pending"] = {"session_id": sid, "a_word": word.hex(),
                                         "protocol_iv": iv.hex(), "hello": hello}
                self._save()
            path = self._queue(self.state["pending"]["hello"])
            self._event("HELLO_SENT", detail="Đã gửi IV và A-word trong gói RSA có chữ ký.")
            return path

    def _new_session(self, sid: str, k2: bytes, iv: bytes):
        self.state["session"] = {"session_id": sid, "k2": k2.hex(), "protocol_iv": iv.hex(),
                                 "next_send": 2, "next_receive": 2}
        self.state["pending"] = None
        self._save()
        self._event("SESSION_READY", session_id=sid,
                    key_fingerprint=hashlib.sha256(k2).hexdigest()[:16],
                    detail="Đã thiết lập K2 = A-word XOR B-word.")

    def _receive_hello(self, packet: dict):
        if self.role != "bob":
            raise ProtocolError("ROLE", "Chỉ Bob nhận hello.")
        body = open_handshake(packet, kind="hello", sender=self.other, recipient=self.role,
                              private_pem=self.private, peer_public_pem=self.peer_public)
        length = self.key_bytes
        if len(body) != 17 + 2 * length + 32 or body[16] != length:
            raise ProtocolError("FORMAT", "Độ dài hello không khớp cấu hình.")
        sid, iv, word = body[:16].hex(), body[17:17 + length], body[17 + length:17 + 2 * length]
        if sid != packet["session_id"] or body[-32:] != profile_digest(self.config):
            raise ProtocolError("CONFIG", "Thông số hello không khớp.")
        hello_digest = hashlib.sha256(canonical(packet)).hexdigest()
        if self.state["session"] is not None:
            if hello_digest == self.state["last_incoming_hello_digest"]:
                self._queue(self.state["cached_welcome"])
                self._event("WELCOME_RESENT", detail="Gửi lại phản hồi hello cũ, giữ nguyên bộ đếm.")
                return
            raise ProtocolError("SESSION_ACTIVE", "Đã có phiên; không chấp nhận hello thay phiên đang dùng.")
        b_word = secrets.token_bytes(length)
        response_body = bytes.fromhex(sid) + rs(iv, 1) + b_word + bytes.fromhex(hello_digest)
        welcome = seal_handshake("welcome", self.role, self.other, sid, response_body,
                                 self.private, self.peer_public)
        self.state["last_incoming_hello_digest"] = hello_digest
        self.state["cached_welcome"] = welcome
        self._new_session(sid, xor_bytes(word, b_word), iv)
        self._queue(welcome)

    def _receive_welcome(self, packet: dict):
        if self.role != "alice":
            raise ProtocolError("ROLE", "Chỉ Alice nhận welcome.")
        body = open_handshake(packet, kind="welcome", sender=self.other, recipient=self.role,
                              private_pem=self.private, peer_public_pem=self.peer_public)
        pending = self.state["pending"]
        if pending is None:
            raise ProtocolError("REPLAY", "Không có hello đang chờ; bỏ phản hồi lặp lại.")
        length = self.key_bytes
        iv = bytes.fromhex(pending["protocol_iv"])
        if (len(body) != 16 + 2 * length + 32 or packet["session_id"] != pending["session_id"]
                or body[:16].hex() != pending["session_id"]
                or body[16:16 + length] != rs(iv, 1)
                or body[-32:] != hashlib.sha256(canonical(pending["hello"])).digest()):
            raise ProtocolError("AUTH", "Phản hồi IV hoặc nội dung hello không khớp.")
        b_word = body[16 + length:16 + 2 * length]
        self._new_session(pending["session_id"], xor_bytes(bytes.fromhex(pending["a_word"]), b_word), iv)

    def send_file(self, path: Path, tamper: str | None = None) -> Path:
        with self.lock:
            if tamper not in (None, "hash", "ciphertext", "key", "iv"):
                raise ValueError("Unknown tamper scenario")
            session = self._session()
            sequence = session["next_send"]
            if sequence > MAX_SEQUENCE:
                raise ProtocolError("COUNTER", "Đã hết phạm vi bộ đếm; cần phiên mới.")
            path = path.expanduser()
            if not path.is_absolute():
                path = self.root / path
            filename = validate_filename(path.name)
            if not path.is_file() or path.stat().st_size > self.config["max_file_bytes"]:
                raise ProtocolError("FILE", "Không tìm thấy file hoặc file lớn hơn giới hạn cấu hình.")
            with path.open("rb") as stream:
                plaintext = stream.read(self.config["max_file_bytes"] + 1)
            if len(plaintext) > self.config["max_file_bytes"]:
                raise ProtocolError("SIZE", "File vượt giới hạn trong khi đọc.")
            used = set(self.state["used_key_fingerprints"])
            while True:
                key = secrets.token_bytes(self.key_bytes)
                fingerprint = hashlib.sha256(key).hexdigest()
                if fingerprint not in used:
                    break
            packet = make_data(sender=self.role, recipient=self.other,
                               session_id=session["session_id"], sequence=sequence,
                               filename=filename, plaintext=plaintext, key=key,
                               k2=bytes.fromhex(session["k2"]),
                               protocol_iv=bytes.fromhex(session["protocol_iv"]))
            # The clean original is kept BEFORE any deliberate tampering.
            atomic_json(self.directory / "sent" / f"{sequence:020d}" / "config.json", packet)
            self.state["used_key_fingerprints"].append(fingerprint)
            self.state["last_sent_sequence"] = sequence
            self.state["last_sent_hash"] = packet["hash"]
            self.state["last_wrapped_key"] = packet["wrapped_key"]
            session["next_send"] += 1
            self._save()  # Persist sequence reservation before publishing the bundle.
            transmitted = corrupt(packet, tamper) if tamper else packet
            destination = self._queue(transmitted)
            self._event("QUEUED", sequence=sequence, filename=filename,
                        key_fingerprint=fingerprint[:16], tampered=tamper,
                        detail="Đã xếp gói vào thư mục nhận; chờ bên nhận kiểm tra.",
                        packet_path=str(destination))
            return destination

    def resend(self, sequence: int | None = None) -> Path:
        with self.lock:
            self._session()
            if sequence is None:
                sequence = self.state["last_sent_sequence"]
            if type(sequence) is not int or not 2 <= sequence <= MAX_SEQUENCE:
                raise ProtocolError("RESEND", "Chưa có gói để gửi lại hoặc số thứ tự không hợp lệ.")
            original = self.directory / "sent" / f"{sequence:020d}" / "config.json"
            if not original.exists():
                raise ProtocolError("RESEND", "Không có bản gốc của số thứ tự này.")
            path = self._queue(load_json(original))
            self._event("RESENT", sequence=sequence,
                        detail="Gửi lại đúng bản gốc; không sinh khóa mới, không tăng bộ đếm.")
            return path

    def _session(self) -> dict:
        if self.state["session"] is None:
            raise ProtocolError("NO_SESSION", "Chưa thiết lập phiên. Mở cả Alice/Bob rồi chờ SESSION_READY.")
        return self.state["session"]

    def _receive_data(self, packet: dict):
        session = self._session()
        plaintext, filename = read_data(packet, sender=self.other, recipient=self.role,
                                        session_id=session["session_id"],
                                        expected_sequence=session["next_receive"],
                                        k2=bytes.fromhex(session["k2"]),
                                        protocol_iv=bytes.fromhex(session["protocol_iv"]),
                                        max_file_bytes=self.config["max_file_bytes"])
        # Received filenames are prefixed, so CON.txt etc. are safe on Windows too.
        target = self.root / "received" / self.role / f"{packet['sequence']:04d}_{packet['message_id']}_{filename}"
        atomic_bytes(target, plaintext)
        session["next_receive"] += 1
        self._save()
        self._event("ACCEPTED", sequence=packet["sequence"], filename=filename,
                    bytes=len(plaintext), output_path=str(target),
                    detail="Hash đúng -> giải mã thành công -> lưu file.")

    def poll(self) -> list[dict]:
        with self.lock:
            start = len(self.events)
            inbox = self.root / "wire" / ("to_" + self.role)
            inbox.mkdir(parents=True, exist_ok=True)
            for bundle in sorted(inbox.glob("*.packet")):
                # Transport is a local demo, not an isolation boundary between OS users.
                if not bundle.is_dir() or bundle.is_symlink():
                    continue
                accepted = False
                try:
                    packet = load_json(bundle / "config.json", 2 * self.config["max_file_bytes"] + 16384)
                    kind = packet.get("kind")
                    if kind == "hello":
                        self._receive_hello(packet)
                    elif kind == "welcome":
                        self._receive_welcome(packet)
                    elif kind == "data":
                        self._receive_data(packet)
                    else:
                        raise ProtocolError("FORMAT", "Loại gói không được hỗ trợ.")
                    accepted = True
                except ProtocolError as exc:
                    self._event("REJECTED", code=exc.code, detail=str(exc))
                except OSError:
                    # A disk error is not a protocol failure. Keep the input for retry.
                    self._event("IO_ERROR", detail="Lỗi đọc/ghi ổ đĩa; giữ gói trong wire để thử lại.")
                    continue
                destination = self.directory / ("processed" if accepted else "rejected") / bundle.name
                os.replace(bundle, destination)
            return self.events[start:]

    def status(self) -> dict:
        with self.lock:
            session = self.state["session"]
            if session is None:
                return {"role": self.role, "ready": False,
                        "pending": self.state["pending"] is not None}
            return {"role": self.role, "ready": True, "session_id": session["session_id"],
                    "key_bits": self.config["key_bits"],
                    "k2_fingerprint": hashlib.sha256(bytes.fromhex(session["k2"])).hexdigest()[:16],
                    "next_send": session["next_send"], "next_receive": session["next_receive"],
                    "last_sent_hash": self.state["last_sent_hash"],
                    "last_wrapped_key": self.state["last_wrapped_key"]}


def corrupt(packet: dict, field: str) -> dict:
    """Simulate tampering after construction; never mutate the clean cached copy."""
    damaged = copy.deepcopy(packet)
    if field == "ciphertext":
        raw = bytearray(unb64(damaged["ciphertext"], "ciphertext"))
        raw[0] ^= 1
        damaged["ciphertext"] = b64(bytes(raw))
    else:
        target = {"hash": "hash", "key": "wrapped_key", "iv": "cbc_iv"}[field]
        raw = bytearray(bytes.fromhex(damaged[target]))
        raw[0] ^= 1
        damaged[target] = raw.hex()
    return damaged
