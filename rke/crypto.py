"""Cryptographic primitives and explicit wire format for the classroom demo.

RKE equations come from Pirzada et al. (2020), equations (1)-(11).
This is a demonstration of that construction, not a reviewed secure protocol.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import re
import secrets
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, padding, serialization
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

PROTOCOL = "RKE-LOCAL-DEMO-v1"
HEADER_FIELDS = {
    "protocol", "kind", "sender", "recipient", "session_id", "sequence",
    "message_id", "filename", "cipher", "hash_algorithm", "cbc_iv", "wrapped_key",
}
HANDSHAKE_FIELDS = {
    "protocol", "kind", "sender", "recipient", "session_id", "payload", "signature",
}
DOMAIN = b"RKE-LOCAL-DEMO-v1\x00DATA\x00"
MAX_SEQUENCE = (1 << 63) - 1


class ProtocolError(ValueError):
    """An expected rejection, with a stable code for logs and tests."""

    def __init__(self, code: str, detail: str):
        super().__init__(detail)
        self.code = code


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def unb64(value: Any, field: str) -> bytes:
    if not isinstance(value, str):
        raise ProtocolError("FORMAT", f"{field}: cần chuỗi Base64.")
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        raise ProtocolError("FORMAT", f"{field}: Base64 không hợp lệ.") from None


def hexbytes(value: Any, length: int, field: str) -> bytes:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{%d}" % (2 * length), value):
        raise ProtocolError("FORMAT", f"{field}: cần {length} byte dạng hex chữ thường.")
    return bytes.fromhex(value)


def xor_bytes(*values: bytes) -> bytes:
    if not values or not values[0] or any(len(v) != len(values[0]) for v in values):
        raise ValueError("XOR requires nonempty, equal-length byte strings")
    result = bytearray(values[0])
    for value in values[1:]:
        for index, byte in enumerate(value):
            result[index] ^= byte
    return bytes(result)


def rs(iv: bytes, counter: int, shift: int = 1) -> bytes:
    """RS(IV + counter): modular addition, then circular RIGHT rotation.

    The paper does not fix the number of rotation bits. We explicitly use one.
    A logical >> alone would incorrectly discard the least significant bit.
    """
    width = len(iv) * 8
    if type(counter) is not int or not 0 <= counter <= MAX_SEQUENCE:
        raise ProtocolError("COUNTER", "Bộ đếm ngoài phạm vi cho phép.")
    if not 0 < shift < width:
        raise ValueError("Invalid rotation width")
    mask = (1 << width) - 1
    value = (int.from_bytes(iv, "big") + counter) & mask
    value = ((value >> shift) | (value << (width - shift))) & mask
    return value.to_bytes(len(iv), "big")


def aes_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return encryptor.update(padded) + encryptor.finalize()


def aes_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    try:
        return unpadder.update(padded) + unpadder.finalize()
    except ValueError:
        raise ProtocolError("DECRYPT", "Dữ liệu không hợp lệ sau bước xác minh hash.") from None


def message_hash(header: dict, ciphertext: bytes, key: bytes, rotated_iv: bytes) -> str:
    """Eq. (6)/(7), extended to bind the transport header and CBC IV.

    h = SHA256(domain || len(header) || header || len(C) || C || K || RS).
    Key and RS are fixed-width, and the two variable fields are length-prefixed.
    This follows the paper's keyed hash construction; it is NOT HMAC.
    """
    encoded = canonical(header)
    digest = hashlib.sha256()
    for part in (DOMAIN, len(encoded).to_bytes(4, "big"), encoded,
                 len(ciphertext).to_bytes(8, "big"), ciphertext, key, rotated_iv):
        digest.update(part)
    return digest.hexdigest()


def make_data(*, sender: str, recipient: str, session_id: str, sequence: int,
              filename: str, plaintext: bytes, key: bytes, k2: bytes, protocol_iv: bytes) -> dict:
    rotated = rs(protocol_iv, sequence)
    cbc_iv = secrets.token_bytes(16)  # Different from the secret protocol IV.
    ciphertext = aes_encrypt(plaintext, key, cbc_iv)
    header = {
        "protocol": PROTOCOL, "kind": "data", "sender": sender, "recipient": recipient,
        "session_id": session_id, "sequence": sequence, "message_id": secrets.token_hex(16),
        "filename": filename, "cipher": f"AES-{len(key) * 8}-CBC",
        "hash_algorithm": "sha256", "cbc_iv": cbc_iv.hex(),
        "wrapped_key": xor_bytes(k2, rotated, key).hex(),
    }
    return {**header, "ciphertext": b64(ciphertext),
            "hash": message_hash(header, ciphertext, key, rotated)}


def validate_filename(value: Any) -> str:
    if (not isinstance(value, str) or not value or len(value) > 160
            or value in {".", ".."} or value[-1:] in {".", " "}
            or re.search(r'[<>:"/\\|?*\x00-\x1f\x7f]', value)):
        raise ProtocolError("FILENAME", "Tên file không hợp lệ hoặc chứa đường dẫn.")
    try:
        encoded = value.encode("utf-8")
    except UnicodeError:
        raise ProtocolError("FILENAME", "Tên file chứa ký tự Unicode không hợp lệ.") from None
    if len(encoded) > 180:
        raise ProtocolError("FILENAME", "Tên file quá dài; hãy rút gọn tên trước khi gửi.")
    return value


def read_data(packet: dict, *, sender: str, recipient: str, session_id: str,
              expected_sequence: int, k2: bytes, protocol_iv: bytes,
              max_file_bytes: int) -> tuple[bytes, str]:
    """Validate EVERYTHING needed, verify the hash, and only then decrypt."""
    if not isinstance(packet, dict) or set(packet) != HEADER_FIELDS | {"ciphertext", "hash"}:
        raise ProtocolError("FORMAT", "Các trường config.json không đúng định dạng.")
    if (packet["protocol"] != PROTOCOL or packet["kind"] != "data"
            or packet["sender"] != sender or packet["recipient"] != recipient):
        raise ProtocolError("ROUTE", "Sai giao thức, bên gửi hoặc bên nhận.")
    if packet["session_id"] != session_id:
        raise ProtocolError("SESSION", "Gói thuộc phiên khác.")
    sequence = packet["sequence"]
    if type(sequence) is not int or not 2 <= sequence <= MAX_SEQUENCE:
        raise ProtocolError("COUNTER", "Bộ đếm phải là số nguyên từ 2.")
    if sequence < expected_sequence:
        raise ProtocolError("REPLAY", "Gói này đã được nhận: từ chối phát lại.")
    if sequence > expected_sequence:
        raise ProtocolError("OUT_OF_ORDER", f"Đang chờ gói {expected_sequence}; cần gửi lại gói thiếu.")
    if packet["cipher"] != f"AES-{len(k2) * 8}-CBC" or packet["hash_algorithm"] != "sha256":
        raise ProtocolError("ALGORITHM", "Thuật toán không khớp cấu hình phiên.")
    hexbytes(packet["message_id"], 16, "message_id")
    filename = validate_filename(packet["filename"])
    cbc_iv = hexbytes(packet["cbc_iv"], 16, "cbc_iv")
    wrapped_key = hexbytes(packet["wrapped_key"], len(k2), "wrapped_key")
    supplied_hash = hexbytes(packet["hash"], 32, "hash")
    ciphertext = unb64(packet["ciphertext"], "ciphertext")
    if not ciphertext or len(ciphertext) % 16 or len(ciphertext) > max_file_bytes + 16:
        raise ProtocolError("SIZE", "Kích thước bản mã không hợp lệ.")
    rotated = rs(protocol_iv, sequence)
    key = xor_bytes(wrapped_key, k2, rotated)  # Eq. (8)/(9).
    header = {field: packet[field] for field in HEADER_FIELDS}
    expected_hash = bytes.fromhex(message_hash(header, ciphertext, key, rotated))
    if not hmac.compare_digest(expected_hash, supplied_hash):
        # No AES decryption or plaintext write has happened at this point.
        raise ProtocolError("HASH_MISMATCH", "Hash sai: hủy gói, không giải mã, không tạo file kết quả.")
    plaintext = aes_decrypt(ciphertext, key, cbc_iv)  # Eq. (10)/(11).
    if len(plaintext) > max_file_bytes:
        raise ProtocolError("SIZE", "File giải mã vượt giới hạn.")
    return plaintext, filename


def generate_identity() -> tuple[bytes, bytes]:
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return (
        private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                              serialization.NoEncryption()),
        private.public_key().public_bytes(serialization.Encoding.PEM,
                                          serialization.PublicFormat.SubjectPublicKeyInfo),
    )


def seal_handshake(kind: str, sender: str, recipient: str, session_id: str,
                   plaintext: bytes, private_pem: bytes, peer_public_pem: bytes) -> dict:
    private = serialization.load_pem_private_key(private_pem, password=None)
    public = serialization.load_pem_public_key(peer_public_pem)
    ciphertext = public.encrypt(plaintext, rsa_padding.OAEP(
        mgf=rsa_padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=PROTOCOL.encode()))
    envelope = {"protocol": PROTOCOL, "kind": kind, "sender": sender,
                "recipient": recipient, "session_id": session_id, "payload": b64(ciphertext)}
    signature = private.sign(canonical(envelope), rsa_padding.PSS(
        mgf=rsa_padding.MGF1(hashes.SHA256()), salt_length=rsa_padding.PSS.MAX_LENGTH), hashes.SHA256())
    return {**envelope, "signature": b64(signature)}


def open_handshake(packet: dict, *, kind: str, sender: str, recipient: str,
                   private_pem: bytes, peer_public_pem: bytes) -> bytes:
    if not isinstance(packet, dict) or set(packet) != HANDSHAKE_FIELDS:
        raise ProtocolError("FORMAT", "Sai định dạng gói thiết lập phiên.")
    if (packet["protocol"] != PROTOCOL or packet["kind"] != kind
            or packet["sender"] != sender or packet["recipient"] != recipient):
        raise ProtocolError("ROUTE", "Sai bên gửi/nhận trong thiết lập phiên.")
    hexbytes(packet["session_id"], 16, "session_id")
    envelope = {k: v for k, v in packet.items() if k != "signature"}
    signature = unb64(packet["signature"], "signature")
    ciphertext = unb64(packet["payload"], "payload")
    public = serialization.load_pem_public_key(peer_public_pem)
    try:
        public.verify(signature, canonical(envelope), rsa_padding.PSS(
            mgf=rsa_padding.MGF1(hashes.SHA256()), salt_length=rsa_padding.PSS.MAX_LENGTH), hashes.SHA256())
        private = serialization.load_pem_private_key(private_pem, password=None)
        return private.decrypt(ciphertext, rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=PROTOCOL.encode()))
    except (InvalidSignature, ValueError):
        raise ProtocolError("AUTH", "Không xác minh được gói thiết lập phiên.") from None
