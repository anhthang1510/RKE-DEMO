"""Behavioral checks for the actual crypto boundary and file transport."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import secrets
import tempfile
import unittest
from unittest.mock import patch

from rke.crypto import (ProtocolError, b64, make_data, read_data, rs,
                        unb64, validate_filename, xor_bytes)
from rke.peer import (DEFAULT_CONFIG, Endpoint, ProcessLock, atomic_json,
                      corrupt, initialize, load_json)


class MathTests(unittest.TestCase):
    def test_circular_shift_keeps_low_bit(self):
        self.assertEqual(rs(bytes(16), 1), bytes.fromhex("80000000000000000000000000000000"))
        self.assertEqual(rs(bytes(16), 2), bytes.fromhex("00000000000000000000000000000001"))

    def test_addition_wraps_at_128_bits(self):
        self.assertEqual(rs(bytes.fromhex("ff" * 16), 1), bytes(16))

    def test_256_bit_rotation(self):
        self.assertEqual(rs(bytes(32), 1), b"\x80" + bytes(31))

    def test_mask_unmask_equations(self):
        k2 = bytes.fromhex("10" * 16)
        key = bytes.fromhex("22" * 16)
        mask = rs(bytes(16), 2)
        wrapped = xor_bytes(k2, mask, key)
        self.assertEqual(wrapped.hex(), "32" * 15 + "33")
        self.assertEqual(xor_bytes(wrapped, k2, mask), key)

    def test_invalid_filenames(self):
        for value in ("../a.txt", "..\\a.txt", "/tmp/x", "a:b", "\x00", "", "..", "file. ", "\ud800"):
            with self.subTest(value=repr(value)), self.assertRaises(ProtocolError):
                validate_filename(value)


class CryptoBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.key, self.k2, self.iv = bytes.fromhex("42" * 16), bytes.fromhex("ab" * 16), bytes(16)
        self.packet = make_data(sender="alice", recipient="bob", session_id="11" * 16, sequence=2,
                                filename="hello.txt", plaintext=b"secret data", key=self.key,
                                k2=self.k2, protocol_iv=self.iv)

    def receive(self, packet):
        return read_data(packet, sender="alice", recipient="bob", session_id="11" * 16,
                         expected_sequence=2, k2=self.k2, protocol_iv=self.iv, max_file_bytes=1024)

    def test_round_trip(self):
        self.assertEqual(self.receive(self.packet), (b"secret data", "hello.txt"))

    def test_tampering_never_calls_aes_decrypt(self):
        for field in ("hash", "ciphertext", "key", "iv"):
            with self.subTest(field=field), patch("rke.crypto.aes_decrypt") as decrypt:
                with self.assertRaises(ProtocolError) as caught:
                    self.receive(corrupt(self.packet, field))
                self.assertEqual(caught.exception.code, "HASH_MISMATCH")
                decrypt.assert_not_called()

    def test_modified_filename_is_hash_bound(self):
        packet = {**self.packet, "filename": "renamed.txt"}
        with self.assertRaises(ProtocolError) as caught:
            self.receive(packet)
        self.assertEqual(caught.exception.code, "HASH_MISMATCH")

    def test_reflection_cannot_change_roles(self):
        with self.assertRaises(ProtocolError) as caught:
            self.receive({**self.packet, "sender": "bob", "recipient": "alice"})
        self.assertEqual(caught.exception.code, "ROUTE")

    def test_unexpected_fields_rejected(self):
        with self.assertRaises(ProtocolError):
            self.receive({**self.packet, "extra": "ignored?"})

    def test_missing_fields_rejected(self):
        packet = dict(self.packet)
        del packet["hash"]
        with self.assertRaises(ProtocolError):
            self.receive(packet)

    def test_bool_and_noninteger_counters_rejected(self):
        for value in (True, 2.0, "2", -1, 1 << 64):
            with self.subTest(value=value), self.assertRaises(ProtocolError):
                self.receive({**self.packet, "sequence": value})

    def test_invalid_base64_and_truncated_ciphertext(self):
        for value in ("not base64?", b64(b"short"), ""):
            with self.subTest(value=value), self.assertRaises(ProtocolError):
                self.receive({**self.packet, "ciphertext": value})

    def test_wrong_session_rejected(self):
        with self.assertRaises(ProtocolError) as caught:
            self.receive({**self.packet, "session_id": "ff" * 16})
        self.assertEqual(caught.exception.code, "SESSION")

    def test_plain_session_key_not_sent(self):
        self.assertNotIn("key", self.packet)
        self.assertNotIn("k2", self.packet)
        self.assertNotIn("protocol_iv", self.packet)
        self.assertNotEqual(self.packet["wrapped_key"], self.key.hex())


class EndpointTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        atomic_json(self.root / "config.json", DEFAULT_CONFIG)
        initialize(self.root)
        self.alice = Endpoint(self.root, "alice")
        self.bob = Endpoint(self.root, "bob")
        self.sample = self.root / "Thử file có dấu.txt"
        self.sample.write_bytes("Nội dung tiếng Việt, chữ ký số.\n".encode("utf-8"))

    def connect(self):
        self.alice.connect()
        self.bob.poll()
        self.alice.poll()
        self.assertTrue(self.alice.status()["ready"])
        self.assertTrue(self.bob.status()["ready"])

    def accepted(self, receiver):
        return [e for e in receiver.poll() if e["event"] == "ACCEPTED"]

    def test_handshake_establishes_equal_secret(self):
        self.connect()
        self.assertEqual(self.alice.state["session"]["k2"], self.bob.state["session"]["k2"])
        self.assertEqual(self.alice.state["session"]["protocol_iv"], self.bob.state["session"]["protocol_iv"])

    def test_both_directions_and_independent_counters(self):
        self.connect()
        self.alice.send_file(self.sample)
        self.alice.send_file(self.sample)
        self.bob.send_file(self.sample)
        self.assertEqual(len(self.accepted(self.alice)), 1)
        accepted = self.accepted(self.bob)
        self.assertEqual(len(accepted), 2)
        for record in accepted:
            self.assertEqual(Path(record["output_path"]).read_bytes(), self.sample.read_bytes())
        self.assertEqual(self.bob.status()["next_send"], 3)
        self.assertEqual(self.bob.status()["next_receive"], 4)

    def test_invalid_then_valid_no_output_on_rejection(self):
        self.connect()
        self.alice.send_file(self.sample, "hash")
        events = self.bob.poll()
        self.assertEqual(events[-1]["code"], "HASH_MISMATCH")
        self.assertEqual(list((self.root / "received/bob").iterdir()), [])
        self.assertEqual(self.bob.status()["next_receive"], 2)
        self.alice.resend()
        received = self.accepted(self.bob)
        self.assertEqual(len(received), 1)
        self.assertEqual(Path(received[0]["output_path"]).read_bytes(), self.sample.read_bytes())

    def test_replay_rejected(self):
        self.connect()
        self.alice.send_file(self.sample)
        self.assertEqual(len(self.accepted(self.bob)), 1)
        self.alice.resend()
        self.assertEqual(self.bob.poll()[-1]["code"], "REPLAY")
        self.assertEqual(len(list((self.root / "received/bob").iterdir())), 1)

    def test_wrong_order_requires_original_gap_to_be_filled(self):
        self.connect()
        path2 = self.alice.send_file(self.sample)
        held = self.root / "held.packet"
        path2.parent.rename(held)
        self.alice.send_file(self.sample)
        self.assertEqual(self.bob.poll()[-1]["code"], "OUT_OF_ORDER")
        self.assertEqual(self.bob.status()["next_receive"], 2)
        self.alice.resend(2)
        self.assertEqual(len(self.accepted(self.bob)), 1)
        self.alice.resend(3)
        self.assertEqual(len(self.accepted(self.bob)), 1)

    def test_restart_preserves_session_and_replay_protection(self):
        self.connect()
        self.alice.send_file(self.sample)
        self.bob.poll()
        reloaded_alice = Endpoint(self.root, "alice")
        reloaded_bob = Endpoint(self.root, "bob")
        self.assertEqual(self.alice.status(), reloaded_alice.status())
        self.assertEqual(self.bob.status(), reloaded_bob.status())
        reloaded_alice.resend()
        self.assertEqual(reloaded_bob.poll()[-1]["code"], "REPLAY")

    def test_unique_keys_for_repeated_sends(self):
        self.connect()
        packets = [load_json(self.alice.send_file(self.sample)) for _ in range(5)]
        fingerprints = self.alice.state["used_key_fingerprints"]
        self.assertEqual(len(fingerprints), len(set(fingerprints)))
        self.assertEqual(len({p["cbc_iv"] for p in packets}), 5)
        self.assertEqual(len({p["hash"] for p in packets}), 5)

    def test_random_collision_retries_key_generation(self):
        self.connect()
        duplicate, fresh = bytes.fromhex("11" * 16), bytes.fromhex("22" * 16)
        self.alice.state["used_key_fingerprints"] = [hashlib.sha256(duplicate).hexdigest()]
        original_random = secrets.token_bytes
        choices = [duplicate, fresh]
        def random_with_collision(size=None):
            return choices.pop(0) if choices else original_random(size)
        with patch("rke.peer.secrets.token_bytes", side_effect=random_with_collision):
            self.alice.send_file(self.sample)
        self.assertEqual(self.alice.state["used_key_fingerprints"][-1], hashlib.sha256(fresh).hexdigest())

    def test_hello_signature_tampering_rejected(self):
        path = self.alice.connect()
        packet = load_json(path)
        signature = bytearray(unb64(packet["signature"], "signature"))
        signature[0] ^= 1
        packet["signature"] = b64(signature)
        atomic_json(path, packet)
        self.assertEqual(self.bob.poll()[-1]["code"], "AUTH")
        self.assertFalse(self.bob.status()["ready"])

    def test_welcome_signature_tampering_rejected(self):
        self.alice.connect()
        self.bob.poll()
        path = next((self.root / "wire/to_alice").glob("*.packet/config.json"))
        packet = load_json(path)
        packet["signature"] = b64(bytes(256))
        atomic_json(path, packet)
        self.assertEqual(self.alice.poll()[-1]["code"], "AUTH")
        self.assertFalse(self.alice.status()["ready"])

    def test_lost_welcome_recovered_by_connect(self):
        self.alice.connect()
        self.bob.poll()
        # Simulate a lost response without losing Bob's persistent session.
        path = next((self.root / "wire/to_alice").glob("*.packet"))
        path.rename(self.root / "lost.packet")
        old_session = copy.deepcopy(self.bob.state["session"])
        self.alice.connect()
        self.bob.poll()
        self.alice.poll()
        self.assertEqual(old_session, self.bob.state["session"])
        self.assertTrue(self.alice.status()["ready"])

    def test_replayed_hello_does_not_reset_data_counter(self):
        path = self.alice.connect()
        hello = load_json(path)
        self.bob.poll()
        self.alice.poll()
        self.alice.send_file(self.sample)
        self.bob.poll()
        self.alice._queue(hello)
        self.bob.poll()
        self.assertEqual(self.bob.status()["next_receive"], 3)
        self.assertEqual(self.alice.poll()[-1]["code"], "REPLAY")

    def test_setup_is_idempotent(self):
        key = (self.root / "runtime/alice/private_key.pem").read_bytes()
        self.assertFalse(initialize(self.root))
        self.assertEqual((self.root / "runtime/alice/private_key.pem").read_bytes(), key)

    def test_changing_configuration_after_setup_fails(self):
        config = {**DEFAULT_CONFIG, "key_bits": 256}
        atomic_json(self.root / "config.json", config)
        with self.assertRaises(ProtocolError):
            Endpoint(self.root, "alice")
        with self.assertRaises(ProtocolError):
            initialize(self.root)

    def test_no_session_cannot_send(self):
        with self.assertRaises(ProtocolError) as caught:
            self.alice.send_file(self.sample)
        self.assertEqual(caught.exception.code, "NO_SESSION")

    def test_empty_block_aligned_and_binary_files(self):
        self.connect()
        for payload in (b"", bytes(16), bytes(range(256)) * 8):
            with self.subTest(size=len(payload)):
                self.sample.write_bytes(payload)
                self.alice.send_file(self.sample)
                events = self.accepted(self.bob)
                self.assertEqual(Path(events[0]["output_path"]).read_bytes(), payload)

    def test_malformed_json_is_quarantined_receiver_keeps_working(self):
        self.connect()
        path = self.alice.send_file(self.sample)
        path.write_text('{"kind": "data", BROKEN', encoding="utf-8")
        self.assertEqual(self.bob.poll()[-1]["code"], "FORMAT")
        self.alice.resend()
        self.assertEqual(len(self.accepted(self.bob)), 1)

    def test_duplicate_json_fields_rejected(self):
        path = self.root / "bad.json"
        path.write_text('{"hash":"first","hash":"second"}', encoding="utf-8")
        with self.assertRaises(ProtocolError):
            load_json(path)

    def test_incomplete_temporary_bundle_is_ignored(self):
        partial = self.root / "wire/to_bob/.partial.tmp"
        partial.mkdir()
        (partial / "config.json").write_text("{", encoding="utf-8")
        self.assertEqual(self.bob.poll(), [])

    def test_process_lock_prevents_second_same_role_instance(self):
        path = self.root / "runtime/alice/process.lock"
        with ProcessLock(path):
            with self.assertRaises(ProtocolError):
                with ProcessLock(path):
                    self.fail("Second process lock should not be acquired")
        with ProcessLock(path):
            pass


class ProfileTests(unittest.TestCase):
    def test_256_profile_round_trip_and_limit(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            atomic_json(root / "config.json", {**DEFAULT_CONFIG, "key_bits": 256, "max_file_bytes": 32})
            initialize(root)
            alice, bob = Endpoint(root, "alice"), Endpoint(root, "bob")
            alice.connect()
            bob.poll()
            alice.poll()
            self.assertEqual(len(bytes.fromhex(alice.state["session"]["k2"])), 32)
            sample = root / "binary.bin"
            sample.write_bytes(bytes(range(32)))
            packet = load_json(alice.send_file(sample))
            self.assertEqual(packet["cipher"], "AES-256-CBC")
            self.assertEqual(len(bytes.fromhex(packet["cbc_iv"])), 16)
            self.assertEqual(len(bytes.fromhex(packet["wrapped_key"])), 32)
            events = [e for e in bob.poll() if e["event"] == "ACCEPTED"]
            self.assertEqual(Path(events[0]["output_path"]).read_bytes(), sample.read_bytes())
            sample.write_bytes(bytes(33))
            with self.assertRaises(ProtocolError):
                alice.send_file(sample)


if __name__ == "__main__":
    unittest.main()
