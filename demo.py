"""End-to-end scripted demo. Outputs go into an isolated demos/<run>/ folder."""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import secrets
import shutil
import sys
import time

from rke.cli import print_event
from rke.peer import Endpoint, atomic_json, initialize, load_config


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser()
    parser.add_argument("--key-bits", type=int, choices=(128, 256), default=128)
    parser.add_argument("--output", type=Path, help="Một thư mục mới để giữ kết quả")
    args = parser.parse_args()
    source = Path(__file__).resolve().parent
    root = args.output or source / "demos" / (time.strftime("%Y%m%d_%H%M%S") + "_" + secrets.token_hex(3))
    root = root.resolve()
    root.mkdir(parents=True, exist_ok=False)
    config = load_config(source)
    config["key_bits"] = args.key_bits
    atomic_json(root / "config.json", config)
    shutil.copytree(source / "samples", root / "samples")
    initialize(root)
    alice = Endpoint(root, "alice", print_event)
    bob = Endpoint(root, "bob", print_event)
    results = []

    def check(name: str, condition: bool):
        results.append({"case": name, "passed": bool(condition)})
        print(f"\n{'PASS' if condition else 'FAIL'} | {name}")
        if not condition:
            raise AssertionError(name)

    print("\n1. THIẾT LẬP PHIÊN")
    alice.connect()
    bob.poll()
    alice.poll()
    check("Alice/Bob có cùng K2 và IV", alice.state["session"]["k2"] == bob.state["session"]["k2"]
          and alice.state["session"]["protocol_iv"] == bob.state["session"]["protocol_iv"])

    def valid(sender: Endpoint, receiver: Endpoint, sample: str):
        sender.send_file(Path("samples") / sample)
        events = receiver.poll()
        accepted = [e for e in events if e["event"] == "ACCEPTED"]
        return len(accepted) == 1 and Path(accepted[0]["output_path"]).read_bytes() == (root / "samples" / sample).read_bytes()

    print("\n2. FILE ĐÚNG HASH: GỬI HAI CHIỀU")
    check("Alice -> Bob, toàn bộ nội dung trùng file gốc", valid(alice, bob, "loi_chao.txt"))
    check("Bob -> Alice, toàn bộ nội dung trùng file gốc", valid(bob, alice, "phan_hoi.txt"))
    for tamper in ("hash", "ciphertext", "key", "iv"):
        print(f"\n3. CỐ Ý SỬA {tamper.upper()} RỒI GỬI LẠI BẢN GỐC")
        count = len(list((root / "received" / "bob").iterdir()))
        counter = bob.status()["next_receive"]
        alice.send_file(Path("samples/loi_chao.txt"), tamper=tamper)
        rejected = bob.poll()
        check(f"Sửa {tamper}: HASH_MISMATCH, không tạo kết quả, không tăng bộ đếm",
              any(e.get("code") == "HASH_MISMATCH" for e in rejected)
              and count == len(list((root / "received" / "bob").iterdir()))
              and counter == bob.status()["next_receive"])
        alice.resend()
        events = bob.poll()
        check(f"Gửi lại bản gốc sau lỗi {tamper}: nhận thành công",
              len([e for e in events if e["event"] == "ACCEPTED"]) == 1)

    print("\n4. PHÁT LẠI MỘT GÓI ĐÃ NHẬN")
    count = len(list((root / "received" / "bob").iterdir()))
    alice.resend()
    events = bob.poll()
    check("REPLAY bị từ chối, không tạo file thứ hai", any(e.get("code") == "REPLAY" for e in events)
          and count == len(list((root / "received" / "bob").iterdir())))
    fingerprints = alice.state["used_key_fingerprints"] + bob.state["used_key_fingerprints"]
    check("Các khóa ngẫu nhiên trong lần chạy này đều khác nhau", len(fingerprints) == len(set(fingerprints)))
    # Persist nonsecret, verifiable results; runtime keys remain in this isolated demo folder.
    received = []
    for file in sorted((root / "received").glob("*/*")):
        received.append({"path": str(file.relative_to(root)), "bytes": file.stat().st_size,
                         "sha256": hashlib.sha256(file.read_bytes()).hexdigest()})
    report = {"python": sys.version.split()[0], "key_bits": args.key_bits,
              "checks": results, "received_files": received,
              "passed": all(result["passed"] for result in results)}
    atomic_json(root / "demo_results.json", report)
    print(f"\nDEMO PASS: {len(results)}/{len(results)} checks")
    print(f"Kết quả và log: {root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
