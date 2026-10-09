"""Shared interactive CLI used by alice.py and bob.py."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import threading

from .crypto import ProtocolError
from .peer import Endpoint, ProcessLock

HELP = """
LỆNH DEMO (nhấn Enter sau mỗi lệnh)
  send samples/loi_chao.txt      Gửi file bằng một khóa mới
  send \"C:\\Du lieu\\bai tap.pdf\" Gửi đường dẫn có dấu cách
  bad-hash samples/loi_chao.txt  Cố ý làm sai hash trước khi gửi
  bad-data samples/loi_chao.txt  Cố ý sửa bản mã trước khi gửi
  bad-key samples/loi_chao.txt   Cố ý sửa khóa đã che
  bad-iv samples/loi_chao.txt    Cố ý sửa IV của AES-CBC
  resend                       Gửi lại BẢN GỐC của gói vừa gửi
  resend 2                     Gửi lại BẢN GỐC của gói số 2
  status                       Xem phiên, bộ đếm, hash và khóa đã che
  connect                      Alice gửi/gửi lại yêu cầu thiết lập phiên
  help                         Xem hướng dẫn lệnh
  quit                         Thoát; giữ trạng thái để lần sau chạy tiếp

Bên nhận tự theo dõi thư mục wire. Chỉ ACCEPTED mới có nghĩa là nhận thành công.
Sau gói lỗi: dùng resend trước khi gửi file tiếp theo.
"""


def print_event(event: dict):
    print(f"\n[{event['role'].upper()}] {event['event']}: {event.get('detail', '')}", flush=True)
    if "code" in event:
        print(f"  Lý do: {event['code']}", flush=True)
    for field, label in (("sequence", "Số gói"), ("key_fingerprint", "Dấu vân tay khóa"),
                         ("output_path", "File đã nhận"), ("packet_path", "Gói config.json")):
        if field in event:
            print(f"  {label}: {event[field]}", flush=True)
    if event.get("tampered"):
        print(f"  Ca demo cố ý sửa: {event['tampered']}", flush=True)


def execute(endpoint: Endpoint, command: str) -> bool:
    operation, _, argument = command.strip().partition(" ")
    operation = operation.lower()
    argument = argument.strip()
    if operation in {"quit", "exit", "q"}:
        return False
    if operation in {"help", "?"}:
        print(HELP)
    elif operation == "connect":
        endpoint.connect()
    elif operation == "status":
        print(json.dumps(endpoint.status(), ensure_ascii=False, indent=2))
    elif operation == "resend":
        if argument and not argument.isdecimal():
            raise ProtocolError("COMMAND", "Ví dụ: resend 2")
        endpoint.resend(int(argument) if argument else None)
    elif operation in {"send", "bad-hash", "bad-data", "bad-key", "bad-iv"}:
        if len(argument) >= 2 and argument[0] == argument[-1] and argument[0] in "\"'":
            argument = argument[1:-1]
        if not argument:
            raise ProtocolError("COMMAND", "Cần đường dẫn file. Ví dụ: send samples/loi_chao.txt")
        tamper = {"send": None, "bad-hash": "hash", "bad-data": "ciphertext",
                  "bad-key": "key", "bad-iv": "iv"}[operation]
        endpoint.send_file(Path(argument), tamper)
    elif operation:
        raise ProtocolError("COMMAND", "Lệnh không đúng. Gõ help để xem hướng dẫn.")
    return True


def run(role: str, project_root: Path) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser(description=f"RKE local demo - {role}")
    parser.add_argument("--root", type=Path, default=project_root, help="Thư mục dự án")
    actions = parser.add_mutually_exclusive_group()
    actions.add_argument("--connect", action="store_true")
    actions.add_argument("--receive-once", action="store_true")
    actions.add_argument("--send", type=Path)
    actions.add_argument("--resend", nargs="?", const="last")
    actions.add_argument("--status", action="store_true")
    parser.add_argument("--tamper", choices=["hash", "ciphertext", "key", "iv"])
    args = parser.parse_args()
    if args.tamper and args.send is None:
        parser.error("--tamper chỉ dùng cùng --send")
    root = args.root.resolve()
    try:
        if not (root / "runtime" / "READY").exists():
            raise ProtocolError("SETUP", "Chạy 0_CAI_DAT.cmd hoặc python setup_demo.py trước.")
        with ProcessLock(root / "runtime" / role / "process.lock"):
            endpoint = Endpoint(root, role, print_event)
            if args.connect:
                endpoint.connect()
                return 0
            if args.receive_once:
                events = endpoint.poll()
                return 1 if any(e["event"] in {"REJECTED", "IO_ERROR"} for e in events) else 0
            if args.send is not None:
                endpoint.send_file(args.send, args.tamper)
                return 0
            if args.resend is not None:
                if args.resend != "last" and not args.resend.isdecimal():
                    raise ProtocolError("COMMAND", "--resend cần số nguyên, ví dụ --resend 2")
                endpoint.resend(None if args.resend == "last" else int(args.resend))
                return 0
            if args.status:
                print(json.dumps(endpoint.status(), ensure_ascii=False, indent=2))
                return 0
            return interactive(endpoint)
    except (ProtocolError, OSError) as exc:
        print(f"LỖI [{getattr(exc, 'code', 'IO')}]: {exc}", file=sys.stderr)
        return 1


def interactive(endpoint: Endpoint) -> int:
    print(f"RKE LOCAL DEMO | {endpoint.role.upper()} | AES-{endpoint.config['key_bits']}-CBC + SHA-256")
    print("Mô phỏng học thuật. Khoá bí mật được lưu cục bộ trong runtime của từng bên.")
    print(HELP)
    stop = threading.Event()
    failed = threading.Event()

    def receive_loop():
        while not stop.is_set():
            try:
                endpoint.poll()
            except Exception as exc:
                failed.set()
                print(f"\nBộ nhận đã dừng vì lỗi: {exc}. Gõ quit và mở lại chương trình.", flush=True)
                return
            stop.wait(endpoint.config["poll_interval_seconds"])

    if endpoint.role == "alice" and not endpoint.status()["ready"]:
        endpoint.connect()
    worker = threading.Thread(target=receive_loop, name="inbox-watcher", daemon=True)
    worker.start()
    try:
        while not stop.is_set():
            try:
                command = input(f"{endpoint.role}> ")
                if failed.is_set() and command.strip().lower() not in {"quit", "exit", "q"}:
                    print("Bộ nhận đã dừng; hãy gõ quit rồi mở lại.")
                    continue
                if not execute(endpoint, command):
                    break
            except (ProtocolError, OSError) as exc:
                print(f"LỖI [{getattr(exc, 'code', 'IO')}]: {exc}")
            except (KeyboardInterrupt, EOFError):
                break
    finally:
        stop.set()
        worker.join()
    print("Đã thoát. Trạng thái phiên được giữ lại.")
    return 1 if failed.is_set() else 0
