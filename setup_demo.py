"""Create fresh local identities once; rerunning does not reset the demo."""
import argparse
from pathlib import Path


def main() -> int:
    try:
        from rke.peer import initialize
        from rke.crypto import ProtocolError
    except ModuleNotFoundError:
        print("Chay: python -m pip install -r requirements.txt")
        return 1
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent)
    args = parser.parse_args()
    try:
        created = initialize(args.root)
    except (OSError, ProtocolError) as exc:
        print(f"SETUP ERROR: {exc}")
        return 1
    print("SETUP OK: Da tao khoa RSA rieng cho Alice/Bob." if created
          else "SETUP OK: Giu nguyen khoa va trang thai da co.")
    print("Mo 1_ALICE.cmd va 2_BOB.cmd, doi SESSION_READY o ca hai cua so.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
