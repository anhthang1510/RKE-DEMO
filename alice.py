from pathlib import Path

if __name__ == "__main__":
    try:
        from rke.cli import run
    except ModuleNotFoundError as exc:
        if exc.name == "cryptography":
            raise SystemExit("Chay 0_CAI_DAT.cmd hoac: python -m pip install -r requirements.txt") from None
        raise
    raise SystemExit(run("alice", Path(__file__).resolve().parent))
