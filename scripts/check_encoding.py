from __future__ import annotations

import argparse
from pathlib import Path


def is_utf8(path: Path) -> tuple[bool, str]:
    raw = path.read_bytes()
    if b"\x00" in raw:
        return False, "contains null bytes (likely UTF-16)"
    try:
        raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        return False, f"not valid UTF-8 ({exc})"
    return True, "ok"


def main() -> int:
    parser = argparse.ArgumentParser(description="Check project .py files are UTF-8.")
    parser.add_argument(
        "--root",
        default=".",
        help="Project root to scan (default: current directory).",
    )
    args = parser.parse_args()

    root = Path(args.root).resolve()
    bad: list[tuple[Path, str]] = []
    for path in root.rglob("*.py"):
        if ".venv" in path.parts or "__pycache__" in path.parts:
            continue
        ok, reason = is_utf8(path)
        if not ok:
            bad.append((path, reason))

    if not bad:
        print("All .py files are UTF-8.")
        return 0

    print("Non-UTF-8 Python files found:")
    for p, reason in bad:
        print(f"- {p}: {reason}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
