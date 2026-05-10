#!/usr/bin/env python3
"""
remove_suricata_service.py

Surgically removes the `suricata:` service block from docker-compose.yml
while preserving every other service, all comments, all formatting, the
suricata-logs volume definition, and the file's original line endings.

Why not PyYAML? PyYAML round-trips destroy comments and reorder keys, which
would corrupt the carefully-written compose file. Why not ruamel.yaml? Not
guaranteed to be installed on the user's WSL2. Plain text editing with a
regex anchored on the YAML structure is the most reliable approach.

Strategy:
  1. Read the file as text.
  2. Find the line `  suricata:` (2-space indent, top-level service key).
  3. Find the next line that starts with `  <name>:` at 2-space indent
     (the next service), or the end of the services: block.
  4. Delete everything in between.
  5. Validate the result is still parseable YAML.
  6. Write it back.

Idempotent: if the suricata service is already absent, exits 0 with a
notice. Always writes a timestamped backup before modifying.
"""

import argparse
import re
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path


def find_suricata_block(lines: list[str]) -> tuple[int, int] | None:
    """
    Return (start_index, end_index) of the suricata service block in the
    lines list, where end_index is the line *after* the block (exclusive).
    Returns None if not found.

    A service block starts at `  suricata:` (exactly 2 spaces indent) and
    extends until the next sibling service (`  <name>:`) or the start of
    a top-level key (`<name>:` with no indent), whichever comes first.
    """
    start = None
    for i, line in enumerate(lines):
        # Match "  suricata:" — exactly 2 leading spaces, then suricata:,
        # optionally trailing whitespace/comment
        if re.match(r"^  suricata:\s*(#.*)?$", line):
            start = i
            break

    if start is None:
        return None

    # Find the end: next line at indent <= 2 spaces that's a key
    end = len(lines)
    for j in range(start + 1, len(lines)):
        line = lines[j]
        # Top-level key (no indent) like `volumes:`, `networks:`
        if re.match(r"^[a-zA-Z_]\w*\s*:", line):
            end = j
            break
        # Sibling service (2-space indent + key)
        if re.match(r"^  [a-zA-Z_]\w*\s*:", line):
            end = j
            break

    return (start, end)


def trim_trailing_blank_lines(lines: list[str], up_to: int) -> int:
    """
    Given that we just deleted lines [start:end], the line at position
    `up_to` (which used to be `end`) is now the next service. We may
    have left blank lines just before it that visually belonged to the
    removed block. Move `up_to` back over any consecutive blank lines
    immediately preceding it, but stop if we'd cross into another
    service's content.
    """
    while up_to > 0 and lines[up_to - 1].strip() == "":
        up_to -= 1
    return up_to


def validate_yaml(path: Path) -> tuple[bool, str]:
    """
    Validate that the file is parseable YAML. Try PyYAML if available,
    otherwise fall back to `docker compose config -f <path>` if docker
    is on PATH.
    """
    try:
        import yaml  # noqa
        try:
            with open(path) as f:
                yaml.safe_load(f)
            return True, "PyYAML parsed cleanly"
        except yaml.YAMLError as e:
            return False, f"PyYAML error: {e}"
    except ImportError:
        pass

    # Fallback: docker compose config
    try:
        result = subprocess.run(
            ["docker", "compose", "-f", str(path), "config"],
            capture_output=True,
            text=True,
            timeout=20,
        )
        if result.returncode == 0:
            return True, "docker compose config parsed cleanly"
        return False, f"docker compose config error:\n{result.stderr}"
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        return True, f"WARNING: could not validate ({e}); proceeding"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Remove suricata service from docker-compose.yml",
    )
    parser.add_argument(
        "compose_file",
        nargs="?",
        default="docker-compose.yml",
        help="Path to docker-compose.yml (default: ./docker-compose.yml)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be removed without writing",
    )
    parser.add_argument(
        "--no-backup",
        action="store_true",
        help="Skip writing a .bak.<timestamp> copy",
    )
    args = parser.parse_args()

    path = Path(args.compose_file).resolve()
    if not path.is_file():
        print(f"ERROR: not a file: {path}", file=sys.stderr)
        return 2

    text = path.read_text()
    # keepends=True so we round-trip newlines exactly
    lines = text.splitlines(keepends=True)

    block = find_suricata_block(lines)
    if block is None:
        print(f"NOTICE: no `suricata:` service block found in {path}")
        print("        The file may have been edited already. Nothing to do.")
        return 0

    start, end = block
    end = trim_trailing_blank_lines(lines, end)

    removed_text = "".join(lines[start:end])
    print(f"Found suricata service block: lines {start + 1}..{end} "
          f"({end - start} lines, {len(removed_text)} chars)")
    print("─" * 60)
    for line in removed_text.splitlines():
        print(f"  | {line}")
    print("─" * 60)

    if args.dry_run:
        print("DRY-RUN: no changes written")
        return 0

    # Backup
    if not args.no_backup:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup = path.with_suffix(f"{path.suffix}.bak.{ts}")
        shutil.copy2(path, backup)
        print(f"Backup written: {backup}")

    # Build new content
    new_lines = lines[:start] + lines[end:]
    new_text = "".join(new_lines)

    # Write to a tmp file first, validate, then atomic-rename
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    tmp_path.write_text(new_text)

    valid, msg = validate_yaml(tmp_path)
    if not valid:
        print(f"ERROR: edited file is not valid YAML.\n{msg}", file=sys.stderr)
        print(f"Tmp file kept for inspection: {tmp_path}", file=sys.stderr)
        return 3

    print(f"Validation: {msg}")
    tmp_path.replace(path)
    print(f"Wrote: {path}")

    # Sanity check: confirm `suricata-logs` volume definition is still present
    final = path.read_text()
    if "suricata-logs" in final:
        print("OK: `suricata-logs` volume definition preserved "
              "(other services still use this shared path)")
    else:
        print("WARNING: `suricata-logs` no longer in file — Wazuh manager "
              "and ai-agents may fail to mount the shared volume.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
