from __future__ import annotations

import argparse
import csv
import hashlib
import os
from datetime import datetime
from pathlib import Path


# Operating-system housekeeping directories that are not part of the
# traffic-calming archive. These directories are pruned during traversal,
# so Python never attempts to descend into them.
SKIP_DIRECTORIES = {
    ".Spotlight-V100",
    ".Trashes",
    ".fseventsd",
    "System Volume Information",
}


def should_skip_file(path: Path) -> bool:
    """
    Return True for filesystem metadata and temporary application files.

    These are artifacts created by macOS or Microsoft Office rather than
    source documents in the traffic-calming archive.
    """
    return path.name.startswith("._") or path.name.startswith("~$")


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    """
    Calculate a SHA-256 fingerprint for a file.

    Files are read in chunks rather than loaded into memory all at once.
    The hash gives us a durable identifier for the file contents and lets
    us detect byte-for-byte duplicates even when filenames or paths differ.

    This function only reads the source file; it does not modify it.
    """
    digest = hashlib.sha256()

    with path.open("rb") as file:
        while chunk := file.read(chunk_size):
            digest.update(chunk)

    return digest.hexdigest()


def build_inventory(root: Path) -> tuple[list[dict], list[dict]]:
    """
    Recursively inventory source documents beneath the archive root.

    System housekeeping directories are pruned before traversal. macOS
    metadata sidecars and Microsoft Office temporary files are excluded.

    For each source file we preserve filesystem metadata and calculate a
    SHA-256 hash. Paths are stored relative to the supplied root so the
    inventory remains portable.

    Files that cannot be read are recorded separately rather than causing
    the entire inventory operation to fail.

    The source archive is treated as read-only.
    """
    rows = []
    errors = []

    for current_dir, dirs, filenames in os.walk(root, topdown=True):

        # Modify dirs in place so os.walk never enters housekeeping dirs.
        dirs[:] = [
            directory
            for directory in dirs
            if directory not in SKIP_DIRECTORIES
        ]

        current_path = Path(current_dir)

        for filename in filenames:
            path = current_path / filename

            if should_skip_file(path):
                continue

            try:
                stat = path.stat()

                rows.append(
                    {
                        # Relative paths keep the inventory independent
                        # of the USB drive's mount point.
                        "relative_path": str(path.relative_to(root)),
                        "parent_directory": str(
                            path.parent.relative_to(root)
                        ),
                        "filename": path.name,
                        "extension": path.suffix.lower(),
                        "size_bytes": stat.st_size,

                        # Preserve the source filesystem modification time.
                        "modified_time": datetime.fromtimestamp(
                            stat.st_mtime
                        ).isoformat(timespec="seconds"),

                        # Content fingerprint for provenance and duplicate
                        # detection.
                        "sha256": sha256_file(path),
                    }
                )

            except (PermissionError, OSError) as error:
                # An inaccessible or damaged file should not stop the
                # inventory of the rest of the archive.
                errors.append(
                    {
                        "relative_path": str(path.relative_to(root)),
                        "error": str(error),
                    }
                )

    # Deterministic ordering makes inventories easier to compare.
    rows.sort(key=lambda row: row["relative_path"].lower())

    return rows, errors


def write_csv(rows: list[dict], output: Path) -> None:
    """
    Write the inventory to a UTF-8 CSV file.
    """
    fieldnames = [
        "relative_path",
        "parent_directory",
        "filename",
        "extension",
        "size_bytes",
        "modified_time",
        "sha256",
    ]

    with output.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    """
    Command-line entry point.

    Example:

        python3 scripts/inventory.py /Volumes/EASTFUN local-data/inventory.csv
    """
    parser = argparse.ArgumentParser(
        description="Create a non-destructive file inventory of a source archive."
    )

    parser.add_argument(
        "source",
        type=Path,
        help="Root directory of the source archive",
    )

    parser.add_argument(
        "output",
        type=Path,
        help="CSV inventory file to create",
    )

    args = parser.parse_args()

    source = args.source.expanduser().resolve()
    output = args.output.expanduser().resolve()

    if not source.is_dir():
        raise SystemExit(f"Source directory does not exist: {source}")

    # In normal use this is local-data/, which is excluded from Git.
    output.parent.mkdir(parents=True, exist_ok=True)

    rows, errors = build_inventory(source)
    write_csv(rows, output)

    print()
    print("Inventory complete")
    print("------------------")
    print(f"Source: {source}")
    print(f"Files:  {len(rows):,}")
    print(f"Errors: {len(errors):,}")
    print(f"Output: {output}")

    if errors:
        print("\nFiles that could not be inventoried:")

        for error in errors:
            print(f"  {error['relative_path']}")
            print(f"    {error['error']}")


if __name__ == "__main__":
    main()