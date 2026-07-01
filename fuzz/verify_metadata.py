#!/usr/bin/env python3
"""Verify that fuzz metadata stays aligned with tracked targets and seeds."""

from __future__ import annotations

import re
import subprocess
import sys
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FUZZ = ROOT / "fuzz"


def fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    sys.exit(1)


def warn(message: str) -> None:
    print(f"WARN: {message}", file=sys.stderr)


def read(path: Path) -> str:
    try:
        return path.read_text()
    except OSError as exc:
        fail(f"cannot read {path.relative_to(ROOT)}: {exc}")


def parse_assoc_array(script: str, name: str) -> dict[str, str]:
    match = re.search(rf"declare -A {name}=\((.*?)\)", script, re.S)
    if not match:
        fail(f"missing {name} associative array in fuzz/run_regression.sh")
    return dict(re.findall(r"\[([A-Za-z0-9_]+)\]=([A-Za-z0-9_/-]+)", match.group(1)))


def parse_default_targets(script: str) -> set[str]:
    match = re.search(r"DEFAULT_TARGETS=\((.*?)\)", script, re.S)
    if not match:
        fail("missing DEFAULT_TARGETS in fuzz/run_regression.sh")
    return set(re.findall(r"\bfuzz_[A-Za-z0-9_]+\b", match.group(1)))


def parse_make_var(makefile: str, name: str) -> set[str]:
    match = re.search(rf"^{name}\s*:=\s*(.*)$", makefile, re.M)
    if not match:
        fail(f"missing {name} in Makefile.fuzz")
    return set(re.findall(r"\bfuzz_[A-Za-z0-9_]+\b", match.group(1)))


def git_check(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def ensure_not_ignored(path: Path) -> None:
    rel = path.relative_to(ROOT).as_posix()
    result = git_check(["check-ignore", "-v", rel])
    if result.returncode == 0:
        fail(f"{rel} is ignored by {result.stdout.strip()}")
    if result.returncode not in (0, 1):
        warn(f"git check-ignore failed for {rel}: {result.stderr.strip()}")


def main() -> None:
    cargo = tomllib.loads(read(FUZZ / "Cargo.toml"))
    bins: dict[str, dict[str, object]] = {
        item["name"]: item for item in cargo.get("bin", [])
    }
    if not bins:
        fail("fuzz/Cargo.toml has no [[bin]] targets")

    for name, item in sorted(bins.items()):
        path_value = item.get("path")
        if not isinstance(path_value, str):
            fail(f"{name} has no string path")
        path = FUZZ / path_value
        if not path.is_file():
            fail(f"{name} target path is missing: {path.relative_to(ROOT)}")
        ensure_not_ignored(path)

    advanced = {
        name
        for name, item in bins.items()
        if "advanced" in item.get("required-features", [])
    }
    expected_seed_targets = set(bins) - advanced

    runner = read(FUZZ / "run_regression.sh")
    seed_map = parse_assoc_array(runner, "TARGET_SEEDS")
    regression_map = parse_assoc_array(runner, "TARGET_REGRESSION")
    default_targets = parse_default_targets(runner)

    if set(seed_map) != expected_seed_targets:
        fail(
            "TARGET_SEEDS mismatch: "
            f"missing={sorted(expected_seed_targets - set(seed_map))} "
            f"extra={sorted(set(seed_map) - expected_seed_targets)}"
        )
    if set(regression_map) != set(bins):
        fail(
            "TARGET_REGRESSION mismatch: "
            f"missing={sorted(set(bins) - set(regression_map))} "
            f"extra={sorted(set(regression_map) - set(bins))}"
        )
    if default_targets != set(bins):
        fail(
            "DEFAULT_TARGETS mismatch: "
            f"missing={sorted(set(bins) - default_targets)} "
            f"extra={sorted(default_targets - set(bins))}"
        )

    for target, seed_dir in sorted(seed_map.items()):
        path = FUZZ / "corpus" / "seeds" / seed_dir
        if not path.is_dir():
            fail(f"{target} seed directory missing: {path.relative_to(ROOT)}")
        if not any(child.is_file() for child in path.iterdir()):
            fail(f"{target} seed directory is empty: {path.relative_to(ROOT)}")

    for target, reg_dir in sorted(regression_map.items()):
        path = FUZZ / "regression" / reg_dir
        if not path.is_dir():
            fail(f"{target} regression directory missing: {path.relative_to(ROOT)}")
        ensure_not_ignored(path / ".gitkeep")

    makefile = read(ROOT / "Makefile.fuzz")
    make_targets = (
        parse_make_var(makefile, "CORE_TARGETS")
        | parse_make_var(makefile, "PROTOCOL_TARGETS")
        | parse_make_var(makefile, "NETWORK_TARGETS")
        | parse_make_var(makefile, "API_TARGETS")
    )
    if make_targets != set(bins):
        fail(
            "Makefile.fuzz target set mismatch: "
            f"missing={sorted(set(bins) - make_targets)} "
            f"extra={sorted(make_targets - set(bins))}"
        )

    readme = read(FUZZ / "README.md")
    count_match = re.search(r"reports\s+(\d+)\s+targets", readme)
    if not count_match:
        fail("README target count line not found")
    if int(count_match.group(1)) != len(bins):
        fail(
            "README target count mismatch: "
            f"README={count_match.group(1)} Cargo.toml={len(bins)}"
        )

    print(f"FUZZ_METADATA_PASS targets={len(bins)} seeded={len(seed_map)}")


if __name__ == "__main__":
    main()
