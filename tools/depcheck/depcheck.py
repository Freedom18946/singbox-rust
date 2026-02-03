#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Iterable

try:
    import tomllib  # py3.11+
except ModuleNotFoundError:  # pragma: no cover
    print("error: python 3.11+ required (tomllib missing)", file=sys.stderr)
    sys.exit(2)


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_RULES = Path(__file__).resolve().parent / "rules.toml"


class DepCheckError(Exception):
    pass


def load_toml(path: Path) -> dict:
    return tomllib.loads(path.read_text())


def read_workspace_members(root: Path) -> list[str]:
    data = load_toml(root / "Cargo.toml")
    return data.get("workspace", {}).get("members", [])


def read_crate_name(cargo_toml: Path) -> str:
    data = load_toml(cargo_toml)
    return data.get("package", {}).get("name", cargo_toml.parent.name)


def read_direct_deps(cargo_toml: Path) -> dict[str, set[str]]:
    data = load_toml(cargo_toml)
    deps = set(data.get("dependencies", {}).keys())
    dev = set(data.get("dev-dependencies", {}).keys())
    build = set(data.get("build-dependencies", {}).keys())
    return {
        "dependencies": deps,
        "dev-dependencies": dev,
        "build-dependencies": build,
    }


def parse_lock(lock_path: Path) -> tuple[dict[str, list[str]], dict[str, str]]:
    data = load_toml(lock_path)
    packages = data.get("package", [])
    adj: dict[str, list[str]] = {}
    key_by_name: dict[str, str] = {}

    def dep_key(dep: str) -> str | None:
        parts = dep.split()
        if len(parts) < 2:
            return None
        return f"{parts[0]} {parts[1]}"

    for pkg in packages:
        name = pkg.get("name")
        version = pkg.get("version")
        if not name or not version:
            continue
        key = f"{name} {version}"
        source = pkg.get("source")
        if source is None or (isinstance(source, str) and source.startswith("path+")):
            key_by_name.setdefault(name, key)
        deps = []
        for dep in pkg.get("dependencies", []):
            dk = dep_key(dep)
            if dk:
                deps.append(dk)
        adj[key] = deps

    return adj, key_by_name


def transitive_names(start_key: str, adj: dict[str, list[str]]) -> set[str]:
    seen: set[str] = set()
    stack = list(adj.get(start_key, []))
    while stack:
        cur = stack.pop()
        if cur in seen:
            continue
        seen.add(cur)
        stack.extend(adj.get(cur, []))
    return {k.split()[0] for k in seen}


def load_rules(path: Path) -> dict[str, set[str]]:
    data = load_toml(path)
    forbid = data.get("forbid", {})
    rules: dict[str, set[str]] = {}
    for crate, deps in forbid.items():
        if not isinstance(deps, list):
            continue
        rules[crate] = set(deps)
    return rules


def main(argv: Iterable[str]) -> int:
    parser = argparse.ArgumentParser(description="Dependency boundary checker")
    parser.add_argument("--rules", default=str(DEFAULT_RULES), help="rules.toml path")
    parser.add_argument("--format", choices=["text", "json"], default="text")
    parser.add_argument("--no-transitive", action="store_true", help="skip transitive checks")
    args = parser.parse_args(list(argv))

    rules_path = Path(args.rules)
    if not rules_path.exists():
        raise DepCheckError(f"rules file not found: {rules_path}")

    members = read_workspace_members(ROOT)
    rules = load_rules(rules_path)

    violations: list[dict[str, str]] = []

    # Direct checks
    for member in members:
        cargo_path = ROOT / member / "Cargo.toml"
        if not cargo_path.exists():
            continue
        crate_name = read_crate_name(cargo_path)
        forbidden = rules.get(crate_name, set())
        if not forbidden:
            continue
        direct = read_direct_deps(cargo_path)
        for scope, deps in direct.items():
            for dep in sorted(deps):
                if dep in forbidden:
                    violations.append({
                        "crate": crate_name,
                        "dependency": dep,
                        "scope": scope,
                        "kind": "direct",
                    })

    # Transitive checks
    if not args.no_transitive:
        lock_path = ROOT / "Cargo.lock"
        if lock_path.exists():
            adj, key_by_name = parse_lock(lock_path)
            for member in members:
                cargo_path = ROOT / member / "Cargo.toml"
                if not cargo_path.exists():
                    continue
                crate_name = read_crate_name(cargo_path)
                forbidden = rules.get(crate_name, set())
                if not forbidden:
                    continue
                start_key = key_by_name.get(crate_name)
                if not start_key:
                    continue
                trans_names = transitive_names(start_key, adj)
                for dep in sorted(trans_names & forbidden):
                    violations.append({
                        "crate": crate_name,
                        "dependency": dep,
                        "scope": "transitive",
                        "kind": "transitive",
                    })
        else:
            print("warning: Cargo.lock not found; skipping transitive checks", file=sys.stderr)

    if args.format == "json":
        print(json.dumps({"violations": violations}, indent=2))
    else:
        if not violations:
            print("depcheck: no violations")
        else:
            print("depcheck: violations found")
            for v in violations:
                print(f"- {v['crate']}: {v['dependency']} ({v['kind']}/{v['scope']})")

    return 1 if violations else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except DepCheckError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2)
