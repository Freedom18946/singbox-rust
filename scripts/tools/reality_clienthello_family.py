#!/usr/bin/env python3
import argparse
import collections
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import reality_clienthello_diff as diffmod  # noqa: E402


def summarize_many(paths):
    runs = [diffmod.summarize_record(diffmod.load_hex(str(path))) for path in paths]
    order_counts = collections.Counter(tuple(run["extensions_order"]) for run in runs)
    record_len_counts = collections.Counter(run["record_len"] for run in runs)
    cipher_counts = collections.Counter(run["cipher_suites"][0] for run in runs)
    first_ext_counts = collections.Counter(
        run["extensions_order"][0] for run in runs if run["extensions_order"]
    )
    last_ext_counts = collections.Counter(
        run["extensions_order"][-1] for run in runs if run["extensions_order"]
    )
    fe0d_len_counts = collections.Counter(
        ext["len"]
        for run in runs
        for ext in run["extensions"]
        if ext["type"] == "0xfe0d"
    )

    ext_presence = collections.defaultdict(int)
    for run in runs:
        for ext_type in run["extensions_order"]:
            ext_presence[ext_type] += 1

    return {
        "runs": len(runs),
        "record_len_counts": dict(sorted(record_len_counts.items())),
        "first_cipher_suite_counts": dict(sorted(cipher_counts.items())),
        "first_extension_counts": dict(sorted(first_ext_counts.items())),
        "last_extension_counts": dict(sorted(last_ext_counts.items())),
        "fe0d_len_counts": dict(sorted(fe0d_len_counts.items())),
        "extension_presence_counts": dict(sorted(ext_presence.items())),
        "order_family_count": len(order_counts),
        "top_order_families": [
            {"count": count, "order": list(order)}
            for order, count in order_counts.most_common(8)
        ],
    }


def load_paths(dir_path: str):
    return sorted(pathlib.Path(dir_path).glob("*.hex"))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--go-hex-dir")
    parser.add_argument("--rust-hex-dir")
    args = parser.parse_args()

    output = {}
    if args.go_hex_dir:
        output["go"] = summarize_many(load_paths(args.go_hex_dir))
    if args.rust_hex_dir:
        output["rust"] = summarize_many(load_paths(args.rust_hex_dir))

    json.dump(output, sys.stdout, indent=2, ensure_ascii=True)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
