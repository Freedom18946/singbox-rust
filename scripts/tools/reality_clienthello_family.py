#!/usr/bin/env python3
import argparse
import collections
import json
import pathlib
import sys
from itertools import combinations

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import reality_clienthello_diff as diffmod  # noqa: E402

KEY_PRECEDENCE_EXTENSIONS = (
    "0x0000",
    "0x0012",
    "0x0017",
    "0x002b",
    "0xfe0d",
    "0xff01",
)
KEY_SIGNATURE_PAIRS = (
    ("0x0000", "0x002b"),
    ("0x0012", "0xfe0d"),
    ("0x0017", "0xfe0d"),
    ("0x002b", "0xfe0d"),
    ("0xfe0d", "0xff01"),
)
FE0D_POSITION_PROFILES = {
    186: [2, 3, 4, 4, 6, 6, 8, 9, 10, 12, 15, 15],
    218: [2, 2, 3, 3, 5, 6, 6, 6, 9, 12, 12, 13, 16, 16],
    250: [2, 3, 4, 6, 6, 9, 9, 11, 11, 12, 12, 14, 15, 15, 16, 16, 16, 16, 16, 16],
    282: [2, 2, 3, 5, 5, 5, 6, 8, 10, 11, 13, 13, 15, 16],
}


def classify_fe0d_position_band(fe0d_len, fe0d_position):
    profile = FE0D_POSITION_PROFILES.get(fe0d_len)
    if not profile:
        return "unknown"

    sorted_profile = sorted(profile)
    count = len(sorted_profile)
    early_cut = sorted_profile[(count - 1) // 3]
    late_cut = sorted_profile[((count - 1) * 2) // 3]
    if fe0d_position <= early_cut:
        return "early"
    if fe0d_position >= late_cut:
        return "late"
    return "mid"


def build_key_signature(positions):
    key_signature = []
    for left, right in KEY_SIGNATURE_PAIRS:
        left_pos = positions.get(left)
        right_pos = positions.get(right)
        if left_pos is None or right_pos is None:
            continue
        if left_pos < right_pos:
            key_signature.append(f"{left}<{right}")
        else:
            key_signature.append(f"{right}<{left}")
    return tuple(key_signature)


def counter_to_pairs(counter, limit=None):
    items = counter.most_common(limit)
    output = []
    for key, count in items:
        if isinstance(key, tuple):
            key = list(key)
        output.append({"key": key, "count": count})
    return output


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
    record_len_to_fe0d_len = collections.Counter()
    fe0d_position_counts = collections.Counter()
    fe0d_len_to_position = collections.Counter()
    ext_position_counts = collections.defaultdict(collections.Counter)
    fe0d_len_to_ext_position_counts = collections.defaultdict(collections.Counter)
    fe0d_len_to_pairwise_precedence = collections.defaultdict(collections.Counter)
    fe0d_len_to_key_order_families = collections.Counter()
    fe0d_len_to_key_signature_families = collections.Counter()
    fe0d_len_to_position_band_counts = collections.defaultdict(collections.Counter)
    fe0d_len_band_to_key_signature_families = collections.Counter()
    record_len_to_key_signature_families = collections.Counter()
    record_len_fe0d_len_band_counts = collections.Counter()
    record_len_fe0d_len_band_to_key_signature_families = collections.Counter()
    fe0d_len_pos_to_key_signature_families = collections.Counter()
    fe0d_len_to_prefix4 = collections.Counter()
    fe0d_len_to_suffix4 = collections.Counter()
    position_vectors = set()

    ext_presence = collections.defaultdict(int)
    for run in runs:
        positions = {ext_type: idx for idx, ext_type in enumerate(run["extensions_order"])}
        for ext_type in run["extensions_order"]:
            ext_presence[ext_type] += 1
        for ext_type, idx in positions.items():
            ext_position_counts[ext_type][idx] += 1

        fe0d = next((ext for ext in run["extensions"] if ext["type"] == "0xfe0d"), None)
        if fe0d is not None and "0xfe0d" in positions:
            record_len_to_fe0d_len[(run["record_len"], fe0d["len"])] += 1
            fe0d_position_counts[positions["0xfe0d"]] += 1
            fe0d_len_to_position[(fe0d["len"], positions["0xfe0d"])] += 1
            band = classify_fe0d_position_band(fe0d["len"], positions["0xfe0d"])
            fe0d_len_to_position_band_counts[fe0d["len"]][band] += 1
            for ext_type, idx in positions.items():
                fe0d_len_to_ext_position_counts[(fe0d["len"], ext_type)][idx] += 1
            key_order = tuple(
                ext_type
                for ext_type in run["extensions_order"]
                if ext_type in KEY_PRECEDENCE_EXTENSIONS
            )
            if key_order:
                fe0d_len_to_key_order_families[(fe0d["len"], key_order)] += 1
                key_signature = build_key_signature(positions)
                if key_signature:
                    fe0d_len_to_key_signature_families[
                        (fe0d["len"], key_signature)
                    ] += 1
                    record_len_to_key_signature_families[
                        (run["record_len"], key_signature)
                    ] += 1
                    record_len_fe0d_len_band_counts[
                        (run["record_len"], fe0d["len"], band)
                    ] += 1
                    fe0d_len_band_to_key_signature_families[
                        (fe0d["len"], band, key_signature)
                    ] += 1
                    record_len_fe0d_len_band_to_key_signature_families[
                        (run["record_len"], fe0d["len"], band, key_signature)
                    ] += 1
                    fe0d_len_pos_to_key_signature_families[
                        (fe0d["len"], positions["0xfe0d"], key_signature)
                    ] += 1
            for left, right in combinations(key_order, 2):
                earlier, later = (left, right)
                canonical_left, canonical_right = sorted((left, right))
                fe0d_len_to_pairwise_precedence[
                    (fe0d["len"], canonical_left, canonical_right)
                ][f"{earlier}<{later}"] += 1
            fe0d_len_to_prefix4[(fe0d["len"], tuple(run["extensions_order"][1:5]))] += 1
            fe0d_len_to_suffix4[(fe0d["len"], tuple(run["extensions_order"][-5:-1]))] += 1

        position_vectors.add(
            tuple(
                positions[ext_type]
                for ext_type in run["extensions_order"]
                if ext_type not in {"GREASE"}
            )
        )

    return {
        "runs": len(runs),
        "record_len_counts": dict(sorted(record_len_counts.items())),
        "first_cipher_suite_counts": dict(sorted(cipher_counts.items())),
        "first_extension_counts": dict(sorted(first_ext_counts.items())),
        "last_extension_counts": dict(sorted(last_ext_counts.items())),
        "fe0d_len_counts": dict(sorted(fe0d_len_counts.items())),
        "record_len_to_fe0d_len": counter_to_pairs(record_len_to_fe0d_len),
        "fe0d_position_counts": dict(sorted(fe0d_position_counts.items())),
        "fe0d_len_to_position": counter_to_pairs(fe0d_len_to_position),
        "fe0d_len_to_position_band_counts": {
            str(fe0d_len): dict(sorted(counts.items()))
            for fe0d_len, counts in sorted(fe0d_len_to_position_band_counts.items())
        },
        "extension_position_counts": {
            ext_type: dict(sorted(counts.items()))
            for ext_type, counts in sorted(ext_position_counts.items())
        },
        "fe0d_len_to_extension_position_counts": {
            f"{fe0d_len}:{ext_type}": dict(sorted(counts.items()))
            for (fe0d_len, ext_type), counts in sorted(fe0d_len_to_ext_position_counts.items())
        },
        "fe0d_len_to_extension_mean_positions": {
            f"{fe0d_len}:{ext_type}": round(
                sum(position * count for position, count in counts.items()) / sum(counts.values()), 3
            )
            for (fe0d_len, ext_type), counts in sorted(fe0d_len_to_ext_position_counts.items())
        },
        "fe0d_len_to_pairwise_precedence_counts": {
            f"{fe0d_len}:{left}|{right}": dict(sorted(counts.items()))
            for (fe0d_len, left, right), counts in sorted(fe0d_len_to_pairwise_precedence.items())
        },
        "fe0d_len_to_pairwise_majority": {
            f"{fe0d_len}:{left}|{right}": max(
                counts.items(),
                key=lambda item: (item[1], item[0]),
            )[0]
            for (fe0d_len, left, right), counts in sorted(fe0d_len_to_pairwise_precedence.items())
        },
        "fe0d_len_to_key_order_families": counter_to_pairs(
            fe0d_len_to_key_order_families,
            limit=16,
        ),
        "fe0d_len_to_key_signature_families": counter_to_pairs(
            fe0d_len_to_key_signature_families,
            limit=20,
        ),
        "fe0d_len_band_to_key_signature_families": counter_to_pairs(
            fe0d_len_band_to_key_signature_families,
            limit=24,
        ),
        "record_len_to_key_signature_families": counter_to_pairs(
            record_len_to_key_signature_families,
            limit=20,
        ),
        "record_len_fe0d_len_band_counts": counter_to_pairs(
            record_len_fe0d_len_band_counts,
            limit=20,
        ),
        "record_len_fe0d_len_band_to_key_signature_families": counter_to_pairs(
            record_len_fe0d_len_band_to_key_signature_families,
            limit=24,
        ),
        "fe0d_len_pos_to_key_signature_families": counter_to_pairs(
            fe0d_len_pos_to_key_signature_families,
            limit=24,
        ),
        "fe0d_len_to_prefix4": counter_to_pairs(fe0d_len_to_prefix4, limit=12),
        "fe0d_len_to_suffix4": counter_to_pairs(fe0d_len_to_suffix4, limit=12),
        "extension_presence_counts": dict(sorted(ext_presence.items())),
        "order_family_count": len(order_counts),
        "position_vector_family_count": len(position_vectors),
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
