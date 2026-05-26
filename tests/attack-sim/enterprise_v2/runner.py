#!/usr/bin/env python3
"""
Enterprise v2 test runner — orchestrates 1200+ tests across all categories.

Usage:
  python3 runner.py [--filter <category>] [--skip-from <csv>] [--results <csv>]

Output:
  results-pass<N>.csv   per-test row
  debug-pass<N>.log     per-test alert detail
"""
import argparse, csv, os, sys, time
from datetime import datetime
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import framework
import cat01_injection
import cat02_rootkit
import cat03_c2
import cat04_lolbin
import cat_rest


def load_all_tests():
    """Load all generators."""
    all_tests = []
    all_tests += cat01_injection.gen()
    all_tests += cat02_rootkit.gen()
    all_tests += cat03_c2.gen()
    all_tests += cat04_lolbin.gen()
    rest = cat_rest.gen_all()
    for cat, tests in rest.items():
        all_tests += tests
    return all_tests


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--filter", help="comma-list of categories to run", default=None)
    ap.add_argument("--skip-from", help="csv to skip PASSed IDs from", default=None)
    ap.add_argument("--results", help="output CSV (default: results-pass<N>.csv)",
                    default=None)
    ap.add_argument("--debug", help="debug log path", default=None)
    args = ap.parse_args()

    DIR = os.path.dirname(os.path.abspath(__file__))

    # Auto-name pass
    pass_n = 1
    while os.path.exists(os.path.join(DIR, f"results-pass{pass_n}.csv")):
        pass_n += 1

    results_csv = args.results or os.path.join(DIR, f"results-pass{pass_n}.csv")
    debug_log = args.debug or os.path.join(DIR, f"debug-pass{pass_n}.log")

    # Load tests
    all_tests = load_all_tests()
    print(f"Total enterprise test corpus: {len(all_tests)}")
    cat_counts = Counter(t["category"] for t in all_tests)
    for cat, n in cat_counts.most_common():
        mal = sum(1 for t in all_tests if t["category"] == cat and t["malicious"])
        ben = n - mal
        print(f"  {cat:<10} {n:>6}  (malicious={mal}, benign={ben})")

    # Filter
    if args.filter:
        wanted = set(args.filter.split(","))
        all_tests = [t for t in all_tests if t["category"] in wanted]
        print(f"\nAfter --filter={args.filter}: {len(all_tests)} tests")

    # Skip-list
    skip_ids = set()
    if args.skip_from and os.path.exists(args.skip_from):
        skip_ids = framework.load_passed_ids([args.skip_from])
        print(f"Skipping {len(skip_ids)} tests already PASSed in {args.skip_from}")

    # Run
    framework.run_battery(all_tests, results_csv, debug_log, skip_ids=skip_ids)

    # Final summary
    print()
    print(f"Results: {results_csv}")
    print(f"Debug:   {debug_log}")

    # Per-category and TP/FP analysis
    print()
    print("=== TP/FP per category ===")
    cats = {}
    with open(results_csv) as f:
        for row in csv.DictReader(f):
            c = row["category"]
            cats.setdefault(c, {"mal_total": 0, "mal_pass": 0,
                                 "ben_total": 0, "ben_fp": 0})
            if row["malicious"] == "1":
                cats[c]["mal_total"] += 1
                if row["status"] == "PASS":
                    cats[c]["mal_pass"] += 1
            else:
                cats[c]["ben_total"] += 1
                if row["status"] == "FAIL":
                    cats[c]["ben_fp"] += 1

    print(f"{'Cat':<10} {'mTP':>4}/{'mTot':<5} {'TP%':>5}  {'bFP':>4}/{'bTot':<5} {'FP%':>5}")
    print("-" * 60)
    for c in sorted(cats):
        d = cats[c]
        tp_pct = 100 * d["mal_pass"] // max(d["mal_total"], 1)
        fp_pct = 100 * d["ben_fp"] // max(d["ben_total"], 1)
        print(f"{c:<10} {d['mal_pass']:>4}/{d['mal_total']:<5} "
              f"{tp_pct:>4}%   {d['ben_fp']:>4}/{d['ben_total']:<5} {fp_pct:>4}%")


if __name__ == "__main__":
    main()
