#!/usr/bin/env python3
"""Fail CI when canbench metrics regress beyond a configured tolerance."""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass, field
from pathlib import Path


METRICS = ("instructions", "heap_increase", "stable_memory_increase")


@dataclass
class BenchTotal:
    values: dict[str, int] = field(default_factory=dict)


def parse_canbench_results(path: Path) -> dict[str, BenchTotal]:
    benches: dict[str, BenchTotal] = {}
    in_benches = False
    in_total = False
    current_bench: str | None = None

    bench_re = re.compile(r"^  ([A-Za-z0-9_]+):\s*$")
    metric_re = re.compile(r"^      (instructions|heap_increase|stable_memory_increase):\s*([0-9]+)\s*$")

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.rstrip("\n")
        if line == "benches:":
            in_benches = True
            continue
        if not in_benches:
            continue

        bench_match = bench_re.match(line)
        if bench_match:
            current_bench = bench_match.group(1)
            benches[current_bench] = BenchTotal()
            in_total = False
            continue

        if current_bench is None:
            continue

        if line == "    total:":
            in_total = True
            continue
        if line.startswith("    scopes:"):
            in_total = False
            continue

        if in_total:
            metric_match = metric_re.match(line)
            if metric_match:
                metric, raw_value = metric_match.groups()
                benches[current_bench].values[metric] = int(raw_value)

    return benches


def allowed_max(baseline_value: int, tolerance_percent: float) -> int:
    if baseline_value == 0:
        return 0
    return int(round(baseline_value * (1.0 + tolerance_percent / 100.0)))


def main() -> int:
    if len(sys.argv) != 4:
        print(
            "usage: check_canbench_regression.py <baseline.yml> <candidate.yml> <tolerance_percent>",
            file=sys.stderr,
        )
        return 2

    baseline_path = Path(sys.argv[1])
    candidate_path = Path(sys.argv[2])
    tolerance_percent = float(sys.argv[3])

    baseline = parse_canbench_results(baseline_path)
    candidate = parse_canbench_results(candidate_path)

    if not baseline:
        print(f"baseline has no benches: {baseline_path}", file=sys.stderr)
        return 2
    if not candidate:
        print(f"candidate has no benches: {candidate_path}", file=sys.stderr)
        return 2

    regressions: list[str] = []
    missing: list[str] = []

    for bench_name, baseline_total in baseline.items():
        candidate_total = candidate.get(bench_name)
        if candidate_total is None:
            missing.append(bench_name)
            continue

        for metric in METRICS:
            baseline_value = baseline_total.values.get(metric, 0)
            candidate_value = candidate_total.values.get(metric, 0)
            threshold = allowed_max(baseline_value, tolerance_percent)
            if candidate_value > threshold:
                regressions.append(
                    (
                        f"{bench_name}.{metric}: baseline={baseline_value}, "
                        f"candidate={candidate_value}, allowed={threshold}"
                    )
                )

    if missing:
        print("missing benches in candidate results:", file=sys.stderr)
        for bench in missing:
            print(f"  - {bench}", file=sys.stderr)
        return 1

    if regressions:
        print(
            f"canbench regression detected (tolerance={tolerance_percent:.1f}%):",
            file=sys.stderr,
        )
        for item in regressions:
            print(f"  - {item}", file=sys.stderr)
        return 1

    print(f"canbench regression check passed (tolerance={tolerance_percent:.1f}%).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
