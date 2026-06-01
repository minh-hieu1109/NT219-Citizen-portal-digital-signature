import csv
import json
import statistics
from pathlib import Path

from common import ensure_demo_citizen, log, run_remote_sign_and_verify


ITERATIONS = 20
RESULTS_DIR = Path(__file__).resolve().parent / "results"
CSV_PATH = RESULTS_DIR / "benchmark_sign_verify.csv"
SUMMARY_PATH = RESULTS_DIR / "benchmark_sign_verify_summary.json"


def _ms(values):
    if not values:
        return {"avg": 0, "min": 0, "max": 0, "p95": 0}
    ordered = sorted(values)
    p95_index = max(0, int(round(0.95 * len(ordered))) - 1)
    return {
        "avg": round(statistics.mean(values), 3),
        "min": round(min(values), 3),
        "max": round(max(values), 3),
        "p95": round(ordered[p95_index], 3),
    }


def main():
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    user = ensure_demo_citizen(email="laqun0211@gmail.com")
    rows = []

    for i in range(1, ITERATIONS + 1):
        res = run_remote_sign_and_verify(user, content=f"benchmark-{i}".encode("utf-8"))
        t = res["timings_ms"]
        rows.append(
            {
                "iteration": i,
                "remote_sign_ms": round(t["remote_sign"], 3),
                "verify_ms": round(t["verify"], 3),
                "ltv_verify_ms": round(t["ltv_verify"], 3),
                "verification_status": res["verification_result"].status,
                "ltv_valid": bool(res["ltv_result"].get("valid")),
            }
        )

    with CSV_PATH.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "iteration",
                "remote_sign_ms",
                "verify_ms",
                "ltv_verify_ms",
                "verification_status",
                "ltv_valid",
            ],
        )
        writer.writeheader()
        writer.writerows(rows)

    remote_vals = [r["remote_sign_ms"] for r in rows]
    verify_vals = [r["verify_ms"] for r in rows]
    ltv_vals = [r["ltv_verify_ms"] for r in rows]

    summary = {
        "iterations": ITERATIONS,
        "remote_sign_ms": _ms(remote_vals),
        "verify_ms": _ms(verify_vals),
        "ltv_verify_ms": _ms(ltv_vals),
        "csv_path": str(CSV_PATH),
    }

    SUMMARY_PATH.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    log("INFO", f"benchmark_done iterations={ITERATIONS}")
    log("INFO", f"csv={CSV_PATH}")
    log("INFO", f"summary={SUMMARY_PATH}")
    log("INFO", f"summary_data={summary}")


if __name__ == "__main__":
    main()
