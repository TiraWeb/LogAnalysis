#!/usr/bin/env python3
"""
Evaluation harness — precision / recall for the Z-score anomaly detector.

Replays the evaluation day (2026-04-18) in 5-minute steps and compares
detector output against ground-truth incident windows.

Ground truth
------------
  INCIDENT_1  token-ms         14:00 – 14:30 local  (70 % error rate spike)
  INCIDENT_2  success-plan-ms  18:30 – 19:00 local  (latency + 35 % 503s)

Also compares against a naive static-threshold baseline (> 1 % error rate).

Usage
-----
    python evaluation/replay.py
    python evaluation/replay.py --step 15      # 15-minute step size
    python evaluation/replay.py --threshold 5  # custom Z threshold
"""
import argparse
import sys
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / 'engine'))
from detector import query_current_window, query_baseline, compute_z   # noqa: E402

# ---------------------------------------------------------------------------
# Ground truth
# ---------------------------------------------------------------------------

GROUND_TRUTH = [
    {
        'name':    'INCIDENT_1',
        'service': 'token-ms',
        'start':   datetime(2026, 4, 18, 14,  0),
        'end':     datetime(2026, 4, 18, 14, 30),
        'type':    'error_rate',
    },
    {
        'name':    'INCIDENT_2',
        'service': 'success-plan-ms',
        'start':   datetime(2026, 4, 18, 18, 30),
        'end':     datetime(2026, 4, 18, 19,  0),
        'type':    'latency',
    },
]

EVAL_DAY_START = datetime(2026, 4, 18,  0, 0)
EVAL_DAY_END   = datetime(2026, 4, 18, 23, 59)

STATIC_ERROR_THRESHOLD = 0.01  # 1 % for naive baseline comparison


def in_any_incident(window_end: datetime, service: str) -> bool:
    window_start = window_end - timedelta(minutes=5)
    for gt in GROUND_TRUTH:
        if gt['service'] != service:
            continue
        # overlap check
        if window_start < gt['end'] and window_end > gt['start']:
            return True
    return False


# ---------------------------------------------------------------------------
# Replay
# ---------------------------------------------------------------------------

def replay(step_minutes: int, z_threshold: float) -> None:
    print(f'Replay: step={step_minutes} min, Z threshold={z_threshold}')
    print('=' * 60)

    # Pre-compute baseline for the two incident times (slow — do once per service)
    print('Pre-fetching baselines...')
    sample_times = {
        'token-ms':       datetime(2026, 4, 18, 14, 15),
        'success-plan-ms': datetime(2026, 4, 18, 18, 45),
    }
    baselines: dict[str, dict] = {}
    for svc, t in sample_times.items():
        bl = query_baseline(t)
        if svc in bl:
            baselines[svc] = bl[svc]
        else:
            print(f'  WARNING: no baseline for {svc}')

    print()

    # Metrics per method
    results = {
        'z_score':  {'tp': 0, 'fp': 0, 'tn': 0, 'fn': 0},
        'static':   {'tp': 0, 'fp': 0, 'tn': 0, 'fn': 0},
    }
    detections: list[dict] = []

    cursor = EVAL_DAY_START + timedelta(minutes=step_minutes)
    while cursor <= EVAL_DAY_END:
        current_data = query_current_window(cursor)

        for svc_data in current_data:
            svc = svc_data['service']
            if svc not in baselines:
                cursor += timedelta(minutes=step_minutes)
                continue

            bl         = baselines[svc]
            er         = svc_data['error_rate']
            lat        = svc_data['avg_duration']
            z_err      = compute_z(er,  bl['mean_error_rate'], bl['std_error_rate'])
            z_lat      = compute_z(lat, bl['mean_duration'],   bl['std_duration'])
            is_gt      = in_any_incident(cursor, svc)

            # Z-score method
            z_detected = z_err > z_threshold or z_lat > z_threshold
            # Static threshold method
            static_det = er > STATIC_ERROR_THRESHOLD

            for method, detected in [('z_score', z_detected), ('static', static_det)]:
                if detected and is_gt:
                    results[method]['tp'] += 1
                elif detected and not is_gt:
                    results[method]['fp'] += 1
                elif not detected and is_gt:
                    results[method]['fn'] += 1
                else:
                    results[method]['tn'] += 1

            if z_detected:
                detections.append({
                    'time':      cursor.strftime('%H:%M'),
                    'service':   svc,
                    'z_err':     round(z_err, 1),
                    'z_lat':     round(z_lat, 1),
                    'is_ground_truth': is_gt,
                })

        cursor += timedelta(minutes=step_minutes)

    # ---- Print detections ----
    print(f'{"Time":>5}  {"Service":25}  {"Z_err":>7}  {"Z_lat":>7}  {"GT":>4}')
    print('-' * 60)
    for d in detections:
        gt_marker = 'TRUE' if d['is_ground_truth'] else 'FALSE'
        print(f'{d["time"]:>5}  {d["service"]:25}  {d["z_err"]:>7.1f}  {d["z_lat"]:>7.1f}  {gt_marker:>5}')

    # ---- Precision / Recall ----
    print()
    print(f'{"Method":12}  {"Precision":>9}  {"Recall":>7}  {"F1":>6}  {"TP":>4}  {"FP":>4}  {"FN":>4}')
    print('-' * 60)
    for method, m in results.items():
        tp, fp, fn = m['tp'], m['fp'], m['fn']
        precision = tp / (tp + fp) if (tp + fp) else 0
        recall    = tp / (tp + fn) if (tp + fn) else 0
        f1        = (2 * precision * recall / (precision + recall)
                     if (precision + recall) else 0)
        print(
            f'{method:12}  {precision:>9.1%}  {recall:>7.1%}  '
            f'{f1:>6.3f}  {tp:>4}  {fp:>4}  {fn:>4}'
        )


def main() -> None:
    ap = argparse.ArgumentParser(description='Velaris detector evaluation harness')
    ap.add_argument('--step',      type=int,   default=5,   help='Replay step in minutes')
    ap.add_argument('--threshold', type=float, default=3.0, help='Z-score threshold')
    args = ap.parse_args()
    replay(args.step, args.threshold)


if __name__ == '__main__':
    main()
