#!/usr/bin/env python3
"""
Export evaluation results to CSV and a comparison bar chart (PNG).

Usage
-----
    python evaluation/export_results.py
    python evaluation/export_results.py --out results/          # custom output dir
    python evaluation/export_results.py --threshold 3.0 --step 5
"""
import argparse
import csv
import sys
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / 'engine'))
from detector import query_current_window, query_baseline, compute_z  # noqa: E402

GROUND_TRUTH = [
    {
        'service': 'token-ms',
        'start':   datetime(2026, 4, 18, 14,  0),
        'end':     datetime(2026, 4, 18, 14, 30),
    },
    {
        'service': 'success-plan-ms',
        'start':   datetime(2026, 4, 18, 18, 30),
        'end':     datetime(2026, 4, 18, 19,  0),
    },
]

EVAL_START = datetime(2026, 4, 18,  0, 0)
EVAL_END   = datetime(2026, 4, 18, 23, 59)
STATIC_THRESHOLD = 0.01


def in_incident(window_end: datetime, service: str) -> bool:
    window_start = window_end - timedelta(minutes=5)
    for gt in GROUND_TRUTH:
        if gt['service'] == service and window_start < gt['end'] and window_end > gt['start']:
            return True
    return False


def _metrics(tp, fp, fn):
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall    = tp / (tp + fn) if (tp + fn) else 0.0
    f1        = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return precision, recall, f1


def run(step: int, z_threshold: float, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)

    print('Pre-fetching baselines...')
    sample_times = {
        'token-ms':        datetime(2026, 4, 18, 14, 15),
        'success-plan-ms': datetime(2026, 4, 18, 18, 45),
    }
    baselines = {}
    for svc, t in sample_times.items():
        bl = query_baseline(t)
        if svc in bl:
            baselines[svc] = bl[svc]

    counts = {
        'z_score': {'tp': 0, 'fp': 0, 'tn': 0, 'fn': 0},
        'static':  {'tp': 0, 'fp': 0, 'tn': 0, 'fn': 0},
    }
    detections = []

    cursor = EVAL_START + timedelta(minutes=step)
    while cursor <= EVAL_END:
        current_data = query_current_window(cursor)
        for row in current_data:
            svc = row['service']
            if svc not in baselines:
                continue
            bl      = baselines[svc]
            er      = row['error_rate']
            lat     = row['avg_duration']
            z_err   = compute_z(er,  bl['mean_error_rate'], bl['std_error_rate'])
            z_lat   = compute_z(lat, bl['mean_duration'],   bl['std_duration'])
            is_gt   = in_incident(cursor, svc)
            z_det   = z_err > z_threshold or z_lat > z_threshold
            st_det  = er > STATIC_THRESHOLD

            for method, detected in [('z_score', z_det), ('static', st_det)]:
                key = ('tp' if detected else 'fn') if is_gt else ('fp' if detected else 'tn')
                counts[method][key] += 1

            detections.append({
                'time':    cursor.strftime('%Y-%m-%d %H:%M'),
                'service': svc,
                'error_rate': round(er, 4),
                'avg_duration_ms': round(lat, 1),
                'z_err': round(z_err, 2),
                'z_lat': round(z_lat, 2),
                'z_score_alert': z_det,
                'static_alert':  st_det,
                'ground_truth':  is_gt,
            })
        cursor += timedelta(minutes=step)

    # ── CSV: per-window detections ────────────────────────────────────────────
    det_path = out_dir / 'detections.csv'
    with open(det_path, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=detections[0].keys())
        writer.writeheader()
        writer.writerows(detections)
    print(f'Detections  → {det_path}')

    # ── CSV: summary metrics ──────────────────────────────────────────────────
    summary_rows = []
    for method, m in counts.items():
        p, r, f1 = _metrics(m['tp'], m['fp'], m['fn'])
        summary_rows.append({
            'method':    'Z-Score (ours)' if method == 'z_score' else 'Static Threshold',
            'precision': round(p, 4),
            'recall':    round(r, 4),
            'f1':        round(f1, 4),
            'tp': m['tp'], 'fp': m['fp'], 'fn': m['fn'], 'tn': m['tn'],
        })
        print(f'{method:12}  Precision={p:.1%}  Recall={r:.1%}  F1={f1:.3f}')

    sum_path = out_dir / 'summary.csv'
    with open(sum_path, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=summary_rows[0].keys())
        writer.writeheader()
        writer.writerows(summary_rows)
    print(f'Summary     → {sum_path}')

    # ── PNG: bar chart comparison ─────────────────────────────────────────────
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
        import numpy as np

        labels  = ['Precision', 'Recall', 'F1 Score']
        z_vals  = [summary_rows[0]['precision'], summary_rows[0]['recall'], summary_rows[0]['f1']]
        st_vals = [summary_rows[1]['precision'], summary_rows[1]['recall'], summary_rows[1]['f1']]

        x   = np.arange(len(labels))
        w   = 0.35
        fig, ax = plt.subplots(figsize=(7, 4))
        bars_z  = ax.bar(x - w/2, z_vals,  w, label='Z-Score (ours)', color='#6366F1')
        bars_st = ax.bar(x + w/2, st_vals, w, label='Static Threshold', color='#94A3B8')

        for bar in bars_z + bars_st:
            ax.text(
                bar.get_x() + bar.get_width() / 2,
                bar.get_height() + 0.01,
                f'{bar.get_height():.2f}',
                ha='center', va='bottom', fontsize=9,
            )

        ax.set_ylim(0, 1.15)
        ax.set_xticks(x)
        ax.set_xticklabels(labels)
        ax.set_ylabel('Score')
        ax.set_title('Z-Score Detector vs Static Threshold — Evaluation Results')
        ax.legend()
        ax.grid(axis='y', alpha=0.3)
        fig.tight_layout()

        chart_path = out_dir / 'comparison_chart.png'
        fig.savefig(chart_path, dpi=150)
        plt.close(fig)
        print(f'Chart       → {chart_path}')
    except ImportError:
        print('matplotlib not installed — skipping chart (pip install matplotlib)')


def main() -> None:
    ap = argparse.ArgumentParser(description='Export evaluation results to CSV + PNG')
    ap.add_argument('--out',       default='evaluation/results', help='Output directory')
    ap.add_argument('--step',      type=int,   default=5,   help='Replay step in minutes')
    ap.add_argument('--threshold', type=float, default=3.0, help='Z-score threshold')
    args = ap.parse_args()
    run(args.step, args.threshold, Path(args.out))


if __name__ == '__main__':
    main()
