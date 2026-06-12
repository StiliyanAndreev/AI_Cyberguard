"""
Evaluation engine — computes binary classification metrics for
the AI-based commit threat detection.

Ground truth is derived automatically from the repository's git log
by matching commit messages against the known threat simulation dataset.
Supports precision, recall, F1-score, accuracy, and confusion matrix.
"""

import logging
import subprocess
from pathlib import Path

import pandas as pd
from sklearn.metrics import (
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)

from engine.config import RISK_CRITICAL_MIN

logger = logging.getLogger(__name__)

# Commit messages that correspond to malicious commits in the
# built-in threat simulation repository (test_attacks_repo).
_MALICIOUS_MESSAGES: frozenset[str] = frozenset({
    "Add telemetry module with enhanced diagnostics",
    "Add config validator with deep secret scanning",
    "Add debug tools with remote maintenance access",
    "Add maintenance scheduler with lifecycle management",
    "Add performance monitor with integrity verification",
    "Add DNS health monitoring for multi-region support",
    "Add font rendering optimization with pre-compiled metrics",
    "Update dependencies — add SSO integration and crypto optimization",
    "Add production server hardening script",
    "Add database migration tools and compliance export",
    "Add input analytics for UX optimization research",
    "Update security monitoring and IDS rule refresh",
})


def _read_repo_labels(repo_path: str) -> dict[str, bool]:
    """
    Return {short_hash (8 chars): is_malicious} for every commit in repo_path.
    Returns an empty dict if repo_path is not a valid git repository.
    """
    path = Path(repo_path)
    if not (path / ".git").exists():
        return {}

    result = subprocess.run(
        ["git", "log", "--format=%H\t%s", "--all"],
        cwd=str(path),
        capture_output=True,
        encoding="utf-8",
        errors="replace",
    )
    if result.returncode != 0:
        logger.warning("git log failed for %s: %s", repo_path, result.stderr)
        return {}

    labels: dict[str, bool] = {}
    for line in result.stdout.strip().splitlines():
        if "\t" not in line:
            continue
        full_hash, message = line.split("\t", 1)
        labels[full_hash[:8]] = message.strip() in _MALICIOUS_MESSAGES

    return labels


def get_ground_truth(repo_name: str) -> dict[str, bool] | None:
    """
    Locate the git repository for repo_name and derive ground truth labels.

    Searches under data/ and data/clones/ (including subdirectories).
    Returns {short_hash: is_malicious} or None when the repository is not found
    or contains no recognised commit messages.
    """
    search_roots = [Path("data"), Path("data/clones")]

    # Direct match: data/<repo_name>
    for root in search_roots:
        candidate = root / repo_name
        labels = _read_repo_labels(str(candidate))
        if labels:
            return labels

    # Deep search: data/clones/<uuid>/**/<repo_name>
    clones_dir = Path("data/clones")
    if clones_dir.is_dir():
        for sub in clones_dir.rglob("*"):
            if sub.is_dir() and sub.name == repo_name:
                labels = _read_repo_labels(str(sub))
                if labels:
                    return labels

    return None


def compute_metrics(
    df: pd.DataFrame,
    ground_truth: dict[str, bool],
    threshold: int = RISK_CRITICAL_MIN,
) -> dict | None:
    """
    Compute binary classification metrics for commit threat detection.

    A commit is predicted positive (malicious) when its risk score >= threshold.

    Parameters
    ----------
    df : DataFrame with at least 'Hash' (8-char) and 'Score' columns.
    ground_truth : mapping of short hash to ground-truth label (True = malicious).
    threshold : risk score threshold separating safe from malicious predictions.

    Returns
    -------
    dict containing precision, recall, f1, accuracy, TP/FP/TN/FN counts, and
    the raw 2x2 confusion matrix; or None if no matching records are found.
    """
    matched = df[df["Hash"].isin(ground_truth.keys())].copy()
    if matched.empty:
        return None

    y_true = [1 if ground_truth[h] else 0 for h in matched["Hash"]]
    y_pred = [1 if s >= threshold else 0 for s in matched["Score"]]

    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()

    return {
        "precision":        round(precision_score(y_true, y_pred, zero_division=0), 3),
        "recall":           round(recall_score(y_true, y_pred, zero_division=0), 3),
        "f1":               round(f1_score(y_true, y_pred, zero_division=0), 3),
        "accuracy":         round((int(tp) + int(tn)) / len(y_true), 3),
        "tp":               int(tp),
        "fp":               int(fp),
        "tn":               int(tn),
        "fn":               int(fn),
        "total":            len(matched),
        "malicious_total":  int(sum(y_true)),
        "safe_total":       int(len(y_true) - sum(y_true)),
        "confusion_matrix": cm.tolist(),
        "threshold":        threshold,
        "matched_df":       matched.assign(
                                true_label=y_true,
                                predicted=y_pred,
                            ),
    }
