"""
UEBA Engine — User & Entity Behaviour Analytics

Builds per-developer risk profiles and applies Isolation Forest anomaly
detection to identify statistical outliers in commit behaviour.

Academic note:
    Isolation Forest (Liu et al., 2008) works by randomly partitioning
    the feature space with binary trees. Anomalies require fewer splits
    to isolate, resulting in shorter average path lengths and a lower
    decision-function score.  We invert this to get an "anomaly score"
    where higher = more suspicious.

Temporal features:
    avg_commit_hour  — mean hour of day (0-23). Commits at unusual hours
                       (e.g. 2-5 AM) are a known insider threat signal.
    weekend_ratio    — fraction of commits made on Saturday/Sunday.
                       A high ratio can indicate unauthorised off-hours access.
"""

import logging

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from engine.config import UEBA_AVG_RISK_THRESHOLD, UEBA_MAX_RISK_THRESHOLD

logger = logging.getLogger(__name__)

_MIN_SAMPLES_FOR_ML = 3


def _temporal_features(df: pd.DataFrame) -> pd.DataFrame:
    """Return per-author avg_commit_hour and weekend_ratio from the Date column."""
    tmp = df.copy()
    tmp["_hour"] = tmp["Date"].dt.hour
    tmp["_is_weekend"] = tmp["Date"].dt.dayofweek >= 5  # 5=Sat, 6=Sun

    temporal = (
        tmp.groupby("Author")
        .agg(
            avg_commit_hour=("_hour", "mean"),
            weekend_ratio=("_is_weekend", "mean"),
        )
        .reset_index()
    )
    return temporal


def build_developer_profiles(df: pd.DataFrame) -> pd.DataFrame:
    """
    Compute developer risk profiles from the scan history DataFrame and
    classify each developer using Isolation Forest (when enough data is
    available) or a rule-based fallback.

    Input columns expected: Author, Score, Repo, Date

    Output adds:
        total_scans       — number of commits analysed
        avg_risk          — mean risk score
        max_risk          — worst-case risk score
        min_risk          — best-case risk score
        std_risk          — standard deviation (consistency indicator)
        risk_range        — max - min  (volatility indicator)
        avg_commit_hour   — average hour of day commits are made
        weekend_ratio     — fraction of commits on weekends
        projects          — list of distinct repos touched
        rule_flag         — True when avg > threshold OR max >= threshold
        if_anomaly        — True when Isolation Forest marks as outlier
        if_score          — normalised anomaly score [0, 1]; higher = riskier
        is_risky          — final verdict (rule_flag OR if_anomaly)
    """
    if df.empty:
        return pd.DataFrame()

    profiles = (
        df.groupby("Author")
        .agg(
            total_scans=("Score", "count"),
            avg_risk=("Score", "mean"),
            max_risk=("Score", "max"),
            min_risk=("Score", "min"),
            std_risk=("Score", "std"),
            projects=("Repo", lambda x: list(set(x))),
        )
        .reset_index()
    )

    profiles["std_risk"] = profiles["std_risk"].fillna(0.0)
    profiles["risk_range"] = profiles["max_risk"] - profiles["min_risk"]

    # Merge temporal behavioural features
    temporal = _temporal_features(df)
    profiles = profiles.merge(temporal, on="Author", how="left")
    profiles["avg_commit_hour"] = profiles["avg_commit_hour"].fillna(12.0)
    profiles["weekend_ratio"] = profiles["weekend_ratio"].fillna(0.0)

    # --- Rule-based baseline ---
    profiles["rule_flag"] = (
        (profiles["avg_risk"] > UEBA_AVG_RISK_THRESHOLD)
        | (profiles["max_risk"] >= UEBA_MAX_RISK_THRESHOLD)
    )

    # --- ML anomaly detection ---
    if len(profiles) >= _MIN_SAMPLES_FOR_ML:
        feature_cols = [
            "avg_risk", "max_risk", "std_risk", "risk_range",
            "total_scans", "avg_commit_hour", "weekend_ratio",
        ]
        X = profiles[feature_cols].values.astype(float)

        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)

        contamination = float(np.clip(1.0 / len(profiles), 0.05, 0.25))

        clf = IsolationForest(
            n_estimators=200,
            contamination=contamination,
            random_state=42,
        )
        clf.fit(X_scaled)

        raw_scores = clf.decision_function(X_scaled)  # higher = more normal
        predictions = clf.predict(X_scaled)           # -1 = anomaly

        # Normalise to [0, 1] where 1 = most anomalous
        inverted = -raw_scores
        score_range = inverted.max() - inverted.min()
        normalised = (inverted - inverted.min()) / score_range if score_range > 0 else inverted

        profiles["if_anomaly"] = predictions == -1
        profiles["if_score"] = np.round(normalised, 3)
        profiles["detection_method"] = "Isolation Forest"
    else:
        profiles["if_anomaly"] = False
        profiles["if_score"] = (profiles["avg_risk"] / 100.0).round(3)
        profiles["detection_method"] = "Rule-based (insufficient data for ML)"
        logger.info(
            "Fewer than %d developers in DB — Isolation Forest skipped.",
            _MIN_SAMPLES_FOR_ML,
        )

    profiles["is_risky"] = profiles["rule_flag"] | profiles["if_anomaly"]

    return profiles
