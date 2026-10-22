"""Loads the two trained models and labels one feature row at a time.

    from detector import Detector
    det = Detector()
    result = det.classify(row)      # row = dict with the seven FEATURES
    result.abnormal, result.label   # e.g. (True, "syn_flood")

Stage 1 (Isolation Forest) decides whether the row is abnormal. Only abnormal
rows go to Stage 2 (Random Forest), which names the problem. If Stage 2 then
says "normal" the label is "unknown" and the decision engine takes no action.
"""
import os
from dataclasses import dataclass

import joblib
import pandas as pd

from config import MODELS_DIR


@dataclass(frozen=True)
class Detection:
    abnormal: bool
    label: str        # normal, syn_flood, port_scan, link_failure, congestion, unknown
    score: float      # Isolation Forest score; lower means more abnormal


class Detector:
    def __init__(self, models_dir=MODELS_DIR):
        iso_path = os.path.join(models_dir, "isolation_forest.joblib")
        rf_path = os.path.join(models_dir, "random_forest.joblib")
        for path in (iso_path, rf_path):
            if not os.path.exists(path):
                raise FileNotFoundError(
                    f"{path} not found. Run  python train_models.py  first.")
        iso, rf = joblib.load(iso_path), joblib.load(rf_path)
        self.iso, self.threshold = iso["model"], iso["threshold"]
        self.rf = rf["model"]
        self.features = iso["features"]

    def classify(self, row):
        X = pd.DataFrame([[float(row[f]) for f in self.features]],
                         columns=self.features)
        score = float(self.iso.decision_function(X)[0])
        if score >= self.threshold:
            return Detection(False, "normal", score)
        label = str(self.rf.predict(X)[0])
        return Detection(True, "unknown" if label == "normal" else label, score)
