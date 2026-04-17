"""
Supervised Alert Classifier using Random Forest.

PhD Contribution: Learns from analyst-labeled incidents to automatically
classify new alerts by severity and type, reducing SOC analyst workload.
Integrates with the DSPy agent pipeline for hybrid AI (ML + LLM) decisions.
"""
import logging
import os
import pickle
from datetime import datetime
from typing import Any, Dict, List, Optional

import numpy as np

logger = logging.getLogger(__name__)

SEVERITY_LABELS = ["low", "medium", "high", "critical"]
TYPE_LABELS = [
    "brute_force", "malware", "lateral_movement", "exfiltration",
    "recon", "privilege_escalation", "c2", "web_attack",
    "policy_violation", "other",
]


class AlertClassifierML:
    """Random Forest classifier for security alert severity and type."""

    def __init__(self, models_path: str = "/models"):
        self._models_path = models_path
        self._severity_model = None
        self._type_model = None
        self._is_fitted = False
        self._load_models()

    def _load_models(self):
        sev_file = os.path.join(self._models_path, "classifier_severity.pkl")
        type_file = os.path.join(self._models_path, "classifier_type.pkl")
        try:
            if os.path.exists(sev_file) and os.path.exists(type_file):
                with open(sev_file, "rb") as f:
                    self._severity_model = pickle.load(f)
                with open(type_file, "rb") as f:
                    self._type_model = pickle.load(f)
                self._is_fitted = True
                logger.info("alert_classifier.models_loaded")
        except Exception as e:
            logger.warning("alert_classifier.load_failed: %s", e)

    def _save_models(self):
        os.makedirs(self._models_path, exist_ok=True)
        try:
            with open(os.path.join(self._models_path, "classifier_severity.pkl"), "wb") as f:
                pickle.dump(self._severity_model, f)
            with open(os.path.join(self._models_path, "classifier_type.pkl"), "wb") as f:
                pickle.dump(self._type_model, f)
        except Exception as e:
            logger.error("alert_classifier.save_failed: %s", e)

    def train(
        self,
        features: np.ndarray,
        severity_labels: List[str],
        type_labels: List[str],
    ) -> Dict[str, Any]:
        """
        Train both classifiers on labeled data.

        Args:
            features: (n_samples, n_features) array
            severity_labels: list of severity strings
            type_labels: list of alert type strings
        """
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.model_selection import cross_val_score

        if features.shape[0] < 30:
            return {"status": "insufficient_data", "samples": features.shape[0]}

        # Encode labels
        sev_encoded = np.array([SEVERITY_LABELS.index(s) if s in SEVERITY_LABELS else 1 for s in severity_labels])
        type_encoded = np.array([TYPE_LABELS.index(t) if t in TYPE_LABELS else 9 for t in type_labels])

        # Train severity classifier
        self._severity_model = RandomForestClassifier(
            n_estimators=150, max_depth=10, random_state=42, n_jobs=-1, class_weight="balanced",
        )
        self._severity_model.fit(features, sev_encoded)
        sev_cv = cross_val_score(self._severity_model, features, sev_encoded, cv=min(5, features.shape[0])).mean()

        # Train type classifier
        self._type_model = RandomForestClassifier(
            n_estimators=150, max_depth=12, random_state=42, n_jobs=-1, class_weight="balanced",
        )
        self._type_model.fit(features, type_encoded)
        type_cv = cross_val_score(self._type_model, features, type_encoded, cv=min(5, features.shape[0])).mean()

        self._is_fitted = True
        self._save_models()

        return {
            "status": "trained",
            "samples": int(features.shape[0]),
            "severity_cv_accuracy": round(float(sev_cv), 4),
            "type_cv_accuracy": round(float(type_cv), 4),
            "trained_at": datetime.utcnow().isoformat(),
        }

    def predict(self, features: np.ndarray) -> Dict[str, Any]:
        """Predict severity and type for a single event."""
        if not self._is_fitted:
            return {"status": "model_not_trained"}

        if features.ndim == 1:
            features = features.reshape(1, -1)

        sev_pred = self._severity_model.predict(features)[0]
        sev_proba = self._severity_model.predict_proba(features)[0]
        type_pred = self._type_model.predict(features)[0]
        type_proba = self._type_model.predict_proba(features)[0]

        return {
            "predicted_severity": SEVERITY_LABELS[sev_pred],
            "severity_confidence": round(float(sev_proba.max()), 4),
            "severity_probabilities": {SEVERITY_LABELS[i]: round(float(p), 4) for i, p in enumerate(sev_proba)},
            "predicted_type": TYPE_LABELS[type_pred],
            "type_confidence": round(float(type_proba.max()), 4),
        }

    @property
    def is_fitted(self) -> bool:
        return self._is_fitted

    def health(self) -> Dict:
        return {"is_fitted": self._is_fitted}
