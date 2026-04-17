"""
Unsupervised Anomaly Detection using Isolation Forest.

PhD Contribution: Detects novel attack patterns that rule-based systems miss
by learning the statistical distribution of normal security events and
flagging outliers across both HIDS and NIDS telemetry.
"""
import logging
import os
import pickle
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

logger = logging.getLogger(__name__)


class AnomalyDetector:
    """Isolation Forest-based anomaly detector for security events."""

    def __init__(self, models_path: str = "/models"):
        self._models_path = models_path
        self._contamination = float(os.getenv("ML_ANOMALY_CONTAMINATION", "0.05"))
        self._model = None
        self._scaler = None
        self._is_fitted = False
        self._training_samples = 0
        self._load_model()

    def _load_model(self):
        """Load persisted model if available."""
        model_file = os.path.join(self._models_path, "anomaly_iforest.pkl")
        scaler_file = os.path.join(self._models_path, "anomaly_scaler.pkl")
        try:
            if os.path.exists(model_file) and os.path.exists(scaler_file):
                with open(model_file, "rb") as f:
                    self._model = pickle.load(f)
                with open(scaler_file, "rb") as f:
                    self._scaler = pickle.load(f)
                self._is_fitted = True
                logger.info("anomaly_detector.model_loaded")
        except Exception as e:
            logger.warning("anomaly_detector.load_failed: %s", e)

    def _save_model(self):
        """Persist model to disk."""
        os.makedirs(self._models_path, exist_ok=True)
        try:
            with open(os.path.join(self._models_path, "anomaly_iforest.pkl"), "wb") as f:
                pickle.dump(self._model, f)
            with open(os.path.join(self._models_path, "anomaly_scaler.pkl"), "wb") as f:
                pickle.dump(self._scaler, f)
            logger.info("anomaly_detector.model_saved")
        except Exception as e:
            logger.error("anomaly_detector.save_failed: %s", e)

    def train(self, features: np.ndarray) -> Dict[str, Any]:
        """
        Train the Isolation Forest on a batch of feature vectors.

        Args:
            features: numpy array of shape (n_samples, n_features)

        Returns:
            Training summary dict
        """
        from sklearn.ensemble import IsolationForest
        from sklearn.preprocessing import StandardScaler

        if features.shape[0] < 50:
            return {"status": "insufficient_data", "samples": features.shape[0], "min_required": 50}

        self._scaler = StandardScaler()
        X_scaled = self._scaler.fit_transform(features)

        self._model = IsolationForest(
            n_estimators=200,
            max_samples="auto",
            contamination=self._contamination,
            random_state=42,
            n_jobs=-1,
        )
        self._model.fit(X_scaled)
        self._is_fitted = True
        self._training_samples = features.shape[0]

        # Get training anomaly scores
        scores = self._model.decision_function(X_scaled)
        predictions = self._model.predict(X_scaled)
        n_anomalies = int((predictions == -1).sum())

        self._save_model()

        return {
            "status": "trained",
            "samples": int(features.shape[0]),
            "features": int(features.shape[1]),
            "anomalies_in_training": n_anomalies,
            "anomaly_rate": round(n_anomalies / features.shape[0], 4),
            "mean_score": round(float(scores.mean()), 4),
            "trained_at": datetime.utcnow().isoformat(),
        }

    def predict(self, features: np.ndarray) -> List[Dict[str, Any]]:
        """
        Predict anomaly scores for new events.

        Args:
            features: numpy array of shape (n_samples, n_features) or (n_features,)

        Returns:
            List of dicts with is_anomaly, anomaly_score, confidence
        """
        if not self._is_fitted:
            return [{"is_anomaly": False, "anomaly_score": 0.0, "confidence": 0.0, "status": "model_not_trained"}]

        if features.ndim == 1:
            features = features.reshape(1, -1)

        X_scaled = self._scaler.transform(features)
        predictions = self._model.predict(X_scaled)
        scores = self._model.decision_function(X_scaled)

        results = []
        for pred, score in zip(predictions, scores):
            # Convert score to 0-1 confidence (more negative = more anomalous)
            confidence = max(0.0, min(1.0, (0.5 - score) / 1.0))
            results.append({
                "is_anomaly": bool(pred == -1),
                "anomaly_score": round(float(score), 4),
                "confidence": round(confidence, 4),
            })
        return results

    @property
    def is_fitted(self) -> bool:
        return self._is_fitted

    def health(self) -> Dict:
        return {
            "is_fitted": self._is_fitted,
            "training_samples": self._training_samples,
            "contamination": self._contamination,
        }
