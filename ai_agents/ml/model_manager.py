"""
Model Manager — orchestrates ML model training and inference.

Provides a unified interface for the REST API to:
  - Trigger training from historical data
  - Run inference on new events
  - Check model health
"""
import logging
from typing import Any, Dict, List

import numpy as np

from ai_agents.ml.anomaly_detector import AnomalyDetector
from ai_agents.ml.alert_classifier import AlertClassifierML
from ai_agents.ml.feature_extractor import FeatureExtractor
from ai_agents.database.db_manager import get_db
from ai_agents.database.models import Incident

logger = logging.getLogger(__name__)


class ModelManager:
    """Unified ML model management."""

    def __init__(self, models_path: str = "/models"):
        self.feature_extractor = FeatureExtractor()
        self.anomaly_detector = AnomalyDetector(models_path)
        self.alert_classifier = AlertClassifierML(models_path)

    def train_from_db(self) -> Dict[str, Any]:
        """Train all models from historical incident data."""
        try:
            with get_db() as db:
                incidents = db.query(Incident).all()

            if not incidents:
                return {"status": "no_data", "message": "No incidents in database to train on."}

            features_list = []
            severity_labels = []
            type_labels = []

            for inc in incidents:
                alert_data = inc.alert_data or {}
                try:
                    feat = self.feature_extractor.extract_wazuh_features(alert_data)
                    features_list.append(feat)
                    severity_labels.append(inc.severity or "medium")
                    # Derive type from playbook or default
                    atype = "other"
                    if inc.playbook_executed:
                        if "brute" in inc.playbook_executed:
                            atype = "brute_force"
                        elif "malware" in inc.playbook_executed:
                            atype = "malware"
                        elif "lateral" in inc.playbook_executed:
                            atype = "lateral_movement"
                    type_labels.append(atype)
                except Exception as e:
                    logger.debug("feature_extraction_failed for incident %s: %s", inc.id, e)

            if not features_list:
                return {"status": "no_extractable_features"}

            X = np.array(features_list)

            # Train anomaly detector (unsupervised)
            anomaly_result = self.anomaly_detector.train(X)

            # Train classifier (supervised)
            classifier_result = self.alert_classifier.train(X, severity_labels, type_labels)

            return {
                "status": "success",
                "total_incidents": len(incidents),
                "usable_samples": len(features_list),
                "anomaly_detector": anomaly_result,
                "alert_classifier": classifier_result,
            }
        except Exception as e:
            logger.error("model_manager.train_failed: %s", e)
            return {"status": "error", "error": str(e)}

    def predict_alert(self, alert: Dict) -> Dict[str, Any]:
        """Run both models on a single alert."""
        features = self.feature_extractor.extract_wazuh_features(alert)

        anomaly = self.anomaly_detector.predict(features)
        classification = self.alert_classifier.predict(features)

        return {
            "anomaly_detection": anomaly[0] if anomaly else {},
            "ml_classification": classification,
        }

    def health(self) -> Dict:
        return {
            "anomaly_detector": self.anomaly_detector.health(),
            "alert_classifier": self.alert_classifier.health(),
        }
