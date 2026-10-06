import json
import os

MODEL_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(MODEL_DIR, "isolation_forest.joblib")
FEATURES_PATH = os.path.join(MODEL_DIR, "features.joblib")
BASELINE_PATH = os.path.join(MODEL_DIR, "baseline.json")

_model = None
_feature_cols = None
_fallback_detector = None
_baseline = None

try:
    import joblib
    import pandas as pd
    _ML_LIBS_AVAILABLE = True
except (ImportError, Exception):
    joblib = None
    pd = None
    _ML_LIBS_AVAILABLE = False


def load_model():
    global _model, _feature_cols
    if not _ML_LIBS_AVAILABLE:
        return False
    if not os.path.exists(MODEL_PATH) or not os.path.exists(FEATURES_PATH):
        return False

    try:
        _model = joblib.load(MODEL_PATH)
        _feature_cols = joblib.load(FEATURES_PATH)
        return True
    except Exception as e:
        print(f"Error loading AI model: {e}")
        return False


def load_baseline():
    global _baseline
    if _baseline is not None:
        return _baseline
    if os.path.exists(BASELINE_PATH):
        try:
            with open(BASELINE_PATH, "r", encoding="utf-8") as f:
                _baseline = json.load(f)
                return _baseline
        except Exception:
            pass
    return None


def extract_features_single(packet_data: dict, feature_cols: list):
    """
    Format a single packet's data into the feature DataFrame expected by the model.
    """
    if not _ML_LIBS_AVAILABLE or pd is None:
        return None

    proto = packet_data.get("protocol", "")

    # Create feature dict
    features = {
        "packet_length": packet_data.get("packet_length", 0),
        "source_port": packet_data.get("source_port") or 0,
        "destination_port": packet_data.get("destination_port") or 0,
        "is_tcp": 1 if proto == "TCP" else 0,
        "is_udp": 1 if proto == "UDP" else 0,
        "is_icmp": 1 if proto == "ICMP" else 0,
    }

    df = pd.DataFrame([features])

    for col in feature_cols:
        if col not in df:
            df[col] = 0

    return df[feature_cols]


def analyze_packet(packet_data: dict) -> bool:
    """
    Analyze a packet using:
    1. Trained Scikit-learn Isolation Forest model (if available)
    2. Learned statistical baseline profile (baseline.json)
    3. Pure-Python Isolation Forest AnomalyDetector (ai_service)
    """
    global _model, _feature_cols, _fallback_detector

    # 1. Try Scikit-learn model if available and loaded
    if _ML_LIBS_AVAILABLE:
        if _model is None or _feature_cols is None:
            load_model()

        if _model is not None and _feature_cols is not None:
            try:
                X = extract_features_single(packet_data, _feature_cols)
                if X is not None:
                    prediction = _model.predict(X)
                    if prediction[0] == -1:
                        return True
            except Exception:
                pass

    # 2. Check statistical baseline thresholds
    baseline = load_baseline()
    if baseline:
        length = float(packet_data.get("packet_length") or 0)
        threshold = baseline.get("anomaly_threshold_length", 1200)
        if length > threshold:
            return True

    # 3. Pure-Python anomaly detector fallback (runs offline, zero extra dependencies)
    try:
        from app.services.ai_service import AnomalyDetector
        if _fallback_detector is None:
            _fallback_detector = AnomalyDetector(sample_size=32)

        scored = _fallback_detector.score([packet_data])
        if scored and scored[0].get("score", 0.0) >= 0.78:
            return True
    except Exception:
        pass

    return False


