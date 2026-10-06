import json
import math
import os
from sqlalchemy.orm import Session
from app.database import SessionLocal
from app.models import Packet

MODEL_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(MODEL_DIR, "isolation_forest.joblib")
FEATURES_PATH = os.path.join(MODEL_DIR, "features.joblib")
BASELINE_PATH = os.path.join(MODEL_DIR, "baseline.json")

# Detect whether Scikit-learn and Pandas C-extensions can be loaded
_SCIKIT_AVAILABLE = False
try:
    import joblib
    import pandas as pd
    from sklearn.ensemble import IsolationForest
    _SCIKIT_AVAILABLE = True
except (ImportError, Exception) as exc:
    _SCIKIT_AVAILABLE = False
    _import_err = exc


def extract_features(df):
    """
    Convert raw packet DataFrame into numerical features suitable for ML.
    """
    if df.empty:
        return df

    df["source_port"] = df["source_port"].fillna(0)
    df["destination_port"] = df["destination_port"].fillna(0)

    df["is_tcp"] = (df["protocol"] == "TCP").astype(int)
    df["is_udp"] = (df["protocol"] == "UDP").astype(int)
    df["is_icmp"] = (df["protocol"] == "ICMP").astype(int)

    features = [
        "packet_length",
        "source_port",
        "destination_port",
        "is_tcp",
        "is_udp",
        "is_icmp",
    ]
    return df[features]


def train_anomaly_detector():
    print("Loading data from database...")
    db: Session = SessionLocal()

    packets = db.query(Packet).all()
    db.close()

    if len(packets) < 50:
        print(f"Not enough data to train. Found {len(packets)} packets, need at least 50.")
        return False

    print(f"Found {len(packets)} packets. Analyzing statistical baseline...")

    lengths = [float(p.packet_length or 0) for p in packets]
    ports = [p.destination_port for p in packets if p.destination_port is not None]
    protocols = [p.protocol for p in packets if p.protocol]

    mean_length = sum(lengths) / len(lengths)
    std_length = math.sqrt(sum((x - mean_length) ** 2 for x in lengths) / len(lengths)) or 1.0

    port_frequencies = {}
    for pt in ports:
        port_frequencies[str(pt)] = port_frequencies.get(str(pt), 0) + 1

    proto_frequencies = {}
    for pr in protocols:
        proto_frequencies[pr] = proto_frequencies.get(pr, 0) + 1

    baseline_data = {
        "sample_count": len(packets),
        "mean_packet_length": round(mean_length, 2),
        "std_packet_length": round(std_length, 2),
        "frequent_ports": sorted(port_frequencies.keys(), key=lambda k: port_frequencies[k], reverse=True)[:25],
        "protocol_distribution": proto_frequencies,
        "anomaly_threshold_length": round(mean_length + 2.5 * std_length, 2),
    }

    with open(BASELINE_PATH, "w", encoding="utf-8") as f:
        json.dump(baseline_data, f, indent=2)
    print(f"Saved statistical baseline to {BASELINE_PATH}")

    if _SCIKIT_AVAILABLE:
        try:
            print("Training Scikit-learn Isolation Forest model...")
            data = [
                {
                    "packet_length": p.packet_length,
                    "source_port": p.source_port,
                    "destination_port": p.destination_port,
                    "protocol": p.protocol,
                }
                for p in packets
            ]
            df = pd.DataFrame(data)
            X = extract_features(df)
            feature_cols = X.columns.tolist()

            model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
            model.fit(X)

            print(f"Saving model to {MODEL_PATH}...")
            joblib.dump(model, MODEL_PATH)
            joblib.dump(feature_cols, FEATURES_PATH)
            print("Scikit-learn Isolation Forest trained and saved successfully!")
            return True
        except Exception as e:
            print(f"Scikit-learn training failed ({e}); pure-Python baseline will be used.")
    else:
        print(f"Scikit-learn / Pandas unavailable ({_import_err}).")
        print("Pure-Python Anomaly Engine initialized with learned baseline!")

    print("Training complete!")
    return True


if __name__ == "__main__":
    train_anomaly_detector()
