"""
Predictor module for DDoS threat classification.

Loads the trained CICIDS2017 model artifact and scores live threat
dictionaries against the full CICIDS feature set.
"""

from functools import lru_cache
from pathlib import Path

import joblib
import numpy as np

MODEL_PATH = Path(__file__).parent / "model.pkl"

# Fallback feature list (mirrors trainer.py) used when the artifact
# pre-dates the feature_names key.
_DEFAULT_FEATURE_COLUMNS = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Fwd PSH Flags",
]


class Protocol:
    """Application-level protocol constants."""
    TCP = 0
    UDP = 1
    ICMP = 2
    HTTP = 3
    HTTPS = 4
    DNS = 5


@lru_cache(maxsize=1)
def get_artifact() -> dict:
    """
    Load model.pkl and return a normalised artifact dict.

    The result is cached after the first call so subsequent predictions
    pay no I/O cost.  Legacy models (bare sklearn estimators) are wrapped
    automatically.

    Raises:
        FileNotFoundError: If model.pkl has not been generated yet.
    """
    if not MODEL_PATH.exists():
        raise FileNotFoundError(
            f"Model file not found at {MODEL_PATH}. "
            "Run backend/ml/trainer.py first to train the model."
        )

    raw = joblib.load(MODEL_PATH, mmap_mode='r')

    if not isinstance(raw, dict):
        # Legacy artifact: bare RandomForestClassifier
        return {
            "model": raw,
            "scaler": None,
            "feature_names": _DEFAULT_FEATURE_COLUMNS,
            "roc_auc": None,
        }

    return raw


def score_threat(threat: dict) -> float:
    """
    Score a threat dictionary and return a severity value between 0 and 10.

    Maps ``packet_rate`` and ``protocol_id`` to the CICIDS2017 feature vector,
    runs inference through the trained model, then applies a packet-rate bonus
    to produce an interpretable severity score.

    Args:
        threat: Dict containing at least ``packet_rate`` (int) and
                ``protocol_id`` (int, using the ``Protocol`` constants).

    Returns:
        Severity score in [0.0, 10.0], rounded to two decimal places.
    """
    packet_rate: int = int(threat.get("packet_rate", 0))
    protocol_id: int = int(threat.get("protocol_id", 0))

    # TCP-based protocols: TCP=0, HTTP=3, HTTPS=4
    is_tcp = protocol_id in (0, 3, 4)

    # Derive plausible CICIDS feature values from the available signal.
    # Assumes a 1-second observation window and a symmetric bidirectional flow.
    safe_rate = max(packet_rate, 1)
    fwd_pkts = max(packet_rate // 2, 1)

    feature_map: dict[str, float] = {
        "Flow Duration":                1_000_000.0,           # 1 s in microseconds
        "Total Fwd Packets":            float(fwd_pkts),
        "Total Backward Packets":       float(fwd_pkts),
        "Total Length of Fwd Packets":  float(fwd_pkts * 64),  # 64-byte average payload
        "Flow Bytes/s":                 float(packet_rate * 64),
        "Flow Packets/s":               float(packet_rate),
        "Flow IAT Mean":                1_000_000.0 / safe_rate,
        "Fwd PSH Flags":                1.0 if is_tcp else 0.0,
    }

    artifact = get_artifact()
    feature_names: list[str] = artifact.get("feature_names", _DEFAULT_FEATURE_COLUMNS)
    X = np.array([[feature_map[f] for f in feature_names]], dtype=np.float32)

    scaler = artifact.get("scaler")
    if scaler is not None:
        X = scaler.transform(X)

    probability: float = float(artifact["model"].predict_proba(X)[0, 1])

    # Packet-rate bonus: high-volume floods warrant extra severity
    if packet_rate > 100_000:
        rate_bonus = min(2.0, (packet_rate - 100_000) / 200_000 * 2)
    elif packet_rate > 50_000:
        rate_bonus = 1.0
    elif packet_rate > 20_000:
        rate_bonus = 0.5
    else:
        rate_bonus = 0.0

    severity = min(10.0, probability * 8.0 + rate_bonus)
    return round(severity, 2)


def init() -> None:
    """Pre-warm the model cache.  Safe to call at application startup."""
    try:
        get_artifact()
        print(f"ML model loaded successfully from {MODEL_PATH}")
    except FileNotFoundError as e:
        print(f"Warning: {e}")


if __name__ == "__main__":
    init()

    test_cases = [
        (100,    Protocol.HTTPS, "Low HTTPS traffic"),
        (50,     Protocol.TCP,   "Low TCP traffic"),
        (25_000, Protocol.UDP,   "High UDP traffic"),
        (80_000, Protocol.ICMP,  "Very high ICMP traffic"),
        (45_000, Protocol.DNS,   "DNS amplification pattern"),
    ]

    print("\nTest Predictions:")
    print("-" * 60)
    for pkt_rate, proto, description in test_cases:
        severity = score_threat({"packet_rate": pkt_rate, "protocol_id": proto})
        print(f"{description}:")
        print(f"  packet_rate={pkt_rate}, protocol={proto}")
        print(f"  Severity: {severity:.2f} / 10.0")
        print()
