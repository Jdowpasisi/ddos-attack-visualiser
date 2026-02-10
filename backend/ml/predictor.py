"""
Predictor module for DDoS threat classification.

Loads a trained model and provides prediction functionality
for classifying network traffic as normal or DDoS.
"""
from pathlib import Path
from typing import Optional

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier

# Model path
MODEL_DIR = Path(__file__).parent
MODEL_PATH = MODEL_DIR / "model.pkl"

# Global model instance (loaded on module import)
_model: Optional[RandomForestClassifier] = None


def load_model(path: Path = MODEL_PATH) -> RandomForestClassifier:
    """
    Load the trained model from disk.
    
    Args:
        path: Path to the saved model file.
    
    Returns:
        Loaded RandomForestClassifier model.
    
    Raises:
        FileNotFoundError: If the model file doesn't exist.
    """
    if not path.exists():
        raise FileNotFoundError(
            f"Model file not found at {path}. "
            "Please run trainer.py first to train and save the model."
        )
    
    return joblib.load(path)


def get_model() -> RandomForestClassifier:
    """
    Get the loaded model instance (singleton pattern).
    
    Returns:
        The loaded RandomForestClassifier model.
    """
    global _model
    if _model is None:
        _model = load_model()
    return _model


def predict_threat(packet_rate: int, protocol_id: int) -> float:
    """
    Predict the threat probability for given traffic characteristics.
    
    Args:
        packet_rate: Number of packets per second.
        protocol_id: Protocol identifier (0=TCP, 1=UDP, 2=ICMP, 3=HTTP, 4=HTTPS, 5=DNS).
    
    Returns:
        Probability score between 0 and 1, where:
        - 0.0 = definitely normal traffic
        - 1.0 = definitely DDoS attack
    
    Example:
        >>> predict_threat(packet_rate=50000, protocol_id=1)  # High UDP traffic
        0.95
        >>> predict_threat(packet_rate=100, protocol_id=4)    # Low HTTPS traffic
        0.02
    """
    model = get_model()
    
    # Prepare features as 2D array
    features = np.array([[packet_rate, protocol_id]])
    
    # Get probability of DDoS class (class 1)
    probabilities = model.predict_proba(features)
    ddos_probability = probabilities[0, 1]
    
    return float(ddos_probability)


def predict_threat_batch(
    packet_rates: list[int],
    protocol_ids: list[int]
) -> list[float]:
    """
    Predict threat probabilities for multiple traffic samples.
    
    Args:
        packet_rates: List of packet rates.
        protocol_ids: List of protocol identifiers.
    
    Returns:
        List of probability scores between 0 and 1.
    """
    model = get_model()
    
    features = np.column_stack([packet_rates, protocol_ids])
    probabilities = model.predict_proba(features)
    
    return probabilities[:, 1].tolist()


def classify_threat(packet_rate: int, protocol_id: int, threshold: float = 0.5) -> str:
    """
    Classify traffic as 'normal' or 'ddos' based on threshold.
    
    Args:
        packet_rate: Number of packets per second.
        protocol_id: Protocol identifier.
        threshold: Classification threshold (default 0.5).
    
    Returns:
        'normal' or 'ddos' classification string.
    """
    probability = predict_threat(packet_rate, protocol_id)
    return "ddos" if probability >= threshold else "normal"


# Protocol constants for convenience
class Protocol:
    TCP = 0
    UDP = 1
    ICMP = 2
    HTTP = 3
    HTTPS = 4
    DNS = 5


# Load model on module import for fast predictions
def init():
    """Initialize the predictor by loading the model."""
    try:
        get_model()
        print(f"ML model loaded successfully from {MODEL_PATH}")
    except FileNotFoundError as e:
        print(f"Warning: {e}")


# Example usage
if __name__ == "__main__":
    init()
    
    # Test predictions
    test_cases = [
        (100, Protocol.HTTPS, "Low HTTPS traffic"),
        (50, Protocol.TCP, "Low TCP traffic"),
        (25000, Protocol.UDP, "High UDP traffic"),
        (80000, Protocol.ICMP, "Very high ICMP traffic"),
        (45000, Protocol.DNS, "DNS amplification pattern"),
    ]
    
    print("\nTest Predictions:")
    print("-" * 60)
    for packet_rate, protocol_id, description in test_cases:
        prob = predict_threat(packet_rate, protocol_id)
        classification = classify_threat(packet_rate, protocol_id)
        print(f"{description}:")
        print(f"  packet_rate={packet_rate}, protocol={protocol_id}")
        print(f"  Threat probability: {prob:.4f} ({classification})")
        print()
