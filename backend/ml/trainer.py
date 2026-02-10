"""
Training script for DDoS attack classification model.

Generates synthetic traffic data and trains a RandomForestClassifier
to distinguish between normal traffic and DDoS attacks.

Usage:
    python trainer.py
"""
import os
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.model_selection import train_test_split

# Protocol mapping for reference
PROTOCOLS = {
    0: "TCP",
    1: "UDP", 
    2: "ICMP",
    3: "HTTP",
    4: "HTTPS",
    5: "DNS",
}

# Model output path
MODEL_DIR = Path(__file__).parent
MODEL_PATH = MODEL_DIR / "model.pkl"


def generate_synthetic_data(n_samples: int = 2000, random_state: int = 42) -> tuple:
    """
    Generate synthetic network traffic data.
    
    Args:
        n_samples: Total number of samples to generate.
        random_state: Random seed for reproducibility.
    
    Returns:
        Tuple of (features, labels) where:
        - features: numpy array of shape (n_samples, 2) with [packet_rate, protocol_id]
        - labels: numpy array of shape (n_samples,) with 0=normal, 1=DDoS
    """
    np.random.seed(random_state)
    
    n_normal = n_samples // 2
    n_ddos = n_samples - n_normal
    
    # Normal traffic characteristics:
    # - Low to moderate packet rates (10-500 packets/sec)
    # - Any protocol, but more HTTP/HTTPS (3, 4)
    normal_packet_rates = np.random.exponential(scale=100, size=n_normal)
    normal_packet_rates = np.clip(normal_packet_rates, 10, 500)
    
    # Normal traffic uses more web protocols
    normal_protocols = np.random.choice(
        [0, 1, 2, 3, 4, 5],
        size=n_normal,
        p=[0.15, 0.10, 0.05, 0.35, 0.30, 0.05]
    )
    
    # DDoS attack characteristics:
    # - High packet rates (1000-100000 packets/sec)
    # - Typically UDP (1), ICMP (2), or DNS amplification (5)
    ddos_packet_rates = np.random.exponential(scale=15000, size=n_ddos)
    ddos_packet_rates = np.clip(ddos_packet_rates, 1000, 100000)
    
    # DDoS tends to use UDP, ICMP, DNS for amplification attacks
    ddos_protocols = np.random.choice(
        [0, 1, 2, 3, 4, 5],
        size=n_ddos,
        p=[0.10, 0.35, 0.25, 0.05, 0.05, 0.20]
    )
    
    # Combine features
    normal_features = np.column_stack([normal_packet_rates, normal_protocols])
    ddos_features = np.column_stack([ddos_packet_rates, ddos_protocols])
    
    features = np.vstack([normal_features, ddos_features])
    
    # Labels: 0 = normal, 1 = DDoS
    labels = np.array([0] * n_normal + [1] * n_ddos)
    
    # Shuffle the data
    shuffle_idx = np.random.permutation(len(labels))
    features = features[shuffle_idx]
    labels = labels[shuffle_idx]
    
    return features, labels


def train_model(features: np.ndarray, labels: np.ndarray) -> RandomForestClassifier:
    """
    Train a RandomForestClassifier on the provided data.
    
    Args:
        features: Feature matrix of shape (n_samples, 2).
        labels: Label array of shape (n_samples,).
    
    Returns:
        Trained RandomForestClassifier model.
    """
    # Split data for training and validation
    X_train, X_test, y_train, y_test = train_test_split(
        features, labels, test_size=0.2, random_state=42, stratify=labels
    )
    
    # Initialize and train the model
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        min_samples_split=5,
        min_samples_leaf=2,
        random_state=42,
        n_jobs=-1,
    )
    
    print("Training RandomForestClassifier...")
    model.fit(X_train, y_train)
    
    # Evaluate on test set
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    
    print(f"\nModel Accuracy: {accuracy:.4f}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=["Normal", "DDoS"]))
    
    print("Confusion Matrix:")
    print(confusion_matrix(y_test, y_pred))
    
    # Feature importance
    print("\nFeature Importance:")
    print(f"  packet_rate: {model.feature_importances_[0]:.4f}")
    print(f"  protocol_id: {model.feature_importances_[1]:.4f}")
    
    return model


def save_model(model: RandomForestClassifier, path: Path = MODEL_PATH) -> None:
    """
    Save the trained model to disk using joblib.
    
    Args:
        model: Trained model to save.
        path: File path for the saved model.
    """
    joblib.dump(model, path)
    print(f"\nModel saved to: {path}")


def main():
    """Main training pipeline."""
    print("=" * 60)
    print("DDoS Attack Classification Model Training")
    print("=" * 60)
    
    # Generate synthetic data
    print("\nGenerating synthetic traffic data (2000 samples)...")
    features, labels = generate_synthetic_data(n_samples=2000)
    
    print(f"  Total samples: {len(labels)}")
    print(f"  Normal traffic: {np.sum(labels == 0)}")
    print(f"  DDoS attacks: {np.sum(labels == 1)}")
    print(f"  Feature shape: {features.shape}")
    
    # Train the model
    model = train_model(features, labels)
    
    # Save the model
    save_model(model)
    
    print("\n" + "=" * 60)
    print("Training complete!")
    print("=" * 60)


if __name__ == "__main__":
    main()
