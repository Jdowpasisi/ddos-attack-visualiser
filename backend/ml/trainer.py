import gc
import numpy as np
import pandas as pd
import joblib
from pathlib import Path

from imblearn.over_sampling import SMOTE
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

DATA_DIR = Path(__file__).parent / "data"

# Maximum rows kept per class before SMOTE.  Caps memory use while keeping
# the dataset large enough to be representative.
MAX_SAMPLES_PER_CLASS = 200_000

FEATURE_COLUMNS = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Fwd PSH Flags",
]

DDOS_LABELS = {
    "DDoS",
    "DoS Hulk",
    "DoS GoldenEye",
    "DoS slowloris",
    "DoS Slowhttptest",
    "PortScan",
    "Bot",
}


def load_cicids2017() -> pd.DataFrame:
    csv_files = list(DATA_DIR.glob("*.csv"))
    if not csv_files:
        raise FileNotFoundError(f"No CSV files found in {DATA_DIR}")

    frames = []
    for path in csv_files:
        # Build a case-insensitive, whitespace-stripped map: lower_stripped -> raw
        raw_cols = pd.read_csv(path, nrows=0).columns.tolist()
        ci_map = {c.strip().lower(): c for c in raw_cols}

        label_raw = ci_map.get("label")
        if label_raw is None:
            raise KeyError(f"No 'Label' column found in {path.name}")

        missing = [f for f in FEATURE_COLUMNS if f.lower() not in ci_map]
        if missing:
            raise KeyError(f"Missing columns {missing} in {path.name}")

        use_cols = [ci_map[f.lower()] for f in FEATURE_COLUMNS] + [label_raw]

        df = pd.read_csv(path, usecols=use_cols, low_memory=False)

        # Normalise to canonical names regardless of original casing/spacing
        rename = {ci_map[f.lower()].strip(): f for f in FEATURE_COLUMNS}
        rename[label_raw.strip()] = "Label"
        df.columns = df.columns.str.strip()
        df.rename(columns=rename, inplace=True)

        frames.append(df)
        print(f"  Loaded {path.name}: {len(df):,} rows")

    combined = pd.concat(frames, ignore_index=True)
    del frames
    gc.collect()
    return combined


def prepare_features(df: pd.DataFrame) -> tuple[np.ndarray, np.ndarray]:
    label_col = next(
        (c for c in df.columns if c.strip().lower() == "label"),
        None,
    )
    if label_col is None:
        raise KeyError("No 'Label' column found in dataset")

    y = df[label_col].str.strip().isin(DDOS_LABELS).astype(np.int8).values

    missing = [c for c in FEATURE_COLUMNS if c not in df.columns]
    if missing:
        raise KeyError(f"Missing feature columns: {missing}")

    X = df[FEATURE_COLUMNS].copy()
    X.replace([np.inf, -np.inf], np.nan, inplace=True)
    valid = X.notna().all(axis=1)
    X = X[valid]
    y = y[valid.values]

    return X.values.astype(np.float32), y


def _cap_classes(X: np.ndarray, y: np.ndarray, max_per_class: int) -> tuple[np.ndarray, np.ndarray]:
    """Randomly downsample each class to at most *max_per_class* rows."""
    rng = np.random.default_rng(42)
    keep = []
    for cls in np.unique(y):
        idx = np.where(y == cls)[0]
        if len(idx) > max_per_class:
            idx = rng.choice(idx, size=max_per_class, replace=False)
        keep.append(idx)
    idx_all = np.concatenate(keep)
    rng.shuffle(idx_all)
    return X[idx_all], y[idx_all]


def main() -> None:
    print("Loading CICIDS2017 data …")
    df = load_cicids2017()
    print(f"  Total rows loaded: {len(df):,}")

    X, y = prepare_features(df)
    del df
    gc.collect()
    print(f"  Samples after cleaning: {len(X):,}  |  Attack ratio: {y.mean():.2%}")

    # Cap each class before the train/test split to avoid SMOTE OOM
    X, y = _cap_classes(X, y, MAX_SAMPLES_PER_CLASS)
    print(f"  After class cap: {len(X):,} samples")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    del X, y
    gc.collect()

    print("Applying SMOTE to balance training set …")
    smote = SMOTE(random_state=42, k_neighbors=3)
    X_train_res, y_train_res = smote.fit_resample(X_train, y_train)
    del X_train, y_train
    gc.collect()
    print(f"  Resampled training size: {len(X_train_res):,}")

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train_res)
    X_test_scaled = scaler.transform(X_test)

    print("Training RandomForestClassifier …")
    model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    model.fit(X_train_scaled, y_train_res)

    y_pred = model.predict(X_test_scaled)
    y_proba = model.predict_proba(X_test_scaled)[:, 1]

    roc_auc = roc_auc_score(y_test, y_proba)

    print("\n--- Evaluation on held-out test set ---")
    print(classification_report(y_test, y_pred, target_names=["Benign", "Attack"]))
    print(f"ROC-AUC: {roc_auc:.4f}")
    print("Confusion matrix:")
    print(confusion_matrix(y_test, y_pred))

    artifact = {
        "model": model,
        "scaler": scaler,
        "feature_names": FEATURE_COLUMNS,
        "roc_auc": roc_auc,
    }
    output_path = Path(__file__).parent / "model.pkl"
    joblib.dump(artifact, output_path)
    print(f"\nModel artifact saved to {output_path}")


if __name__ == "__main__":
    main()
