"""
train_model.py
----------------
Loads/generates dataset.csv, extracts the expanded feature set for every
URL, trains a RandomForestClassifier, prints evaluation metrics, and
saves the trained model + feature column order to model.pkl.
"""

import os
import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report,
)

from features import extract_features
from generate_dataset import build_dataset


def load_or_build_dataset(path="dataset.csv"):
    if not os.path.exists(path):
        print("dataset.csv not found — generating synthetic dataset...")
        build_dataset(out_path=path)
    return pd.read_csv(path)


def build_feature_matrix(df: pd.DataFrame) -> pd.DataFrame:
    feature_rows = [extract_features(u) for u in df["url"]]
    return pd.DataFrame(feature_rows)


def main():
    df = load_or_build_dataset()
    print(f"Loaded {len(df)} URLs")

    X = build_feature_matrix(df)
    y = df["label"]
    feature_columns = list(X.columns)
    print(f"Extracted {len(feature_columns)} features per URL")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    model = RandomForestClassifier(
        n_estimators=400,
        max_depth=14,
        min_samples_leaf=2,
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X_train, y_train)

    preds = model.predict(X_test)

    print("\n=== Evaluation on held-out test set ===")
    print(f"Accuracy : {accuracy_score(y_test, preds):.4f}")
    print(f"Precision: {precision_score(y_test, preds):.4f}")
    print(f"Recall   : {recall_score(y_test, preds):.4f}")
    print(f"F1 score : {f1_score(y_test, preds):.4f}")
    print("\nConfusion matrix [ [TN FP] [FN TP] ]:")
    print(confusion_matrix(y_test, preds))
    print("\nClassification report:")
    print(classification_report(y_test, preds, target_names=["Safe", "Phishing"]))

    importances = sorted(
        zip(feature_columns, model.feature_importances_),
        key=lambda x: x[1], reverse=True
    )
    print("\nTop 15 most important features:")
    for name, imp in importances[:15]:
        print(f"  {name:<28s} {imp:.4f}")

    joblib.dump({"model": model, "feature_columns": feature_columns}, "model.pkl")
    print("\nSaved trained model -> model.pkl")


if __name__ == "__main__":
    main()
