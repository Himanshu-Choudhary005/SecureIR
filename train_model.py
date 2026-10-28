
from pathlib import Path

import joblib
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
)
from sklearn.model_selection import LeaveOneOut, cross_val_predict
from sklearn.pipeline import make_pipeline


BASE_DIR = Path(__file__).resolve().parent
DATASET_PATH = BASE_DIR / "dataset" / "features.csv"
MODEL_PATH = BASE_DIR / "secureir_model.joblib"


def main():
    print("=" * 55)
    print("          SecureIR ML Classifier")
    print("=" * 55)

    # 1. Check that the dataset exists.
    if not DATASET_PATH.exists():
        raise FileNotFoundError(
            f"Dataset not found: {DATASET_PATH}"
        )

    df = pd.read_csv(DATASET_PATH)

    # 2. Validate required columns.
    required_columns = {"program", "label"}
    missing_columns = required_columns - set(df.columns)

    if missing_columns:
        raise ValueError(
            f"Missing required columns: {sorted(missing_columns)}"
        )

    if df.empty:
        raise ValueError("Dataset is empty.")

    if df["label"].isna().any():
        raise ValueError("Dataset contains missing labels.")

    if df["program"].isna().any():
        raise ValueError("Dataset contains missing program names.")

    if df["program"].duplicated().any():
        duplicates = df.loc[
            df["program"].duplicated(keep=False),
            "program",
        ].tolist()

        raise ValueError(
            f"Duplicate program names detected: {duplicates}"
        )

    # 3. Separate features and labels.
    feature_columns = [
        column
        for column in df.columns
        if column not in {"program", "label"}
    ]

    if not feature_columns:
        raise ValueError("No feature columns found.")

    X = df[feature_columns].apply(
        pd.to_numeric,
        errors="coerce",
    )

    if X.isna().all(axis=1).any():
        bad_rows = df.loc[
            X.isna().all(axis=1),
            "program",
        ].tolist()

        raise ValueError(
            "Some programs have no usable numeric features: "
            + ", ".join(bad_rows)
        )

    y = df["label"].astype(str).str.strip().str.upper()

    if y.eq("").any():
        raise ValueError("Dataset contains empty labels.")

    if y.nunique() < 2:
        raise ValueError(
            "At least two different classes are required."
        )

    # 4. Display dataset information.
    print(f"\nDataset: {DATASET_PATH}")
    print(f"Number of programs: {len(df)}")
    print(f"Number of features: {len(feature_columns)}")

    print("\nClass distribution:")
    print(y.value_counts().sort_index().to_string())

    print("\nFeature columns:")
    print(", ".join(feature_columns))

    print(
        "\nWARNING: A small dataset cannot establish "
        "real-world security detection performance."
    )

    # 5. Create the model pipeline.
    def create_model():
        return make_pipeline(
            SimpleImputer(strategy="median"),
            RandomForestClassifier(
                n_estimators=200,
                random_state=42,
                class_weight="balanced",
            ),
        )

    # 6. Leave-One-Out cross-validation.
    cv = LeaveOneOut()

    predictions = cross_val_predict(
        create_model(),
        X,
        y,
        cv=cv,
    )

    accuracy = accuracy_score(y, predictions)

    macro_f1 = f1_score(
        y,
        predictions,
        average="macro",
        zero_division=0,
    )

    print("\n" + "=" * 55)
    print("        LEAVE-ONE-OUT EVALUATION")
    print("=" * 55)

    print(f"\nAccuracy : {accuracy:.3f}")
    print(f"Macro F1 : {macro_f1:.3f}")

    print("\nClassification Report:")
    print(
        classification_report(
            y,
            predictions,
            labels=sorted(y.unique()),
            zero_division=0,
        )
    )

    labels = sorted(y.unique())

    cm = confusion_matrix(
        y,
        predictions,
        labels=labels,
    )

    cm_df = pd.DataFrame(
        cm,
        index=[f"Actual {label}" for label in labels],
        columns=[f"Predicted {label}" for label in labels],
    )

    print("Confusion Matrix:")
    print(cm_df.to_string())

    # 7. Save cross-validation predictions for inspection.
    evaluation_df = pd.DataFrame({
        "program": df["program"],
        "actual_label": y,
        "predicted_label": predictions,
        "correct": y.to_numpy() == predictions,
    })

    evaluation_path = (
        BASE_DIR / "dataset" / "evaluation_predictions.csv"
    )

    evaluation_df.to_csv(
        evaluation_path,
        index=False,
    )

    print(f"\nEvaluation predictions saved to:")
    print(evaluation_path)

    # 8. Train the final demonstration model on all samples.
    final_model = create_model()
    final_model.fit(X, y)

    joblib.dump(final_model, MODEL_PATH)

    print(f"\nFinal model saved to:")
    print(MODEL_PATH)

    print("\nTraining completed.")
    print(
        "NOTE: Cross-validation results are more informative "
        "than training-set accuracy, but this tiny dataset "
        "is insufficient to establish real-world reliability."
    )


if __name__ == "__main__":
    main()

