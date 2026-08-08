

from pathlib import Path
import joblib
import numpy as np

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    precision_score,
    recall_score,
    f1_score,
)

from image_features import extract_features, features_to_vector, FEATURE_NAMES


# ============================================================
# CONFIG
# ============================================================

BASE_DIR = Path(__file__).resolve().parent
DATASET_DIR = BASE_DIR / "dataset"

TRAIN_DIR = DATASET_DIR / "train"
VALIDATION_DIR = DATASET_DIR / "validation"
TEST_DIR = DATASET_DIR / "test"

MODEL_PATH = BASE_DIR / "image_authenticity_model.pkl"

IMAGE_EXTENSIONS = {
    ".jpg",
    ".jpeg",
    ".png",
    ".webp",
    ".bmp",
    ".tif",
    ".tiff",
}


# ============================================================
# FIND IMAGES
# ============================================================

def get_images(folder):
    if not folder.exists():
        return []

    return sorted(
        [
            p
            for p in folder.rglob("*")
            if p.is_file()
            and p.suffix.lower() in IMAGE_EXTENSIONS
        ]
    )


# ============================================================
# EXTRACT FEATURES
# ============================================================

def load_dataset(dataset_dir, dataset_name):

    authentic_dir = dataset_dir / "authentic"
    manipulated_dir = dataset_dir / "manipulated"

    authentic_images = get_images(authentic_dir)
    manipulated_images = get_images(manipulated_dir)

    print()
    print(f"========== {dataset_name.upper()} ==========")
    print(f"Authentic images:   {len(authentic_images)}")
    print(f"Manipulated images: {len(manipulated_images)}")

    if not authentic_images:
        raise RuntimeError(
            f"No authentic images found in:\n{authentic_dir}"
        )

    if not manipulated_images:
        raise RuntimeError(
            f"No manipulated images found in:\n{manipulated_dir}"
        )

    X = []
    y = []

    # --------------------------------------------------------
    # Authentic = 0
    # --------------------------------------------------------

    for index, image_path in enumerate(authentic_images, 1):

        try:

            image_bytes = image_path.read_bytes()

            features = extract_features(image_bytes)

            vector = features_to_vector(features)

            X.append(vector)
            y.append(0)

            print(
                f"[AUTHENTIC] "
                f"{index}/{len(authentic_images)} "
                f"{image_path.name}"
            )

        except Exception as exc:

            print(
                f"[WARNING] Failed authentic image "
                f"{image_path.name}: {exc}"
            )

    # --------------------------------------------------------
    # Manipulated = 1
    # --------------------------------------------------------

    for index, image_path in enumerate(manipulated_images, 1):

        try:

            image_bytes = image_path.read_bytes()

            features = extract_features(image_bytes)

            vector = features_to_vector(features)

            X.append(vector)
            y.append(1)

            print(
                f"[MANIPULATED] "
                f"{index}/{len(manipulated_images)} "
                f"{image_path.name}"
            )

        except Exception as exc:

            print(
                f"[WARNING] Failed manipulated image "
                f"{image_path.name}: {exc}"
            )

    if not X:
        raise RuntimeError(
            f"No usable images were found in {dataset_name}."
        )

    X = np.asarray(X, dtype=np.float32)
    y = np.asarray(y, dtype=np.int32)

    return X, y


# ============================================================
# METRICS
# ============================================================

def evaluate_model(model, X, y, name):

    predictions = model.predict(X)

    accuracy = accuracy_score(y, predictions)
    precision = precision_score(
        y,
        predictions,
        zero_division=0,
    )
    recall = recall_score(
        y,
        predictions,
        zero_division=0,
    )
    f1 = f1_score(
        y,
        predictions,
        zero_division=0,
    )

    print()
    print("==============================================")
    print(f"{name.upper()} RESULTS")
    print("==============================================")

    print(f"Accuracy : {accuracy * 100:.2f}%")
    print(f"Precision: {precision * 100:.2f}%")
    print(f"Recall   : {recall * 100:.2f}%")
    print(f"F1 Score : {f1 * 100:.2f}%")

    print()
    print("Confusion Matrix:")
    print(
        confusion_matrix(
            y,
            predictions,
        )
    )

    print()
    print("Classification Report:")
    print(
        classification_report(
            y,
            predictions,
            target_names=[
                "Authentic",
                "Manipulated",
            ],
            zero_division=0,
        )
    )

    return {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
    }


# ============================================================
# MAIN TRAINING
# ============================================================

def main():

    print()
    print("==============================================")
    print("       CYBERGUARD AI IMAGE MODEL")
    print("==============================================")
    print()

    # --------------------------------------------------------
    # Check directories
    # --------------------------------------------------------

    required_dirs = [
        TRAIN_DIR,
        VALIDATION_DIR,
        TEST_DIR,
    ]

    for directory in required_dirs:

        if not directory.exists():

            raise FileNotFoundError(
                f"Dataset directory not found:\n{directory}"
            )

    # --------------------------------------------------------
    # Load datasets
    # --------------------------------------------------------

    X_train, y_train = load_dataset(
        TRAIN_DIR,
        "Training",
    )

    X_validation, y_validation = load_dataset(
        VALIDATION_DIR,
        "Validation",
    )

    X_test, y_test = load_dataset(
        TEST_DIR,
        "Test",
    )

    # --------------------------------------------------------
    # Feature validation
    # --------------------------------------------------------

    expected_features = len(FEATURE_NAMES)

    print()
    print("==============================================")
    print("FEATURE INFORMATION")
    print("==============================================")

    print(
        f"Expected features: {expected_features}"
    )

    print(
        f"Training vector size: {X_train.shape[1]}"
    )

    print(
        f"Validation vector size: {X_validation.shape[1]}"
    )

    print(
        f"Test vector size: {X_test.shape[1]}"
    )

    if X_train.shape[1] != expected_features:
        raise RuntimeError(
            "Training feature count does not match "
            "FEATURE_NAMES."
        )

    if X_validation.shape[1] != expected_features:
        raise RuntimeError(
            "Validation feature count does not match "
            "FEATURE_NAMES."
        )

    if X_test.shape[1] != expected_features:
        raise RuntimeError(
            "Test feature count does not match "
            "FEATURE_NAMES."
        )

    # --------------------------------------------------------
    # Train Random Forest
    # --------------------------------------------------------

    print()
    print("==============================================")
    print("TRAINING RANDOM FOREST")
    print("==============================================")
    print()

    model = RandomForestClassifier(
        n_estimators=400,
        max_features="sqrt",
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )

    model.fit(
        X_train,
        y_train,
    )

    print()
    print("Training complete.")

    # --------------------------------------------------------
    # Validation
    # --------------------------------------------------------

    validation_metrics = evaluate_model(
        model,
        X_validation,
        y_validation,
        "Validation",
    )

    # --------------------------------------------------------
    # Final test
    # --------------------------------------------------------

    test_metrics = evaluate_model(
        model,
        X_test,
        y_test,
        "FINAL TEST",
    )

    # --------------------------------------------------------
    # Feature importance
    # --------------------------------------------------------

    print()
    print("==============================================")
    print("TOP FORENSIC FEATURES")
    print("==============================================")

    importances = model.feature_importances_

    ranked_features = sorted(
        zip(FEATURE_NAMES, importances),
        key=lambda item: item[1],
        reverse=True,
    )

    for name, importance in ranked_features[:15]:

        print(
            f"{name:<35} "
            f"{importance:.6f}"
        )

    # --------------------------------------------------------
    # Save model package
    # --------------------------------------------------------

    model_package = {
        "model": model,

        "feature_names": list(FEATURE_NAMES),

        "classes": {
            0: "authentic",
            1: "manipulated",
        },

        "validation_metrics": validation_metrics,

        "test_metrics": test_metrics,

        "model_type": "RandomForestClassifier",

        "version": "1.0",

    }

    joblib.dump(
        model_package,
        MODEL_PATH,
    )

    print()
    print("==============================================")
    print("MODEL SAVED")
    print("==============================================")
    print()
    print(
        f"Model file:\n{MODEL_PATH}"
    )
    print()

    print(
        "CyberGuard image model training completed."
    )


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()

