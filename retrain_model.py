import os
import json
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split

from app.db import get_db_connection
from model.feature_extraction import extract_features
from model.live_features import FEATURE_COLUMNS


BASE_DIR = Path(__file__).resolve().parent
MODEL_DIR = BASE_DIR / 'model'
ORIGINAL_DATASET_PATH = MODEL_DIR / 'phishing.csv'
MODEL_OUTPUT_PATH = MODEL_DIR / 'phishing_model.pkl'
MODEL_VERSION_GLOB = 'model_v*.pkl'
METRICS_OUTPUT_PATH = MODEL_DIR / 'model_metrics.json'

def _get_next_model_version(model_dir):
    version_numbers = []

    for path in model_dir.glob(MODEL_VERSION_GLOB):
        stem = path.stem
        suffix = stem.replace('model_v', '')
        if suffix.isdigit():
            version_numbers.append(int(suffix))

    return max(version_numbers, default=0) + 1


def _load_original_dataset():
    original_df = pd.read_csv(ORIGINAL_DATASET_PATH)

    if 'url' in original_df.columns:
        urls = original_df['url'].astype(str)
        X = urls.apply(extract_features).apply(pd.Series)
        y = original_df['label'] if 'label' in original_df.columns else original_df['phishing']
        return X.reindex(columns=FEATURE_COLUMNS, fill_value=0), y

    if 'phishing' not in original_df.columns:
        raise ValueError('Original dataset must contain either url+label or phishing feature columns.')

    missing_columns = [column for column in FEATURE_COLUMNS if column not in original_df.columns]
    if missing_columns:
        raise ValueError(f'Original dataset is missing required feature columns: {missing_columns}')

    X = original_df.reindex(columns=FEATURE_COLUMNS, fill_value=0).copy()
    y = original_df['phishing'].copy()
    return X, y


def _load_feedback_dataset(connection):
    feedback_df = pd.read_sql(
        "SELECT url, correct_label FROM feedback WHERE review_status = 'APPROVED'",
        connection,
    )

    if feedback_df.empty:
        return pd.DataFrame(columns=FEATURE_COLUMNS), pd.Series(dtype='int64')

    feedback_df = feedback_df.rename(columns={'correct_label': 'label'})
    feedback_df['label'] = feedback_df['label'].replace({
        'PHISHING': 1,
        'LEGITIMATE': 0,
        'SAFE': 0,
        'SUSPICIOUS': 1,
    })
    feedback_df['label'] = pd.to_numeric(feedback_df['label'], errors='coerce')
    feedback_df = feedback_df.dropna(subset=['label'])
    feedback_df['label'] = feedback_df['label'].astype(int)

    feature_rows = feedback_df['url'].astype(str).apply(extract_features).apply(pd.Series)
    feature_rows = feature_rows.reindex(columns=FEATURE_COLUMNS, fill_value=0)
    labels = feedback_df['label'].reset_index(drop=True)
    return feature_rows, labels


def main():
    # This script is intentionally offline-only.
    # Run it periodically via cron, a scheduler, or a manual admin job.

    # LOAD ORIGINAL DATASET
    original_X, original_y = _load_original_dataset()

    # LOAD FEEDBACK DATA
    connection = get_db_connection()
    try:
        feedback_X, feedback_y = _load_feedback_dataset(connection)
    finally:
        if connection is not None and hasattr(connection, 'close'):
            connection.close()

    # MERGE DATASETS
    combined_X = pd.concat([original_X, feedback_X], ignore_index=True)
    combined_y = pd.concat([pd.Series(original_y).reset_index(drop=True), feedback_y.reset_index(drop=True)], ignore_index=True)

    combined_X = combined_X.reindex(columns=FEATURE_COLUMNS, fill_value=0)
    combined_y = pd.to_numeric(combined_y, errors='coerce').fillna(0).astype(int)

    # Hold out a test split so we can track performance after each retraining.
    X_train, X_test, y_train, y_test = train_test_split(
        combined_X,
        combined_y,
        test_size=0.2,
        random_state=42,
        stratify=combined_y if combined_y.nunique() > 1 else None,
    )

    # TRAIN MODEL
    model = RandomForestClassifier(random_state=42)
    model.fit(X_train, y_train)

    # EVALUATE MODEL
    y_pred = model.predict(X_test)
    precision = precision_score(y_test, y_pred, zero_division=0)
    recall = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)

    tn, fp, fn, tp = confusion_matrix(y_test, y_pred, labels=[0, 1]).ravel()
    false_positive_rate = fp / (fp + tn) if (fp + tn) else 0.0

    metrics = {
        'rows_trained': int(len(combined_X)),
        'train_rows': int(len(X_train)),
        'test_rows': int(len(X_test)),
        'feature_count': int(len(FEATURE_COLUMNS)),
        'precision': round(float(precision), 4),
        'recall': round(float(recall), 4),
        'f1_score': round(float(f1), 4),
        'false_positive_rate': round(float(false_positive_rate), 4),
        'confusion_matrix': {
            'tn': int(tn),
            'fp': int(fp),
            'fn': int(fn),
            'tp': int(tp),
        },
    }

    # SAVE MODEL
    os.makedirs(MODEL_OUTPUT_PATH.parent, exist_ok=True)
    os.makedirs(METRICS_OUTPUT_PATH.parent, exist_ok=True)

    model_version = _get_next_model_version(MODEL_OUTPUT_PATH.parent)
    versioned_model_path = MODEL_OUTPUT_PATH.parent / f'model_v{model_version}.pkl'

    joblib.dump(model, versioned_model_path)
    joblib.dump(model, MODEL_OUTPUT_PATH)

    metrics['model_version'] = model_version
    metrics['versioned_model_path'] = str(versioned_model_path)
    metrics['latest_model_path'] = str(MODEL_OUTPUT_PATH)

    with open(METRICS_OUTPUT_PATH, 'w', encoding='utf-8') as metrics_file:
        json.dump(metrics, metrics_file, indent=2)

    print(f'Trained on {len(combined_X)} rows')
    print(f'Saved versioned model to {versioned_model_path}')
    print(f'Saved model to {MODEL_OUTPUT_PATH}')
    print(f"Precision: {metrics['precision']}")
    print(f"Recall: {metrics['recall']}")
    print(f"F1-score: {metrics['f1_score']}")
    print(f"False positive rate: {metrics['false_positive_rate']}")
    print(f"Model version: {model_version}")
    print(f'Saved metrics to {METRICS_OUTPUT_PATH}')


if __name__ == '__main__':
    main()
