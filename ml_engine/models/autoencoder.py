"""
=============================================================
 ThreatHunter Pro — Autoencoder (Network Flow Anomaly Detection)
 models/autoencoder.py

 Architecture:
   Input(15) → Dense(12,relu) → Dense(8,relu) → Dense(4,relu)  [Encoder]
             → Dense(8,relu)  → Dense(12,relu) → Dense(15,linear) [Decoder]

 Training:  Only on NORMAL traffic (unsupervised)
 Inference: Reconstruction error (MSE) = anomaly score
            Score > threshold → anomaly detected

 Threshold: 95th percentile of training reconstruction errors
=============================================================
"""

import os
from typing import Optional, Tuple

import numpy as np
from loguru import logger

os.environ["TF_CPP_MIN_LOG_LEVEL"] = "2"   # suppress TF info/warnings
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers, Model, callbacks


# ------------------------------------------------------------------
# Model Definition
# ------------------------------------------------------------------
def build_autoencoder(input_dim: int = 15) -> Model:
    """
    Builds and returns the autoencoder model.
    Encoder compresses 15 → 4 features (bottleneck).
    Decoder reconstructs 4 → 15 features.
    """
    # --- Encoder ---
    inputs  = keras.Input(shape=(input_dim,), name="network_flow_input")
    x       = layers.Dense(12, activation="relu",    name="enc_1")(inputs)
    x       = layers.BatchNormalization(name="bn_1")(x)
    x       = layers.Dense(8,  activation="relu",    name="enc_2")(x)
    x       = layers.BatchNormalization(name="bn_2")(x)
    encoded = layers.Dense(4,  activation="relu",    name="bottleneck")(x)

    # --- Decoder ---
    x       = layers.Dense(8,        activation="relu",    name="dec_1")(encoded)
    x       = layers.BatchNormalization(name="bn_3")(x)
    x       = layers.Dense(12,       activation="relu",    name="dec_2")(x)
    decoded = layers.Dense(input_dim, activation="linear", name="reconstruction")(x)

    model = Model(inputs=inputs, outputs=decoded, name="ThreatHunter_Autoencoder")
    model.compile(
        optimizer=keras.optimizers.Adam(learning_rate=1e-3),
        loss="mse",
        metrics=["mae"],
    )
    return model


# ------------------------------------------------------------------
# Autoencoder Wrapper
# ------------------------------------------------------------------
class NetworkAutoencoder:
    """
    Wraps the Keras autoencoder model with training,
    threshold computation, and inference methods.
    """

    MODEL_FILE     = "network_autoencoder.keras"
    THRESHOLD_FILE = "network_threshold.npy"

    def __init__(self, model_dir: str = "./data/models"):
        self.model_dir = model_dir
        self.model: Optional[Model] = None
        self.threshold: float = 0.0
        os.makedirs(model_dir, exist_ok=True)

    # ------------------------------------------------------------------
    # Training
    # ------------------------------------------------------------------
    def train(
        self,
        X_train: np.ndarray,
        X_val:   Optional[np.ndarray] = None,
        epochs:  int = 50,
        batch_size: int = 256,
    ) -> dict:
        """
        Train the autoencoder on normal traffic data.

        Args:
            X_train:    Shape [N, 15] — normalised feature matrix (normal traffic only)
            X_val:      Optional validation set
            epochs:     Training epochs
            batch_size: Batch size

        Returns:
            Training history dict
        """
        logger.info(f"Training Autoencoder | samples={len(X_train)} | epochs={epochs}")

        input_dim   = X_train.shape[1]
        self.model  = build_autoencoder(input_dim)
        self.model.summary(print_fn=logger.info)

        cb_list = [
            callbacks.EarlyStopping(
                monitor="val_loss" if X_val is not None else "loss",
                patience=5,
                restore_best_weights=True,
                verbose=1,
            ),
            callbacks.ReduceLROnPlateau(
                monitor="val_loss" if X_val is not None else "loss",
                factor=0.5,
                patience=3,
                min_lr=1e-6,
                verbose=1,
            ),
        ]

        val_data = (X_val, X_val) if X_val is not None else None

        history = self.model.fit(
            X_train, X_train,          # autoencoder: input = target
            epochs          = epochs,
            batch_size      = batch_size,
            validation_data = val_data,
            callbacks       = cb_list,
            verbose         = 1,
        )

        # Compute threshold from training reconstruction errors
        self.threshold = self._compute_threshold(X_train)
        logger.success(f"Autoencoder trained. Threshold={self.threshold:.6f}")

        self.save()
        return history.history

    def _compute_threshold(self, X: np.ndarray, percentile: float = 95.0) -> float:
        """
        Threshold = Nth percentile of reconstruction errors on training data.
        Events above this threshold are flagged as anomalies.
        """
        errors = self._reconstruction_errors(X)
        threshold = float(np.percentile(errors, percentile))
        logger.info(
            f"Threshold stats | mean={errors.mean():.6f} | "
            f"std={errors.std():.6f} | p95={threshold:.6f} | "
            f"max={errors.max():.6f}"
        )
        return threshold

    # ------------------------------------------------------------------
    # Inference
    # ------------------------------------------------------------------
    def score(self, x: np.ndarray) -> float:
        """
        Score a single feature vector.
        Returns reconstruction error (MSE) as anomaly score [0, inf).
        Higher = more anomalous.
        """
        if self.model is None:
            raise RuntimeError("Model not trained or loaded. Call train() or load() first.")

        x_input = x.reshape(1, -1).astype(np.float32)
        x_recon = self.model.predict(x_input, verbose=0)
        error   = float(np.mean(np.square(x_input - x_recon)))
        return error

    def score_batch(self, X: np.ndarray) -> np.ndarray:
        """Score a batch of feature vectors. Returns error array shape [N]."""
        if self.model is None:
            raise RuntimeError("Model not trained or loaded.")
        X_recon = self.model.predict(X, batch_size=512, verbose=0)
        errors  = np.mean(np.square(X - X_recon), axis=1)
        return errors

    def is_anomaly(self, score: float) -> bool:
        return score > self.threshold

    def get_severity(self, score: float) -> str:
        """Map anomaly score to severity level."""
        if score <= self.threshold:
            return "none"
        ratio = score / max(self.threshold, 1e-9)
        if ratio < 2.0:
            return "low"
        elif ratio < 5.0:
            return "medium"
        elif ratio < 10.0:
            return "high"
        else:
            return "critical"

    def _reconstruction_errors(self, X: np.ndarray) -> np.ndarray:
        X_recon = self.model.predict(X, batch_size=512, verbose=0)
        return np.mean(np.square(X - X_recon), axis=1)

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------
    def save(self):
        model_path     = os.path.join(self.model_dir, self.MODEL_FILE)
        threshold_path = os.path.join(self.model_dir, self.THRESHOLD_FILE)
        self.model.save(model_path)
        np.save(threshold_path, np.array([self.threshold]))
        logger.success(f"Autoencoder saved to {model_path}")
        logger.success(f"Threshold saved to {threshold_path}")

    def load(self) -> bool:
        model_path     = os.path.join(self.model_dir, self.MODEL_FILE)
        threshold_path = os.path.join(self.model_dir, self.THRESHOLD_FILE)

        if not os.path.exists(model_path):
            logger.warning(f"No saved autoencoder found at {model_path}")
            return False

        self.model = keras.models.load_model(model_path)

        if os.path.exists(threshold_path):
            self.threshold = float(np.load(threshold_path)[0])
        else:
            logger.warning("No threshold file found. Using default 0.05")
            self.threshold = 0.05

        logger.success(f"Autoencoder loaded. Threshold={self.threshold:.6f}")
        return True
