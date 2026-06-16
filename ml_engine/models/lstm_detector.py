"""
=============================================================
 ThreatHunter Pro — LSTM Sequence Detector
 models/lstm_detector.py

 Architecture (LSTM Autoencoder):
   Input [seq_len=10, features=8]
   → LSTM(64, return_sequences=True)
   → LSTM(32, return_sequences=False)   [Encoder]
   → RepeatVector(seq_len)
   → LSTM(32, return_sequences=True)
   → LSTM(64, return_sequences=True)    [Decoder]
   → TimeDistributed(Dense(8))          [Reconstruction]

 Training:  On normal Windows event sequences (unsupervised)
 Inference: Sequence reconstruction error = anomaly score
            Score > threshold → anomalous event chain detected

 Why LSTM Autoencoder:
   - Learns temporal patterns in event sequences per host
   - Flags unusual chains: e.g. failed_login×10 → new_user → log_clear
     is very different from normal logon → process_create patterns
=============================================================
"""

import os
from typing import Optional

import numpy as np
from loguru import logger

os.environ["TF_CPP_MIN_LOG_LEVEL"] = "2"
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers, Model, callbacks


# ------------------------------------------------------------------
# Model Definition
# ------------------------------------------------------------------
def build_lstm_autoencoder(seq_len: int = 10, feature_dim: int = 8) -> Model:
    """
    Builds an LSTM Autoencoder.

    Encoder: compresses sequence → fixed-size context vector
    Decoder: reconstructs original sequence from context vector
    """
    inputs = keras.Input(shape=(seq_len, feature_dim), name="event_sequence_input")

    # --- Encoder ---
    x       = layers.LSTM(64, return_sequences=True,  name="lstm_enc_1")(inputs)
    x       = layers.Dropout(0.2, name="drop_1")(x)
    encoded = layers.LSTM(32, return_sequences=False, name="lstm_enc_2")(x)

    # --- Bridge: repeat context vector seq_len times ---
    x = layers.RepeatVector(seq_len, name="repeat_vector")(encoded)

    # --- Decoder ---
    x       = layers.LSTM(32, return_sequences=True, name="lstm_dec_1")(x)
    x       = layers.Dropout(0.2, name="drop_2")(x)
    x       = layers.LSTM(64, return_sequences=True, name="lstm_dec_2")(x)
    decoded = layers.TimeDistributed(
        layers.Dense(feature_dim, activation="linear"),
        name="reconstruction"
    )(x)

    model = Model(inputs=inputs, outputs=decoded, name="ThreatHunter_LSTM_AE")
    model.compile(
        optimizer=keras.optimizers.Adam(learning_rate=1e-3),
        loss="mse",
        metrics=["mae"],
    )
    return model


# ------------------------------------------------------------------
# LSTM Detector Wrapper
# ------------------------------------------------------------------
class WindowsLSTMDetector:
    """
    LSTM Autoencoder for Windows event sequence anomaly detection.
    """

    MODEL_FILE     = "windows_lstm.keras"
    THRESHOLD_FILE = "windows_threshold.npy"

    def __init__(
        self,
        model_dir:   str = "./data/models",
        seq_len:     int = 10,
        feature_dim: int = 8,
    ):
        self.model_dir   = model_dir
        self.seq_len     = seq_len
        self.feature_dim = feature_dim
        self.model: Optional[Model] = None
        self.threshold: float = 0.0
        os.makedirs(model_dir, exist_ok=True)

    # ------------------------------------------------------------------
    # Training
    # ------------------------------------------------------------------
    def train(
        self,
        X_train:    np.ndarray,
        X_val:      Optional[np.ndarray] = None,
        epochs:     int = 50,
        batch_size: int = 128,
    ) -> dict:
        """
        Train on normal event sequences.

        Args:
            X_train:    Shape [N, seq_len, feature_dim]
            X_val:      Optional validation sequences
            epochs:     Training epochs
            batch_size: Batch size

        Returns:
            Training history dict
        """
        logger.info(
            f"Training LSTM AE | sequences={len(X_train)} | "
            f"seq_len={self.seq_len} | feature_dim={self.feature_dim} | "
            f"epochs={epochs}"
        )

        self.model = build_lstm_autoencoder(self.seq_len, self.feature_dim)
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
            X_train, X_train,          # reconstruct input sequence
            epochs          = epochs,
            batch_size      = batch_size,
            validation_data = val_data,
            callbacks       = cb_list,
            verbose         = 1,
        )

        self.threshold = self._compute_threshold(X_train)
        logger.success(f"LSTM AE trained. Threshold={self.threshold:.6f}")

        self.save()
        return history.history

    def _compute_threshold(self, X: np.ndarray, percentile: float = 95.0) -> float:
        errors    = self._reconstruction_errors(X)
        threshold = float(np.percentile(errors, percentile))
        logger.info(
            f"LSTM Threshold | mean={errors.mean():.6f} | "
            f"std={errors.std():.6f} | p95={threshold:.6f}"
        )
        return threshold

    # ------------------------------------------------------------------
    # Inference
    # ------------------------------------------------------------------
    def score(self, sequence: np.ndarray) -> float:
        """
        Score a single event sequence.

        Args:
            sequence: Shape [seq_len, feature_dim]

        Returns:
            Reconstruction error (MSE) — higher = more anomalous
        """
        if self.model is None:
            raise RuntimeError("Model not loaded. Call train() or load() first.")

        x_input = sequence.reshape(1, self.seq_len, self.feature_dim).astype(np.float32)
        x_recon = self.model.predict(x_input, verbose=0)
        error   = float(np.mean(np.square(x_input - x_recon)))
        return error

    def score_batch(self, X: np.ndarray) -> np.ndarray:
        """Score a batch of sequences. Returns error array [N]."""
        if self.model is None:
            raise RuntimeError("Model not loaded.")
        X_recon = self.model.predict(X, batch_size=256, verbose=0)
        errors  = np.mean(np.square(X - X_recon), axis=(1, 2))
        return errors

    def is_anomaly(self, score: float) -> bool:
        return score > self.threshold

    def get_severity(self, score: float) -> str:
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
        X_recon = self.model.predict(X, batch_size=256, verbose=0)
        return np.mean(np.square(X - X_recon), axis=(1, 2))

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------
    def save(self):
        model_path     = os.path.join(self.model_dir, self.MODEL_FILE)
        threshold_path = os.path.join(self.model_dir, self.THRESHOLD_FILE)
        self.model.save(model_path)
        np.save(threshold_path, np.array([self.threshold]))
        logger.success(f"LSTM model saved to {model_path}")

    def load(self) -> bool:
        model_path     = os.path.join(self.model_dir, self.MODEL_FILE)
        threshold_path = os.path.join(self.model_dir, self.THRESHOLD_FILE)

        if not os.path.exists(model_path):
            logger.warning(f"No saved LSTM model at {model_path}")
            return False

        self.model = keras.models.load_model(model_path)

        if os.path.exists(threshold_path):
            self.threshold = float(np.load(threshold_path)[0])
        else:
            self.threshold = 0.05

        logger.success(f"LSTM model loaded. Threshold={self.threshold:.6f}")
        return True
