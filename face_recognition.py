"""YuNet face detection and SFace embedding/matching helpers."""
import os
from pathlib import Path
from threading import RLock

import cv2
import numpy as np

MODEL_DIR = Path(__file__).resolve().parent / "models"
YUNET_MODEL = MODEL_DIR / "face_detection_yunet_2023mar.onnx"
SFACE_MODEL = MODEL_DIR / "face_recognition_sface_2021dec.onnx"
SIMILARITY_THRESHOLD = float(os.environ.get("FACE_SIMILARITY_THRESHOLD", "0.363"))

_detector = None
_recognizer = None
_model_lock = RLock()


class FaceError(ValueError):
    """An image cannot be used for face recognition."""


def _models():
    global _detector, _recognizer
    with _model_lock:
        if _detector is None or _recognizer is None:
            missing = [str(path) for path in (YUNET_MODEL, SFACE_MODEL) if not path.is_file()]
            if missing:
                raise RuntimeError("Missing face model file(s): " + ", ".join(missing))
            _detector = cv2.FaceDetectorYN_create(str(YUNET_MODEL), "", (320, 320), 0.7, 0.3, 5000)
            _recognizer = cv2.FaceRecognizerSF_create(str(SFACE_MODEL), "")
    return _detector, _recognizer


def _read_image(image_bytes):
    if not image_bytes:
        raise FaceError("The image is empty.")
    image = cv2.imdecode(np.frombuffer(image_bytes, dtype=np.uint8), cv2.IMREAD_COLOR)
    if image is None:
        raise FaceError("The file could not be read as an image.")
    return image


def detect_one_face(image_bytes):
    """Decode an image and return its sole YuNet face row (box + five landmarks)."""
    image = _read_image(image_bytes)
    detector, _ = _models()
    height, width = image.shape[:2]
    with _model_lock:
        detector.setInputSize((width, height))
        _, faces = detector.detect(image)
    count = 0 if faces is None else len(faces)
    if count == 0:
        raise FaceError("No face detected. Use a clear, front-facing image.")
    if count != 1:
        raise FaceError("Exactly one face must be visible in the image.")
    return image, faces[0]


def generate_embedding(image_bytes):
    """Return a normalized 128-dimensional SFace embedding for exactly one face."""
    image, face = detect_one_face(image_bytes)
    _, recognizer = _models()
    with _model_lock:
        aligned_face = recognizer.alignCrop(image, face)
        embedding = recognizer.feature(aligned_face).reshape(-1).astype(np.float32)
    if embedding.size != 128:
        raise RuntimeError(f"SFace returned {embedding.size} values; expected 128.")
    norm = np.linalg.norm(embedding)
    if not np.isfinite(norm) or norm == 0:
        raise RuntimeError("SFace returned an invalid embedding.")
    embedding /= norm
    return embedding


def compare_embeddings(registered, probe, threshold=None):
    """Compare normalized embeddings using cosine similarity."""
    registered = np.asarray(registered, dtype=np.float32).reshape(-1)
    probe = np.asarray(probe, dtype=np.float32).reshape(-1)
    if registered.size != 128 or probe.size != 128:
        raise ValueError("Both face embeddings must contain 128 values.")
    registered_norm = np.linalg.norm(registered)
    probe_norm = np.linalg.norm(probe)
    if registered_norm == 0 or probe_norm == 0:
        raise ValueError("Cannot compare an empty face embedding.")
    similarity = float(np.clip(np.dot(registered / registered_norm, probe / probe_norm), -1.0, 1.0))
    cutoff = SIMILARITY_THRESHOLD if threshold is None else float(threshold)
    return similarity, similarity >= cutoff
