
from io import BytesIO

import cv2
import numpy as np


# ============================================================
# FEATURE NAMES
# ============================================================

FEATURE_NAMES = [
    "width",
    "height",
    "aspect_ratio",
    "mean_r",
    "mean_g",
    "mean_b",
    "std_r",
    "std_g",
    "std_b",
    "gray_mean",
    "gray_std",
    "laplacian_variance",
    "edge_density",
    "brightness",
    "contrast",
    "noise_estimate",
]


# ============================================================
# IMAGE DECODER
# ============================================================

def decode_image(image_bytes: bytes):

    if not image_bytes:
        raise ValueError("Empty image data")

    array = np.frombuffer(
        image_bytes,
        dtype=np.uint8,
    )

    image = cv2.imdecode(
        array,
        cv2.IMREAD_COLOR,
    )

    if image is None:
        raise ValueError("Could not decode image")

    return image


# ============================================================
# FEATURE EXTRACTION
# ============================================================

def extract_features(image_bytes: bytes):

    image = decode_image(image_bytes)

    height, width = image.shape[:2]

    # OpenCV uses BGR
    b, g, r = cv2.split(image)

    gray = cv2.cvtColor(
        image,
        cv2.COLOR_BGR2GRAY,
    )

    # --------------------------------------------------------
    # Basic image properties
    # --------------------------------------------------------

    aspect_ratio = (
        float(width) / float(height)
        if height
        else 0.0
    )

    # --------------------------------------------------------
    # Color statistics
    # --------------------------------------------------------

    mean_r = float(np.mean(r))
    mean_g = float(np.mean(g))
    mean_b = float(np.mean(b))

    std_r = float(np.std(r))
    std_g = float(np.std(g))
    std_b = float(np.std(b))

    # --------------------------------------------------------
    # Grayscale statistics
    # --------------------------------------------------------

    gray_mean = float(np.mean(gray))
    gray_std = float(np.std(gray))

    # --------------------------------------------------------
    # Laplacian variance
    #
    # Useful as a simple sharpness / texture indicator.
    # --------------------------------------------------------

    laplacian = cv2.Laplacian(
        gray,
        cv2.CV_64F,
    )

    laplacian_variance = float(
        laplacian.var()
    )

    # --------------------------------------------------------
    # Edge density
    # --------------------------------------------------------

    edges = cv2.Canny(
        gray,
        100,
        200,
    )

    edge_density = float(
        np.mean(edges > 0)
    )

    # --------------------------------------------------------
    # Brightness
    # --------------------------------------------------------

    brightness = float(
        np.mean(gray)
    )

    # --------------------------------------------------------
    # Contrast
    # --------------------------------------------------------

    contrast = float(
        np.std(gray)
    )

    # --------------------------------------------------------
    # Simple noise estimate
    # --------------------------------------------------------

    blurred = cv2.GaussianBlur(
        gray,
        (3, 3),
        0,
    )

    noise = gray.astype(
        np.float32
    ) - blurred.astype(
        np.float32
    )

    noise_estimate = float(
        np.std(noise)
    )

    # --------------------------------------------------------
    # Return dictionary
    # --------------------------------------------------------

    features = {
        "width": float(width),
        "height": float(height),
        "aspect_ratio": aspect_ratio,

        "mean_r": mean_r,
        "mean_g": mean_g,
        "mean_b": mean_b,

        "std_r": std_r,
        "std_g": std_g,
        "std_b": std_b,

        "gray_mean": gray_mean,
        "gray_std": gray_std,

        "laplacian_variance": laplacian_variance,

        "edge_density": edge_density,

        "brightness": brightness,
        "contrast": contrast,

        "noise_estimate": noise_estimate,
    }

    return features


# ============================================================
# DICTIONARY → ML VECTOR
# ============================================================

def features_to_vector(features):

    vector = []

    for feature_name in FEATURE_NAMES:

        value = features.get(
            feature_name,
            0.0,
        )

        try:
            value = float(value)
        except (TypeError, ValueError):
            value = 0.0

        if not np.isfinite(value):
            value = 0.0

        vector.append(value)

    return np.asarray(
        vector,
        dtype=np.float32,
    )


# ============================================================
# CONVENIENCE FUNCTION
# ============================================================

def extract_feature_vector(image_bytes: bytes):

    features = extract_features(
        image_bytes
    )

    return features_to_vector(
        features
    )

