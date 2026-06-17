from __future__ import annotations

import math
from pathlib import Path

import numpy as np
from skimage.metrics import structural_similarity

from utils import capacity_report, load_image, prepare_image_for_lsb, psnr_from_mse


DIMENSION_ERROR = "Images must have the same dimensions for quality evaluation."


def _metric_arrays(original_path: str | Path, stego_path: str | Path) -> tuple[np.ndarray, np.ndarray]:
    original, _ = load_image(original_path)
    stego, _ = load_image(stego_path)
    if original.size != stego.size:
        raise ValueError(DIMENSION_ERROR)
    if original.mode == "L" and stego.mode == "L":
        return np.asarray(original, dtype=np.float64), np.asarray(stego, dtype=np.float64)
    return (
        np.asarray(prepare_image_for_lsb(original), dtype=np.float64),
        np.asarray(prepare_image_for_lsb(stego), dtype=np.float64),
    )


def mse(original_path: str | Path, stego_path: str | Path) -> float:
    original, stego = _metric_arrays(original_path, stego_path)
    return float(np.mean(np.square(original - stego)))


def psnr(original_path: str | Path, stego_path: str | Path) -> float:
    return psnr_from_mse(mse(original_path, stego_path))


def ssim(original_path: str | Path, stego_path: str | Path) -> float:
    original, stego = _metric_arrays(original_path, stego_path)
    channel_axis = None if original.ndim == 2 else -1
    return float(structural_similarity(original, stego, channel_axis=channel_axis, data_range=255))


def bit_error_rate(expected: bytes, actual: bytes) -> dict[str, float | int]:
    """Compare byte sequences bitwise, counting missing or extra bytes as errors."""
    common_length = min(len(expected), len(actual))
    incorrect_bits = sum((expected[index] ^ actual[index]).bit_count() for index in range(common_length))
    incorrect_bits += abs(len(expected) - len(actual)) * 8
    total_bits = max(len(expected), len(actual)) * 8
    ber = incorrect_bits / total_bits if total_bits else 0.0
    return {
        "ber": ber,
        "incorrect_bits": incorrect_bits,
        "total_bits": total_bits,
    }


def evaluate_quality(original_path: str | Path, stego_path: str | Path, payload_size: int = 0) -> dict:
    original, original_format = load_image(original_path)
    _, stego_format = load_image(stego_path)
    current_mse = mse(original_path, stego_path)
    return {
        "original_format": original_format,
        "stego_format": stego_format,
        "dimensions": original.size,
        "mse": current_mse,
        "psnr": psnr_from_mse(current_mse),
        "ssim": ssim(original_path, stego_path),
        "capacity": capacity_report(original, payload_size),
    }
