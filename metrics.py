from __future__ import annotations

from pathlib import Path

from utils import capacity_report, load_image, prepare_image_for_lsb, psnr_from_mse


def mse(original_path: str | Path, stego_path: str | Path) -> float:
    original, _ = load_image(original_path)
    stego, _ = load_image(stego_path)
    original_rgb = prepare_image_for_lsb(original)
    stego_rgb = prepare_image_for_lsb(stego)
    if original_rgb.size != stego_rgb.size:
        raise ValueError("Images must have the same dimensions for quality evaluation.")

    original_bytes = original_rgb.tobytes()
    stego_bytes = stego_rgb.tobytes()
    squared_error = sum((a - b) ** 2 for a, b in zip(original_bytes, stego_bytes))
    return squared_error / len(original_bytes)


def psnr(original_path: str | Path, stego_path: str | Path) -> float:
    return psnr_from_mse(mse(original_path, stego_path))


def evaluate_quality(original_path: str | Path, stego_path: str | Path, payload_size: int = 0) -> dict:
    original, original_format = load_image(original_path)
    stego, stego_format = load_image(stego_path)
    current_mse = mse(original_path, stego_path)
    return {
        "original_format": original_format,
        "stego_format": stego_format,
        "dimensions": prepare_image_for_lsb(original).size,
        "mse": current_mse,
        "psnr": psnr_from_mse(current_mse),
        "capacity": capacity_report(original, payload_size),
    }
