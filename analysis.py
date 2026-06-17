from __future__ import annotations

import math
from pathlib import Path

import matplotlib
import numpy as np

matplotlib.use("Agg")
from matplotlib import pyplot as plt
from PIL import Image

from utils import capacity_report, load_image, prepare_image_for_lsb


EDUCATIONAL_WARNING = "Educational statistical indicator only; this is not definitive proof of steganography."
DIMENSION_ERROR = "Images must have the same dimensions for comparison."
CHANNELS = (("Red", "red"), ("Green", "green"), ("Blue", "blue"))


def _entropy(ones: int, total: int) -> float:
    if total == 0:
        return 0.0
    p1 = ones / total
    p0 = 1.0 - p1
    return -sum(value * math.log2(value) for value in (p0, p1) if value > 0)


def _rgb_array(image_path: str | Path) -> np.ndarray:
    image, _ = load_image(image_path)
    return np.asarray(prepare_image_for_lsb(image), dtype=np.uint8)


def _safe_output_path(output_path: str | Path, overwrite: bool) -> Path:
    output = Path(output_path)
    if output.exists() and not overwrite:
        raise FileExistsError(f"Refusing to overwrite existing file: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    return output


def rgb_histogram(image_path: str | Path) -> dict[str, np.ndarray]:
    array = _rgb_array(image_path)
    return {
        name.lower(): np.bincount(array[:, :, index].ravel(), minlength=256)
        for index, (name, _) in enumerate(CHANNELS)
    }


def histogram_distance(cover_path: str | Path, stego_path: str | Path) -> dict[str, float]:
    cover = rgb_histogram(cover_path)
    stego = rgb_histogram(stego_path)
    return {channel: float(np.abs(cover[channel] - stego[channel]).sum()) for channel in cover}


def generate_rgb_histogram(
    image_path: str | Path,
    output_path: str | Path,
    title: str = "RGB Histogram",
    overwrite: bool = False,
) -> Path:
    output = _safe_output_path(output_path, overwrite)
    histogram = rgb_histogram(image_path)
    figure, axis = plt.subplots(figsize=(9, 5))
    try:
        for name, color in CHANNELS:
            axis.plot(range(256), histogram[name.lower()], color=color, label=name)
        axis.set(title=title, xlabel="Pixel intensity", ylabel="Frequency", xlim=(0, 255))
        axis.legend()
        figure.tight_layout()
        figure.savefig(output, dpi=140)
    finally:
        plt.close(figure)
    return output


def generate_combined_histogram(
    cover_path: str | Path,
    stego_path: str | Path,
    output_path: str | Path,
    overwrite: bool = False,
) -> Path:
    cover = rgb_histogram(cover_path)
    stego = rgb_histogram(stego_path)
    output = _safe_output_path(output_path, overwrite)
    figure, axes = plt.subplots(3, 1, figsize=(9, 9), sharex=True)
    try:
        for axis, (name, color) in zip(axes, CHANNELS):
            key = name.lower()
            axis.plot(range(256), cover[key], color=color, label=f"Cover {name}")
            axis.plot(range(256), stego[key], color=color, linestyle="--", label=f"Stego {name}")
            axis.set(ylabel="Frequency", xlim=(0, 255))
            axis.legend()
        axes[-1].set_xlabel("Pixel intensity")
        figure.suptitle("Cover versus Stego RGB Histogram")
        figure.tight_layout()
        figure.savefig(output, dpi=140)
    finally:
        plt.close(figure)
    return output


def difference_statistics(cover_path: str | Path, stego_path: str | Path) -> dict[str, float | int]:
    cover = _rgb_array(cover_path).astype(np.int16)
    stego = _rgb_array(stego_path).astype(np.int16)
    if cover.shape != stego.shape:
        raise ValueError(DIMENSION_ERROR)
    difference = np.abs(cover - stego)
    changed_channels = int(np.count_nonzero(difference))
    changed_pixels = int(np.count_nonzero(np.any(difference > 0, axis=2)))
    total_pixels = int(cover.shape[0] * cover.shape[1])
    return {
        "changed_pixels": changed_pixels,
        "changed_channels": changed_channels,
        "changed_pixel_percent": changed_pixels / total_pixels * 100 if total_pixels else 0.0,
        "maximum_absolute_difference": int(difference.max()) if difference.size else 0,
        "mean_absolute_difference": float(difference.mean()) if difference.size else 0.0,
    }


def generate_difference_map(
    cover_path: str | Path,
    stego_path: str | Path,
    output_path: str | Path,
    amplification: int = 32,
    overwrite: bool = False,
) -> dict[str, object]:
    if amplification <= 0:
        raise ValueError("Amplification must be greater than zero.")
    cover = _rgb_array(cover_path).astype(np.int16)
    stego = _rgb_array(stego_path).astype(np.int16)
    if cover.shape != stego.shape:
        raise ValueError(DIMENSION_ERROR)
    difference = np.abs(cover - stego)
    amplified = np.clip(difference * amplification, 0, 255)
    # LSB edits usually differ by only 1 intensity level, so a raw amplified
    # map can still look blank. Force changed channels to full brightness for
    # a clear educational visualization of where embedding touched pixels.
    visualization = np.where(difference > 0, 255, amplified).astype(np.uint8)
    output = _safe_output_path(output_path, overwrite)
    Image.fromarray(visualization, mode="RGB").save(output)
    return {
        "output_path": output,
        "amplification": amplification,
        **difference_statistics(cover_path, stego_path),
    }


def analyze_image_lsb(image_path: str | Path) -> dict:
    image, image_format = load_image(image_path)
    rgb = prepare_image_for_lsb(image)
    pixels = rgb.tobytes()
    total = len(pixels)
    ones = sum(value & 1 for value in pixels)
    zeros = total - ones
    ones_ratio = ones / total if total else 0.0
    balance_distance = abs(ones_ratio - 0.5)
    entropy = _entropy(ones, total)
    channel_stats = []
    for channel, name in enumerate(("Red", "Green", "Blue")):
        channel_values = pixels[channel::3]
        channel_total = len(channel_values)
        channel_ones = sum(value & 1 for value in channel_values)
        channel_stats.append(
            {
                "name": name,
                "ones_ratio": channel_ones / channel_total if channel_total else 0.0,
                "ones": channel_ones,
                "zeros": channel_total - channel_ones,
            }
        )
    if balance_distance < 0.015 and entropy > 0.998:
        suspicion = "High"
        explanation = "The LSB plane is very close to random, which can happen after encrypted/randomized embedding."
    elif balance_distance < 0.04 and entropy > 0.99:
        suspicion = "Medium"
        explanation = "The LSB plane is fairly balanced. This is not proof, but it is worth inspecting."
    else:
        suspicion = "Low"
        explanation = "The LSB plane is not strongly balanced, so this simple test is less suspicious."
    return {
        "format": image_format,
        "dimensions": rgb.size,
        "total_lsb_bits": total,
        "ones": ones,
        "zeros": zeros,
        "ones_ratio": ones_ratio,
        "entropy": entropy,
        "suspicion": suspicion,
        "explanation": explanation,
        "warning": EDUCATIONAL_WARNING,
        "channels": channel_stats,
        "capacity": capacity_report(rgb, 0),
    }
