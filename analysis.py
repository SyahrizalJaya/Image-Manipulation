from __future__ import annotations

import math
from pathlib import Path

from utils import capacity_report, load_image, prepare_image_for_lsb


def _entropy(ones: int, total: int) -> float:
    if total == 0:
        return 0.0
    p1 = ones / total
    p0 = 1.0 - p1
    entropy = 0.0
    for value in (p0, p1):
        if value > 0:
            entropy -= value * math.log2(value)
    return entropy


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
        "channels": channel_stats,
        "capacity": capacity_report(rgb, 0),
    }
