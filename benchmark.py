from __future__ import annotations

import csv
import random
import sys
import time
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
from matplotlib import pyplot as plt
from PIL import Image, ImageDraw

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from analysis import difference_statistics
from decoder import decode_basic, decode_edge_adaptive, decode_randomized
from encoder import encode_basic, encode_edge_adaptive, encode_randomized
from metrics import evaluate_quality
from utils import payload_capacity_bytes


PAYLOAD_LEVELS = (10, 25, 50, 75)
BENCHMARK_COLUMNS = [
    "image_name",
    "image_type",
    "width",
    "height",
    "method",
    "payload_percent",
    "message_bytes",
    "stored_payload_bytes",
    "compression_used",
    "encryption_used",
    "mse",
    "psnr",
    "ssim",
    "changed_pixels",
    "changed_pixel_percent",
    "encode_time_seconds",
    "decode_time_seconds",
    "decode_success",
    "message_match",
]


def ensure_result_directories(base_dir: str | Path) -> tuple[Path, Path]:
    base = Path(base_dir)
    csv_dir = base / "csv"
    figure_dir = base / "figures"
    csv_dir.mkdir(parents=True, exist_ok=True)
    figure_dir.mkdir(parents=True, exist_ok=True)
    return csv_dir, figure_dir


def generate_representative_images(output_dir: str | Path, size: tuple[int, int] = (256, 256)) -> dict[str, Path]:
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    width, height = size
    paths: dict[str, Path] = {}

    smooth = output / "smooth.png"
    Image.new("RGB", size, (120, 140, 160)).save(smooth)
    paths["smooth"] = smooth

    textured = output / "textured.png"
    rng = random.Random(20260615)
    textured_pixels = bytes(rng.randrange(256) for _ in range(width * height * 3))
    Image.frombytes("RGB", size, textured_pixels).save(textured)
    paths["textured"] = textured

    edge_heavy = output / "edge_heavy.png"
    edge_image = Image.new("RGB", size, "white")
    draw = ImageDraw.Draw(edge_image)
    block = max(4, width // 16)
    for y in range(0, height, block):
        for x in range(0, width, block):
            if (x // block + y // block) % 2:
                draw.rectangle((x, y, x + block - 1, y + block - 1), fill="black")
    edge_image.save(edge_heavy)
    paths["edge-heavy"] = edge_heavy
    return paths


def write_csv_rows(path: str | Path, columns: list[str], rows: list[dict]) -> Path:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)
    return output


def plot_benchmark_results(rows: list[dict], figure_dir: str | Path) -> list[Path]:
    output = Path(figure_dir)
    output.mkdir(parents=True, exist_ok=True)
    configurations = [
        ("psnr", "PSNR versus Payload", "PSNR (dB)", "psnr_versus_payload.png"),
        ("ssim", "SSIM versus Payload", "SSIM", "ssim_versus_payload.png"),
        ("encode_time_seconds", "Encoding Time versus Payload", "Seconds", "encoding_time_versus_payload.png"),
        ("changed_pixel_percent", "Changed Pixels versus Payload", "Changed pixels (%)", "changed_pixels_versus_payload.png"),
    ]
    paths = []
    for field, title, ylabel, filename in configurations:
        figure, axis = plt.subplots(figsize=(8, 5))
        try:
            for method in ("basic", "randomized", "edge-adaptive"):
                method_rows = [row for row in rows if row["method"] == method]
                grouped = {}
                for row in method_rows:
                    grouped.setdefault(row["payload_percent"], []).append(float(row[field]))
                x_values = sorted(grouped)
                y_values = [sum(grouped[x]) / len(grouped[x]) for x in x_values]
                axis.plot(x_values, y_values, marker="o", label=method)
            axis.set(title=title, xlabel="Payload (%)", ylabel=ylabel)
            axis.legend()
            figure.tight_layout()
            path = output / filename
            figure.savefig(path, dpi=140)
            paths.append(path)
        finally:
            plt.close(figure)
    return paths


def run_benchmark(results_dir: str | Path = ROOT / "results") -> list[dict]:
    csv_dir, figure_dir = ensure_result_directories(results_dir)
    generated_dir = Path(results_dir) / "generated_inputs"
    images = generate_representative_images(generated_dir)
    methods = {
        "basic": (encode_basic, decode_basic),
        "randomized": (encode_randomized, decode_randomized),
        "edge-adaptive": (encode_edge_adaptive, decode_edge_adaptive),
    }
    rows = []
    for image_type, cover_path in images.items():
        image = Image.open(cover_path)
        capacity = payload_capacity_bytes(image)
        for payload_percent in PAYLOAD_LEVELS:
            message = "A" * max(1, int(capacity * payload_percent / 100))
            for method_name, (encode, decode) in methods.items():
                stego = Path(results_dir) / "generated_stego" / f"{image_type}_{method_name}_{payload_percent}.png"
                started = time.perf_counter()
                if method_name == "randomized":
                    result = encode(cover_path, stego, message, "benchmark-password", use_compression=False)
                else:
                    result = encode(cover_path, stego, message, use_compression=False)
                encode_time = time.perf_counter() - started
                decode_started = time.perf_counter()
                try:
                    recovered = decode(stego, "benchmark-password") if method_name == "randomized" else decode(stego)
                    decode_success = True
                except Exception:
                    recovered = ""
                    decode_success = False
                decode_time = time.perf_counter() - decode_started
                quality = evaluate_quality(cover_path, stego, result["stored_payload_bytes"])
                changes = difference_statistics(cover_path, stego)
                rows.append(
                    {
                        "image_name": cover_path.name,
                        "image_type": image_type,
                        "width": image.width,
                        "height": image.height,
                        "method": method_name,
                        "payload_percent": payload_percent,
                        "message_bytes": len(message.encode("utf-8")),
                        "stored_payload_bytes": result["stored_payload_bytes"],
                        "compression_used": result["compressed"],
                        "encryption_used": result["encrypted"],
                        "mse": quality["mse"],
                        "psnr": quality["psnr"],
                        "ssim": quality["ssim"],
                        "changed_pixels": changes["changed_pixels"],
                        "changed_pixel_percent": changes["changed_pixel_percent"],
                        "encode_time_seconds": encode_time,
                        "decode_time_seconds": decode_time,
                        "decode_success": decode_success,
                        "message_match": recovered == message,
                    }
                )
    write_csv_rows(csv_dir / "benchmark_results.csv", BENCHMARK_COLUMNS, rows)
    plot_benchmark_results(rows, figure_dir)
    return rows


if __name__ == "__main__":
    run_benchmark()
