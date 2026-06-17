from __future__ import annotations

import csv
import random
import sys
from pathlib import Path

from PIL import Image, ImageFilter

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from decoder import decode_basic, decode_edge_adaptive, decode_randomized
from encoder import encode_basic, encode_edge_adaptive, encode_randomized
from metrics import bit_error_rate, psnr, ssim


ROBUSTNESS_COLUMNS = [
    "method",
    "transformation",
    "decode_success",
    "message_match",
    "integrity_status",
    "ber",
    "incorrect_bits",
    "total_bits",
    "psnr",
    "ssim",
]


def transformation_specs() -> list[tuple[str, dict]]:
    return [
        ("png_resave", {"kind": "save", "format": "PNG"}),
        ("bmp_conversion", {"kind": "save", "format": "BMP"}),
        ("jpeg_quality_95", {"kind": "save", "format": "JPEG", "quality": 95}),
        ("jpeg_quality_85", {"kind": "save", "format": "JPEG", "quality": 85}),
        ("jpeg_quality_75", {"kind": "save", "format": "JPEG", "quality": 75}),
        ("jpeg_quality_50", {"kind": "save", "format": "JPEG", "quality": 50}),
        ("resize_90_percent", {"kind": "resize", "scale": 0.90}),
        ("resize_75_percent", {"kind": "resize", "scale": 0.75}),
        ("light_gaussian_blur", {"kind": "blur", "radius": 0.5}),
        ("light_image_noise", {"kind": "noise", "amplitude": 2}),
    ]


def apply_transformation(source_path: str | Path, output_path: str | Path, spec: dict) -> Path:
    source = Image.open(source_path).convert("RGB")
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    kind = spec["kind"]
    if kind == "save":
        kwargs = {"format": spec["format"]}
        if "quality" in spec:
            kwargs["quality"] = spec["quality"]
        source.save(output, **kwargs)
    elif kind == "resize":
        size = (max(1, round(source.width * spec["scale"])), max(1, round(source.height * spec["scale"])))
        source.resize(size, Image.Resampling.LANCZOS).save(output, format="PNG")
    elif kind == "blur":
        source.filter(ImageFilter.GaussianBlur(radius=spec["radius"])).save(output, format="PNG")
    elif kind == "noise":
        rng = random.Random(20260615)
        amplitude = int(spec["amplitude"])
        pixels = bytearray(source.tobytes())
        for index, value in enumerate(pixels):
            pixels[index] = max(0, min(255, value + rng.randint(-amplitude, amplitude)))
        Image.frombytes("RGB", source.size, bytes(pixels)).save(output, format="PNG")
    else:
        raise ValueError(f"Unsupported transformation kind: {kind}")
    return output


def write_robustness_csv(path: str | Path, rows: list[dict]) -> Path:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=ROBUSTNESS_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    return output


def run_robustness_benchmark(results_dir: str | Path = ROOT / "results") -> list[dict]:
    results = Path(results_dir)
    csv_dir = results / "csv"
    transformed_dir = results / "robustness_transformed"
    stego_dir = results / "robustness_stego"
    csv_dir.mkdir(parents=True, exist_ok=True)
    transformed_dir.mkdir(parents=True, exist_ok=True)
    stego_dir.mkdir(parents=True, exist_ok=True)
    cover = results / "robustness_cover.png"
    Image.new("RGB", (256, 256), (80, 130, 180)).save(cover)
    message = "Controlled robustness benchmark payload"
    methods = {
        "basic": (encode_basic, decode_basic),
        "randomized": (encode_randomized, decode_randomized),
        "edge-adaptive": (encode_edge_adaptive, decode_edge_adaptive),
    }
    rows = []
    for method, (encode, decode) in methods.items():
        stego = stego_dir / f"{method}.png"
        if method == "randomized":
            encode(cover, stego, message, "benchmark-password", use_compression=False)
        else:
            encode(cover, stego, message, use_compression=False)
        for transformation, spec in transformation_specs():
            suffix = ".jpg" if spec.get("format") == "JPEG" else ".bmp" if spec.get("format") == "BMP" else ".png"
            transformed = apply_transformation(stego, transformed_dir / f"{method}_{transformation}{suffix}", spec)
            try:
                recovered = decode(transformed, "benchmark-password") if method == "randomized" else decode(transformed)
                decode_success = True
                integrity_status = "verified"
            except Exception:
                recovered = ""
                decode_success = False
                integrity_status = "failed"
            ber = bit_error_rate(message.encode("utf-8"), recovered.encode("utf-8"))
            try:
                current_psnr = psnr(stego, transformed)
                current_ssim = ssim(stego, transformed)
            except ValueError:
                current_psnr = ""
                current_ssim = ""
            rows.append(
                {
                    "method": method,
                    "transformation": transformation,
                    "decode_success": decode_success,
                    "message_match": recovered == message,
                    "integrity_status": integrity_status,
                    **ber,
                    "psnr": current_psnr,
                    "ssim": current_ssim,
                }
            )
    write_robustness_csv(csv_dir / "robustness_results.csv", rows)
    return rows


if __name__ == "__main__":
    run_robustness_benchmark()
