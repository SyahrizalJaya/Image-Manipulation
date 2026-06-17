from __future__ import annotations

import csv
import math

import pytest
from PIL import Image

from analysis import (
    difference_statistics,
    generate_combined_histogram,
    generate_difference_map,
    generate_rgb_histogram,
    histogram_distance,
    rgb_histogram,
)
from experiments.benchmark import (
    BENCHMARK_COLUMNS,
    ensure_result_directories,
    generate_representative_images,
    plot_benchmark_results,
    write_csv_rows,
)
from experiments.robustness_benchmark import (
    ROBUSTNESS_COLUMNS,
    apply_transformation,
    transformation_specs,
    write_robustness_csv,
)
from metrics import bit_error_rate, mse, psnr, ssim


def save_image(path, color=(10, 20, 30), size=(16, 16), mode="RGB"):
    Image.new(mode, size, color).save(path)
    return path


def test_metrics_identical_and_single_channel_difference(tmp_path):
    original = save_image(tmp_path / "original.png")
    identical = save_image(tmp_path / "identical.png")
    changed = save_image(tmp_path / "changed.png", color=(10, 20, 31))

    assert mse(original, identical) == 0
    assert math.isinf(psnr(original, identical))
    assert ssim(original, identical) == pytest.approx(1.0)
    assert mse(original, changed) == pytest.approx(1 / 3)
    assert psnr(original, changed) > 0
    assert 0 <= ssim(original, changed) < 1


def test_ssim_supports_grayscale(tmp_path):
    first = save_image(tmp_path / "first.png", color=40, mode="L")
    second = save_image(tmp_path / "second.png", color=40, mode="L")

    assert ssim(first, second) == pytest.approx(1.0)


@pytest.mark.parametrize("metric", [mse, psnr, ssim])
def test_metric_dimension_mismatch_is_clear(tmp_path, metric):
    first = save_image(tmp_path / "first.png", size=(16, 16))
    second = save_image(tmp_path / "second.png", size=(17, 16))

    with pytest.raises(ValueError, match="same dimensions"):
        metric(first, second)


def test_bit_error_rate_behaviors():
    assert bit_error_rate(b"", b"") == {"ber": 0.0, "incorrect_bits": 0, "total_bits": 0}
    assert bit_error_rate(b"\x00", b"\x00") == {"ber": 0.0, "incorrect_bits": 0, "total_bits": 8}
    assert bit_error_rate(b"\x00", b"\x01") == {"ber": 1 / 8, "incorrect_bits": 1, "total_bits": 8}
    assert bit_error_rate(b"\x00", b"\x00\x00") == {"ber": 0.5, "incorrect_bits": 8, "total_bits": 16}


def test_histogram_functions_generate_temp_outputs_and_ignore_alpha(tmp_path):
    cover = save_image(tmp_path / "cover.png", color=(10, 20, 30, 1), mode="RGBA")
    stego = save_image(tmp_path / "stego.png", color=(10, 20, 30, 250), mode="RGBA")
    cover_output = tmp_path / "figures" / "cover_histogram.png"
    combined_output = tmp_path / "figures" / "combined_histogram.png"

    histogram = rgb_histogram(cover)
    assert histogram["red"][10] == 256
    assert histogram_distance(cover, stego) == {"red": 0.0, "green": 0.0, "blue": 0.0}
    assert generate_rgb_histogram(cover, cover_output) == cover_output
    assert generate_combined_histogram(cover, stego, combined_output) == combined_output
    assert cover_output.exists() and combined_output.exists()
    with pytest.raises(FileExistsError, match="Refusing to overwrite"):
        generate_rgb_histogram(cover, cover_output)


def test_difference_map_and_statistics(tmp_path):
    cover = save_image(tmp_path / "cover.png", color=(10, 20, 30, 1), mode="RGBA")
    stego = save_image(tmp_path / "stego.png", color=(10, 20, 30, 250), mode="RGBA")
    assert difference_statistics(cover, stego)["changed_pixels"] == 0

    changed = Image.open(stego).convert("RGBA")
    changed.putpixel((0, 0), (11, 20, 30, 250))
    changed.save(stego)
    output = tmp_path / "figures" / "amplified_difference.png"
    result = generate_difference_map(cover, stego, output, amplification=64)

    assert result["output_path"] == output
    assert result["changed_pixels"] == 1
    assert result["changed_channels"] == 1
    assert result["maximum_absolute_difference"] == 1
    assert output.exists()


def test_difference_map_dimension_mismatch(tmp_path):
    cover = save_image(tmp_path / "cover.png", size=(16, 16))
    stego = save_image(tmp_path / "stego.png", size=(15, 16))

    with pytest.raises(ValueError, match="same dimensions"):
        generate_difference_map(cover, stego, tmp_path / "difference.png")


def test_benchmark_helpers_use_temporary_directories(tmp_path):
    csv_dir, figure_dir = ensure_result_directories(tmp_path / "results")
    images = generate_representative_images(tmp_path / "generated", size=(32, 32))
    assert set(images) == {"smooth", "textured", "edge-heavy"}
    assert all(path.exists() for path in images.values())
    assert csv_dir.exists() and figure_dir.exists()

    row = {column: 0 for column in BENCHMARK_COLUMNS}
    row.update({"method": "basic", "payload_percent": 10, "psnr": 50, "ssim": 0.99, "encode_time_seconds": 0.01, "changed_pixel_percent": 1})
    csv_path = write_csv_rows(csv_dir / "schema.csv", BENCHMARK_COLUMNS, [row])
    with csv_path.open(newline="", encoding="utf-8") as handle:
        assert next(csv.reader(handle)) == BENCHMARK_COLUMNS
    figures = plot_benchmark_results([row], figure_dir)
    assert len(figures) == 4
    assert all(path.exists() for path in figures)


@pytest.mark.parametrize(("name", "spec"), transformation_specs())
def test_robustness_transformation_helpers(tmp_path, name, spec):
    source = save_image(tmp_path / "source.png", size=(24, 24))
    suffix = ".jpg" if spec.get("format") == "JPEG" else ".bmp" if spec.get("format") == "BMP" else ".png"

    output = apply_transformation(source, tmp_path / f"{name}{suffix}", spec)

    assert output.exists()
    Image.open(output).verify()


def test_robustness_csv_schema(tmp_path):
    row = {column: "" for column in ROBUSTNESS_COLUMNS}
    output = write_robustness_csv(tmp_path / "results" / "robustness.csv", [row])

    with output.open(newline="", encoding="utf-8") as handle:
        assert next(csv.reader(handle)) == ROBUSTNESS_COLUMNS
