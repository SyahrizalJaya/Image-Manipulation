# Image Manipulation: LSB Steganography Desktop App

Image Manipulation is an academic Python desktop application for hiding and
recovering text messages inside lossless images using Least Significant Bit
(LSB) steganography. It includes a Tkinter GUI, a terminal menu, quality
metrics, visual analysis tools, and controlled benchmark scripts.

The project keeps the core modules in the repository root so existing commands
and imports remain simple for presentation use.

## Main Features

- Basic sequential LSB.
- Password-randomized LSB with salt-derived position ordering.
- Edge-adaptive LSB that prioritizes high-detail regions.
- AES-GCM encryption with fail-closed password and dependency validation.
- Adaptive zlib compression that is used only when it reduces payload size.
- Structured header v2 with method, flags, salt, nonce, payload length, and
  integrity checks.
- Legacy v1 decoding compatibility.
- UTF-8 and emoji support.
- PNG stego output with alpha preservation where practical.
- MSE, PSNR, SSIM, BER, capacity, and runtime reporting.
- RGB histogram comparison and amplified pixel-difference maps.
- Benchmark and robustness scripts.
- Presentation-ready desktop GUI.

## Folder Structure

```text
Image-Manipulation/
|-- app.py
|-- main.py
|-- encoder.py
|-- decoder.py
|-- utils.py
|-- metrics.py
|-- analysis.py
|-- requirements.txt
|-- README.md
|-- .gitignore
|-- images/
|   |-- input/
|   `-- output/
|-- results/
|   |-- csv/
|   `-- figures/
|-- experiments/
|   |-- __init__.py
|   |-- benchmark.py
|   `-- robustness_benchmark.py
|-- tests/
|-- docs/
|   |-- repository_audit.md
|   |-- gui_smoke_test.md
|   |-- experiment_guide.md
|   |-- architecture.md
|   |-- demo_guide.md
|   |-- validation_report.md
|   |-- final_experiment_summary.md
|   `-- project_structure.md
|-- cleanup_archive/
`-- codex_plan/
```

See `docs/project_structure.md` for a short explanation of each folder.

## Installation

From the repository root:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

## Run the Desktop GUI

```powershell
.\.venv\Scripts\python.exe app.py
```

The GUI supports encoding, decoding, quality checks, image previews, histogram
generation, amplified difference maps, and CSV export for analysis results.

## Run the CLI

```powershell
.\.venv\Scripts\python.exe main.py
```

The CLI keeps the original menu workflow for quick demos and compatibility.

## Run Tests

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

The test suite uses generated temporary images and does not require private
assets.

## Run Benchmark

```powershell
.\.venv\Scripts\python.exe experiments\benchmark.py
```

This compares Basic, Password-randomized, and Edge-adaptive LSB across smooth,
textured, and edge-heavy generated images at 10%, 25%, 50%, and 75% payload
levels.

## Run Robustness Benchmark

```powershell
.\.venv\Scripts\python.exe experiments\robustness_benchmark.py
```

This applies controlled transformations such as PNG re-save, BMP conversion,
JPEG compression, resizing, blur, and light image noise.

## Output Folders

- `images/output/` stores demo stego images.
- `results/csv/` stores benchmark and robustness CSV files.
- `results/figures/` stores generated benchmark charts and analysis figures.
- `cleanup_archive/` stores intermediate generated experiment images that are
  not required for the final presentation folder.

Expected experiment outputs include:

- `results/csv/benchmark_results.csv`
- `results/csv/robustness_results.csv`
- `results/figures/psnr_versus_payload.png`
- `results/figures/ssim_versus_payload.png`
- `results/figures/encoding_time_versus_payload.png`
- `results/figures/changed_pixels_versus_payload.png`

## Short Demo Workflow

1. Open the GUI.
2. Select a PNG cover image from `images/input/`.
3. Enter a short secret message.
4. Choose Edge-adaptive LSB.
5. Enable AES-GCM encryption and adaptive compression.
6. Enter a password and encode.
7. Review MSE, PSNR, SSIM, capacity, runtime, and previews.
8. Decode the generated stego image with the same password.
9. Open the Analysis tab and show quality metrics, LSB statistics, histogram,
   and amplified difference map.

## Metrics and Analysis

- MSE measures mean squared RGB-channel error. Lower is better.
- PSNR uses maximum pixel value 255. Higher is generally better.
- SSIM estimates structural similarity. Values near 1 indicate high similarity.
- BER is used only in controlled experiments where the expected payload is
  known.
- Histograms compare RGB intensity distributions and ignore alpha.
- Difference maps amplify absolute RGB differences for visualization.

## Security and Limitations

- AES-GCM protects message confidentiality and integrity when encryption is
  enabled, but this is still an academic demonstration.
- LSB steganography is fragile under JPEG compression, resizing, blur, noise,
  screenshots, and social-media recompression.
- JPEG cover images are accepted, but stego output is saved as PNG.
- Histogram analysis and LSB statistics are educational indicators only, not
  definitive steganalysis.
- This project is a presentation-ready academic desktop application, not
  production security software.

## Documentation

- `docs/architecture.md` explains the module design and workflows.
- `docs/demo_guide.md` provides a 3-5 minute presentation plan.
- `docs/validation_report.md` records the final validation status.
- `docs/final_experiment_summary.md` summarizes benchmark and robustness CSV
  results.
- `docs/project_structure.md` explains the cleaned repository layout.
- `docs/repository_audit.md` records the initial repository audit.
- `docs/gui_smoke_test.md` records GUI smoke-test coverage.
- `docs/experiment_guide.md` explains benchmark and robustness experiments.
