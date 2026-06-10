# Image Steganography Demo

This project is a Python image steganography demo with basic sequential LSB, password-randomized LSB, edge-adaptive LSB, image quality metrics, robustness testing, and simple LSB steganalysis. It includes both a terminal menu and a small desktop app.

## Installation

```bash
python -m pip install pillow
```

Optional AES encryption uses `cryptography`:

```bash
python -m pip install cryptography
```

If `cryptography` is not installed, the program still runs and clearly warns that AES encryption was skipped.

## Run

```bash
python main.py
```

To open the desktop app directly:

```bash
python app.py
```

Menu:

```text
[1] Basic LSB Encode
[2] Basic LSB Decode
[3] Advanced Randomized LSB Encode
[4] Advanced Randomized LSB Decode
[5] Edge-Adaptive LSB Encode
[6] Edge-Adaptive LSB Decode
[7] Image Quality Evaluation
[8] LSB Steganalysis
[9] Launch Desktop App
[10] Exit
```

## Desktop App

The desktop app uses Python's built-in Tkinter library. It provides tabs for:

- encoding an image
- decoding a hidden message
- checking image quality
- running a conversion/compression robustness demo
- analyzing LSB statistics for simple steganalysis

You can launch it from the terminal menu with option `9`, or directly with `python app.py`.

## Supported Formats

Input formats:

- PNG
- JPG / JPEG
- BMP
- TIFF
- WEBP, if your Pillow installation supports it

The program keeps the same output format when it is safe:

- PNG saves as PNG.
- BMP saves as BMP.
- TIFF saves as TIFF.
- WEBP saves as lossless WEBP.
- JPEG/JPG inputs are automatically saved as PNG for steganography output, because JPEG compression is lossy and usually destroys LSB data.

## Steganography Methods

Basic LSB stores the hidden message in the least significant bits of image channels in normal sequential order. It is easy to understand and useful for demonstrating the core idea, but it is also easy to detect or attack.

Advanced Randomized LSB asks for a password/key. The key generates a deterministic random pixel/channel order, so the same key is required for decoding. This is more secure than sequential LSB because the hidden bits are scattered across the image instead of being placed from the beginning.

Edge-Adaptive LSB ranks pixels by local edge/detail strength and hides data in the strongest-detail areas first. Small changes are less visible in textured or edge-heavy regions, so this method improves imperceptibility compared with simply writing from the start of the image.

If AES is enabled and `cryptography` is installed, the message is encrypted before embedding. With randomized LSB, the same password/key is used for the random order and AES encryption.

## Demo Flow

Start the menu:

```bash
python main.py
```

Basic encode:

```text
Choose an option: 1
Input image path: sample.png
Output image path (leave blank for auto):
Secret message: Hello from UTF-8: 你好
Encrypt with AES if available? (y/N): n
```

Basic decode:

```text
Choose an option: 2
Stego image path: sample_stego.png
AES password if encrypted (leave blank if not encrypted):
```

Randomized encode:

```text
Choose an option: 3
Input image path: sample.bmp
Output image path (leave blank for auto):
Password/key: my-secret-key
Secret message: randomized secret
Encrypt with AES if available? (Y/n): y
```

Randomized decode:

```text
Choose an option: 4
Stego image path: sample_stego.bmp
Password/key: my-secret-key
```

Quality evaluation:

```text
Choose an option: 5
Original image path: sample.png
Stego image path: sample_stego.png
Payload size in bytes if known (leave blank for 0):
Run robustness/demo conversion tests? (Y/n): y
```

## Quality Metrics

The quality menu reports:

- MSE
- PSNR
- total LSB channel capacity
- usable payload capacity
- payload bytes used
- percentage of capacity used

It can also run a robustness demo by converting the stego image to PNG, BMP, and compressed JPEG in a temporary folder. Temporary files are deleted automatically after the test.

## Steganalysis

The Steganalysis tab inspects the least significant bit plane and reports:

- zero/one bit counts
- one-bit ratio
- LSB entropy
- per-channel ratios
- a simple low/medium/high suspicion estimate

This is a teaching/demo feature, not proof that an image does or does not contain hidden data. It is useful for showing that encrypted or randomized payloads can make the LSB plane look more statistically random.

## Limitations

- LSB steganography is fragile under lossy compression, resizing, filtering, screenshots, or social media re-encoding.
- JPEG is especially unsafe for direct LSB embedding because saving JPEG changes pixel values. This project warns about JPEG and saves a PNG stego copy instead.
- Randomized and edge-adaptive LSB improve the basic method, but they are still not full steganalysis-resistant systems.
- AES protects the message content only when `cryptography` is installed and encryption is enabled.
- Decoding requires the correct method. A basic decode will not decode a randomized message, and randomized decode requires the same key used for encoding.
