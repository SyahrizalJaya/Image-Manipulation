from __future__ import annotations

import math
import tempfile
from pathlib import Path

from analysis import analyze_image_lsb
from decoder import decode_basic, decode_edge_adaptive, decode_randomized
from encoder import encode_basic, encode_edge_adaptive, encode_randomized
from metrics import evaluate_quality
from utils import (
    HiddenMessageNotFoundError,
    MessageTooLargeError,
    SteganographyError,
    WrongPasswordError,
    aes_available,
    human_size,
    load_image,
    payload_capacity_bytes,
)


def prompt_path(label: str) -> str:
    return input(label).strip().strip('"')


def prompt_yes_no(label: str, default: bool = False) -> bool:
    suffix = "Y/n" if default else "y/N"
    value = input(f"{label} ({suffix}): ").strip().lower()
    if not value:
        return default
    return value in {"y", "yes"}


def print_warnings(warnings: list[str]) -> None:
    for warning in warnings:
        print(f"Warning: {warning}")


def print_capacity(report: dict) -> None:
    print(f"Payload capacity: {human_size(int(report['payload_capacity_bytes']))}")
    print(f"Payload used: {human_size(int(report['payload_used_bytes']))}")
    print(f"Capacity used: {report['capacity_used_percent']:.4f}%")


def print_payload_summary(result: dict) -> None:
    print(f"AES encrypted: {'yes' if result['encrypted'] else 'no'}")
    print(f"Compression used: {'yes' if result['compressed'] else 'no'}")
    print(f"Original message: {human_size(result['original_message_bytes'])}")
    print(f"Stored payload: {human_size(result['stored_payload_bytes'])}")
    print(f"Size reduction: {result['compression_reduction_percent']:.2f}%")


def basic_encode_menu() -> None:
    input_path = prompt_path("Input image path: ")
    output_path = prompt_path("Output image path (leave blank for auto): ") or None
    message = input("Secret message: ")
    use_compression = prompt_yes_no("Use adaptive compression?", default=True)
    use_aes = prompt_yes_no("Encrypt with AES-GCM?", default=False)
    password = input("AES password: ") if use_aes else None

    result = encode_basic(
        input_path,
        output_path,
        message,
        use_aes=use_aes,
        password=password,
        use_compression=use_compression,
    )
    print_warnings(result["warnings"])
    print(f"Saved stego image: {result['output_path']}")
    print(f"Input format: {result['input_format']} -> saved as {result['save_format']}")
    print_payload_summary(result)
    print_capacity(result["capacity"])


def basic_decode_menu() -> None:
    image_path = prompt_path("Stego image path: ")
    password = input("AES password if encrypted (leave blank if not encrypted): ") or None
    message = decode_basic(image_path, password=password)
    print("\nDecoded message:")
    print(message)


def randomized_encode_menu() -> None:
    input_path = prompt_path("Input image path: ")
    output_path = prompt_path("Output image path (leave blank for auto): ") or None
    key = input("Password/key: ")
    message = input("Secret message: ")
    use_compression = prompt_yes_no("Use adaptive compression?", default=True)
    use_aes = prompt_yes_no("Encrypt with AES-GCM?", default=True)
    result = encode_randomized(
        input_path,
        output_path,
        message,
        key,
        use_aes=use_aes,
        use_compression=use_compression,
    )
    print_warnings(result["warnings"])
    print(f"Saved stego image: {result['output_path']}")
    print(f"Input format: {result['input_format']} -> saved as {result['save_format']}")
    print_payload_summary(result)
    print_capacity(result["capacity"])


def randomized_decode_menu() -> None:
    image_path = prompt_path("Stego image path: ")
    key = input("Password/key: ")
    message = decode_randomized(image_path, key)
    print("\nDecoded message:")
    print(message)


def edge_encode_menu() -> None:
    input_path = prompt_path("Input image path: ")
    output_path = prompt_path("Output image path (leave blank for auto): ") or None
    message = input("Secret message: ")
    use_compression = prompt_yes_no("Use adaptive compression?", default=True)
    use_aes = prompt_yes_no("Encrypt with AES-GCM?", default=True)
    password = input("AES password: ") if use_aes else None
    result = encode_edge_adaptive(
        input_path,
        output_path,
        message,
        use_aes=use_aes,
        password=password,
        use_compression=use_compression,
    )
    print_warnings(result["warnings"])
    print(f"Saved stego image: {result['output_path']}")
    print(f"Input format: {result['input_format']} -> saved as {result['save_format']}")
    print_payload_summary(result)
    print_capacity(result["capacity"])


def edge_decode_menu() -> None:
    image_path = prompt_path("Stego image path: ")
    password = input("AES password if encrypted (leave blank if not encrypted): ") or None
    message = decode_edge_adaptive(image_path, password=password)
    print("\nDecoded message:")
    print(message)


def analysis_menu() -> None:
    image_path = prompt_path("Image path: ")
    result = analyze_image_lsb(image_path)
    print("\nLSB steganalysis report:")
    print(f"Format: {result['format']}")
    print(f"Dimensions: {result['dimensions'][0]} x {result['dimensions'][1]}")
    print(f"One-bit ratio: {result['ones_ratio']:.4f}")
    print(f"LSB entropy: {result['entropy']:.4f} / 1.0000")
    print(f"Suspicion level: {result['suspicion']}")
    print(result["explanation"])
    print("Per-channel one-bit ratios:")
    for channel in result["channels"]:
        print(f"- {channel['name']}: {channel['ones_ratio']:.4f}")


def robustness_demo(stego_path: str, method: str, key: str | None) -> None:
    print("\nRobustness demo:")
    print("This writes conversions into a temporary directory and deletes them automatically.")

    if method == "random":
        decode_fn = lambda path, password=None: decode_randomized(path, key or "")
    elif method == "edge":
        decode_fn = lambda path, password=None: decode_edge_adaptive(path, password=key)
    else:
        decode_fn = decode_basic
    try:
        original_message = decode_fn(stego_path, key)
        print("Original stego decode: works")
    except Exception as exc:
        print(f"Original stego decode: failed ({exc})")
        original_message = None

    if original_message is None:
        return

    with tempfile.TemporaryDirectory() as temp_dir:
        source, _ = load_image(stego_path)
        rgb = source.convert("RGB")
        tests = [
            ("PNG conversion", Path(temp_dir) / "converted.png", {"format": "PNG"}),
            ("BMP conversion", Path(temp_dir) / "converted.bmp", {"format": "BMP"}),
            ("JPEG compression", Path(temp_dir) / "compressed.jpg", {"format": "JPEG", "quality": 85}),
        ]
        for label, path, save_kwargs in tests:
            try:
                rgb.save(path, **save_kwargs)
                decoded = decode_fn(path, key)
                status = "works" if decoded == original_message else "decoded different text"
            except Exception:
                status = "failed"
            print(f"{label}: {status}")


def quality_menu() -> None:
    original_path = prompt_path("Original image path: ")
    stego_path = prompt_path("Stego image path: ")
    payload_text = input("Payload size in bytes if known (leave blank for 0): ").strip()
    payload_size = int(payload_text) if payload_text.isdigit() else 0
    result = evaluate_quality(original_path, stego_path, payload_size=payload_size)

    print("\nImage quality:")
    print(f"Formats: {result['original_format']} -> {result['stego_format']}")
    print(f"Dimensions: {result['dimensions'][0]} x {result['dimensions'][1]}")
    print(f"MSE: {result['mse']:.6f}")
    psnr = result["psnr"]
    print(f"PSNR: {'infinite' if math.isinf(psnr) else f'{psnr:.2f} dB'}")
    print(f"SSIM: {result['ssim']:.6f}")
    print_capacity(result["capacity"])

    if prompt_yes_no("Run robustness/demo conversion tests?", default=True):
        method_choice = input("Decode method for test (basic/random/edge, leave blank to skip decode tests): ").strip().lower()
        if method_choice in {"basic", "b"}:
            key = input("AES password if encrypted (leave blank if not encrypted): ") or None
            robustness_demo(stego_path, "basic", key)
        elif method_choice in {"random", "randomized", "r"}:
            key = input("Password/key used for randomized LSB: ")
            robustness_demo(stego_path, "random", key)
        elif method_choice in {"edge", "e"}:
            key = input("AES password if encrypted (leave blank if not encrypted): ") or None
            robustness_demo(stego_path, "edge", key)
        else:
            print("Skipped decode-based robustness tests.")


def show_capacity_hint() -> None:
    path = prompt_path("Image path for capacity check (leave blank to skip): ")
    if not path:
        return
    image, fmt = load_image(path)
    print(f"Format: {fmt}")
    print(f"Approximate UTF-8 payload capacity: {human_size(payload_capacity_bytes(image))}")
    if fmt == "JPEG":
        print("Warning: JPEG is lossy. This demo saves JPEG inputs as PNG for reliable LSB embedding.")


def menu() -> None:
    print("\nImage Steganography Demo")
    print("[1] Basic LSB Encode")
    print("[2] Basic LSB Decode")
    print("[3] Advanced Randomized LSB Encode")
    print("[4] Advanced Randomized LSB Decode")
    print("[5] Edge-Adaptive LSB Encode")
    print("[6] Edge-Adaptive LSB Decode")
    print("[7] Image Quality Evaluation")
    print("[8] LSB Steganalysis")
    print("[9] Launch Desktop App")
    print("[10] Exit")


def launch_desktop_app() -> None:
    try:
        from app import run_app
    except ImportError as exc:
        print(f"Error: Could not load desktop app: {exc}")
        return
    run_app()


def main() -> None:
    while True:
        menu()
        choice = input("Choose an option: ").strip()
        try:
            if choice == "1":
                basic_encode_menu()
            elif choice == "2":
                basic_decode_menu()
            elif choice == "3":
                randomized_encode_menu()
            elif choice == "4":
                randomized_decode_menu()
            elif choice == "5":
                edge_encode_menu()
            elif choice == "6":
                edge_decode_menu()
            elif choice == "7":
                quality_menu()
            elif choice == "8":
                analysis_menu()
            elif choice == "9":
                launch_desktop_app()
            elif choice == "10":
                print("Goodbye.")
                break
            elif choice.lower() in {"capacity", "c"}:
                show_capacity_hint()
            else:
                print("Invalid option. Please choose 1-10.")
        except (FileNotFoundError, MessageTooLargeError, HiddenMessageNotFoundError, WrongPasswordError, ValueError) as exc:
            print(f"Error: {exc}")
        except SteganographyError as exc:
            print(f"Error: {exc}")
        except KeyboardInterrupt:
            print("\nCancelled.")


if __name__ == "__main__":
    main()
