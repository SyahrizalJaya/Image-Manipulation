from __future__ import annotations

from pathlib import Path
from typing import Iterable

from PIL import Image

from utils import (
    METHOD_BASIC,
    METHOD_EDGE,
    METHOD_RANDOM,
    aes_available,
    build_header,
    bytes_to_bits,
    capacity_report,
    encrypt_payload,
    ensure_capacity,
    edge_adaptive_positions,
    prepare_image_for_lsb,
    randomized_positions,
    resolve_output_path,
    save_stego_image,
    sequential_positions,
    set_lsb_at_position,
    load_image,
)


def _embed_bits(image: Image.Image, bits: list[int], positions: Iterable[int]) -> Image.Image:
    stego = prepare_image_for_lsb(image)
    pixels = bytearray(stego.tobytes())
    for bit, position in zip(bits, positions):
        set_lsb_at_position(pixels, position, bit)
    return Image.frombytes("RGB", stego.size, bytes(pixels))


def _prepare_payload(message: str, password: str | None, use_aes: bool) -> tuple[bytes, bytes, bytes, bool, list[str]]:
    warnings: list[str] = []
    if use_aes:
        if aes_available():
            if not password:
                warnings.append("AES encryption requested but no password was supplied; embedding plain UTF-8 text.")
                return message.encode("utf-8"), bytes(16), bytes(12), False, warnings
            payload, salt, nonce = encrypt_payload(message, password)
            return payload, salt, nonce, True, warnings
        warnings.append("AES encryption skipped because the 'cryptography' package is not installed.")
    return message.encode("utf-8"), bytes(16), bytes(12), False, warnings


def encode_basic(
    input_path: str | Path,
    output_path: str | Path | None,
    message: str,
    use_aes: bool = False,
    password: str | None = None,
) -> dict:
    image, input_format = load_image(input_path)
    payload, salt, nonce, encrypted, warnings = _prepare_payload(message, password, use_aes)
    ensure_capacity(image, len(payload))
    header = build_header(METHOD_BASIC, encrypted, salt, nonce, len(payload))
    bits = bytes_to_bits(header + payload)
    stego = _embed_bits(image, bits, sequential_positions(image, len(bits)))
    output, save_format, format_warnings = resolve_output_path(input_path, output_path, input_format)
    save_stego_image(stego, output, save_format)
    report = capacity_report(image, len(payload))
    return {
        "output_path": output,
        "input_format": input_format,
        "save_format": save_format,
        "encrypted": encrypted,
        "warnings": warnings + format_warnings,
        "capacity": report,
    }


def encode_randomized(
    input_path: str | Path,
    output_path: str | Path | None,
    message: str,
    key: str,
    use_aes: bool = False,
) -> dict:
    if not key:
        raise ValueError("Randomized LSB requires a password/key.")
    image, input_format = load_image(input_path)
    payload, salt, nonce, encrypted, warnings = _prepare_payload(message, key, use_aes)
    ensure_capacity(image, len(payload))
    header = build_header(METHOD_RANDOM, encrypted, salt, nonce, len(payload))
    bits = bytes_to_bits(header + payload)
    stego = _embed_bits(image, bits, randomized_positions(image, key, len(bits)))
    output, save_format, format_warnings = resolve_output_path(input_path, output_path, input_format)
    save_stego_image(stego, output, save_format)
    report = capacity_report(image, len(payload))
    return {
        "output_path": output,
        "input_format": input_format,
        "save_format": save_format,
        "encrypted": encrypted,
        "warnings": warnings + format_warnings,
        "capacity": report,
    }


def encode_edge_adaptive(
    input_path: str | Path,
    output_path: str | Path | None,
    message: str,
    use_aes: bool = False,
    password: str | None = None,
) -> dict:
    image, input_format = load_image(input_path)
    payload, salt, nonce, encrypted, warnings = _prepare_payload(message, password, use_aes)
    ensure_capacity(image, len(payload))
    header = build_header(METHOD_EDGE, encrypted, salt, nonce, len(payload))
    bits = bytes_to_bits(header + payload)
    stego = _embed_bits(image, bits, edge_adaptive_positions(image, len(bits)))
    output, save_format, format_warnings = resolve_output_path(input_path, output_path, input_format)
    save_stego_image(stego, output, save_format)
    report = capacity_report(image, len(payload))
    return {
        "output_path": output,
        "input_format": input_format,
        "save_format": save_format,
        "encrypted": encrypted,
        "warnings": warnings + format_warnings,
        "capacity": report,
    }


def encode_message(image_path, secret_message, output_path):
    """Backward-compatible wrapper for the original project workflow."""
    result = encode_basic(image_path, output_path, secret_message)
    for warning in result["warnings"]:
        print(f"[WARNING] {warning}")
    print("[OK] Encoding successful!")
    print(f"     - Cover image : {image_path}")
    print(f"     - Stego-image : {result['output_path']}")
    print(f"     - Format      : {result['input_format']} -> {result['save_format']}")
    print(f"     - Capacity    : {result['capacity']['capacity_used_percent']:.4f}% used")
    return str(result["output_path"])
