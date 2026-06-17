from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from PIL import Image

from utils import (
    HEADER_BITS,
    METHOD_BASIC,
    METHOD_EDGE,
    METHOD_RANDOM,
    NONCE_SIZE,
    SALT_SIZE,
    AuthenticationError,
    adaptive_compress,
    apply_visible_watermark,
    aes_available,
    build_header,
    bytes_to_bits,
    capacity_report,
    edge_adaptive_positions,
    encrypt_payload,
    ensure_capacity,
    load_image,
    prepare_image_for_lsb,
    randomized_positions,
    resolve_output_path,
    restore_alpha,
    save_stego_image,
    sequential_positions,
    set_lsb_at_position,
)


@dataclass(frozen=True)
class PreparedPayload:
    payload: bytes
    salt: bytes
    nonce: bytes
    encrypted: bool
    compressed: bool
    original_bytes: int
    stored_bytes: int
    compression_reduction_percent: float
    digest: bytes


def _embed_bits(image: Image.Image, bits: list[int], positions: Iterable[int]) -> Image.Image:
    stego = prepare_image_for_lsb(image)
    pixels = bytearray(stego.tobytes())
    for bit, position in zip(bits, positions):
        set_lsb_at_position(pixels, position, bit)
    return Image.frombytes("RGB", stego.size, bytes(pixels))


def _embed_header_and_payload(
    image: Image.Image,
    header: bytes,
    payload: bytes,
    payload_positions: Iterable[int],
) -> Image.Image:
    stego = _embed_bits(image, bytes_to_bits(header), sequential_positions(image, len(header) * 8))
    stego = _embed_bits(stego, bytes_to_bits(payload), payload_positions)
    return restore_alpha(stego, image)


def _prepare_payload(
    message: str,
    password: str | None,
    use_aes: bool,
    use_compression: bool,
    salt: bytes | None = None,
) -> PreparedPayload:
    if not message:
        raise ValueError("Message cannot be empty.")
    original = message.encode("utf-8")
    stored, compressed = adaptive_compress(original, enabled=use_compression)
    reduction = ((len(original) - len(stored)) / len(original) * 100) if compressed else 0.0
    salt = salt or os.urandom(SALT_SIZE)
    nonce = bytes(NONCE_SIZE)
    encrypted = False
    if use_aes:
        if not password:
            raise AuthenticationError("AES encryption requires a non-empty password.")
        if not aes_available():
            raise AuthenticationError("AES encryption requires the 'cryptography' package.")
        stored, salt, nonce = encrypt_payload(stored, password, salt=salt)
        encrypted = True
    digest = bytes(32) if encrypted else hashlib.sha256(stored).digest()
    return PreparedPayload(
        payload=stored,
        salt=salt,
        nonce=nonce,
        encrypted=encrypted,
        compressed=compressed,
        original_bytes=len(original),
        stored_bytes=len(stored),
        compression_reduction_percent=reduction,
        digest=digest,
    )


def _result(
    image: Image.Image,
    input_format: str,
    output: Path,
    payload: PreparedPayload,
    warnings: list[str],
    visible_watermark: bool = False,
) -> dict:
    return {
        "output_path": output,
        "input_format": input_format,
        "save_format": "PNG",
        "encrypted": payload.encrypted,
        "compressed": payload.compressed,
        "visible_watermark": visible_watermark,
        "original_message_bytes": payload.original_bytes,
        "stored_payload_bytes": payload.stored_bytes,
        "compression_reduction_percent": payload.compression_reduction_percent,
        "warnings": warnings,
        "capacity": capacity_report(image, payload.stored_bytes),
    }


def encode_basic(
    input_path: str | Path,
    output_path: str | Path | None,
    message: str,
    use_aes: bool = False,
    password: str | None = None,
    use_compression: bool = True,
    visible_watermark_text: str | None = None,
) -> dict:
    image, input_format = load_image(input_path)
    if visible_watermark_text:
        image = apply_visible_watermark(image, visible_watermark_text)
    prepared = _prepare_payload(message, password, use_aes, use_compression)
    ensure_capacity(image, prepared.stored_bytes)
    header = build_header(
        METHOD_BASIC,
        prepared.encrypted,
        prepared.salt,
        prepared.nonce,
        prepared.stored_bytes,
        prepared.compressed,
        prepared.original_bytes,
        prepared.digest,
    )
    positions = sequential_positions(image, prepared.stored_bytes * 8, start=HEADER_BITS)
    stego = _embed_header_and_payload(image, header, prepared.payload, positions)
    output, _, warnings = resolve_output_path(input_path, output_path, input_format)
    save_stego_image(stego, output)
    return _result(image, input_format, output, prepared, warnings, bool(visible_watermark_text))


def encode_randomized(
    input_path: str | Path,
    output_path: str | Path | None,
    message: str,
    key: str,
    use_aes: bool = False,
    use_compression: bool = True,
    visible_watermark_text: str | None = None,
) -> dict:
    if not key:
        raise AuthenticationError("Randomized LSB requires a non-empty password/key.")
    image, input_format = load_image(input_path)
    if visible_watermark_text:
        image = apply_visible_watermark(image, visible_watermark_text)
    prepared = _prepare_payload(message, key, use_aes, use_compression)
    ensure_capacity(image, prepared.stored_bytes)
    header = build_header(
        METHOD_RANDOM,
        prepared.encrypted,
        prepared.salt,
        prepared.nonce,
        prepared.stored_bytes,
        prepared.compressed,
        prepared.original_bytes,
        prepared.digest,
    )
    positions = randomized_positions(image, key, prepared.stored_bytes * 8, salt=prepared.salt, start=HEADER_BITS)
    stego = _embed_header_and_payload(image, header, prepared.payload, positions)
    output, _, warnings = resolve_output_path(input_path, output_path, input_format)
    save_stego_image(stego, output)
    return _result(image, input_format, output, prepared, warnings, bool(visible_watermark_text))


def encode_edge_adaptive(
    input_path: str | Path,
    output_path: str | Path | None,
    message: str,
    use_aes: bool = False,
    password: str | None = None,
    use_compression: bool = True,
    visible_watermark_text: str | None = None,
) -> dict:
    image, input_format = load_image(input_path)
    if visible_watermark_text:
        image = apply_visible_watermark(image, visible_watermark_text)
    prepared = _prepare_payload(message, password, use_aes, use_compression)
    ensure_capacity(image, prepared.stored_bytes)
    header = build_header(
        METHOD_EDGE,
        prepared.encrypted,
        prepared.salt,
        prepared.nonce,
        prepared.stored_bytes,
        prepared.compressed,
        prepared.original_bytes,
        prepared.digest,
    )
    positions = edge_adaptive_positions(image, prepared.stored_bytes * 8, start=HEADER_BITS)
    stego = _embed_header_and_payload(image, header, prepared.payload, positions)
    output, _, warnings = resolve_output_path(input_path, output_path, input_format)
    save_stego_image(stego, output)
    return _result(image, input_format, output, prepared, warnings, bool(visible_watermark_text))


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
