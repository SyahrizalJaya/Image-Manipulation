from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Iterable

from utils import (
    HEADER_BITS,
    HEADER_SIZE,
    LEGACY_HEADER_BITS,
    LEGACY_HEADER_SIZE,
    METHOD_BASIC,
    METHOD_EDGE,
    METHOD_RANDOM,
    VERSION,
    AuthenticationError,
    HeaderError,
    bits_to_bytes,
    decrypt_payload,
    decompress_payload,
    edge_adaptive_positions,
    get_lsb_at_position,
    load_image,
    parse_header,
    prepare_image_for_lsb,
    randomized_positions,
    sequential_positions,
    validate_payload_length,
)


def _read_bits_from_pixels(pixels: bytes, positions: Iterable[int]) -> list[int]:
    return [get_lsb_at_position(pixels, position) for position in positions]


def _read_new_header(image, pixels: bytes, expected_method: int):
    bits = _read_bits_from_pixels(pixels, sequential_positions(image, HEADER_BITS))
    header = parse_header(bits_to_bytes(bits), expected_method=expected_method)
    if header.version != VERSION:
        raise HeaderError("Legacy header requires legacy extraction.")
    validate_payload_length(image, header)
    return header


def _decode_new(image_path: str | Path, expected_method: int, password: str | None) -> str:
    image, _ = load_image(image_path)
    rgb = prepare_image_for_lsb(image)
    pixels = rgb.tobytes()
    header = _read_new_header(image, pixels, expected_method)
    bit_count = header.payload_length * 8
    if expected_method == METHOD_RANDOM:
        if not password:
            raise AuthenticationError("Randomized LSB decoding requires the original password/key.")
        positions = randomized_positions(image, password, bit_count, salt=header.salt, start=HEADER_BITS)
    elif expected_method == METHOD_EDGE:
        positions = edge_adaptive_positions(image, bit_count, start=HEADER_BITS)
    else:
        positions = sequential_positions(image, bit_count, start=HEADER_BITS)
    payload = bits_to_bytes(_read_bits_from_pixels(pixels, positions))
    return _decode_payload(payload, header, password)


def _decode_legacy(image_path: str | Path, expected_method: int, password: str | None) -> str:
    image, _ = load_image(image_path)
    rgb = prepare_image_for_lsb(image)
    pixels = rgb.tobytes()
    if expected_method == METHOD_RANDOM:
        if not password:
            raise AuthenticationError("Randomized LSB decoding requires the original password/key.")
        header_positions = randomized_positions(image, password, LEGACY_HEADER_BITS)
    elif expected_method == METHOD_EDGE:
        header_positions = edge_adaptive_positions(image, LEGACY_HEADER_BITS)
    else:
        header_positions = sequential_positions(image, LEGACY_HEADER_BITS)
    header = parse_header(bits_to_bytes(_read_bits_from_pixels(pixels, header_positions)), expected_method)
    validate_payload_length(image, header)
    total_bits = (LEGACY_HEADER_SIZE + header.payload_length) * 8
    if expected_method == METHOD_RANDOM:
        all_positions = randomized_positions(image, password or "", total_bits)
    elif expected_method == METHOD_EDGE:
        all_positions = edge_adaptive_positions(image, total_bits)
    else:
        all_positions = sequential_positions(image, total_bits)
    payload_bits = _read_bits_from_pixels(pixels, all_positions)[LEGACY_HEADER_BITS:]
    return _decode_payload(bits_to_bytes(payload_bits), header, password)


def _decode_with_fallback(image_path: str | Path, expected_method: int, password: str | None) -> str:
    try:
        return _decode_new(image_path, expected_method, password)
    except HeaderError as new_error:
        try:
            return _decode_legacy(image_path, expected_method, password)
        except HeaderError:
            raise new_error


def _decode_payload(payload: bytes, header, password: str | None = None) -> str:
    if header.encrypted:
        payload = decrypt_payload(
            payload,
            password or "",
            header.salt,
            header.nonce,
            legacy=header.version != VERSION,
        )
    elif header.version == VERSION and hashlib.sha256(payload).digest() != header.payload_digest:
        raise HeaderError("Plaintext payload integrity verification failed.")
    if header.compressed:
        payload = decompress_payload(payload)
    if header.version == VERSION and len(payload) != header.original_length:
        raise HeaderError("Recovered message length does not match the header.")
    try:
        return payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise HeaderError("Recovered payload is not valid UTF-8.") from exc


def decode_basic(image_path: str | Path, password: str | None = None) -> str:
    return _decode_with_fallback(image_path, METHOD_BASIC, password)


def decode_randomized(image_path: str | Path, key: str) -> str:
    if not key:
        raise AuthenticationError("Randomized LSB decoding requires the same password/key used for encoding.")
    return _decode_with_fallback(image_path, METHOD_RANDOM, key)


def decode_edge_adaptive(image_path: str | Path, password: str | None = None) -> str:
    return _decode_with_fallback(image_path, METHOD_EDGE, password)


def decode_message(stego_image_path):
    """Backward-compatible wrapper for the original project workflow."""
    message = decode_basic(stego_image_path)
    print("[OK] Decoding successful!")
    print(f"     - Stego-image : {stego_image_path}")
    print(f"     - Message     : {len(message)} characters found")
    return message
