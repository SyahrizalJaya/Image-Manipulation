from __future__ import annotations

from pathlib import Path
from typing import Iterable

from utils import (
    HEADER_BITS,
    HEADER_SIZE,
    METHOD_BASIC,
    METHOD_EDGE,
    METHOD_RANDOM,
    WrongPasswordError,
    bits_to_bytes,
    decrypt_payload,
    edge_adaptive_positions,
    get_lsb_at_position,
    load_image,
    parse_header,
    prepare_image_for_lsb,
    randomized_positions,
    sequential_positions,
)


def _read_bits_from_pixels(pixels: bytes, positions: Iterable[int]) -> list[int]:
    return [get_lsb_at_position(pixels, position) for position in positions]


def _decode_basic_from_image(image_path: str | Path, expected_method: int, password: str | None = None) -> str:
    image, _ = load_image(image_path)
    rgb = prepare_image_for_lsb(image)
    pixels = rgb.tobytes()
    header_positions = sequential_positions(image, HEADER_BITS)
    header_bits = _read_bits_from_pixels(pixels, header_positions)
    header = parse_header(bits_to_bytes(header_bits), expected_method=expected_method)
    total_bits = (HEADER_SIZE + header.payload_length) * 8
    payload_positions = sequential_positions(image, total_bits)
    payload_bits = _read_bits_from_pixels(pixels, payload_positions)[HEADER_BITS:]
    return _decode_payload(payload_bits, header, password)


def _decode_random_from_image(image_path: str | Path, key: str, expected_method: int) -> str:
    image, _ = load_image(image_path)
    rgb = prepare_image_for_lsb(image)
    pixels = rgb.tobytes()
    header_positions = randomized_positions(image, key, HEADER_BITS)
    header_bits = _read_bits_from_pixels(pixels, header_positions)
    header = parse_header(bits_to_bytes(header_bits), expected_method=expected_method)
    total_bits = (HEADER_SIZE + header.payload_length) * 8
    payload_positions = randomized_positions(image, key, total_bits)
    payload_bits = _read_bits_from_pixels(pixels, payload_positions)[HEADER_BITS:]
    return _decode_payload(payload_bits, header, key)


def _decode_edge_from_image(image_path: str | Path, password: str | None = None) -> str:
    image, _ = load_image(image_path)
    rgb = prepare_image_for_lsb(image)
    pixels = rgb.tobytes()
    header_positions = edge_adaptive_positions(image, HEADER_BITS)
    header_bits = _read_bits_from_pixels(pixels, header_positions)
    header = parse_header(bits_to_bytes(header_bits), expected_method=METHOD_EDGE)
    total_bits = (HEADER_SIZE + header.payload_length) * 8
    payload_positions = edge_adaptive_positions(image, total_bits)
    payload_bits = _read_bits_from_pixels(pixels, payload_positions)[HEADER_BITS:]
    return _decode_payload(payload_bits, header, password)


def _decode_payload(payload_bits: list[int], header, password: str | None = None) -> str:
    payload = bits_to_bytes(payload_bits)

    if header.encrypted:
        if not password:
            raise WrongPasswordError("This message is encrypted. A password/key is required.")
        return decrypt_payload(payload, password, header.salt, header.nonce)
    try:
        return payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise WrongPasswordError("Payload could not be decoded as UTF-8. The image may be corrupted.") from exc


def decode_basic(image_path: str | Path, password: str | None = None) -> str:
    return _decode_basic_from_image(image_path, METHOD_BASIC, password=password)


def decode_randomized(image_path: str | Path, key: str) -> str:
    if not key:
        raise ValueError("Randomized LSB decoding requires the same password/key used for encoding.")
    return _decode_random_from_image(image_path, key, METHOD_RANDOM)


def decode_edge_adaptive(image_path: str | Path, password: str | None = None) -> str:
    return _decode_edge_from_image(image_path, password=password)


def decode_message(stego_image_path):
    """Backward-compatible wrapper for the original project workflow."""
    message = decode_basic(stego_image_path)
    print("[OK] Decoding successful!")
    print(f"     - Stego-image : {stego_image_path}")
    print(f"     - Message     : {len(message)} characters found")
    return message
