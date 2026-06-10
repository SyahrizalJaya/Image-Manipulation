from __future__ import annotations

import hashlib
import heapq
import math
import os
import random
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from PIL import Image

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
except ImportError:  # pragma: no cover - depends on local environment
    AESGCM = None
    PBKDF2HMAC = None
    hashes = None


SUPPORTED_FORMATS = {"PNG", "JPEG", "BMP", "TIFF", "WEBP"}
MAGIC = b"STEGDEMO"
VERSION = 1
METHOD_BASIC = 1
METHOD_RANDOM = 2
METHOD_EDGE = 3
FLAG_ENCRYPTED = 1
SALT_SIZE = 16
NONCE_SIZE = 12
HEADER_SIZE = len(MAGIC) + 1 + 1 + 1 + SALT_SIZE + NONCE_SIZE + 4
HEADER_BITS = HEADER_SIZE * 8


class SteganographyError(Exception):
    """Base exception for user-facing steganography errors."""


class UnsupportedImageFormatError(SteganographyError):
    pass


class MessageTooLargeError(SteganographyError):
    pass


class HiddenMessageNotFoundError(SteganographyError):
    pass


class WrongPasswordError(SteganographyError):
    pass


@dataclass(frozen=True)
class StegoHeader:
    method: int
    encrypted: bool
    salt: bytes
    nonce: bytes
    payload_length: int


def aes_available() -> bool:
    return AESGCM is not None and PBKDF2HMAC is not None and hashes is not None


def normalize_format(image_format: str | None) -> str:
    if not image_format:
        raise UnsupportedImageFormatError("Could not detect the input image format.")
    fmt = image_format.upper()
    if fmt == "JPG":
        fmt = "JPEG"
    if fmt not in SUPPORTED_FORMATS:
        supported = ", ".join(sorted(SUPPORTED_FORMATS))
        raise UnsupportedImageFormatError(f"Unsupported image format '{fmt}'. Supported: {supported}.")
    return fmt


def load_image(path: str | Path) -> tuple[Image.Image, str]:
    image_path = Path(path)
    if not image_path.exists():
        raise FileNotFoundError(f"File not found: {image_path}")
    try:
        image = Image.open(image_path)
        fmt = normalize_format(image.format)
        image.load()
    except UnsupportedImageFormatError:
        raise
    except Exception as exc:
        raise SteganographyError(f"Could not open image: {exc}") from exc
    return image, fmt


def prepare_image_for_lsb(image: Image.Image) -> Image.Image:
    if image.mode != "RGB":
        return image.convert("RGB")
    return image.copy()


def channel_capacity_bits(image: Image.Image) -> int:
    rgb = prepare_image_for_lsb(image)
    width, height = rgb.size
    return width * height * 3


def payload_capacity_bytes(image: Image.Image) -> int:
    return max(0, (channel_capacity_bits(image) - HEADER_BITS) // 8)


def capacity_report(image: Image.Image, payload_size: int = 0) -> dict[str, float | int]:
    capacity_bytes = payload_capacity_bytes(image)
    used_percent = (payload_size / capacity_bytes * 100) if capacity_bytes else 0
    return {
        "capacity_bits": channel_capacity_bits(image),
        "payload_capacity_bytes": capacity_bytes,
        "payload_used_bytes": payload_size,
        "capacity_used_percent": used_percent,
    }


def derive_key(password: str, salt: bytes) -> bytes:
    if not aes_available():
        raise SteganographyError("AES support is not available because 'cryptography' is not installed.")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200_000,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_payload(message: str, password: str) -> tuple[bytes, bytes, bytes]:
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key = derive_key(password, salt)
    ciphertext = AESGCM(key).encrypt(nonce, message.encode("utf-8"), None)
    return ciphertext, salt, nonce


def decrypt_payload(payload: bytes, password: str, salt: bytes, nonce: bytes) -> str:
    try:
        key = derive_key(password, salt)
        plaintext = AESGCM(key).decrypt(nonce, payload, None)
        return plaintext.decode("utf-8")
    except Exception as exc:
        raise WrongPasswordError("Wrong password/key, corrupted data, or invalid encrypted payload.") from exc


def build_header(method: int, encrypted: bool, salt: bytes, nonce: bytes, payload_length: int) -> bytes:
    if len(salt) != SALT_SIZE or len(nonce) != NONCE_SIZE:
        raise ValueError("Invalid salt or nonce length.")
    if payload_length < 0 or payload_length > 0xFFFFFFFF:
        raise ValueError("Invalid payload length.")
    flags = FLAG_ENCRYPTED if encrypted else 0
    return (
        MAGIC
        + bytes([VERSION, method, flags])
        + salt
        + nonce
        + payload_length.to_bytes(4, "big")
    )


def parse_header(header: bytes, expected_method: int | None = None) -> StegoHeader:
    if len(header) != HEADER_SIZE or not header.startswith(MAGIC):
        raise HiddenMessageNotFoundError("No hidden message header was found.")
    offset = len(MAGIC)
    version = header[offset]
    method = header[offset + 1]
    flags = header[offset + 2]
    offset += 3
    if version != VERSION:
        raise HiddenMessageNotFoundError(f"Unsupported hidden message version: {version}.")
    if expected_method is not None and method != expected_method:
        raise HiddenMessageNotFoundError("A hidden message exists, but it was encoded with another method.")
    salt = header[offset : offset + SALT_SIZE]
    offset += SALT_SIZE
    nonce = header[offset : offset + NONCE_SIZE]
    offset += NONCE_SIZE
    payload_length = int.from_bytes(header[offset : offset + 4], "big")
    return StegoHeader(
        method=method,
        encrypted=bool(flags & FLAG_ENCRYPTED),
        salt=salt,
        nonce=nonce,
        payload_length=payload_length,
    )


def bytes_to_bits(data: bytes) -> list[int]:
    return [(byte >> shift) & 1 for byte in data for shift in range(7, -1, -1)]


def bits_to_bytes(bits: Iterable[int]) -> bytes:
    bit_list = list(bits)
    if len(bit_list) % 8:
        raise ValueError("Bit length must be a multiple of 8.")
    output = bytearray()
    for index in range(0, len(bit_list), 8):
        value = 0
        for bit in bit_list[index : index + 8]:
            value = (value << 1) | int(bit)
        output.append(value)
    return bytes(output)


def sequential_positions(image: Image.Image, count: int | None = None) -> range:
    capacity = channel_capacity_bits(image)
    if count is None:
        count = capacity
    if count > capacity:
        raise ValueError("Requested more positions than the image can provide.")
    return range(count)


def randomized_positions(image: Image.Image, password: str, count: int | None = None) -> list[int]:
    capacity = channel_capacity_bits(image)
    if count is None:
        count = capacity
    if count > capacity:
        raise ValueError("Requested more positions than the image can provide.")

    seed = hashlib.sha256(password.encode("utf-8")).digest()
    rng = random.Random(seed)

    if count > capacity // 3:
        positions = list(range(capacity))
        rng.shuffle(positions)
        return positions[:count]

    positions: list[int] = []
    seen: set[int] = set()
    while len(positions) < count:
        position = rng.randrange(capacity)
        if position not in seen:
            seen.add(position)
            positions.append(position)
    return positions


def edge_adaptive_positions(image: Image.Image, count: int | None = None) -> list[int]:
    """Return channel positions ordered by strongest local image detail first.

    LSB changes are masked out before scoring, so the same image produces the
    same edge order after embedding.
    """
    capacity = channel_capacity_bits(image)
    if count is None:
        count = capacity
    if count > capacity:
        raise ValueError("Requested more positions than the image can provide.")

    rgb = prepare_image_for_lsb(image)
    width, height = rgb.size
    pixels = rgb.tobytes()

    gray = [0] * (width * height)
    for pixel_index in range(width * height):
        offset = pixel_index * 3
        red = pixels[offset] & 0xFE
        green = pixels[offset + 1] & 0xFE
        blue = pixels[offset + 2] & 0xFE
        gray[pixel_index] = (red * 30 + green * 59 + blue * 11) // 100

    def scored_positions():
        for y in range(height):
            row = y * width
            for x in range(width):
                pixel_index = row + x
                value = gray[pixel_index]
                score = 0
                if x + 1 < width:
                    score += abs(value - gray[pixel_index + 1])
                if y + 1 < height:
                    score += abs(value - gray[pixel_index + width])
                if x > 0:
                    score += abs(value - gray[pixel_index - 1])
                if y > 0:
                    score += abs(value - gray[pixel_index - width])
                base_position = pixel_index * 3
                yield (score, -base_position, base_position)
                yield (score, -(base_position + 1), base_position + 1)
                yield (score, -(base_position + 2), base_position + 2)

    top = heapq.nlargest(count, scored_positions())
    top.sort(key=lambda item: (-item[0], item[2]))
    return [position for _, _, position in top]


def set_lsb_at_position(pixels: bytearray, position: int, bit: int) -> None:
    pixels[position] = (pixels[position] & 0xFE) | bit


def get_lsb_at_position(pixels: bytes | bytearray, position: int) -> int:
    return pixels[position] & 1


def ensure_capacity(image: Image.Image, payload_length: int) -> None:
    needed_bits = (HEADER_SIZE + payload_length) * 8
    capacity_bits = channel_capacity_bits(image)
    if needed_bits > capacity_bits:
        capacity = payload_capacity_bytes(image)
        raise MessageTooLargeError(
            f"Message is too large. Payload needs {payload_length} bytes, "
            f"but this image can hold about {capacity} bytes after metadata."
        )


def resolve_output_path(input_path: str | Path, requested_output: str | Path | None, input_format: str) -> tuple[Path, str, list[str]]:
    warnings: list[str] = []
    source = Path(input_path)
    if requested_output:
        output = Path(requested_output)
    else:
        output = source.with_name(f"{source.stem}_stego{source.suffix}")

    save_format = input_format
    if input_format == "JPEG":
        warnings.append(
            "JPEG is lossy, so normal LSB data usually will not survive JPEG saving. "
            "Saving a PNG lossless copy instead."
        )
        save_format = "PNG"
        output = output.with_suffix(".png")
    elif input_format == "WEBP":
        warnings.append("WEBP output will be saved in lossless mode when Pillow supports it.")
    else:
        extension = {
            "PNG": ".png",
            "BMP": ".bmp",
            "TIFF": ".tiff",
            "WEBP": ".webp",
        }.get(input_format, source.suffix)
        if output.suffix.lower() not in {extension, ".tif" if input_format == "TIFF" else extension}:
            output = output.with_suffix(extension)

    return output, save_format, warnings


def save_stego_image(image: Image.Image, output_path: str | Path, save_format: str) -> None:
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    save_kwargs = {}
    if save_format == "WEBP":
        save_kwargs["lossless"] = True
    image.save(output, format=save_format, **save_kwargs)


def human_size(num_bytes: int) -> str:
    if num_bytes < 1024:
        return f"{num_bytes} B"
    units = ["KB", "MB", "GB"]
    value = float(num_bytes)
    for unit in units:
        value /= 1024
        if abs(value) < 1024:
            return f"{value:.2f} {unit}"
    return f"{value:.2f} TB"


def psnr_from_mse(mse: float) -> float:
    if mse == 0:
        return math.inf
    return 20 * math.log10(255.0 / math.sqrt(mse))
