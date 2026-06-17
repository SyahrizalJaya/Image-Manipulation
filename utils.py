from __future__ import annotations

import hashlib
import heapq
import math
import os
import random
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from PIL import Image, ImageDraw, ImageFont

try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
except ImportError:  # pragma: no cover - depends on local environment
    InvalidTag = Exception
    AESGCM = None
    PBKDF2HMAC = None
    hashes = None


SUPPORTED_FORMATS = {"PNG", "JPEG", "BMP", "TIFF", "WEBP"}
MAGIC = b"STEGDEMO"
LEGACY_VERSION = 1
VERSION = 2
METHOD_BASIC = 1
METHOD_RANDOM = 2
METHOD_EDGE = 3
VALID_METHODS = {METHOD_BASIC, METHOD_RANDOM, METHOD_EDGE}
FLAG_ENCRYPTED = 1
FLAG_COMPRESSED = 2
VALID_FLAGS = FLAG_ENCRYPTED | FLAG_COMPRESSED
SALT_SIZE = 16
NONCE_SIZE = 12
DIGEST_SIZE = 32
CRC_SIZE = 4
LEGACY_HEADER_SIZE = len(MAGIC) + 1 + 1 + 1 + SALT_SIZE + NONCE_SIZE + 4
LEGACY_HEADER_BITS = LEGACY_HEADER_SIZE * 8
HEADER_SIZE = LEGACY_HEADER_SIZE + 4 + DIGEST_SIZE + CRC_SIZE
HEADER_BITS = HEADER_SIZE * 8


class SteganographyError(Exception):
    """Base exception for user-facing steganography errors."""


class UnsupportedImageFormatError(SteganographyError):
    pass


class UnsupportedImageError(UnsupportedImageFormatError):
    pass


class MessageTooLargeError(SteganographyError):
    pass


class CapacityError(MessageTooLargeError):
    pass


class HiddenMessageNotFoundError(SteganographyError):
    pass


class HeaderError(HiddenMessageNotFoundError):
    pass


class WrongPasswordError(SteganographyError):
    pass


class AuthenticationError(WrongPasswordError):
    pass


@dataclass(frozen=True)
class StegoHeader:
    method: int
    encrypted: bool
    compressed: bool
    salt: bytes
    nonce: bytes
    payload_length: int
    original_length: int
    payload_digest: bytes
    version: int
    header_size: int


def aes_available() -> bool:
    return AESGCM is not None and PBKDF2HMAC is not None and hashes is not None


def normalize_format(image_format: str | None) -> str:
    if not image_format:
        raise UnsupportedImageError("Could not detect the input image format.")
    fmt = image_format.upper()
    if fmt == "JPG":
        fmt = "JPEG"
    if fmt not in SUPPORTED_FORMATS:
        supported = ", ".join(sorted(SUPPORTED_FORMATS))
        raise UnsupportedImageError(f"Unsupported image format '{fmt}'. Supported: {supported}.")
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
        raise UnsupportedImageError("The selected image could not be opened or is corrupted.") from exc
    return image, fmt


def prepare_image_for_lsb(image: Image.Image) -> Image.Image:
    if image.mode != "RGB":
        return image.convert("RGB")
    return image.copy()


def restore_alpha(rgb_image: Image.Image, original: Image.Image) -> Image.Image:
    if "A" not in original.getbands():
        return rgb_image
    alpha = original.getchannel("A")
    rgba = rgb_image.convert("RGBA")
    rgba.putalpha(alpha)
    return rgba


def _watermark_font(size: int) -> ImageFont.ImageFont:
    for name in ("arial.ttf", "segoeui.ttf", "DejaVuSans-Bold.ttf"):
        try:
            return ImageFont.truetype(name, size=size)
        except OSError:
            continue
    return ImageFont.load_default()


def apply_visible_watermark(
    image: Image.Image,
    text: str,
    opacity: int = 160,
    margin_ratio: float = 0.035,
) -> Image.Image:
    watermark_text = text.strip() or "VISIBLE WATERMARK"
    base = image.convert("RGBA")
    width, height = base.size
    font_size = max(18, min(width, height) // 22)
    font = _watermark_font(font_size)
    overlay = Image.new("RGBA", base.size, (0, 0, 0, 0))
    draw = ImageDraw.Draw(overlay)
    bbox = draw.textbbox((0, 0), watermark_text, font=font)
    text_width = bbox[2] - bbox[0]
    text_height = bbox[3] - bbox[1]
    margin = max(12, int(min(width, height) * margin_ratio))
    padding_x = max(12, font_size // 2)
    padding_y = max(8, font_size // 3)
    x = max(margin, width - text_width - margin - padding_x * 2)
    y = max(margin, height - text_height - margin - padding_y * 2)
    box = (
        x,
        y,
        min(width - margin, x + text_width + padding_x * 2),
        min(height - margin, y + text_height + padding_y * 2),
    )
    draw.rounded_rectangle(box, radius=max(4, font_size // 4), fill=(0, 0, 0, max(0, min(opacity, 255))))
    draw.text((x + padding_x, y + padding_y - bbox[1]), watermark_text, font=font, fill=(255, 255, 255, 235))
    watermarked = Image.alpha_composite(base, overlay)
    if "A" in image.getbands():
        return watermarked
    return watermarked.convert("RGB")


def channel_capacity_bits(image: Image.Image) -> int:
    width, height = image.size
    return width * height * 3


def payload_capacity_bytes(image: Image.Image, header_size: int = HEADER_SIZE) -> int:
    return max(0, (channel_capacity_bits(image) - header_size * 8) // 8)


def capacity_report(image: Image.Image, payload_size: int = 0, header_size: int = HEADER_SIZE) -> dict[str, float | int]:
    capacity_bytes = payload_capacity_bytes(image, header_size=header_size)
    used_percent = (payload_size / capacity_bytes * 100) if capacity_bytes else 0
    return {
        "capacity_bits": channel_capacity_bits(image),
        "header_bits": header_size * 8,
        "required_bits": (header_size + payload_size) * 8,
        "payload_capacity_bytes": capacity_bytes,
        "payload_used_bytes": payload_size,
        "capacity_used_percent": used_percent,
    }


def _derive_material(password: str, salt: bytes, purpose: bytes) -> bytes:
    if not password:
        raise AuthenticationError("A non-empty password is required.")
    if not aes_available():
        raise SteganographyError("AES encryption requires the 'cryptography' package.")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt + purpose,
        iterations=200_000,
    )
    return kdf.derive(password.encode("utf-8"))


def derive_key(password: str, salt: bytes) -> bytes:
    return _derive_material(password, salt, b"aes-key")


def derive_position_seed(password: str, salt: bytes) -> bytes:
    if not password:
        raise AuthenticationError("Randomized LSB requires a non-empty password.")
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt + b"position-seed",
        200_000,
        dklen=32,
    )


def derive_legacy_key(password: str, salt: bytes) -> bytes:
    if not password:
        raise AuthenticationError("A non-empty password is required.")
    if not aes_available():
        raise SteganographyError("AES decryption requires the 'cryptography' package.")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200_000,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_payload(payload: bytes | str, password: str, salt: bytes | None = None) -> tuple[bytes, bytes, bytes]:
    if not password:
        raise AuthenticationError("AES encryption requires a non-empty password.")
    if not aes_available():
        raise SteganographyError("AES encryption requires the 'cryptography' package.")
    plaintext = payload.encode("utf-8") if isinstance(payload, str) else payload
    salt = salt or os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key = derive_key(password, salt)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)
    return ciphertext, salt, nonce


def decrypt_payload(payload: bytes, password: str, salt: bytes, nonce: bytes, legacy: bool = False) -> bytes:
    if not password:
        raise AuthenticationError("This message is encrypted. A password is required.")
    if not aes_available():
        raise SteganographyError("AES decryption requires the 'cryptography' package.")
    try:
        key = derive_legacy_key(password, salt) if legacy else derive_key(password, salt)
        return AESGCM(key).decrypt(nonce, payload, None)
    except InvalidTag as exc:
        raise AuthenticationError("Authentication failed: wrong password or modified image.") from exc
    except Exception as exc:
        raise AuthenticationError("Authentication failed: invalid encrypted payload.") from exc


def adaptive_compress(payload: bytes, enabled: bool = True) -> tuple[bytes, bool]:
    if not enabled:
        return payload, False
    compressed = zlib.compress(payload)
    if len(compressed) < len(payload):
        return compressed, True
    return payload, False


def decompress_payload(payload: bytes) -> bytes:
    try:
        return zlib.decompress(payload)
    except zlib.error as exc:
        raise HeaderError("Compressed payload is corrupted or invalid.") from exc


def build_header(
    method: int,
    encrypted: bool,
    salt: bytes,
    nonce: bytes,
    payload_length: int,
    compressed: bool = False,
    original_length: int | None = None,
    payload_digest: bytes | None = None,
) -> bytes:
    if method not in VALID_METHODS:
        raise HeaderError("Unsupported steganography method.")
    if len(salt) != SALT_SIZE or len(nonce) != NONCE_SIZE:
        raise HeaderError("Invalid salt or nonce length.")
    if payload_length <= 0 or payload_length > 0xFFFFFFFF:
        raise HeaderError("Invalid payload length.")
    original_length = payload_length if original_length is None else original_length
    if original_length <= 0 or original_length > 0xFFFFFFFF:
        raise HeaderError("Invalid original message length.")
    digest = payload_digest or bytes(DIGEST_SIZE)
    if len(digest) != DIGEST_SIZE:
        raise HeaderError("Invalid payload digest length.")
    flags = (FLAG_ENCRYPTED if encrypted else 0) | (FLAG_COMPRESSED if compressed else 0)
    body = (
        MAGIC
        + bytes([VERSION, method, flags])
        + salt
        + nonce
        + payload_length.to_bytes(4, "big")
        + original_length.to_bytes(4, "big")
        + digest
    )
    return body + (zlib.crc32(body) & 0xFFFFFFFF).to_bytes(CRC_SIZE, "big")


def parse_header(header: bytes, expected_method: int | None = None) -> StegoHeader:
    if len(header) < LEGACY_HEADER_SIZE or not header.startswith(MAGIC):
        raise HeaderError("No supported steganography header was found.")
    version = header[len(MAGIC)]
    if version == LEGACY_VERSION:
        return _parse_legacy_header(header[:LEGACY_HEADER_SIZE], expected_method)
    if version != VERSION:
        raise HeaderError(f"Unsupported hidden message version: {version}.")
    if len(header) < HEADER_SIZE:
        raise HeaderError("The steganography header is truncated.")

    current = header[:HEADER_SIZE]
    body = current[:-CRC_SIZE]
    stored_crc = int.from_bytes(current[-CRC_SIZE:], "big")
    if zlib.crc32(body) & 0xFFFFFFFF != stored_crc:
        raise HeaderError("The steganography header is corrupted.")

    offset = len(MAGIC) + 1
    method = current[offset]
    flags = current[offset + 1]
    offset += 2
    if method not in VALID_METHODS:
        raise HeaderError("The steganography header contains an unsupported method.")
    if expected_method is not None and method != expected_method:
        raise HeaderError("A hidden message exists, but it was encoded with another method.")
    if flags & ~VALID_FLAGS:
        raise HeaderError("The steganography header contains unsupported flags.")
    salt = current[offset : offset + SALT_SIZE]
    offset += SALT_SIZE
    nonce = current[offset : offset + NONCE_SIZE]
    offset += NONCE_SIZE
    payload_length = int.from_bytes(current[offset : offset + 4], "big")
    offset += 4
    original_length = int.from_bytes(current[offset : offset + 4], "big")
    offset += 4
    digest = current[offset : offset + DIGEST_SIZE]
    if payload_length <= 0 or original_length <= 0:
        raise HeaderError("The steganography header contains an impossible payload length.")
    return StegoHeader(
        method=method,
        encrypted=bool(flags & FLAG_ENCRYPTED),
        compressed=bool(flags & FLAG_COMPRESSED),
        salt=salt,
        nonce=nonce,
        payload_length=payload_length,
        original_length=original_length,
        payload_digest=digest,
        version=VERSION,
        header_size=HEADER_SIZE,
    )


def _parse_legacy_header(header: bytes, expected_method: int | None) -> StegoHeader:
    offset = len(MAGIC) + 1
    method = header[offset]
    flags = header[offset + 1]
    offset += 2
    if method not in VALID_METHODS:
        raise HeaderError("The legacy header contains an unsupported method.")
    if expected_method is not None and method != expected_method:
        raise HeaderError("A hidden message exists, but it was encoded with another method.")
    salt = header[offset : offset + SALT_SIZE]
    offset += SALT_SIZE
    nonce = header[offset : offset + NONCE_SIZE]
    offset += NONCE_SIZE
    payload_length = int.from_bytes(header[offset : offset + 4], "big")
    if payload_length <= 0:
        raise HeaderError("The legacy header contains an impossible payload length.")
    return StegoHeader(
        method=method,
        encrypted=bool(flags & FLAG_ENCRYPTED),
        compressed=False,
        salt=salt,
        nonce=nonce,
        payload_length=payload_length,
        original_length=payload_length,
        payload_digest=bytes(DIGEST_SIZE),
        version=LEGACY_VERSION,
        header_size=LEGACY_HEADER_SIZE,
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


def sequential_positions(image: Image.Image, count: int | None = None, start: int = 0) -> range:
    capacity = channel_capacity_bits(image)
    if count is None:
        count = capacity - start
    if start < 0 or count < 0 or start + count > capacity:
        raise CapacityError("Requested more positions than the image can provide.")
    return range(start, start + count)


def randomized_positions(
    image: Image.Image,
    password: str,
    count: int | None = None,
    salt: bytes | None = None,
    start: int = 0,
) -> list[int]:
    capacity = channel_capacity_bits(image)
    available = capacity - start
    if count is None:
        count = available
    if start < 0 or count < 0 or count > available:
        raise CapacityError("Requested more positions than the image can provide.")
    if not password:
        raise AuthenticationError("Randomized LSB requires a non-empty password.")

    seed = derive_position_seed(password, salt) if salt is not None else hashlib.sha256(password.encode("utf-8")).digest()
    rng = random.Random(seed)
    population = range(start, capacity)
    return rng.sample(population, count)


def edge_adaptive_positions(image: Image.Image, count: int | None = None, start: int = 0) -> list[int]:
    """Return RGB-channel positions ordered by strongest local detail first."""
    capacity = channel_capacity_bits(image)
    available = capacity - start
    if count is None:
        count = available
    if start < 0 or count < 0 or count > available:
        raise CapacityError("Requested more positions than the image can provide.")

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
                for position in (base_position, base_position + 1, base_position + 2):
                    if position >= start:
                        yield (score, -position, position)

    top = heapq.nlargest(count, scored_positions())
    top.sort(key=lambda item: (-item[0], item[2]))
    return [position for _, _, position in top]


def set_lsb_at_position(pixels: bytearray, position: int, bit: int) -> None:
    pixels[position] = (pixels[position] & 0xFE) | bit


def get_lsb_at_position(pixels: bytes | bytearray, position: int) -> int:
    return pixels[position] & 1


def ensure_capacity(image: Image.Image, payload_length: int, header_size: int = HEADER_SIZE) -> None:
    needed_bits = (header_size + payload_length) * 8
    capacity_bits = channel_capacity_bits(image)
    if needed_bits > capacity_bits:
        raise CapacityError(
            f"The selected message exceeds image capacity: required {needed_bits} bits, "
            f"available {capacity_bits} bits."
        )


def validate_payload_length(image: Image.Image, header: StegoHeader) -> None:
    available = payload_capacity_bytes(image, header_size=header.header_size)
    if header.payload_length > available:
        raise HeaderError(
            f"The steganography header declares an impossible payload length "
            f"({header.payload_length} bytes; capacity {available} bytes)."
        )


def resolve_output_path(
    input_path: str | Path,
    requested_output: str | Path | None,
    input_format: str,
) -> tuple[Path, str, list[str]]:
    source = Path(input_path)
    output = Path(requested_output) if requested_output else source.with_name(f"{source.stem}_stego.png")
    warnings: list[str] = []
    if input_format == "JPEG":
        warnings.append("JPEG is lossy; the stego image was saved as PNG.")
    elif input_format != "PNG":
        warnings.append(f"{input_format} cover accepted; the stego image was saved as PNG.")
    if output.suffix.lower() != ".png":
        output = output.with_suffix(".png")
        warnings.append("Stego output uses PNG to preserve embedded LSB data.")
    return output, "PNG", warnings


def save_stego_image(image: Image.Image, output_path: str | Path, save_format: str = "PNG") -> None:
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    image.save(output, format="PNG")


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
