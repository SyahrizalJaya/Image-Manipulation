from __future__ import annotations

from pathlib import Path

import pytest
from PIL import Image

import encoder
from decoder import decode_auto, decode_basic, decode_edge_adaptive, decode_randomized
from encoder import encode_basic, encode_edge_adaptive, encode_randomized
from utils import (
    HEADER_BITS,
    HEADER_SIZE,
    LEGACY_VERSION,
    MAGIC,
    METHOD_BASIC,
    METHOD_EDGE,
    NONCE_SIZE,
    SALT_SIZE,
    AuthenticationError,
    CapacityError,
    HeaderError,
    UnsupportedImageError,
    VISIBLE_WATERMARK_METADATA_KEY,
    apply_visible_watermark,
    build_header,
    bytes_to_bits,
    parse_header,
    randomized_positions,
    save_stego_image,
    visible_watermark_metadata,
)


def make_cover(path: Path, size: tuple[int, int] = (80, 80), mode: str = "RGB") -> Path:
    color = (70, 120, 180, 111) if mode == "RGBA" else (70, 120, 180)
    Image.new(mode, size, color).save(path)
    return path


@pytest.mark.parametrize(
    ("encode", "decode", "encode_kwargs", "decode_kwargs"),
    [
        (encode_basic, decode_basic, {}, {}),
        (encode_randomized, decode_randomized, {"key": "random-key"}, {"key": "random-key"}),
        (encode_edge_adaptive, decode_edge_adaptive, {}, {}),
    ],
)
def test_plaintext_round_trips(tmp_path, encode, decode, encode_kwargs, decode_kwargs):
    cover = make_cover(tmp_path / "cover.png")
    output = tmp_path / "stego.png"

    encode(cover, output, "plain round trip", use_compression=False, **encode_kwargs)

    assert decode(output, **decode_kwargs) == "plain round trip"


@pytest.mark.parametrize(
    ("encode", "decode", "encode_kwargs", "decode_kwargs"),
    [
        (encode_basic, decode_basic, {}, {}),
        (encode_randomized, decode_randomized, {"key": "unicode-key"}, {"key": "unicode-key"}),
        (encode_edge_adaptive, decode_edge_adaptive, {}, {}),
    ],
)
def test_unicode_and_emoji_round_trip(tmp_path, encode, decode, encode_kwargs, decode_kwargs):
    cover = make_cover(tmp_path / "cover.png")
    output = tmp_path / "unicode.png"
    message = "Halo, 世界. Encrypted art: 🎨🔐"

    encode(cover, output, message, **encode_kwargs)

    assert decode(output, **decode_kwargs) == message


def test_aes_encrypted_round_trip(tmp_path):
    cover = make_cover(tmp_path / "cover.png")
    output = tmp_path / "encrypted.png"

    result = encode_basic(cover, output, "authenticated secret", use_aes=True, password="correct-password")

    assert result["encrypted"] is True
    assert decode_basic(output, password="correct-password") == "authenticated secret"


def test_aes_requires_non_empty_password(tmp_path):
    cover = make_cover(tmp_path / "cover.png")

    with pytest.raises(AuthenticationError, match="non-empty password"):
        encode_basic(cover, tmp_path / "should-not-exist.png", "secret", use_aes=True, password="")


def test_aes_fails_closed_when_dependency_unavailable(tmp_path, monkeypatch):
    cover = make_cover(tmp_path / "cover.png")
    output = tmp_path / "should-not-exist.png"
    monkeypatch.setattr(encoder, "aes_available", lambda: False)

    with pytest.raises(AuthenticationError, match="cryptography"):
        encode_basic(cover, output, "secret", use_aes=True, password="password")

    assert not output.exists()


def test_wrong_password_rejected(tmp_path):
    cover = make_cover(tmp_path / "cover.png")
    output = tmp_path / "encrypted.png"
    encode_basic(cover, output, "secret", use_aes=True, password="correct")

    with pytest.raises(AuthenticationError, match="Authentication failed"):
        decode_basic(output, password="wrong")


def test_modified_encrypted_payload_rejected(tmp_path):
    cover = make_cover(tmp_path / "cover.png")
    output = tmp_path / "encrypted.png"
    encode_basic(cover, output, "secret payload", use_aes=True, password="correct", use_compression=False)

    image = Image.open(output).convert("RGB")
    pixels = bytearray(image.tobytes())
    pixels[HEADER_BITS] ^= 1
    Image.frombytes("RGB", image.size, bytes(pixels)).save(output)

    with pytest.raises(AuthenticationError, match="Authentication failed"):
        decode_basic(output, password="correct")


def test_compression_used_for_repetitive_text(tmp_path):
    cover = make_cover(tmp_path / "cover.png")
    output = tmp_path / "compressed.png"
    message = "compress me " * 100

    result = encode_basic(cover, output, message, use_compression=True)

    assert result["compressed"] is True
    assert result["stored_payload_bytes"] < result["original_message_bytes"]
    assert result["compression_reduction_percent"] > 0
    assert decode_basic(output) == message


def test_compression_skipped_when_not_beneficial(tmp_path):
    cover = make_cover(tmp_path / "cover.png")
    output = tmp_path / "short.png"

    result = encode_basic(cover, output, "x", use_compression=True)

    assert result["compressed"] is False
    assert result["stored_payload_bytes"] == result["original_message_bytes"] == 1
    assert decode_basic(output) == "x"


def test_oversized_message_rejected_before_output_is_created(tmp_path):
    cover = make_cover(tmp_path / "tiny.png", size=(10, 10))
    output = tmp_path / "partial.png"

    with pytest.raises(CapacityError, match=r"required \d+ bits, available \d+ bits"):
        encode_basic(cover, output, "x" * 100, use_compression=False)

    assert not output.exists()


@pytest.mark.parametrize(
    ("encode", "kwargs"),
    [
        (encode_basic, {}),
        (encode_randomized, {"key": "key"}),
        (encode_edge_adaptive, {}),
    ],
)
def test_empty_message_rejected(tmp_path, encode, kwargs):
    cover = make_cover(tmp_path / "cover.png")

    with pytest.raises(ValueError, match="cannot be empty"):
        encode(cover, tmp_path / "empty.png", "", **kwargs)


def test_non_stego_image_rejected(tmp_path):
    cover = make_cover(tmp_path / "cover.png")

    with pytest.raises(HeaderError, match="header"):
        decode_basic(cover)


def test_invalid_or_corrupted_image_rejected(tmp_path):
    broken = tmp_path / "broken.png"
    broken.write_bytes(b"not an image")

    with pytest.raises(UnsupportedImageError, match="corrupted"):
        encode_basic(broken, tmp_path / "output.png", "message")


def test_stego_output_is_always_png(tmp_path):
    cover = make_cover(tmp_path / "cover.bmp")

    result = encode_basic(cover, tmp_path / "requested.bmp", "message")

    assert result["save_format"] == "PNG"
    assert Path(result["output_path"]).suffix.lower() == ".png"
    assert Image.open(result["output_path"]).format == "PNG"


def test_alpha_transparency_is_preserved(tmp_path):
    cover = make_cover(tmp_path / "cover.png", mode="RGBA")

    result = encode_basic(cover, tmp_path / "alpha.png", "message")
    stego = Image.open(result["output_path"])

    assert stego.mode == "RGBA"
    assert stego.getchannel("A").getextrema() == (111, 111)
    assert decode_basic(result["output_path"]) == "message"


def test_visible_watermark_changes_image_without_lsb(tmp_path):
    cover = make_cover(tmp_path / "cover.png", size=(160, 100))
    original = Image.open(cover).convert("RGB")

    watermarked = apply_visible_watermark(original, "IPUL Team")

    assert watermarked.size == original.size
    assert list(watermarked.getdata()) != list(original.getdata())


def test_visible_watermark_metadata_can_be_recovered(tmp_path):
    cover = make_cover(tmp_path / "cover.png", size=(160, 100))
    output = tmp_path / "visible.png"
    watermarked = apply_visible_watermark(Image.open(cover), "IPUL Team")

    save_stego_image(watermarked, output, metadata={VISIBLE_WATERMARK_METADATA_KEY: "IPUL Team"})

    assert visible_watermark_metadata(output) == "IPUL Team"


def test_visible_and_invisible_watermarks_can_coexist(tmp_path):
    cover = make_cover(tmp_path / "cover.png", size=(160, 100))
    output = tmp_path / "both.png"

    result = encode_edge_adaptive(
        cover,
        output,
        "visible plus hidden",
        use_aes=True,
        password="password",
        visible_watermark_text="IPUL Team",
    )

    assert result["visible_watermark"] is True
    assert decode_edge_adaptive(output, password="password") == "visible plus hidden"
    assert visible_watermark_metadata(output) == "IPUL Team"


def test_auto_decode_detects_edge_adaptive_message(tmp_path):
    cover = make_cover(tmp_path / "cover.png", size=(160, 100))
    output = tmp_path / "edge.png"
    encode_edge_adaptive(cover, output, "auto detected", use_aes=True, password="password")

    message, method = decode_auto(output, password="password")

    assert message == "auto detected"
    assert method == METHOD_EDGE


def test_header_magic_and_version_validation():
    header = build_header(
        METHOD_BASIC,
        False,
        bytes(SALT_SIZE),
        bytes(NONCE_SIZE),
        1,
        payload_digest=bytes(32),
    )

    with pytest.raises(HeaderError, match="header"):
        parse_header(b"BADMAGIC" + header[len(MAGIC) :])

    unsupported = bytearray(header)
    unsupported[len(MAGIC)] = 99
    with pytest.raises(HeaderError, match="Unsupported hidden message version"):
        parse_header(bytes(unsupported))


def test_corrupted_header_crc_rejected():
    header = bytearray(
        build_header(
            METHOD_BASIC,
            False,
            bytes(SALT_SIZE),
            bytes(NONCE_SIZE),
            1,
            payload_digest=bytes(32),
        )
    )
    header[-1] ^= 1

    with pytest.raises(HeaderError, match="corrupted"):
        parse_header(bytes(header))


def test_randomized_encodings_use_different_salts_and_positions(tmp_path):
    cover = make_cover(tmp_path / "cover.png")
    first = encode_randomized(cover, tmp_path / "first.png", "randomized message", "password")
    second = encode_randomized(cover, tmp_path / "second.png", "randomized message", "password")

    def read_header(path):
        image = Image.open(path).convert("RGB")
        bits = [value & 1 for value in image.tobytes()[:HEADER_BITS]]
        data = bytes(sum(bits[i + offset] << (7 - offset) for offset in range(8)) for i in range(0, len(bits), 8))
        return parse_header(data)

    first_header = read_header(first["output_path"])
    second_header = read_header(second["output_path"])
    first_positions = randomized_positions(Image.open(cover), "password", 64, salt=first_header.salt, start=HEADER_BITS)
    second_positions = randomized_positions(Image.open(cover), "password", 64, salt=second_header.salt, start=HEADER_BITS)

    assert first_header.salt != second_header.salt
    assert first_positions != second_positions


def test_legacy_plaintext_basic_image_can_still_decode(tmp_path):
    cover = make_cover(tmp_path / "cover.png")
    output = tmp_path / "legacy.png"
    payload = b"legacy plaintext"
    header = (
        MAGIC
        + bytes([LEGACY_VERSION, METHOD_BASIC, 0])
        + bytes(SALT_SIZE)
        + bytes(NONCE_SIZE)
        + len(payload).to_bytes(4, "big")
    )
    bits = bytes_to_bits(header + payload)
    image = Image.open(cover).convert("RGB")
    pixels = bytearray(image.tobytes())
    for index, bit in enumerate(bits):
        pixels[index] = (pixels[index] & 0xFE) | bit
    Image.frombytes("RGB", image.size, bytes(pixels)).save(output)

    assert decode_basic(output) == payload.decode("utf-8")
