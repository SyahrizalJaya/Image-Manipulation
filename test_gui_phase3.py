from __future__ import annotations

import tkinter as tk

import pytest
from PIL import Image

from app import SteganographyApp
from metrics import evaluate_quality


def test_quality_evaluation_includes_ssim(tmp_path):
    original = tmp_path / "original.png"
    stego = tmp_path / "stego.png"
    Image.new("RGB", (32, 32), (10, 20, 30)).save(original)
    Image.new("RGB", (32, 32), (10, 20, 31)).save(stego)

    result = evaluate_quality(original, stego)

    assert 0.0 <= result["ssim"] <= 1.0


def test_gui_constructs_and_password_state_tracks_method():
    try:
        root = tk.Tk()
    except tk.TclError as exc:
        pytest.skip(f"Tk display unavailable: {exc}")
    root.withdraw()
    try:
        app = SteganographyApp(root)
        root.update_idletasks()
        assert len(app.notebook.tabs()) == 4
        assert app.encode_method_var.get() == "edge"
        assert app.aes_var.get() is True
        assert str(app.encode_key_entry.cget("state")) == "normal"
        assert app.cover_path.get() == ""
        assert app.output_path.get() == ""
        assert app.stego_path.get() == ""
        assert app.original_quality_path.get() == ""
        assert app.stego_quality_path.get() == ""
        assert app.analysis_cover_path.get() == ""
        assert app.analysis_stego_path.get() == ""
        assert app.encode_key_var.get() == ""
        assert app.decode_key_var.get() == ""
        assert app.quality_key_var.get() == ""
        assert app.payload_size_var.get() == ""
        assert app.watermark_text_var.get() == ""
        assert app.message_text.get("1.0", "end-1c") == ""

        app.encode_method_var.set("random")
        root.update_idletasks()
        assert str(app.encode_key_entry.cget("state")) == "normal"

        app.encode_method_var.set("basic")
        app.aes_var.set(True)
        app._update_encode_password_state()
        assert str(app.encode_key_entry.cget("state")) == "normal"
    finally:
        root.destroy()
