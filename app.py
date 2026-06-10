from __future__ import annotations

import math
import tempfile
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from analysis import analyze_image_lsb
from decoder import decode_basic, decode_edge_adaptive, decode_randomized
from encoder import encode_basic, encode_edge_adaptive, encode_randomized
from metrics import evaluate_quality
from utils import (
    HiddenMessageNotFoundError,
    MessageTooLargeError,
    SteganographyError,
    WrongPasswordError,
    human_size,
    load_image,
)


IMAGE_FILE_TYPES = [
    ("Image files", "*.png *.jpg *.jpeg *.bmp *.tif *.tiff *.webp"),
    ("PNG", "*.png"),
    ("JPEG", "*.jpg *.jpeg"),
    ("BMP", "*.bmp"),
    ("TIFF", "*.tif *.tiff"),
    ("WEBP", "*.webp"),
    ("All files", "*.*"),
]


class SteganographyApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Image Steganography Demo")
        self.root.geometry("900x680")
        self.root.minsize(820, 620)

        self.encode_method_var = tk.StringVar(value="basic")
        self.decode_method_var = tk.StringVar(value="basic")
        self.quality_method_var = tk.StringVar(value="basic")
        self.aes_var = tk.BooleanVar(value=False)
        self.cover_path = tk.StringVar()
        self.output_path = tk.StringVar()
        self.stego_path = tk.StringVar()
        self.original_quality_path = tk.StringVar()
        self.stego_quality_path = tk.StringVar()
        self.encode_key_var = tk.StringVar()
        self.decode_key_var = tk.StringVar()
        self.quality_key_var = tk.StringVar()
        self.analysis_path = tk.StringVar()
        self.payload_size_var = tk.StringVar(value="0")

        self._build_ui()

    def _build_ui(self) -> None:
        style = ttk.Style()
        style.configure("Title.TLabel", font=("Segoe UI", 16, "bold"))
        style.configure("Hint.TLabel", foreground="#555555")

        outer = ttk.Frame(self.root, padding=16)
        outer.pack(fill="both", expand=True)

        ttk.Label(outer, text="Image Steganography Demo", style="Title.TLabel").pack(anchor="w")
        ttk.Label(
            outer,
            text="Encode, decode, and evaluate basic LSB or password-randomized LSB images.",
            style="Hint.TLabel",
        ).pack(anchor="w", pady=(2, 12))

        notebook = ttk.Notebook(outer)
        notebook.pack(fill="both", expand=True)

        encode_tab = ttk.Frame(notebook, padding=12)
        decode_tab = ttk.Frame(notebook, padding=12)
        quality_tab = ttk.Frame(notebook, padding=12)
        analysis_tab = ttk.Frame(notebook, padding=12)
        notebook.add(encode_tab, text="Encode")
        notebook.add(decode_tab, text="Decode")
        notebook.add(quality_tab, text="Quality")
        notebook.add(analysis_tab, text="Steganalysis")

        self._build_encode_tab(encode_tab)
        self._build_decode_tab(decode_tab)
        self._build_quality_tab(quality_tab)
        self._build_analysis_tab(analysis_tab)

        self.status = tk.StringVar(value="Ready.")
        ttk.Label(outer, textvariable=self.status, style="Hint.TLabel").pack(anchor="w", pady=(10, 0))

    def _path_row(self, parent: ttk.Frame, label: str, variable: tk.StringVar, save: bool = False) -> ttk.Frame:
        row = ttk.Frame(parent)
        row.pack(fill="x", pady=5)
        ttk.Label(row, text=label, width=18).pack(side="left")
        ttk.Entry(row, textvariable=variable).pack(side="left", fill="x", expand=True, padx=(0, 8))
        command = (lambda: self._browse_save(variable)) if save else (lambda: self._browse_open(variable))
        ttk.Button(row, text="Browse", command=command).pack(side="left")
        return row

    def _build_encode_tab(self, parent: ttk.Frame) -> None:
        self._path_row(parent, "Input image", self.cover_path)
        self._path_row(parent, "Output image", self.output_path, save=True)

        options = ttk.LabelFrame(parent, text="Method", padding=10)
        options.pack(fill="x", pady=(8, 10))
        ttk.Radiobutton(options, text="Basic LSB", variable=self.encode_method_var, value="basic").pack(side="left", padx=(0, 18))
        ttk.Radiobutton(options, text="Advanced randomized LSB", variable=self.encode_method_var, value="random").pack(side="left")
        ttk.Radiobutton(options, text="Edge-adaptive LSB", variable=self.encode_method_var, value="edge").pack(side="left", padx=(18, 0))
        ttk.Checkbutton(options, text="AES encryption if available", variable=self.aes_var).pack(side="right")

        key_row = ttk.Frame(parent)
        key_row.pack(fill="x", pady=5)
        ttk.Label(key_row, text="Password/key", width=18).pack(side="left")
        ttk.Entry(key_row, textvariable=self.encode_key_var, show="*").pack(side="left", fill="x", expand=True)

        ttk.Label(parent, text="Secret message").pack(anchor="w", pady=(12, 4))
        self.message_text = tk.Text(parent, height=10, wrap="word")
        self.message_text.pack(fill="both", expand=True)

        action_row = ttk.Frame(parent)
        action_row.pack(fill="x", pady=(12, 0))
        ttk.Button(action_row, text="Encode Image", command=self.encode_image).pack(side="left")
        ttk.Button(action_row, text="Clear", command=self.clear_encode).pack(side="left", padx=8)

        self.encode_result = tk.Text(parent, height=8, wrap="word", state="disabled")
        self.encode_result.pack(fill="x", pady=(12, 0))

    def _build_decode_tab(self, parent: ttk.Frame) -> None:
        self._path_row(parent, "Stego image", self.stego_path)

        options = ttk.LabelFrame(parent, text="Decode method", padding=10)
        options.pack(fill="x", pady=(8, 10))
        ttk.Radiobutton(options, text="Basic LSB", variable=self.decode_method_var, value="basic").pack(side="left", padx=(0, 18))
        ttk.Radiobutton(options, text="Advanced randomized LSB", variable=self.decode_method_var, value="random").pack(side="left")
        ttk.Radiobutton(options, text="Edge-adaptive LSB", variable=self.decode_method_var, value="edge").pack(side="left", padx=(18, 0))

        key_row = ttk.Frame(parent)
        key_row.pack(fill="x", pady=5)
        ttk.Label(key_row, text="Password/key", width=18).pack(side="left")
        ttk.Entry(key_row, textvariable=self.decode_key_var, show="*").pack(side="left", fill="x", expand=True)

        action_row = ttk.Frame(parent)
        action_row.pack(fill="x", pady=(12, 0))
        ttk.Button(action_row, text="Decode Message", command=self.decode_image).pack(side="left")

        ttk.Label(parent, text="Decoded message").pack(anchor="w", pady=(12, 4))
        self.decoded_text = tk.Text(parent, height=14, wrap="word")
        self.decoded_text.pack(fill="both", expand=True)

    def _build_quality_tab(self, parent: ttk.Frame) -> None:
        self._path_row(parent, "Original image", self.original_quality_path)
        self._path_row(parent, "Stego image", self.stego_quality_path)

        payload_row = ttk.Frame(parent)
        payload_row.pack(fill="x", pady=5)
        ttk.Label(payload_row, text="Payload bytes", width=18).pack(side="left")
        ttk.Entry(payload_row, textvariable=self.payload_size_var, width=12).pack(side="left")

        options = ttk.LabelFrame(parent, text="Decode method for robustness demo", padding=10)
        options.pack(fill="x", pady=(8, 10))
        ttk.Radiobutton(options, text="Basic LSB", variable=self.quality_method_var, value="basic").pack(side="left", padx=(0, 18))
        ttk.Radiobutton(options, text="Advanced randomized LSB", variable=self.quality_method_var, value="random").pack(side="left")
        ttk.Radiobutton(options, text="Edge-adaptive LSB", variable=self.quality_method_var, value="edge").pack(side="left", padx=(18, 0))

        key_row = ttk.Frame(parent)
        key_row.pack(fill="x", pady=5)
        ttk.Label(key_row, text="Password/key", width=18).pack(side="left")
        ttk.Entry(key_row, textvariable=self.quality_key_var, show="*").pack(side="left", fill="x", expand=True)

        action_row = ttk.Frame(parent)
        action_row.pack(fill="x", pady=(12, 0))
        ttk.Button(action_row, text="Evaluate Quality", command=self.evaluate_quality).pack(side="left")
        ttk.Button(action_row, text="Robustness Demo", command=self.robustness_demo).pack(side="left", padx=8)

        self.quality_result = tk.Text(parent, height=20, wrap="word", state="disabled")
        self.quality_result.pack(fill="both", expand=True, pady=(12, 0))

    def _build_analysis_tab(self, parent: ttk.Frame) -> None:
        self._path_row(parent, "Image", self.analysis_path)

        action_row = ttk.Frame(parent)
        action_row.pack(fill="x", pady=(12, 0))
        ttk.Button(action_row, text="Analyze LSB Plane", command=self.analyze_image).pack(side="left")

        self.analysis_result = tk.Text(parent, height=26, wrap="word", state="disabled")
        self.analysis_result.pack(fill="both", expand=True, pady=(12, 0))

    def _browse_open(self, variable: tk.StringVar) -> None:
        filename = filedialog.askopenfilename(filetypes=IMAGE_FILE_TYPES)
        if filename:
            variable.set(filename)

    def _browse_save(self, variable: tk.StringVar) -> None:
        filename = filedialog.asksaveasfilename(
            filetypes=IMAGE_FILE_TYPES,
            defaultextension=".png",
        )
        if filename:
            variable.set(filename)

    def _set_text(self, widget: tk.Text, text: str) -> None:
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", text)
        if widget is not self.message_text and widget is not self.decoded_text:
            widget.configure(state="disabled")

    def _handle_error(self, exc: Exception) -> None:
        self.status.set(f"Error: {exc}")
        messagebox.showerror("Steganography error", str(exc))

    def _run_background(self, label: str, worker, on_success) -> None:
        self.status.set(f"{label}...")

        def target() -> None:
            try:
                result = worker()
            except Exception as exc:
                self.root.after(0, lambda exc=exc: self._handle_error(exc))
                return
            self.root.after(0, lambda: on_success(result))

        threading.Thread(target=target, daemon=True).start()

    def encode_image(self) -> None:
        try:
            input_path = self.cover_path.get().strip()
            output_path = self.output_path.get().strip() or None
            message = self.message_text.get("1.0", "end-1c")
            key = self.encode_key_var.get()
            if not message:
                raise ValueError("Message cannot be empty.")
            method = self.encode_method_var.get()
            use_aes = self.aes_var.get()
        except ValueError as exc:
            self._handle_error(exc)
            return

        def worker():
            if method == "random":
                return encode_randomized(input_path, output_path, message, key, use_aes=use_aes)
            if method == "edge":
                return encode_edge_adaptive(input_path, output_path, message, use_aes=use_aes, password=key or None)
            return encode_basic(input_path, output_path, message, use_aes=use_aes, password=key or None)

        def on_success(result: dict) -> None:
            lines = [
                "Encoding successful.",
                f"Saved stego image: {result['output_path']}",
                f"Format: {result['input_format']} -> {result['save_format']}",
                f"AES encrypted: {'yes' if result['encrypted'] else 'no'}",
                f"Payload capacity: {human_size(int(result['capacity']['payload_capacity_bytes']))}",
                f"Payload used: {human_size(int(result['capacity']['payload_used_bytes']))}",
                f"Capacity used: {result['capacity']['capacity_used_percent']:.4f}%",
            ]
            for warning in result["warnings"]:
                lines.append(f"Warning: {warning}")
            self._set_text(self.encode_result, "\n".join(lines))
            self.stego_path.set(str(result["output_path"]))
            self.stego_quality_path.set(str(result["output_path"]))
            self.analysis_path.set(str(result["output_path"]))
            self.original_quality_path.set(input_path)
            self.payload_size_var.set(str(result["capacity"]["payload_used_bytes"]))
            self.decode_key_var.set("")
            self.quality_key_var.set("")
            self._set_text(self.decoded_text, "")
            self.status.set("Encoding finished.")

        self._run_background("Encoding image", worker, on_success)

    def decode_image(self) -> None:
        image_path = self.stego_path.get().strip()
        key = self.decode_key_var.get()
        method = self.decode_method_var.get()

        def worker():
            if method == "random":
                return decode_randomized(image_path, key)
            if method == "edge":
                return decode_edge_adaptive(image_path, password=key or None)
            return decode_basic(image_path, password=key or None)

        def on_success(message: str) -> None:
            self._set_text(self.decoded_text, message)
            self.status.set("Decoding finished.")

        self._run_background("Decoding image", worker, on_success)

    def evaluate_quality(self) -> None:
        try:
            payload_text = self.payload_size_var.get().strip()
            payload_size = int(payload_text) if payload_text else 0
            original_path = self.original_quality_path.get().strip()
            stego_path = self.stego_quality_path.get().strip()
        except ValueError as exc:
            self._handle_error(exc)
            return

        def worker():
            return evaluate_quality(original_path, stego_path, payload_size=payload_size)

        def on_success(result: dict) -> None:
            psnr = result["psnr"]
            lines = [
                "Image quality evaluation",
                f"Formats: {result['original_format']} -> {result['stego_format']}",
                f"Dimensions: {result['dimensions'][0]} x {result['dimensions'][1]}",
                f"MSE: {result['mse']:.6f}",
                f"PSNR: {'infinite' if math.isinf(psnr) else f'{psnr:.2f} dB'}",
                f"Payload capacity: {human_size(int(result['capacity']['payload_capacity_bytes']))}",
                f"Payload used: {human_size(int(result['capacity']['payload_used_bytes']))}",
                f"Capacity used: {result['capacity']['capacity_used_percent']:.4f}%",
            ]
            self._set_text(self.quality_result, "\n".join(lines))
            self.status.set("Quality evaluation finished.")

        self._run_background("Evaluating image quality", worker, on_success)

    def robustness_demo(self) -> None:
        stego_path = self.stego_quality_path.get().strip()
        key = self.quality_key_var.get()
        method = self.quality_method_var.get()

        def worker():
            if method == "random":
                decode_fn = lambda path, password=None: decode_randomized(path, key)
            elif method == "edge":
                decode_fn = lambda path, password=None: decode_edge_adaptive(path, password=key or None)
            else:
                decode_fn = decode_basic
            original_message = decode_fn(stego_path, key or None)

            with tempfile.TemporaryDirectory() as temp_dir:
                source, _ = load_image(stego_path)
                rgb = source.convert("RGB")
                tests = [
                    ("PNG conversion", Path(temp_dir) / "converted.png", {"format": "PNG"}),
                    ("BMP conversion", Path(temp_dir) / "converted.bmp", {"format": "BMP"}),
                    ("JPEG compression", Path(temp_dir) / "compressed.jpg", {"format": "JPEG", "quality": 85}),
                ]
                lines = ["Robustness demo", "Original stego decode: works"]
                for label, path, save_kwargs in tests:
                    try:
                        rgb.save(path, **save_kwargs)
                        decoded = decode_fn(path, key or None)
                        status = "works" if decoded == original_message else "decoded different text"
                    except Exception:
                        status = "failed"
                    lines.append(f"{label}: {status}")
            return lines

        def on_success(lines: list[str]) -> None:
            self._set_text(self.quality_result, "\n".join(lines))
            self.status.set("Robustness demo finished. Temporary files were deleted.")

        self._run_background("Running robustness demo", worker, on_success)

    def analyze_image(self) -> None:
        image_path = self.analysis_path.get().strip()

        def worker():
            return analyze_image_lsb(image_path)

        def on_success(result: dict) -> None:
            lines = [
                "LSB steganalysis report",
                f"Format: {result['format']}",
                f"Dimensions: {result['dimensions'][0]} x {result['dimensions'][1]}",
                f"Total LSB bits inspected: {result['total_lsb_bits']}",
                f"Zero bits: {result['zeros']}",
                f"One bits: {result['ones']}",
                f"One-bit ratio: {result['ones_ratio']:.4f}",
                f"LSB entropy: {result['entropy']:.4f} / 1.0000",
                f"Suspicion level: {result['suspicion']}",
                result["explanation"],
                "",
                "Per-channel one-bit ratios:",
            ]
            for channel in result["channels"]:
                lines.append(f"- {channel['name']}: {channel['ones_ratio']:.4f}")
            lines.extend(
                [
                    "",
                    "Important: this is a simple statistical demo, not proof that steganography exists.",
                ]
            )
            self._set_text(self.analysis_result, "\n".join(lines))
            self.status.set("Steganalysis finished.")

        self._run_background("Analyzing LSB plane", worker, on_success)

    def clear_encode(self) -> None:
        self.cover_path.set("")
        self.output_path.set("")
        self.encode_key_var.set("")
        self.message_text.delete("1.0", "end")
        self._set_text(self.encode_result, "")
        self.status.set("Encode form cleared.")


def run_app() -> None:
    root = tk.Tk()
    SteganographyApp(root)
    root.mainloop()


if __name__ == "__main__":
    run_app()
