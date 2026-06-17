from __future__ import annotations

import csv
import math
import queue
import tempfile
import threading
import time
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from PIL import Image, ImageTk

from analysis import (
    EDUCATIONAL_WARNING,
    analyze_image_lsb,
    difference_statistics,
    generate_combined_histogram,
    generate_difference_map,
)
from decoder import decode_basic, decode_edge_adaptive, decode_randomized
from encoder import encode_basic, encode_edge_adaptive, encode_randomized
from metrics import evaluate_quality
from utils import (
    SteganographyError,
    apply_visible_watermark,
    load_image,
    resolve_output_path,
    save_stego_image,
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
METHOD_LABELS = {
    "basic": "Basic LSB",
    "random": "Password-randomized LSB",
    "edge": "Edge-adaptive LSB",
}
DEMO_WATERMARK_TEXT = "IPUL Team"


class ImagePreview(ttk.LabelFrame):
    def __init__(self, parent, title: str) -> None:
        super().__init__(parent, text=title, padding=8)
        self.label = ttk.Label(self, text="No image selected", anchor="center")
        self.label.pack(fill="both", expand=True)
        self._photo = None

    def show(self, path: str | Path) -> None:
        image, _ = load_image(path)
        preview = image.copy()
        preview.thumbnail((320, 220), Image.Resampling.LANCZOS)
        self._photo = ImageTk.PhotoImage(preview)
        self.label.configure(image=self._photo, text="")

    def clear(self) -> None:
        self._photo = None
        self.label.configure(image="", text="No image selected")


class SteganographyApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Image Steganography Desktop")
        self.root.geometry("1120x900")
        self.root.minsize(960, 780)
        self._busy = False
        self._last_analysis: dict | None = None

        self.encode_method_var = tk.StringVar(value="edge")
        self.decode_method_var = tk.StringVar(value="edge")
        self.quality_method_var = tk.StringVar(value="edge")
        self.aes_var = tk.BooleanVar(value=True)
        self.compression_var = tk.BooleanVar(value=True)
        self.invisible_lsb_var = tk.BooleanVar(value=True)
        self.visible_watermark_var = tk.BooleanVar(value=False)
        self.watermark_text_var = tk.StringVar()
        self.cover_path = tk.StringVar()
        self.output_path = tk.StringVar()
        self.stego_path = tk.StringVar()
        self.original_quality_path = tk.StringVar()
        self.stego_quality_path = tk.StringVar()
        self.encode_key_var = tk.StringVar()
        self.decode_key_var = tk.StringVar()
        self.quality_key_var = tk.StringVar()
        self.analysis_cover_path = tk.StringVar()
        self.analysis_stego_path = tk.StringVar()
        self.payload_size_var = tk.StringVar()
        self.status = tk.StringVar(value="Ready.")

        self._build_ui()
        self.encode_method_var.trace_add("write", lambda *_: self._update_encode_password_state())
        self._update_encode_password_state()

    def _build_ui(self) -> None:
        style = ttk.Style()
        style.configure("Title.TLabel", font=("Segoe UI", 16, "bold"))
        style.configure("Hint.TLabel", foreground="#555555")

        outer = ttk.Frame(self.root, padding=14)
        outer.pack(fill="both", expand=True)
        ttk.Label(outer, text="Image Steganography Desktop", style="Title.TLabel").pack(anchor="w")
        ttk.Label(
            outer,
            text="Encode, decode, measure image quality, and inspect educational LSB statistics.",
            style="Hint.TLabel",
        ).pack(anchor="w", pady=(2, 10))

        self.notebook = ttk.Notebook(outer)
        self.notebook.pack(fill="both", expand=True)
        encode_tab = ttk.Frame(self.notebook, padding=10)
        decode_tab = ttk.Frame(self.notebook, padding=10)
        quality_tab = ttk.Frame(self.notebook, padding=10)
        analysis_tab = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(encode_tab, text="Encode")
        self.notebook.add(decode_tab, text="Decode")
        self.notebook.add(quality_tab, text="Quality")
        self.notebook.add(analysis_tab, text="Analysis")

        self._build_encode_tab(encode_tab)
        self._build_decode_tab(decode_tab)
        self._build_quality_tab(quality_tab)
        self._build_analysis_tab(analysis_tab)

        status_row = ttk.Frame(outer)
        status_row.pack(fill="x", pady=(10, 0))
        ttk.Label(status_row, textvariable=self.status, style="Hint.TLabel").pack(side="left", fill="x", expand=True)
        self.progress = ttk.Progressbar(status_row, mode="indeterminate", length=180)
        self.progress.pack(side="right")

    def _path_row(self, parent, label: str, variable: tk.StringVar, save: bool = False, preview=None) -> None:
        row = ttk.Frame(parent)
        row.pack(fill="x", pady=4)
        ttk.Label(row, text=label, width=18).pack(side="left")
        ttk.Entry(row, textvariable=variable).pack(side="left", fill="x", expand=True, padx=(0, 8))
        command = (
            lambda: self._browse_save(variable)
            if save
            else self._browse_open(variable, preview)
        )
        ttk.Button(row, text="Browse", command=command).pack(side="left")

    def _method_controls(self, parent, variable: tk.StringVar) -> ttk.Frame:
        frame = ttk.LabelFrame(parent, text="Method", padding=8)
        frame.pack(fill="x", pady=(6, 8))
        for value, label in METHOD_LABELS.items():
            ttk.Radiobutton(frame, text=label, variable=variable, value=value).pack(side="left", padx=(0, 16))
        return frame

    def _preview_pair(self, parent, left_title: str, right_title: str):
        frame = ttk.Frame(parent)
        frame.pack(fill="both", expand=True, pady=(8, 0))
        left = ImagePreview(frame, left_title)
        right = ImagePreview(frame, right_title)
        left.pack(side="left", fill="both", expand=True, padx=(0, 5))
        right.pack(side="left", fill="both", expand=True, padx=(5, 0))
        return left, right

    def _build_encode_tab(self, parent) -> None:
        self._path_row(parent, "Cover image", self.cover_path)
        self._path_row(parent, "Output PNG", self.output_path, save=True)
        options = self._method_controls(parent, self.encode_method_var)
        ttk.Checkbutton(options, text="Adaptive compression", variable=self.compression_var).pack(side="right")
        ttk.Checkbutton(
            options,
            text="AES-GCM encryption",
            variable=self.aes_var,
            command=self._update_encode_password_state,
        ).pack(side="right", padx=(0, 12))

        watermark_frame = ttk.LabelFrame(parent, text="Watermark output", padding=8)
        watermark_frame.pack(fill="x", pady=(0, 8))
        ttk.Checkbutton(watermark_frame, text="Invisible LSB watermark", variable=self.invisible_lsb_var).pack(side="left")
        ttk.Checkbutton(watermark_frame, text="Visible watermark", variable=self.visible_watermark_var).pack(side="left", padx=(18, 8))
        ttk.Label(watermark_frame, text="Visible text").pack(side="left", padx=(10, 4))
        ttk.Entry(watermark_frame, textvariable=self.watermark_text_var, width=24).pack(side="left")

        key_row = ttk.Frame(parent)
        key_row.pack(fill="x", pady=4)
        ttk.Label(key_row, text="Password/key", width=18).pack(side="left")
        self.encode_key_entry = ttk.Entry(key_row, textvariable=self.encode_key_var, show="*")
        self.encode_key_entry.pack(side="left", fill="x", expand=True)

        ttk.Label(parent, text="Secret message").pack(anchor="w", pady=(8, 3))
        self.message_text = tk.Text(parent, height=5, wrap="word")
        self.message_text.pack(fill="x")
        action_row = ttk.Frame(parent)
        action_row.pack(fill="x", pady=(8, 0))
        self.encode_button = ttk.Button(action_row, text="Encode Image", command=self.encode_image)
        self.encode_button.pack(side="left")
        ttk.Button(action_row, text="Clear", command=self.clear_encode).pack(side="left", padx=8)
        ttk.Button(action_row, text="Demo Difference Message", command=self.use_difference_demo_message).pack(side="left")

        self.encode_cover_preview, self.encode_stego_preview = self._preview_pair(parent, "Cover Preview", "Stego Preview")
        self.encode_result = tk.Text(parent, height=11, wrap="word", state="disabled")
        self.encode_result.pack(fill="x", pady=(8, 0))

    def _build_decode_tab(self, parent) -> None:
        self._path_row(parent, "Stego image", self.stego_path, preview=lambda path: self.decode_preview.show(path))
        self._method_controls(parent, self.decode_method_var)
        key_row = ttk.Frame(parent)
        key_row.pack(fill="x", pady=4)
        ttk.Label(key_row, text="Password/key", width=18).pack(side="left")
        ttk.Entry(key_row, textvariable=self.decode_key_var, show="*").pack(side="left", fill="x", expand=True)
        action_row = ttk.Frame(parent)
        action_row.pack(fill="x", pady=(8, 0))
        self.decode_button = ttk.Button(action_row, text="Decode Message", command=self.decode_image)
        self.decode_button.pack(side="left")
        ttk.Button(action_row, text="Copy Recovered Message", command=self.copy_decoded_message).pack(side="left", padx=8)

        self.decode_preview = ImagePreview(parent, "Stego Preview")
        self.decode_preview.pack(fill="both", expand=True, pady=(8, 0))
        ttk.Label(parent, text="Recovered message").pack(anchor="w", pady=(8, 3))
        self.decoded_text = tk.Text(parent, height=8, wrap="word")
        self.decoded_text.pack(fill="x")
        self.decode_result = tk.Text(parent, height=4, wrap="word", state="disabled")
        self.decode_result.pack(fill="x", pady=(8, 0))

    def _build_quality_tab(self, parent) -> None:
        self._path_row(parent, "Original image", self.original_quality_path)
        self._path_row(parent, "Stego image", self.stego_quality_path)
        payload_row = ttk.Frame(parent)
        payload_row.pack(fill="x", pady=4)
        ttk.Label(payload_row, text="Payload bytes", width=18).pack(side="left")
        ttk.Entry(payload_row, textvariable=self.payload_size_var, width=12).pack(side="left")
        self._method_controls(parent, self.quality_method_var)
        key_row = ttk.Frame(parent)
        key_row.pack(fill="x", pady=4)
        ttk.Label(key_row, text="Password/key", width=18).pack(side="left")
        ttk.Entry(key_row, textvariable=self.quality_key_var, show="*").pack(side="left", fill="x", expand=True)
        action_row = ttk.Frame(parent)
        action_row.pack(fill="x", pady=(8, 0))
        self.quality_button = ttk.Button(action_row, text="Evaluate Quality", command=self.evaluate_quality)
        self.quality_button.pack(side="left")
        ttk.Button(action_row, text="Robustness Demo", command=self.robustness_demo).pack(side="left", padx=8)
        self.quality_cover_preview, self.quality_stego_preview = self._preview_pair(parent, "Original Preview", "Stego Preview")
        self.quality_result = tk.Text(parent, height=9, wrap="word", state="disabled")
        self.quality_result.pack(fill="x", pady=(8, 0))

    def _build_analysis_tab(self, parent) -> None:
        self._path_row(parent, "Cover image", self.analysis_cover_path)
        self._path_row(parent, "Stego image", self.analysis_stego_path)
        action_row = ttk.Frame(parent)
        action_row.pack(fill="x", pady=(8, 0))
        self.analysis_button = ttk.Button(action_row, text="Analyze Images", command=self.analyze_images)
        self.analysis_button.pack(side="left")
        ttk.Button(action_row, text="Generate Histogram", command=self.generate_histogram).pack(side="left", padx=(8, 0))
        ttk.Button(action_row, text="Generate Difference Map", command=self.generate_difference_map).pack(side="left", padx=(8, 0))
        self.export_button = ttk.Button(action_row, text="Export Results CSV", command=self.export_analysis, state="disabled")
        self.export_button.pack(side="left", padx=8)
        self.analysis_cover_preview, self.analysis_stego_preview = self._preview_pair(parent, "Cover Preview", "Stego Preview")
        self.analysis_result = tk.Text(parent, height=12, wrap="word", state="disabled")
        self.analysis_result.pack(fill="x", pady=(8, 0))

    def _browse_open(self, variable: tk.StringVar, preview=None) -> None:
        filename = filedialog.askopenfilename(filetypes=IMAGE_FILE_TYPES)
        if filename:
            variable.set(filename)
            if preview:
                try:
                    preview(filename)
                except Exception as exc:
                    self._handle_error(exc)

    def _browse_save(self, variable: tk.StringVar) -> None:
        filename = filedialog.asksaveasfilename(filetypes=[("PNG image", "*.png")], defaultextension=".png")
        if filename:
            variable.set(filename)

    def _set_text(self, widget: tk.Text, text: str) -> None:
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", text)
        if widget not in {self.message_text, self.decoded_text}:
            widget.configure(state="disabled")

    def _set_busy(self, busy: bool, label: str = "") -> None:
        self._busy = busy
        state = "disabled" if busy else "normal"
        for button in (self.encode_button, self.decode_button, self.quality_button, self.analysis_button):
            button.configure(state=state)
        if busy:
            self.status.set(f"{label}...")
            self.progress.start(12)
        else:
            self.progress.stop()

    def _handle_error(self, exc: Exception) -> None:
        self._set_busy(False)
        message = str(exc) if isinstance(exc, (SteganographyError, ValueError, FileNotFoundError)) else "An unexpected error occurred."
        self.status.set(f"Error: {message}")
        messagebox.showerror("Steganography error", message)

    def _run_background(self, label: str, worker, on_success) -> None:
        if self._busy:
            return
        self._set_busy(True, label)
        result_queue: queue.Queue = queue.Queue(maxsize=1)

        def target() -> None:
            try:
                result_queue.put(("success", worker()))
            except Exception as exc:
                result_queue.put(("error", exc))

        threading.Thread(target=target, daemon=True).start()
        self.root.after(25, lambda: self._poll_background(result_queue, on_success))

    def _poll_background(self, result_queue: queue.Queue, on_success) -> None:
        try:
            status, result = result_queue.get_nowait()
        except queue.Empty:
            self.root.after(25, lambda: self._poll_background(result_queue, on_success))
            return
        if status == "error":
            self._handle_error(result)
            return
        self._finish_background(result, on_success)

    def _finish_background(self, result, on_success) -> None:
        self._set_busy(False)
        try:
            on_success(result)
        except Exception as exc:
            self._handle_error(exc)

    def _update_encode_password_state(self) -> None:
        needs_password = self.aes_var.get() or self.encode_method_var.get() == "random"
        self.encode_key_entry.configure(state="normal" if needs_password else "disabled")
        if not needs_password:
            self.encode_key_var.set("")

    def use_difference_demo_message(self) -> None:
        fragments = []
        for index in range(1, 257):
            fragments.append(f"LSB-DEMO-{index:03d}: {index * 7919:08x}-{index * 104729:08x}-{index * 65537:08x}")
        self._set_text(self.message_text, " | ".join(fragments))
        self.status.set("High-difference demo message loaded.")

    def encode_image(self) -> None:
        input_path = self.cover_path.get().strip()
        output_path = self.output_path.get().strip() or None
        message = self.message_text.get("1.0", "end-1c")
        key = self.encode_key_var.get()
        method = self.encode_method_var.get()
        use_aes = self.aes_var.get()
        use_compression = self.compression_var.get()
        use_lsb = self.invisible_lsb_var.get()
        use_visible_watermark = self.visible_watermark_var.get()
        visible_text = self.watermark_text_var.get().strip() or DEMO_WATERMARK_TEXT
        if not input_path:
            return self._handle_error(ValueError("Select a cover image."))
        if not use_lsb and not use_visible_watermark:
            return self._handle_error(ValueError("Select at least one watermark type."))
        if use_lsb and not message:
            return self._handle_error(ValueError("Message cannot be empty."))
        if output_path and Path(output_path).exists() and not messagebox.askyesno("Overwrite file?", "The output file exists. Replace it?"):
            return

        def worker():
            started = time.perf_counter()
            visible_payload = visible_text if use_visible_watermark else None
            if not use_lsb:
                image, input_format = load_image(input_path)
                watermarked = apply_visible_watermark(image, visible_text)
                output, _, warnings = resolve_output_path(input_path, output_path, input_format)
                save_stego_image(watermarked, output)
                result = {
                    "output_path": output,
                    "warnings": warnings,
                    "stored_payload_bytes": 0,
                    "compression_reduction_percent": 0.0,
                    "capacity": {"capacity_used_percent": 0.0},
                    "visible_watermark": True,
                    "encrypted": False,
                    "compressed": False,
                }
            elif method == "random":
                result = encode_randomized(
                    input_path,
                    output_path,
                    message,
                    key,
                    use_aes=use_aes,
                    use_compression=use_compression,
                    visible_watermark_text=visible_payload,
                )
            elif method == "edge":
                result = encode_edge_adaptive(
                    input_path,
                    output_path,
                    message,
                    use_aes=use_aes,
                    password=key or None,
                    use_compression=use_compression,
                    visible_watermark_text=visible_payload,
                )
            else:
                result = encode_basic(
                    input_path,
                    output_path,
                    message,
                    use_aes=use_aes,
                    password=key or None,
                    use_compression=use_compression,
                    visible_watermark_text=visible_payload,
                )
            result["runtime_seconds"] = time.perf_counter() - started
            result["quality"] = evaluate_quality(input_path, result["output_path"], result["stored_payload_bytes"])
            result["invisible_lsb"] = use_lsb
            return result

        def on_success(result: dict) -> None:
            quality = result["quality"]
            psnr = quality["psnr"]
            lines = [
                f"Invisible LSB watermark: {'yes' if result['invisible_lsb'] else 'no'}",
                f"Visible watermark: {'yes' if result['visible_watermark'] else 'no'}",
                f"Size reduction: {result['compression_reduction_percent']:.2f}%",
                f"Capacity used: {result['capacity']['capacity_used_percent']:.4f}%",
                f"MSE: {quality['mse']:.6f}",
                f"PSNR: {'infinite' if math.isinf(psnr) else f'{psnr:.2f} dB'}",
                f"SSIM: {quality['ssim']:.6f}",
                f"Encoding time: {result['runtime_seconds']:.4f} seconds",
            ]
            if not result["invisible_lsb"]:
                lines.append("No hidden payload was embedded.")
            lines.extend(f"Warning: {warning}" for warning in result["warnings"])
            self._set_text(self.encode_result, "\n".join(lines))
            output = str(result["output_path"])
            self.stego_path.set(output)
            self.original_quality_path.set(input_path)
            self.stego_quality_path.set(output)
            self.analysis_cover_path.set(input_path)
            self.analysis_stego_path.set(output)
            self.payload_size_var.set(str(result["stored_payload_bytes"]))
            self.encode_cover_preview.show(input_path)
            self.encode_stego_preview.show(output)
            self.status.set("Encoding finished.")

        self._run_background("Encoding image", worker, on_success)

    def decode_image(self) -> None:
        image_path = self.stego_path.get().strip()
        key = self.decode_key_var.get()
        method = self.decode_method_var.get()
        if not image_path:
            return self._handle_error(ValueError("Select a stego image."))

        def worker():
            started = time.perf_counter()
            if method == "random":
                message = decode_randomized(image_path, key)
            elif method == "edge":
                message = decode_edge_adaptive(image_path, password=key or None)
            else:
                message = decode_basic(image_path, password=key or None)
            return message, time.perf_counter() - started

        def on_success(result) -> None:
            message, runtime = result
            self._set_text(self.decoded_text, message)
            self._set_text(
                self.decode_result,
                f"Method: {METHOD_LABELS[method]}\nRecovered characters: {len(message)}\nDecoding time: {runtime:.4f} seconds",
            )
            self.decode_preview.show(image_path)
            self.status.set("Decoding finished.")

        self._run_background("Decoding image", worker, on_success)

    def copy_decoded_message(self) -> None:
        message = self.decoded_text.get("1.0", "end-1c")
        if not message:
            return self._handle_error(ValueError("There is no recovered message to copy."))
        self.root.clipboard_clear()
        self.root.clipboard_append(message)
        self.status.set("Recovered message copied to clipboard.")

    def evaluate_quality(self) -> None:
        try:
            payload_size = int(self.payload_size_var.get().strip() or "0")
        except ValueError as exc:
            return self._handle_error(exc)
        original_path = self.original_quality_path.get().strip()
        stego_path = self.stego_quality_path.get().strip()
        if not original_path or not stego_path:
            return self._handle_error(ValueError("Select both original and stego images."))

        def worker():
            started = time.perf_counter()
            result = evaluate_quality(original_path, stego_path, payload_size=payload_size)
            result["runtime_seconds"] = time.perf_counter() - started
            return result

        def on_success(result: dict) -> None:
            psnr = result["psnr"]
            lines = [
                "Image quality evaluation",
                f"Dimensions: {result['dimensions'][0]} x {result['dimensions'][1]}",
                f"MSE: {result['mse']:.6f}",
                f"PSNR: {'infinite' if math.isinf(psnr) else f'{psnr:.2f} dB'}",
                f"SSIM: {result['ssim']:.6f}",
                f"Capacity used: {result['capacity']['capacity_used_percent']:.4f}%",
                f"Evaluation time: {result['runtime_seconds']:.4f} seconds",
            ]
            self._set_text(self.quality_result, "\n".join(lines))
            self.quality_cover_preview.show(original_path)
            self.quality_stego_preview.show(stego_path)
            self.status.set("Quality evaluation finished.")

        self._run_background("Evaluating image quality", worker, on_success)

    def robustness_demo(self) -> None:
        stego_path = self.stego_quality_path.get().strip()
        key = self.quality_key_var.get()
        method = self.quality_method_var.get()
        if not stego_path:
            return self._handle_error(ValueError("Select a stego image."))

        def worker():
            if method == "random":
                decode_fn = lambda path: decode_randomized(path, key)
            elif method == "edge":
                decode_fn = lambda path: decode_edge_adaptive(path, password=key or None)
            else:
                decode_fn = lambda path: decode_basic(path, password=key or None)
            original_message = decode_fn(stego_path)
            with tempfile.TemporaryDirectory() as temp_dir:
                source, _ = load_image(stego_path)
                rgb = source.convert("RGB")
                tests = [
                    ("PNG re-save", Path(temp_dir) / "converted.png", {"format": "PNG"}),
                    ("BMP conversion", Path(temp_dir) / "converted.bmp", {"format": "BMP"}),
                    ("JPEG quality 85", Path(temp_dir) / "compressed.jpg", {"format": "JPEG", "quality": 85}),
                ]
                lines = ["Robustness demo", "Original stego decode: works"]
                for label, path, save_kwargs in tests:
                    try:
                        rgb.save(path, **save_kwargs)
                        status = "works" if decode_fn(path) == original_message else "decoded different text"
                    except Exception:
                        status = "failed"
                    lines.append(f"{label}: {status}")
                return lines

        self._run_background(
            "Running robustness demo",
            worker,
            lambda lines: (self._set_text(self.quality_result, "\n".join(lines)), self.status.set("Robustness demo finished.")),
        )

    def analyze_images(self) -> None:
        cover_path = self.analysis_cover_path.get().strip()
        stego_path = self.analysis_stego_path.get().strip()
        if not cover_path or not stego_path:
            return self._handle_error(ValueError("Select both cover and stego images."))

        def worker():
            started = time.perf_counter()
            return {
                "quality": evaluate_quality(cover_path, stego_path),
                "difference": difference_statistics(cover_path, stego_path),
                "cover_lsb": analyze_image_lsb(cover_path),
                "stego_lsb": analyze_image_lsb(stego_path),
                "runtime_seconds": time.perf_counter() - started,
            }

        def on_success(result: dict) -> None:
            self._last_analysis = result
            difference = result["difference"]
            cover_lsb = result["cover_lsb"]
            stego_lsb = result["stego_lsb"]
            lines = [
                f"Changed pixels: {difference['changed_pixels']}",
                f"Changed channels: {difference['changed_channels']}",
                f"Changed pixel percentage: {difference['changed_pixel_percent']:.6f}%",
                f"Maximum absolute difference: {difference['maximum_absolute_difference']}",
                f"Mean absolute difference: {difference['mean_absolute_difference']:.6f}",
                f"Cover LSB one ratio: {cover_lsb['ones_ratio']:.6f}",
                f"Stego LSB one ratio: {stego_lsb['ones_ratio']:.6f}",
                f"Cover LSB entropy: {cover_lsb['entropy']:.6f}",
                f"Stego LSB entropy: {stego_lsb['entropy']:.6f}",
                f"Stego suspicion: {stego_lsb['suspicion']}",
                EDUCATIONAL_WARNING,
                f"Analysis time: {result['runtime_seconds']:.4f} seconds",
            ]
            self._set_text(self.analysis_result, "\n".join(lines))
            self.analysis_cover_preview.show(cover_path)
            self.analysis_stego_preview.show(stego_path)
            self.export_button.configure(state="normal")
            self.status.set("Analysis finished.")

        self._run_background("Analyzing images", worker, on_success)

    def _analysis_paths(self) -> tuple[str, str] | None:
        cover_path = self.analysis_cover_path.get().strip()
        stego_path = self.analysis_stego_path.get().strip()
        if not cover_path or not stego_path:
            self._handle_error(ValueError("Select both cover and stego images."))
            return None
        return cover_path, stego_path

    def generate_histogram(self) -> None:
        paths = self._analysis_paths()
        if not paths:
            return
        output = filedialog.asksaveasfilename(filetypes=[("PNG image", "*.png")], defaultextension=".png")
        if not output:
            return
        cover_path, stego_path = paths
        self._run_background(
            "Generating histogram",
            lambda: generate_combined_histogram(cover_path, stego_path, output),
            lambda path: self.status.set(f"Histogram saved: {path}"),
        )

    def generate_difference_map(self) -> None:
        paths = self._analysis_paths()
        if not paths:
            return
        output = filedialog.asksaveasfilename(filetypes=[("PNG image", "*.png")], defaultextension=".png")
        if not output:
            return
        cover_path, stego_path = paths

        def on_success(result: dict) -> None:
            self.status.set(f"Amplified difference map saved: {result['output_path']}")

        self._run_background(
            "Generating amplified difference map",
            lambda: generate_difference_map(cover_path, stego_path, output),
            on_success,
        )

    def export_analysis(self) -> None:
        if not self._last_analysis:
            return self._handle_error(ValueError("Run analysis before exporting results."))
        filename = filedialog.asksaveasfilename(filetypes=[("CSV", "*.csv")], defaultextension=".csv")
        if not filename:
            return
        quality = self._last_analysis["quality"]
        difference = self._last_analysis["difference"]
        cover = self._last_analysis["cover_lsb"]
        stego = self._last_analysis["stego_lsb"]
        try:
            with Path(filename).open("w", newline="", encoding="utf-8") as handle:
                writer = csv.writer(handle)
                writer.writerow(["metric", "value"])
                writer.writerows(
                    [
                        ["mse", quality["mse"]],
                        ["psnr", quality["psnr"]],
                        ["ssim", quality["ssim"]],
                        ["changed_pixels", difference["changed_pixels"]],
                        ["changed_channels", difference["changed_channels"]],
                        ["changed_pixel_percent", difference["changed_pixel_percent"]],
                        ["maximum_absolute_difference", difference["maximum_absolute_difference"]],
                        ["mean_absolute_difference", difference["mean_absolute_difference"]],
                        ["cover_lsb_ones_ratio", cover["ones_ratio"]],
                        ["stego_lsb_ones_ratio", stego["ones_ratio"]],
                        ["cover_lsb_entropy", cover["entropy"]],
                        ["stego_lsb_entropy", stego["entropy"]],
                        ["stego_suspicion", stego["suspicion"]],
                    ]
                )
        except Exception as exc:
            self._handle_error(exc)
            return
        self.status.set(f"Analysis exported: {filename}")

    def clear_encode(self) -> None:
        self.cover_path.set("")
        self.output_path.set("")
        self.encode_key_var.set("")
        self.watermark_text_var.set("")
        self.message_text.delete("1.0", "end")
        self._set_text(self.encode_result, "")
        self.encode_cover_preview.clear()
        self.encode_stego_preview.clear()
        self.status.set("Encode form cleared.")


def run_app() -> None:
    root = tk.Tk()
    SteganographyApp(root)
    root.mainloop()


if __name__ == "__main__":
    run_app()
