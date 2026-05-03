# ── Standard library ─────────────────────────────────────────────────────────
import os
import struct
import hashlib
import secrets
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

# ── Third-party ───────────────────────────────────────────────────────────────
try:
    from PIL import Image, ImageTk
except ImportError:
    raise SystemExit("Missing dependency: run  pip install pillow")

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes, padding
    from cryptography.hazmat.backends import default_backend
except ImportError:
    raise SystemExit("Missing dependency: run  pip install cryptography")

# ═════════════════════════════════════════════════════════════════════════════
# PAYLOAD FORMAT
#   Offset  Size   Field
#   0       4      Magic header  b'STEG'
#   4       1      Enc flag      0x01=AES-256-CBC  0x00=plaintext
#   5       4      Payload length (uint32 big-endian)
#   9       16     IV            (only when enc flag == 0x01)
#   9/25    N      Data          ciphertext or raw UTF-8
# ═════════════════════════════════════════════════════════════════════════════
MAGIC          = b"STEG"
FLAG_PLAIN     = b"\x00"
FLAG_ENCRYPTED = b"\x01"


# ─────────────────────────────────────────────────────────────────────────────
# IMAGE I/O HANDLER
# ─────────────────────────────────────────────────────────────────────────────
class ImageIOHandler:
    SUPPORTED = {".png", ".bmp"}

    @staticmethod
    def load(path: str) -> Image.Image:
        ext = os.path.splitext(path)[1].lower()
        if ext not in ImageIOHandler.SUPPORTED:
            raise ValueError(f"Unsupported format '{ext}'. Use PNG or BMP.")
        img = Image.open(path).convert("RGB")
        return img

    @staticmethod
    def save(img: Image.Image, path: str) -> None:
        # Always save as PNG to guarantee lossless output
        if not path.lower().endswith(".png"):
            path += ".png"
        img.save(path, format="PNG")

    @staticmethod
    def capacity_bytes(img: Image.Image) -> int:
        """Maximum bytes that can be hidden (1 LSB per channel, 3 channels)."""
        w, h = img.size
        return (w * h * 3) // 8


# ─────────────────────────────────────────────────────────────────────────────
# INPUT VALIDATOR
# ─────────────────────────────────────────────────────────────────────────────
class InputValidator:
    @staticmethod
    def validate_encode(img: Image.Image, payload: bytes) -> None:
        cap = ImageIOHandler.capacity_bytes(img)
        if len(payload) > cap:
            raise ValueError(
                f"Message too large: payload is {len(payload)} bytes "
                f"but image can only hold {cap} bytes."
            )

    @staticmethod
    def validate_image(path: str) -> None:
        ext = os.path.splitext(path)[1].lower()
        if ext not in ImageIOHandler.SUPPORTED:
            raise ValueError(f"File type '{ext}' not supported. Use PNG or BMP.")


# ─────────────────────────────────────────────────────────────────────────────
# CRYPTO MODULE  (AES-256-CBC + PBKDF2-SHA256)
# ─────────────────────────────────────────────────────────────────────────────
class CryptoModule:
    ITERATIONS = 200_000
    KEY_LEN    = 32   # 256-bit
    SALT       = b"StegoSalt_2024!!"   # fixed salt — fine for academic use

    @classmethod
    def _derive_key(cls, password: str) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=cls.KEY_LEN,
            salt=cls.SALT,
            iterations=cls.ITERATIONS,
            backend=default_backend(),
        )
        return kdf.derive(password.encode("utf-8"))

    @classmethod
    def encrypt(cls, plaintext: str, password: str) -> tuple[bytes, bytes]:
        """Returns (iv, ciphertext)."""
        key = cls._derive_key(password)
        iv  = secrets.token_bytes(16)
        padder = padding.PKCS7(128).padder()
        padded = padder.update(plaintext.encode("utf-8")) + padder.finalize()
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        enc = cipher.encryptor()
        ciphertext = enc.update(padded) + enc.finalize()
        return iv, ciphertext

    @classmethod
    def decrypt(cls, iv: bytes, ciphertext: bytes, password: str) -> str:
        """Returns decrypted plaintext string."""
        key = cls._derive_key(password)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        dec = cipher.decryptor()
        padded = dec.update(ciphertext) + dec.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        plaintext_bytes = unpadder.update(padded) + unpadder.finalize()
        return plaintext_bytes.decode("utf-8")


# ─────────────────────────────────────────────────────────────────────────────
# ENCODER MODULE  (LSB substitution)
# ─────────────────────────────────────────────────────────────────────────────
class EncoderModule:
    @staticmethod
    def _build_payload(message: str, password: str | None) -> bytes:
        if password:
            iv, ciphertext = CryptoModule.encrypt(message, password)
            data  = iv + ciphertext
            flag  = FLAG_ENCRYPTED
        else:
            data  = message.encode("utf-8")
            flag  = FLAG_PLAIN
        length_header = struct.pack(">I", len(data))
        return MAGIC + flag + length_header + data

    @staticmethod
    def encode(img: Image.Image, message: str, password: str | None) -> Image.Image:
        payload = EncoderModule._build_payload(message, password)
        InputValidator.validate_encode(img, payload)

        pixels = list(img.getdata())
        bits   = "".join(f"{byte:08b}" for byte in payload)
        total  = len(bits)

        new_pixels = []
        bit_idx = 0
        for r, g, b in pixels:
            if bit_idx < total:
                r = (r & 0xFE) | int(bits[bit_idx]); bit_idx += 1
            if bit_idx < total:
                g = (g & 0xFE) | int(bits[bit_idx]); bit_idx += 1
            if bit_idx < total:
                b = (b & 0xFE) | int(bits[bit_idx]); bit_idx += 1
            new_pixels.append((r, g, b))

        out = Image.new("RGB", img.size)
        out.putdata(new_pixels)
        return out


# ─────────────────────────────────────────────────────────────────────────────
# DECODER MODULE  (LSB extraction)
# ─────────────────────────────────────────────────────────────────────────────
class DecoderModule:
    HEADER_BITS = (len(MAGIC) + 1 + 4) * 8   # magic(4) + flag(1) + length(4)

    @staticmethod
    def _read_bits(img: Image.Image, n_bits: int) -> str:
        bits = []
        for r, g, b in img.getdata():
            bits += [str(r & 1), str(g & 1), str(b & 1)]
            if len(bits) >= n_bits:
                break
        return "".join(bits[:n_bits])

    @staticmethod
    def _bits_to_bytes(bits: str) -> bytes:
        return bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8))

    @staticmethod
    def decode(img: Image.Image, password: str | None) -> str:
        # Read header
        header_bits  = DecoderModule._read_bits(img, DecoderModule.HEADER_BITS)
        header_bytes = DecoderModule._bits_to_bytes(header_bits)

        magic  = header_bytes[:4]
        if magic != MAGIC:
            raise ValueError("No hidden message found in this image.")

        flag   = header_bytes[4:5]
        length = struct.unpack(">I", header_bytes[5:9])[0]

        # Validate length
        cap = ImageIOHandler.capacity_bytes(img)
        if length > cap:
            raise ValueError("Corrupted payload: reported length exceeds image capacity.")

        # Read data bits
        total_bits = DecoderModule.HEADER_BITS + length * 8
        all_bits   = DecoderModule._read_bits(img, total_bits)
        data       = DecoderModule._bits_to_bytes(all_bits[DecoderModule.HEADER_BITS:])

        # Decrypt if needed
        if flag == FLAG_ENCRYPTED:
            if not password:
                raise ValueError("This message is encrypted. Please provide the password.")
            iv         = data[:16]
            ciphertext = data[16:]
            try:
                return CryptoModule.decrypt(iv, ciphertext, password)
            except Exception:
                raise ValueError("Decryption failed. Wrong password?")
        else:
            return data.decode("utf-8")


# ─────────────────────────────────────────────────────────────────────────────
# THEME & STYLE CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────
BG        = "#F4F7FB"
PANEL_BG  = "#FFFFFF"
BLUE      = "#2E75B6"
DARK_BLUE = "#1F4E79"
ACCENT    = "#E8F4FD"
TEXT      = "#1A1A2E"
MUTED     = "#6B7280"
SUCCESS   = "#16A34A"
ERROR     = "#DC2626"
BORDER    = "#D1D5DB"
FONT      = "Segoe UI" if os.name == "nt" else "Helvetica"


# ─────────────────────────────────────────────────────────────────────────────
# UI MODULE  (Tkinter)
# ─────────────────────────────────────────────────────────────────────────────
class StegoApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Image Steganography System")
        self.configure(bg=BG)
        self.resizable(True, True)
        self.minsize(720, 600)

        self._setup_styles()
        self._build_header()
        self._build_tabs()
        self._build_status_bar()

        self.update_idletasks()
        w, h = 820, 680
        x = (self.winfo_screenwidth()  - w) // 2
        y = (self.winfo_screenheight() - h) // 2
        self.geometry(f"{w}x{h}+{x}+{y}")

    # ── Styles ────────────────────────────────────────────────────────────────
    def _setup_styles(self):
        style = ttk.Style(self)
        style.theme_use("clam")

        style.configure("TNotebook",              background=BG,       borderwidth=0)
        style.configure("TNotebook.Tab",
                        background=ACCENT,        foreground=DARK_BLUE,
                        font=(FONT, 10, "bold"),  padding=[20, 8],     borderwidth=0)
        style.map("TNotebook.Tab",
                  background=[("selected", BLUE)],
                  foreground=[("selected", "white")])

        style.configure("Card.TFrame",   background=PANEL_BG, relief="flat")
        style.configure("TLabel",        background=PANEL_BG, foreground=TEXT, font=(FONT, 10))
        style.configure("Muted.TLabel",  background=PANEL_BG, foreground=MUTED, font=(FONT, 9))
        style.configure("Head.TLabel",   background=PANEL_BG, foreground=DARK_BLUE,
                        font=(FONT, 11, "bold"))
        style.configure("TEntry",        fieldbackground="white", font=(FONT, 10),
                        borderwidth=1, relief="solid")
        style.configure("Primary.TButton",
                        background=BLUE,    foreground="white",
                        font=(FONT, 10, "bold"), padding=[14, 8], borderwidth=0)
        style.map("Primary.TButton",
                  background=[("active", DARK_BLUE), ("pressed", DARK_BLUE)])
        style.configure("Ghost.TButton",
                        background=PANEL_BG, foreground=BLUE,
                        font=(FONT, 9),      padding=[8, 5],  borderwidth=1,
                        relief="solid")
        style.map("Ghost.TButton",
                  background=[("active", ACCENT)])
        style.configure("TScrollbar", background=BORDER)

    # ── Header ────────────────────────────────────────────────────────────────
    def _build_header(self):
        hdr = tk.Frame(self, bg=DARK_BLUE, height=64)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        tk.Label(hdr, text="🔒  Image Steganography System",
                 bg=DARK_BLUE, fg="white",
                 font=(FONT, 15, "bold")).pack(side="left", padx=24, pady=14)
        tk.Label(hdr, text="Hide messages inside images",
                 bg=DARK_BLUE, fg="#90CAF9",
                 font=(FONT, 9)).pack(side="right", padx=24)

    # ── Tabs ──────────────────────────────────────────────────────────────────
    def _build_tabs(self):
        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=16, pady=(12, 0))

        self.encode_tab = EncodeTab(nb, self._set_status)
        self.decode_tab = DecodeTab(nb, self._set_status)

        nb.add(self.encode_tab, text="  🔐  Encode  ")
        nb.add(self.decode_tab, text="  🔓  Decode  ")

    # ── Status bar ────────────────────────────────────────────────────────────
    def _build_status_bar(self):
        bar = tk.Frame(self, bg=BG, height=32)
        bar.pack(fill="x", side="bottom")
        self._status_var = tk.StringVar(value="Ready.")
        self._status_lbl = tk.Label(bar, textvariable=self._status_var,
                                    bg=BG, fg=MUTED, font=(FONT, 9), anchor="w")
        self._status_lbl.pack(side="left", padx=16, pady=6)

        tk.Label(bar,
                 text="Mohamed Aziz Amri · Mohamed Dhia Ben Kilani · Elaa Chaaleb",
                 bg=BG, fg=BORDER, font=(FONT, 8)).pack(side="right", padx=16)

    def _set_status(self, msg: str, kind: str = "info"):
        colors = {"info": MUTED, "ok": SUCCESS, "err": ERROR}
        self._status_var.set(msg)
        self._status_lbl.config(fg=colors.get(kind, MUTED))


# ─── Shared helpers ───────────────────────────────────────────────────────────
def make_card(parent) -> ttk.Frame:
    outer = tk.Frame(parent, bg=BG)
    outer.pack(fill="both", expand=True, padx=0, pady=0)
    card = ttk.Frame(outer, style="Card.TFrame", padding=20)
    card.pack(fill="both", expand=True, padx=12, pady=12)
    return card


def labeled_entry(parent, label: str, show: str = "") -> tk.StringVar:
    ttk.Label(parent, text=label, style="Head.TLabel").pack(anchor="w", pady=(10, 2))
    var = tk.StringVar()
    e = ttk.Entry(parent, textvariable=var, show=show)
    e.pack(fill="x", ipady=4)
    return var


def browse_btn(parent, var: tk.StringVar, title: str, filetypes) -> None:
    def _browse():
        path = filedialog.askopenfilename(title=title, filetypes=filetypes)
        if path:
            var.set(path)
    ttk.Button(parent, text="Browse…", style="Ghost.TButton", command=_browse).pack(
        anchor="w", pady=(4, 0))


def image_filetypes():
    return [("PNG / BMP Images", "*.png *.bmp"), ("All files", "*.*")]


def thumb(img: Image.Image, max_size: int = 200) -> ImageTk.PhotoImage:
    copy = img.copy()
    copy.thumbnail((max_size, max_size))
    return ImageTk.PhotoImage(copy)


# ─────────────────────────────────────────────────────────────────────────────
# ENCODE TAB
# ─────────────────────────────────────────────────────────────────────────────
class EncodeTab(tk.Frame):
    def __init__(self, parent, set_status):
        super().__init__(parent, bg=BG)
        self._set_status = set_status
        self._preview_ref = None
        self._build()

    def _build(self):
        card = make_card(self)

        # ── Left column: inputs ───────────────────────────────────────────────
        left = tk.Frame(card, bg=PANEL_BG)
        left.pack(side="left", fill="both", expand=True, padx=(0, 16))

        ttk.Label(left, text="Cover Image", style="Head.TLabel").pack(anchor="w", pady=(0, 2))
        self._img_var = tk.StringVar()
        ttk.Entry(left, textvariable=self._img_var, state="readonly").pack(fill="x", ipady=4)
        ttk.Button(left, text="Browse…", style="Ghost.TButton",
                   command=self._browse_image).pack(anchor="w", pady=(4, 0))

        ttk.Label(left, text="Secret Message", style="Head.TLabel").pack(
            anchor="w", pady=(16, 2))
        self._msg_text = tk.Text(left, height=7, font=(FONT, 10), relief="solid",
                                 borderwidth=1, wrap="word",
                                 bg="white", fg=TEXT, insertbackground=TEXT)
        self._msg_text.pack(fill="x")

        self._pwd_var = labeled_entry(left, "Password (optional — leave blank for no encryption)",
                                      show="●")

        ttk.Label(left, text="Save Stego-Image As", style="Head.TLabel").pack(
            anchor="w", pady=(16, 2))
        self._out_var = tk.StringVar()
        ttk.Entry(left, textvariable=self._out_var).pack(fill="x", ipady=4)
        ttk.Button(left, text="Browse…", style="Ghost.TButton",
                   command=self._browse_out).pack(anchor="w", pady=(4, 0))

        ttk.Button(left, text="🔐  Encode & Save", style="Primary.TButton",
                   command=self._run).pack(pady=(20, 0), anchor="w")

        # ── Right column: preview ─────────────────────────────────────────────
        right = tk.Frame(card, bg=PANEL_BG, width=220)
        right.pack(side="right", fill="y")
        right.pack_propagate(False)

        ttk.Label(right, text="Preview", style="Head.TLabel").pack(anchor="w")
        self._preview_canvas = tk.Canvas(right, bg=ACCENT, bd=0, highlightthickness=0,
                                         width=200, height=200)
        self._preview_canvas.pack(pady=(8, 0))
        ttk.Label(right, text="", style="Muted.TLabel").pack()
        self._info_var = tk.StringVar(value="No image selected.")
        ttk.Label(right, textvariable=self._info_var, style="Muted.TLabel",
                  wraplength=190).pack(pady=(4, 0), anchor="w")

    def _browse_image(self):
        path = filedialog.askopenfilename(title="Select Cover Image",
                                          filetypes=image_filetypes())
        if not path:
            return
        self._img_var.set(path)
        # Suggest output path
        base, _ = os.path.splitext(path)
        self._out_var.set(base + "_stego.png")
        # Update preview
        try:
            img = ImageIOHandler.load(path)
            cap = ImageIOHandler.capacity_bytes(img)
            self._info_var.set(
                f"{img.width} × {img.height} px\nMax capacity: {cap:,} bytes")
            ph = thumb(img)
            self._preview_ref = ph
            self._preview_canvas.config(width=ph.width(), height=ph.height())
            self._preview_canvas.create_image(0, 0, anchor="nw", image=ph)
        except Exception as e:
            self._info_var.set(str(e))

    def _browse_out(self):
        path = filedialog.asksaveasfilename(title="Save Stego-Image",
                                             defaultextension=".png",
                                             filetypes=[("PNG Image", "*.png")])
        if path:
            self._out_var.set(path)

    def _run(self):
        img_path = self._img_var.get().strip()
        message  = self._msg_text.get("1.0", "end").strip()
        password = self._pwd_var.get().strip() or None
        out_path = self._out_var.get().strip()

        # Validate inputs
        if not img_path:
            messagebox.showerror("Missing input", "Please select a cover image.")
            return
        if not message:
            messagebox.showerror("Missing input", "Please enter a secret message.")
            return
        if not out_path:
            messagebox.showerror("Missing input", "Please choose an output file path.")
            return

        try:
            self._set_status("Loading image…", "info")
            self.update()
            img = ImageIOHandler.load(img_path)

            self._set_status("Encoding message…", "info")
            self.update()
            stego = EncoderModule.encode(img, message, password)

            self._set_status("Saving stego-image…", "info")
            self.update()
            ImageIOHandler.save(stego, out_path)

            enc_note = " (AES-256 encrypted)" if password else " (no encryption)"
            self._set_status(
                f"✓  Saved to {os.path.basename(out_path)}{enc_note}", "ok")
            messagebox.showinfo("Success",
                                f"Stego-image saved successfully!\n\n"
                                f"File: {out_path}\n"
                                f"Encryption: {'AES-256-CBC' if password else 'None'}")
        except Exception as e:
            self._set_status(f"Error: {e}", "err")
            messagebox.showerror("Encoding Error", str(e))


# ─────────────────────────────────────────────────────────────────────────────
# DECODE TAB
# ─────────────────────────────────────────────────────────────────────────────
class DecodeTab(tk.Frame):
    def __init__(self, parent, set_status):
        super().__init__(parent, bg=BG)
        self._set_status = set_status
        self._preview_ref = None
        self._build()

    def _build(self):
        card = make_card(self)

        # ── Left column ───────────────────────────────────────────────────────
        left = tk.Frame(card, bg=PANEL_BG)
        left.pack(side="left", fill="both", expand=True, padx=(0, 16))

        ttk.Label(left, text="Stego-Image", style="Head.TLabel").pack(anchor="w", pady=(0, 2))
        self._img_var = tk.StringVar()
        ttk.Entry(left, textvariable=self._img_var, state="readonly").pack(fill="x", ipady=4)
        ttk.Button(left, text="Browse…", style="Ghost.TButton",
                   command=self._browse_image).pack(anchor="w", pady=(4, 0))

        self._pwd_var = labeled_entry(
            left, "Password (leave blank if message was not encrypted)", show="●")

        ttk.Button(left, text="🔓  Decode Message", style="Primary.TButton",
                   command=self._run).pack(pady=(20, 0), anchor="w")

        # ── Result area ───────────────────────────────────────────────────────
        ttk.Label(left, text="Extracted Message", style="Head.TLabel").pack(
            anchor="w", pady=(20, 2))
        result_frame = tk.Frame(left, bg=PANEL_BG, bd=1, relief="solid")
        result_frame.pack(fill="both", expand=True)

        self._result_text = tk.Text(result_frame, font=(FONT, 10), bg=ACCENT, fg=TEXT,
                                    relief="flat", borderwidth=0, wrap="word",
                                    state="disabled", cursor="arrow")
        sb = ttk.Scrollbar(result_frame, command=self._result_text.yview)
        self._result_text.config(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self._result_text.pack(fill="both", expand=True, padx=8, pady=8)

        ttk.Button(left, text="Copy to clipboard", style="Ghost.TButton",
                   command=self._copy).pack(anchor="w", pady=(6, 0))

        # ── Right column: preview ─────────────────────────────────────────────
        right = tk.Frame(card, bg=PANEL_BG, width=220)
        right.pack(side="right", fill="y")
        right.pack_propagate(False)

        ttk.Label(right, text="Preview", style="Head.TLabel").pack(anchor="w")
        self._preview_canvas = tk.Canvas(right, bg=ACCENT, bd=0, highlightthickness=0,
                                         width=200, height=200)
        self._preview_canvas.pack(pady=(8, 0))
        self._info_var = tk.StringVar(value="No image selected.")
        ttk.Label(right, textvariable=self._info_var, style="Muted.TLabel",
                  wraplength=190).pack(pady=(4, 0), anchor="w")

    def _browse_image(self):
        path = filedialog.askopenfilename(title="Select Stego-Image",
                                          filetypes=image_filetypes())
        if not path:
            return
        self._img_var.set(path)
        try:
            img = ImageIOHandler.load(path)
            self._info_var.set(f"{img.width} × {img.height} px")
            ph = thumb(img)
            self._preview_ref = ph
            self._preview_canvas.config(width=ph.width(), height=ph.height())
            self._preview_canvas.create_image(0, 0, anchor="nw", image=ph)
        except Exception as e:
            self._info_var.set(str(e))

    def _set_result(self, text: str):
        self._result_text.config(state="normal")
        self._result_text.delete("1.0", "end")
        self._result_text.insert("1.0", text)
        self._result_text.config(state="disabled")

    def _copy(self):
        content = self._result_text.get("1.0", "end").strip()
        if content:
            self.clipboard_clear()
            self.clipboard_append(content)
            self._set_status("Copied to clipboard.", "ok")

    def _run(self):
        img_path = self._img_var.get().strip()
        password = self._pwd_var.get().strip() or None

        if not img_path:
            messagebox.showerror("Missing input", "Please select a stego-image.")
            return

        try:
            self._set_status("Loading image…", "info")
            self.update()
            img = ImageIOHandler.load(img_path)

            self._set_status("Extracting hidden message…", "info")
            self.update()
            message = DecoderModule.decode(img, password)

            self._set_result(message)
            enc_note = " (decrypted with AES-256)" if password else ""
            self._set_status(f"✓  Message extracted successfully{enc_note}", "ok")
        except Exception as e:
            self._set_result("")
            self._set_status(f"Error: {e}", "err")
            messagebox.showerror("Decoding Error", str(e))


# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app = StegoApp()
    app.mainloop()