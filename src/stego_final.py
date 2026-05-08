# ── Standard library ─────────────────────────────────────────────────────────
import os
import struct
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
#   5       4      Payload data length (uint32 big-endian)
#   -- When flag == 0x01 (encrypted): --
#   9       16     Random SALT   (unique per message — fixes fixed-salt vuln)
#   25      16     IV
#   41      N      Ciphertext
#   -- When flag == 0x00 (plain): --
#   9       N      Raw UTF-8 data
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
        if not path.lower().endswith(".png"):
            path += ".png"
        img.save(path, format="PNG")

    @staticmethod
    def capacity_bytes(img: Image.Image) -> int:
        """Maximum bytes hideable (1 LSB per channel × 3 channels)."""
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
# FIX: Random salt generated per message and stored in the payload.
#      The old fixed-salt approach allowed pre-computation attacks.
# ─────────────────────────────────────────────────────────────────────────────
class CryptoModule:
    ITERATIONS = 200_000
    KEY_LEN    = 32          # 256-bit AES key
    SALT_LEN   = 16          # 128-bit random salt

    @classmethod
    def _derive_key(cls, password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=cls.KEY_LEN,
            salt=salt,
            iterations=cls.ITERATIONS,
            backend=default_backend(),
        )
        return kdf.derive(password.encode("utf-8"))

    @classmethod
    def encrypt(cls, plaintext: str, password: str) -> tuple[bytes, bytes, bytes]:
        """Returns (salt, iv, ciphertext). Salt is unique per call."""
        salt   = secrets.token_bytes(cls.SALT_LEN)
        key    = cls._derive_key(password, salt)
        iv     = secrets.token_bytes(16)
        padder = padding.PKCS7(128).padder()
        padded = padder.update(plaintext.encode("utf-8")) + padder.finalize()
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        enc    = cipher.encryptor()
        return salt, iv, enc.update(padded) + enc.finalize()

    @classmethod
    def decrypt(cls, salt: bytes, iv: bytes, ciphertext: bytes, password: str) -> str:
        """Returns decrypted plaintext. Raises on wrong password."""
        key    = cls._derive_key(password, salt)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        dec    = cipher.decryptor()
        padded = dec.update(ciphertext) + dec.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        return (unpadder.update(padded) + unpadder.finalize()).decode("utf-8")


# ─────────────────────────────────────────────────────────────────────────────
# PASSWORD STRENGTH CHECKER
# Returns (label, color, score 0-4)
# ─────────────────────────────────────────────────────────────────────────────
def password_strength(pwd: str) -> tuple[str, str, int]:
    if not pwd:
        return ("", "#6B7280", 0)
    score = 0
    if len(pwd) >= 8:  score += 1
    if len(pwd) >= 12: score += 1
    if any(c.isupper() for c in pwd) and any(c.islower() for c in pwd): score += 1
    if any(c.isdigit() for c in pwd): score += 1
    if any(c in "!@#$%^&*()-_=+[]{}|;:',.<>?/`~" for c in pwd): score += 1
    score = min(score, 4)
    labels = ["", "Weak", "Fair", "Strong", "Very Strong"]
    colors = ["", "#DC2626", "#D97706", "#16A34A", "#1F4E79"]
    return (labels[score], colors[score], score)


# ─────────────────────────────────────────────────────────────────────────────
# ENCODER MODULE  (LSB substitution)
# ─────────────────────────────────────────────────────────────────────────────
class EncoderModule:
    @staticmethod
    def _build_payload(message: str, password: str) -> bytes:
        salt, iv, ciphertext = CryptoModule.encrypt(message, password)
        data          = salt + iv + ciphertext
        length_header = struct.pack(">I", len(data))
        return MAGIC + FLAG_ENCRYPTED + length_header + data

    @staticmethod
    def encode(img: Image.Image, message: str, password: str) -> Image.Image:
        payload = EncoderModule._build_payload(message, password)
        InputValidator.validate_encode(img, payload)

        pixels  = list(img.getdata())
        bits    = "".join(f"{byte:08b}" for byte in payload)
        total   = len(bits)

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
    def decode(img: Image.Image, password: str) -> str:
        header_bits  = DecoderModule._read_bits(img, DecoderModule.HEADER_BITS)
        header_bytes = DecoderModule._bits_to_bytes(header_bits)

        if header_bytes[:4] != MAGIC:
            raise ValueError("No hidden message found in this image.")

        flag   = header_bytes[4:5]
        length = struct.unpack(">I", header_bytes[5:9])[0]

        cap = ImageIOHandler.capacity_bytes(img)
        if length > cap:
            raise ValueError("Corrupted payload: reported length exceeds image capacity.")

        total_bits = DecoderModule.HEADER_BITS + length * 8
        all_bits   = DecoderModule._read_bits(img, total_bits)
        data       = DecoderModule._bits_to_bytes(all_bits[DecoderModule.HEADER_BITS:])

        if flag == FLAG_ENCRYPTED:
            salt       = data[:16]
            iv         = data[16:32]
            ciphertext = data[32:]
            try:
                return CryptoModule.decrypt(salt, iv, ciphertext, password)
            except Exception:
                raise ValueError("Decryption failed — wrong password.")
        else:
            return data.decode("utf-8")


# ─────────────────────────────────────────────────────────────────────────────
# HISTOGRAM HELPER  (no matplotlib — pure Tkinter canvas)
# ─────────────────────────────────────────────────────────────────────────────
def compute_histogram(img: Image.Image) -> tuple[list, list, list]:
    """Returns (r_hist, g_hist, b_hist) each a list of 256 counts."""
    r_hist = [0] * 256
    g_hist = [0] * 256
    b_hist = [0] * 256
    for r, g, b in img.getdata():
        r_hist[r] += 1
        g_hist[g] += 1
        b_hist[b] += 1
    return r_hist, g_hist, b_hist


def draw_histogram(canvas: tk.Canvas, hist_r, hist_g, hist_b,
                   title: str, w: int = 300, h: int = 140):
    """Draw an RGB histogram on a Tkinter canvas."""
    canvas.delete("all")
    canvas.config(width=w, height=h)
    pad_l, pad_r, pad_t, pad_b = 6, 6, 22, 20
    chart_w = w - pad_l - pad_r
    chart_h = h - pad_t - pad_b

    # Title
    canvas.create_text(w // 2, 11, text=title, font=("Helvetica", 8, "bold"),
                       fill="#1F4E79")

    # Background
    canvas.create_rectangle(pad_l, pad_t, pad_l + chart_w, pad_t + chart_h,
                             fill="#F8FAFC", outline="#D1D5DB")

    peak = max(max(hist_r), max(hist_g), max(hist_b), 1)
    bar_w = chart_w / 256

    channels = [(hist_r, "#EF4444"), (hist_g, "#22C55E"), (hist_b, "#3B82F6")]
    for hist, colour in channels:
        for i, v in enumerate(hist):
            bar_h = int((v / peak) * chart_h)
            if bar_h < 1:
                continue
            x0 = pad_l + i * bar_w
            x1 = x0 + bar_w + 0.5
            y0 = pad_t + chart_h - bar_h
            y1 = pad_t + chart_h
            canvas.create_rectangle(x0, y0, x1, y1, fill=colour, outline="",
                                    stipple="gray50")

    # Axis labels
    canvas.create_text(pad_l, pad_t + chart_h + 10, text="0",
                       font=("Helvetica", 7), fill="#6B7280", anchor="w")
    canvas.create_text(pad_l + chart_w, pad_t + chart_h + 10, text="255",
                       font=("Helvetica", 7), fill="#6B7280", anchor="e")


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
        self.minsize(820, 640)

        self._setup_styles()
        self._build_header()
        self._build_tabs()
        self._build_status_bar()

        self.update_idletasks()
        w, h = 900, 720
        x = (self.winfo_screenwidth()  - w) // 2
        y = (self.winfo_screenheight() - h) // 2
        self.geometry(f"{w}x{h}+{x}+{y}")

    def _setup_styles(self):
        style = ttk.Style(self)
        style.theme_use("clam")

        style.configure("TNotebook",         background=BG,      borderwidth=0)
        style.configure("TNotebook.Tab",
                        background=ACCENT,   foreground=DARK_BLUE,
                        font=(FONT, 10, "bold"), padding=[20, 8], borderwidth=0)
        style.map("TNotebook.Tab",
                  background=[("selected", BLUE)],
                  foreground=[("selected", "white")])

        style.configure("Card.TFrame",   background=PANEL_BG, relief="flat")
        style.configure("TLabel",        background=PANEL_BG, foreground=TEXT,      font=(FONT, 10))
        style.configure("Muted.TLabel",  background=PANEL_BG, foreground=MUTED,     font=(FONT, 9))
        style.configure("Head.TLabel",   background=PANEL_BG, foreground=DARK_BLUE, font=(FONT, 11, "bold"))
        style.configure("TEntry",        fieldbackground="white", font=(FONT, 10),   borderwidth=1, relief="solid")
        style.configure("Primary.TButton",
                        background=BLUE,    foreground="white",
                        font=(FONT, 10, "bold"), padding=[14, 8], borderwidth=0)
        style.map("Primary.TButton",
                  background=[("active", DARK_BLUE), ("pressed", DARK_BLUE)])
        style.configure("Ghost.TButton",
                        background=PANEL_BG, foreground=BLUE,
                        font=(FONT, 9), padding=[8, 5], borderwidth=1, relief="solid")
        style.map("Ghost.TButton", background=[("active", ACCENT)])
        style.configure("TScrollbar", background=BORDER)

    def _build_header(self):
        hdr = tk.Frame(self, bg=DARK_BLUE, height=64)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        tk.Label(hdr, text="🔒  Image Steganography System",
                 bg=DARK_BLUE, fg="white",
                 font=(FONT, 15, "bold")).pack(side="left", padx=24, pady=14)
        tk.Label(hdr, text="Hide messages inside images  ·  AES-256 Encrypted",
                 bg=DARK_BLUE, fg="#90CAF9",
                 font=(FONT, 9)).pack(side="right", padx=24)

    def _build_tabs(self):
        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=16, pady=(12, 0))

        self.encode_tab   = EncodeTab(nb, self._set_status)
        self.decode_tab   = DecodeTab(nb, self._set_status)
        self.analysis_tab = AnalysisTab(nb, self._set_status)

        nb.add(self.encode_tab,   text="  🔐  Encode  ")
        nb.add(self.decode_tab,   text="  🔓  Decode  ")
        nb.add(self.analysis_tab, text="  📊  Analysis  ")

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
    outer.pack(fill="both", expand=True)
    card = ttk.Frame(outer, style="Card.TFrame", padding=20)
    card.pack(fill="both", expand=True, padx=12, pady=12)
    return card


def labeled_entry(parent, label: str, show: str = "") -> tk.StringVar:
    ttk.Label(parent, text=label, style="Head.TLabel").pack(anchor="w", pady=(10, 2))
    var = tk.StringVar()
    ttk.Entry(parent, textvariable=var, show=show).pack(fill="x", ipady=4)
    return var


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
        self._set_status  = set_status
        self._preview_ref = None
        self._img_cap     = 0      # capacity in bytes once image is loaded
        self._build()

    def _build(self):
        card = make_card(self)

        # ── Left column ───────────────────────────────────────────────────────
        left = tk.Frame(card, bg=PANEL_BG)
        left.pack(side="left", fill="both", expand=True, padx=(0, 16))

        ttk.Label(left, text="Cover Image", style="Head.TLabel").pack(anchor="w", pady=(0, 2))
        self._img_var = tk.StringVar()
        ttk.Entry(left, textvariable=self._img_var, state="readonly").pack(fill="x", ipady=4)
        ttk.Button(left, text="Browse…", style="Ghost.TButton",
                   command=self._browse_image).pack(anchor="w", pady=(4, 0))

        # Secret message + live character counter
        ttk.Label(left, text="Secret Message", style="Head.TLabel").pack(
            anchor="w", pady=(16, 2))
        self._msg_text = tk.Text(left, height=6, font=(FONT, 10), relief="solid",
                                 borderwidth=1, wrap="word",
                                 bg="white", fg=TEXT, insertbackground=TEXT)
        self._msg_text.pack(fill="x")
        self._msg_text.bind("<KeyRelease>", self._update_counter)

        # Character / capacity counter label
        self._counter_var = tk.StringVar(value="0 chars  ·  load an image to see capacity")
        tk.Label(left, textvariable=self._counter_var,
                 bg=PANEL_BG, fg=MUTED, font=(FONT, 8), anchor="w").pack(
                     fill="x", pady=(2, 0))

        # Password field
        ttk.Label(left, text="Password (required — receiver must use the same password)",
                  style="Head.TLabel").pack(anchor="w", pady=(12, 2))
        self._pwd_var = tk.StringVar()
        ttk.Entry(left, textvariable=self._pwd_var, show="●").pack(fill="x", ipady=4)
        self._pwd_var.trace_add("write", self._update_strength)

        # Password strength indicator
        self._strength_var = tk.StringVar(value="")
        self._strength_lbl = tk.Label(left, textvariable=self._strength_var,
                                      bg=PANEL_BG, font=(FONT, 9, "bold"), anchor="w")
        self._strength_lbl.pack(fill="x", pady=(3, 0))

        # Output path
        ttk.Label(left, text="Save Stego-Image As", style="Head.TLabel").pack(
            anchor="w", pady=(14, 2))
        self._out_var = tk.StringVar()
        ttk.Entry(left, textvariable=self._out_var).pack(fill="x", ipady=4)
        ttk.Button(left, text="Browse…", style="Ghost.TButton",
                   command=self._browse_out).pack(anchor="w", pady=(4, 0))

        ttk.Button(left, text="🔐  Encode & Save", style="Primary.TButton",
                   command=self._run).pack(pady=(18, 0), anchor="w")

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
                  wraplength=190).pack(pady=(6, 0), anchor="w")

    # ── Callbacks ─────────────────────────────────────────────────────────────
    def _update_counter(self, *_):
        text = self._msg_text.get("1.0", "end").strip()
        chars = len(text)
        byte_estimate = len(text.encode("utf-8"))
        if self._img_cap:
            remaining = self._img_cap - 9  # subtract header overhead
            color = ERROR if byte_estimate > remaining else MUTED
            self._counter_var.set(
                f"{chars} chars  ·  ~{byte_estimate} bytes used  ·  {max(0, remaining - byte_estimate):,} bytes free")
            self.nametowidget(self._counter_var)  # force redraw
        else:
            self._counter_var.set(f"{chars} chars  ·  load an image to see capacity")
            color = MUTED
        # Find and recolor the counter label
        for w in self.winfo_children():
            pass  # label is updated via StringVar automatically

    def _update_strength(self, *_):
        pwd = self._pwd_var.get()
        label, color, _ = password_strength(pwd)
        self._strength_var.set(f"Strength: {label}" if label else "")
        self._strength_lbl.config(fg=color)

    def _browse_image(self):
        path = filedialog.askopenfilename(title="Select Cover Image",
                                          filetypes=image_filetypes())
        if not path:
            return
        self._img_var.set(path)
        base, _ = os.path.splitext(path)
        self._out_var.set(base + "_stego.png")
        try:
            img = ImageIOHandler.load(path)
            self._img_cap = ImageIOHandler.capacity_bytes(img)
            self._info_var.set(
                f"{img.width} × {img.height} px\nMax capacity: {self._img_cap:,} bytes")
            ph = thumb(img)
            self._preview_ref = ph
            self._preview_canvas.config(width=ph.width(), height=ph.height())
            self._preview_canvas.create_image(0, 0, anchor="nw", image=ph)
            self._update_counter()
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
        password = self._pwd_var.get().strip()
        out_path = self._out_var.get().strip()

        if not img_path:
            messagebox.showerror("Missing input", "Please select a cover image.")
            return
        if not message:
            messagebox.showerror("Missing input", "Please enter a secret message.")
            return
        if not password:
            messagebox.showerror("Missing input",
                                 "Password is required.\nThe receiver needs it to decode the message.")
            return
        _, _, strength_score = password_strength(password)
        if strength_score < 2:
            if not messagebox.askyesno("Weak Password",
                                       "Your password is weak and easy to guess.\n\n"
                                       "Continue anyway?"):
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

            self._set_status(f"✓  Saved to {os.path.basename(out_path)}  (AES-256 encrypted)", "ok")
            messagebox.showinfo("Success",
                                f"Stego-image saved!\n\n"
                                f"File: {out_path}\n"
                                f"Encryption: AES-256-CBC + random salt\n\n"
                                f"Share the image and the password separately.")
        except Exception as e:
            self._set_status(f"Error: {e}", "err")
            messagebox.showerror("Encoding Error", str(e))


# ─────────────────────────────────────────────────────────────────────────────
# DECODE TAB
# ─────────────────────────────────────────────────────────────────────────────
class DecodeTab(tk.Frame):
    def __init__(self, parent, set_status):
        super().__init__(parent, bg=BG)
        self._set_status  = set_status
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

        ttk.Label(left, text="Password (required — same password used during encoding)",
                  style="Head.TLabel").pack(anchor="w", pady=(12, 2))
        self._pwd_var = tk.StringVar()
        ttk.Entry(left, textvariable=self._pwd_var, show="●").pack(fill="x", ipady=4)

        ttk.Button(left, text="🔓  Decode Message", style="Primary.TButton",
                   command=self._run).pack(pady=(18, 0), anchor="w")

        # Extracted message area
        ttk.Label(left, text="Extracted Message", style="Head.TLabel").pack(
            anchor="w", pady=(18, 2))

        # Wrong-password banner (hidden by default)
        self._banner_var = tk.StringVar(value="")
        self._banner_lbl = tk.Label(left, textvariable=self._banner_var,
                                    bg="#FEE2E2", fg=ERROR,
                                    font=(FONT, 9, "bold"), anchor="w",
                                    padx=8, pady=4, relief="flat")

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
                  wraplength=190).pack(pady=(6, 0), anchor="w")

    def _browse_image(self):
        path = filedialog.askopenfilename(title="Select Stego-Image",
                                          filetypes=image_filetypes())
        if not path:
            return
        self._img_var.set(path)
        self._hide_banner()
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

    def _show_banner(self, msg: str):
        self._banner_var.set(msg)
        self._banner_lbl.pack(fill="x", pady=(0, 6), before=self._result_text.master)

    def _hide_banner(self):
        self._banner_var.set("")
        self._banner_lbl.pack_forget()

    def _copy(self):
        content = self._result_text.get("1.0", "end").strip()
        if content:
            self.clipboard_clear()
            self.clipboard_append(content)
            self._set_status("Copied to clipboard.", "ok")

    def _run(self):
        img_path = self._img_var.get().strip()
        password = self._pwd_var.get().strip()
        self._hide_banner()

        if not img_path:
            messagebox.showerror("Missing input", "Please select a stego-image.")
            return
        if not password:
            messagebox.showerror("Missing input",
                                 "Password is required.\n"
                                 "Ask the sender for the password used during encoding.")
            return

        try:
            self._set_status("Loading image…", "info")
            self.update()
            img = ImageIOHandler.load(img_path)

            self._set_status("Extracting hidden message…", "info")
            self.update()
            message = DecoderModule.decode(img, password)

            self._set_result(message)
            self._set_status("✓  Message extracted successfully  (AES-256 decrypted)", "ok")
        except ValueError as e:
            err = str(e)
            self._set_result("")
            # Show a persistent red banner for wrong-password errors
            if "wrong password" in err.lower() or "decryption failed" in err.lower():
                self._show_banner("❌  Wrong password — decryption failed. Try again.")
            self._set_status(f"Error: {err}", "err")
            messagebox.showerror("Decoding Error", err)
        except Exception as e:
            self._set_result("")
            self._set_status(f"Error: {e}", "err")
            messagebox.showerror("Decoding Error", str(e))


# ─────────────────────────────────────────────────────────────────────────────
# ANALYSIS TAB  — histogram comparison (proves imperceptibility)
# ─────────────────────────────────────────────────────────────────────────────
class AnalysisTab(tk.Frame):
    def __init__(self, parent, set_status):
        super().__init__(parent, bg=BG)
        self._set_status = set_status
        self._orig_img   = None
        self._stego_img  = None
        self._build()

    def _build(self):
        card = make_card(self)

        # ── Top controls row ──────────────────────────────────────────────────
        ctrl = tk.Frame(card, bg=PANEL_BG)
        ctrl.pack(fill="x", pady=(0, 14))

        # Original image picker
        orig_col = tk.Frame(ctrl, bg=PANEL_BG)
        orig_col.pack(side="left", fill="x", expand=True, padx=(0, 10))
        ttk.Label(orig_col, text="Original Image", style="Head.TLabel").pack(anchor="w")
        self._orig_var = tk.StringVar()
        ttk.Entry(orig_col, textvariable=self._orig_var, state="readonly").pack(
            fill="x", ipady=3)
        ttk.Button(orig_col, text="Browse…", style="Ghost.TButton",
                   command=lambda: self._browse("orig")).pack(anchor="w", pady=(4, 0))

        # Stego image picker
        stego_col = tk.Frame(ctrl, bg=PANEL_BG)
        stego_col.pack(side="left", fill="x", expand=True, padx=(10, 0))
        ttk.Label(stego_col, text="Stego-Image (output)", style="Head.TLabel").pack(anchor="w")
        self._stego_var = tk.StringVar()
        ttk.Entry(stego_col, textvariable=self._stego_var, state="readonly").pack(
            fill="x", ipady=3)
        ttk.Button(stego_col, text="Browse…", style="Ghost.TButton",
                   command=lambda: self._browse("stego")).pack(anchor="w", pady=(4, 0))

        ttk.Button(card, text="📊  Run Analysis", style="Primary.TButton",
                   command=self._run).pack(anchor="w", pady=(0, 14))

        # Separator
        tk.Frame(card, bg=BORDER, height=1).pack(fill="x", pady=(0, 14))

        # ── Histogram area ────────────────────────────────────────────────────
        hist_row = tk.Frame(card, bg=PANEL_BG)
        hist_row.pack(fill="both", expand=True)

        # Original histogram
        orig_hist_col = tk.Frame(hist_row, bg=PANEL_BG)
        orig_hist_col.pack(side="left", fill="both", expand=True)
        ttk.Label(orig_hist_col, text="Original — RGB Distribution",
                  style="Head.TLabel").pack(anchor="w", pady=(0, 6))
        self._orig_canvas = tk.Canvas(orig_hist_col, bg="#F8FAFC",
                                      bd=1, relief="solid", highlightthickness=0)
        self._orig_canvas.pack(fill="both", expand=True)

        # Divider
        tk.Frame(hist_row, bg=BORDER, width=1).pack(side="left", fill="y", padx=12)

        # Stego histogram
        stego_hist_col = tk.Frame(hist_row, bg=PANEL_BG)
        stego_hist_col.pack(side="left", fill="both", expand=True)
        ttk.Label(stego_hist_col, text="Stego-Image — RGB Distribution",
                  style="Head.TLabel").pack(anchor="w", pady=(0, 6))
        self._stego_canvas = tk.Canvas(stego_hist_col, bg="#F8FAFC",
                                       bd=1, relief="solid", highlightthickness=0)
        self._stego_canvas.pack(fill="both", expand=True)

        # ── Stats row ─────────────────────────────────────────────────────────
        tk.Frame(card, bg=BORDER, height=1).pack(fill="x", pady=(14, 8))
        self._stats_var = tk.StringVar(
            value="Load both images and click Run Analysis to compare their pixel distributions.")
        tk.Label(card, textvariable=self._stats_var, bg=PANEL_BG, fg=MUTED,
                 font=(FONT, 9), anchor="w", justify="left").pack(fill="x")

        # Legend
        legend = tk.Frame(card, bg=PANEL_BG)
        legend.pack(anchor="w", pady=(4, 0))
        for colour, name in [("#EF4444", "Red channel"),
                              ("#22C55E", "Green channel"),
                              ("#3B82F6", "Blue channel")]:
            dot = tk.Frame(legend, bg=colour, width=12, height=12)
            dot.pack(side="left", padx=(0, 4))
            tk.Label(legend, text=name, bg=PANEL_BG, fg=MUTED,
                     font=(FONT, 8)).pack(side="left", padx=(0, 14))

    def _browse(self, target: str):
        path = filedialog.askopenfilename(title="Select Image",
                                          filetypes=image_filetypes())
        if not path:
            return
        try:
            img = ImageIOHandler.load(path)
            if target == "orig":
                self._orig_var.set(path)
                self._orig_img = img
            else:
                self._stego_var.set(path)
                self._stego_img = img
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def _run(self):
        if not self._orig_img or not self._stego_img:
            messagebox.showerror("Missing images",
                                 "Please select both the original and stego images.")
            return

        self._set_status("Computing histograms…", "info")
        self.update()

        # Compute histograms
        o_r, o_g, o_b = compute_histogram(self._orig_img)
        s_r, s_g, s_b = compute_histogram(self._stego_img)

        # Draw them — read canvas dimensions after pack
        self._orig_canvas.update_idletasks()
        self._stego_canvas.update_idletasks()
        cw_o = max(self._orig_canvas.winfo_width(),  300)
        ch_o = max(self._orig_canvas.winfo_height(), 160)
        cw_s = max(self._stego_canvas.winfo_width(), 300)
        ch_s = max(self._stego_canvas.winfo_height(),160)

        draw_histogram(self._orig_canvas,  o_r, o_g, o_b, "Original",  cw_o, ch_o)
        draw_histogram(self._stego_canvas, s_r, s_g, s_b, "Stego",     cw_s, ch_s)

        # Compute similarity stats
        def mad(a, b):
            return sum(abs(x - y) for x, y in zip(a, b)) / 256
        r_diff = mad(o_r, s_r)
        g_diff = mad(o_g, s_g)
        b_diff = mad(o_b, s_b)
        avg_diff = (r_diff + g_diff + b_diff) / 3

        total_pixels = self._orig_img.width * self._orig_img.height
        pct_changed = (avg_diff * 256 / total_pixels) * 100 if total_pixels else 0

        same_size = self._orig_img.size == self._stego_img.size
        size_note = (f"{self._orig_img.width}×{self._orig_img.height}"
                     if same_size else "⚠  Images have different dimensions")

        self._stats_var.set(
            f"Image size: {size_note}   ·   "
            f"Mean Abs. Difference per bin — R: {r_diff:.1f}  G: {g_diff:.1f}  B: {b_diff:.1f}   ·   "
            f"Estimated pixel change: {pct_changed:.4f}%   ·   "
            f"Imperceptibility: {'✓ Excellent' if avg_diff < 50 else '⚠ Noticeable'}"
        )
        self._set_status("✓  Analysis complete", "ok")


# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app = StegoApp()
    app.mainloop()
