# Image Steganography System

Hide secret messages inside ordinary images using **LSB (Least Significant Bit)** substitution, with optional **AES-256-CBC** encryption.

**Authors:** Mohamed Dhia Ben Kilani · Mohamed Aziz Amri · Elaa Chaaleb

---

## How it works

Each pixel in an image has 3 colour channels (R, G, B), each stored as a byte. We replace the least significant bit of each channel with one bit of our secret message. The visual difference is imperceptible to the human eye.

If a password is provided, the message is encrypted with AES-256-CBC (PBKDF2 key derivation) before embedding.

## Installation

```bash
git clone https://github.com/Dhia0184/Security-Project.git
cd image-steganography
pip install -r requirements.txt
```

## Usage

```bash
python src/crypto.py
```

- **Encode tab** — select a cover image, type your message, optionally set a password, save the stego-image
- **Decode tab** — select a stego-image, enter the password if one was used, extract the message

## Run tests

```bash
pip install pytest
pytest tests/
```

## Documentation

See the [`docs/`](docs/) folder for the full High Level Design document.
