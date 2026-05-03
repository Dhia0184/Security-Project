import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from PIL import Image
from stego_app import EncoderModule, DecoderModule, ImageIOHandler

def make_image():
    return Image.new('RGB', (200, 200), color=(255, 255, 255))

def test_plain_round_trip():
    msg = "Hello, Steganography!"
    stego = EncoderModule.encode(make_image(), msg, password=None)
    assert DecoderModule.decode(stego, password=None) == msg

def test_encrypted_round_trip():
    msg = "Top secret message"
    stego = EncoderModule.encode(make_image(), msg, password="pass123")
    assert DecoderModule.decode(stego, password="pass123") == msg

def test_wrong_password():
    stego = EncoderModule.encode(make_image(), "secret", password="correct")
    try:
        DecoderModule.decode(stego, password="wrong")
        assert False, "Should have raised"
    except ValueError:
        pass

def test_no_magic_header():
    clean = Image.new('RGB', (100, 100), color=(0, 0, 0))
    try:
        DecoderModule.decode(clean, password=None)
        assert False, "Should have raised"
    except ValueError:
        pass

def test_capacity_check():
    small = Image.new('RGB', (10, 10))
    cap = ImageIOHandler.capacity_bytes(small)
    try:
        EncoderModule.encode(small, "X" * (cap + 100), password=None)
        assert False, "Should have raised"
    except ValueError:
        pass