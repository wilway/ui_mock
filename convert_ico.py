import sys
import os
import subprocess

try:
    from PIL import Image
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "Pillow"])
    from PIL import Image

png_path = sys.argv[1]
ico_path = sys.argv[2]
img = Image.open(png_path)
img.save(ico_path, format="ICO", sizes=[(256, 256), (128, 128), (64, 64), (48, 48), (32, 32), (16, 16)])
print(f"Icon successfully saved to {ico_path}")
