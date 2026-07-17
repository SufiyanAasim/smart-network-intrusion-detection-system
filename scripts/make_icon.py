"""Generate the Windows icon from the canonical transparent NIDS logo.

The application, documentation, and executable all consume the same
``assets/images/logo.png`` source so the packaged icon cannot drift back to an
older shield variant.
"""

import os

from PIL import Image

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SOURCE_PATH = os.path.join(BASE_DIR, "assets", "images", "logo.png")
OUT_PATH = os.path.join(BASE_DIR, "assets", "images", "logo.ico")
ICON_SIZES = [256, 128, 64, 48, 32, 16]


def render(size=256):
    """Return a square RGBA frame derived from the canonical logo asset."""
    with Image.open(SOURCE_PATH) as source:
        image = source.convert("RGBA")
    return image.resize((size, size), Image.Resampling.LANCZOS)


def main():
    if not os.path.exists(SOURCE_PATH):
        raise SystemExit(f"Missing canonical logo: {SOURCE_PATH}")
    source_image = render()
    os.makedirs(os.path.dirname(OUT_PATH), exist_ok=True)
    source_image.save(OUT_PATH, format="ICO", sizes=[(size, size) for size in ICON_SIZES])
    print(
        f"Wrote {OUT_PATH} ({os.path.getsize(OUT_PATH):,} bytes, "
        f"sizes: {', '.join(f'{size}x{size}' for size in ICON_SIZES)})"
    )


if __name__ == "__main__":
    main()
