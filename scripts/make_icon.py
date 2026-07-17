"""Generate assets/images/logo.ico from the project logo.

Windows needs a real multi-resolution .ico to show a crisp icon in Explorer,
the taskbar and Alt-Tab — a single large PNG scales badly at 16x16.

Pillow cannot rasterise SVG, and pulling in cairosvg/CairoSVG would add a
system-library dependency (libcairo) just for a build-time asset. So the icon
is drawn directly with Pillow, mirroring assets/images/logo.svg: a dark
shield outlined in teal, a red flagged node with radar rings, two green
peer nodes, and a white check.

Run:  python scripts/make_icon.py
"""

import os

from PIL import Image, ImageDraw

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT_PATH = os.path.join(BASE_DIR, "assets", "images", "logo.ico")

# Palette mirrors logo.svg / the Streamlit theme.
SHIELD_FILL = (15, 23, 42, 255)      # #0F172A
SHIELD_EDGE = (34, 211, 238, 255)    # #22D3EE
NODE_OK = (0, 204, 150, 255)         # #00CC96
NODE_ALERT = (239, 85, 59, 255)      # #EF553B
CHECK = (248, 250, 252, 255)         # #F8FAFC

# Sizes Windows actually picks between.
ICON_SIZES = [256, 128, 64, 48, 32, 16]

# Supersample, then downscale — gives smooth edges without antialiased drawing.
SS = 8
CANVAS = 256 * SS


def _shield_polygon(w, h):
    """Shield outline as a fraction of the canvas, matching the SVG path."""
    return [
        (0.50 * w, 0.03 * h),
        (0.91 * w, 0.16 * h),
        (0.91 * w, 0.49 * h),
        (0.78 * w, 0.79 * h),
        (0.50 * w, 0.97 * h),
        (0.22 * w, 0.79 * h),
        (0.09 * w, 0.49 * h),
        (0.09 * w, 0.16 * h),
    ]


def render(size=CANVAS):
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    w = h = size

    d.polygon(_shield_polygon(w, h), fill=SHIELD_FILL,
              outline=SHIELD_EDGE, width=int(0.018 * w))

    def circle(cx, cy, r, **kw):
        d.ellipse([cx - r, cy - r, cx + r, cy + r], **kw)

    # Network links between the flagged node and its two peers.
    link = int(0.013 * w)
    d.line([(0.33 * w, 0.62 * h), (0.50 * w, 0.43 * h)], fill=NODE_OK, width=link)
    d.line([(0.67 * w, 0.62 * h), (0.50 * w, 0.43 * h)], fill=NODE_OK, width=link)
    d.line([(0.33 * w, 0.62 * h), (0.67 * w, 0.62 * h)], fill=NODE_OK, width=link)

    # Radar rings around the flagged node.
    for r_frac, alpha in ((0.135, 90), (0.105, 150)):
        circle(0.50 * w, 0.43 * h, r_frac * w,
               outline=NODE_ALERT[:3] + (alpha,), width=int(0.010 * w))

    circle(0.33 * w, 0.62 * h, 0.045 * w, fill=NODE_OK)
    circle(0.67 * w, 0.62 * h, 0.045 * w, fill=NODE_OK)
    circle(0.50 * w, 0.43 * h, 0.072 * w, fill=NODE_ALERT)

    # Check mark ("protected").
    d.line(
        [(0.36 * w, 0.735 * h), (0.46 * w, 0.825 * h), (0.65 * w, 0.655 * h)],
        fill=CHECK, width=int(0.035 * w), joint="curve",
    )
    return img


def main():
    master = render()
    frames = [
        master.resize((s, s), Image.LANCZOS).convert("RGBA") for s in ICON_SIZES
    ]
    os.makedirs(os.path.dirname(OUT_PATH), exist_ok=True)
    # Pillow writes every requested size into the single .ico container.
    frames[0].save(OUT_PATH, format="ICO",
                   sizes=[(s, s) for s in ICON_SIZES])
    print(f"Wrote {OUT_PATH} ({os.path.getsize(OUT_PATH):,} bytes, "
          f"sizes: {', '.join(f'{s}x{s}' for s in ICON_SIZES)})")


if __name__ == "__main__":
    main()
