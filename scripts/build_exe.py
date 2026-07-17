"""Build the NIDS desktop executable with PyInstaller.

Usage (from the repo root):

    pip install -r requirements-dev.txt
    python scripts/build_exe.py

Output: dist/NIDS/NIDS.exe (Windows) — a folder build, so the whole
`dist/NIDS/` directory must be shipped together, not just the .exe.

A one-file build (--onefile) is deliberately not used: Streamlit's static
assets and scikit-learn's compiled extensions make startup unpack hundreds of
megabytes to a temp dir on every launch, which is far slower and flakier than
the folder build.
"""

import os
import shutil
import subprocess
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SPEC = os.path.join(BASE_DIR, "nids.spec")


def main():
    if shutil.which("pyinstaller") is None:
        try:
            import PyInstaller  # noqa: F401
        except ImportError:
            sys.exit(
                "PyInstaller is not installed.\n"
                "Install the dev requirements first:  pip install -r requirements-dev.txt"
            )

    for required in ("models/rf_model.pkl", "data/nsl-kdd/KDDTrain+.txt"):
        if not os.path.exists(os.path.join(BASE_DIR, required)):
            sys.exit(
                f"Missing {required}.\n"
                "Run `python scripts/train_models.py` and make sure the NSL-KDD "
                "data is in data/nsl-kdd/ before building."
            )

    cmd = [sys.executable, "-m", "PyInstaller", SPEC, "--noconfirm"]
    print("Running:", " ".join(cmd))
    result = subprocess.run(cmd, cwd=BASE_DIR)
    if result.returncode != 0:
        sys.exit(result.returncode)

    out = os.path.join(BASE_DIR, "dist", "NIDS")
    print(f"\n✅ Built: {out}")
    print("Ship the whole dist/NIDS/ folder. Launch it with NIDS.exe.")


if __name__ == "__main__":
    main()
