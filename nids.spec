# PyInstaller spec for the NIDS desktop build.
#
# Build with:  pyinstaller nids.spec --noconfirm
# (or: python scripts/build_exe.py, which wraps this)
#
# Streamlit needs more than its Python modules: it loads static front-end
# assets from its package directory and reads its own distribution metadata at
# import time, so both must be collected or the frozen app dies on startup.
# scapy and sklearn pull in submodules dynamically, hence the hidden imports.

from PyInstaller.utils.hooks import collect_all, copy_metadata

datas = []
binaries = []
hiddenimports = []

# Streamlit + its front-end assets and metadata.
for pkg in ("streamlit", "altair", "pyarrow"):
    p_datas, p_binaries, p_hidden = collect_all(pkg)
    datas += p_datas
    binaries += p_binaries
    hiddenimports += p_hidden

# Packages that read their own version metadata at runtime.
for pkg in ("streamlit", "altair", "pandas", "numpy", "scikit-learn", "scapy", "joblib"):
    try:
        datas += copy_metadata(pkg)
    except Exception:
        pass

# Dynamically imported submodules.
hiddenimports += [
    "sklearn.ensemble._forest",
    "sklearn.tree._classes",
    "sklearn.ensemble._iforest",
    "sklearn.preprocessing._label",
    "sklearn.utils._typedefs",
    "sklearn.neighbors._partition_nodes",
    "scapy.layers.inet",
    "scapy.layers.l2",
    "scapy.all",
    "pandas._libs.tslibs.timedeltas",
]

# Application resources. app.py resolves its paths relative to src/, so the
# tree layout inside the bundle must mirror the repo.
datas += [
    ("src", "src"),
    ("models", "models"),
    ("assets", "assets"),
    (".streamlit", ".streamlit"),
    # Only the two files load_resources() actually reads — the rest of the
    # NSL-KDD corpus (.arff, -21, 20Percent) would bloat the exe for nothing.
    ("data/nsl-kdd/KDDTrain+.txt", "data/nsl-kdd"),
    ("data/nsl-kdd/KDDTest+.txt", "data/nsl-kdd"),
]

a = Analysis(
    ["scripts/desktop_launcher.py"],
    pathex=["src"],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=["matplotlib", "tkinter", "PyQt5", "notebook", "IPython"],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="NIDS",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,  # keep the console: it shows the server URL and errors
    icon=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    name="NIDS",
)
