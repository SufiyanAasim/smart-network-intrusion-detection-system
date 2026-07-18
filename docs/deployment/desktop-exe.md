# Desktop executable (Smart Network Intrusion Detection System)

Packages the dashboard as a double-clickable desktop app, so it can be run on
a machine without a Python install.

## Build

```bash
pip install -r requirements-dev.txt
python scripts/train_models.py     # only if models/ is empty
python scripts/build_exe.py
```

Output: **`dist/NIDS/NIDS.exe`**.

Ship the whole `dist/NIDS/` folder — it's a folder build, not a single file.
`NIDS.exe` alone will not run.

## How it works

Streamlit is a web server, not a plain script, so the build can't just freeze
`app.py`. Instead:

1. `scripts/desktop_launcher.py` is the frozen entry point. It starts the
   Streamlit server in-process and opens the dashboard in the default browser.
2. `nids.spec` tells PyInstaller to collect Streamlit's front-end assets and
   package metadata (both are read at runtime and are invisible to static
   analysis), plus the dynamically imported scikit-learn/scapy submodules.
3. Resources (`src/`, `models/`, `assets/`, `.streamlit/`, and the two NSL-KDD
   files the app actually reads) are bundled at the bundle root, mirroring the
   repo layout so `app.py`'s relative path resolution keeps working.

A console window is kept on purpose: it shows the local URL and any startup
error. Close it to quit the app.

## Where data goes

The bundle is unpacked to a **read-only temp dir that is wiped on exit**, so
the launcher redirects the detection history to a writable per-user location:

| Platform | History database |
| --- | --- |
| Windows | `%LOCALAPPDATA%\NIDS\history.db` |
| macOS | `~/Library/Application Support/NIDS/history.db` |
| Linux | `~/.local/share/NIDS/history.db` |

Override it by setting `NIDS_DB_PATH` before launching.

## Notes and limits

- **Size:** expect a few hundred MB — scikit-learn, Streamlit, pyarrow and
  scapy are all bundled. `--onefile` is intentionally not used: it would
  re-unpack that payload to temp on every launch.
- **Live capture** needs Npcap on Windows. Administrator is only required
  when Npcap was installed in admin-only mode or Windows denies capture
  access. Pcap upload works without either.
- **Cross-compiling isn't possible.** PyInstaller builds for the OS it runs
  on — build the Windows .exe on Windows.
- Only `KDDTrain+.txt` and `KDDTest+.txt` are bundled (the encoders and the
  accuracy figures need them). The rest of the NSL-KDD corpus is not.
