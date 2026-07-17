"""Entry point for the packaged desktop build (NIDS.exe).

Streamlit is a *server* application, not a plain script, so a frozen build
can't simply "run app.py". This launcher boots the Streamlit server in-process
and opens the dashboard in the user's default browser, which is what the
double-clicked .exe needs to do.

It also fixes up two things that only matter once frozen:
- Resources (models/, data/, assets/, .streamlit/) are unpacked into a
  read-only temp dir (sys._MEIPASS), so paths are resolved from there.
- That temp dir is wiped on exit, so the detection history DB is redirected
  to a writable per-user location via NIDS_DB_PATH.

Run it unfrozen too (`python scripts/desktop_launcher.py`) to test the same
flow without building.
"""

import os
import sys


def _is_frozen():
    return getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS")


def bundle_root():
    """Directory holding models/, data/, assets/ — temp dir when frozen."""
    if _is_frozen():
        return sys._MEIPASS
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def user_data_dir():
    """A writable per-user directory for the history database."""
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    elif sys.platform == "darwin":
        base = os.path.join(os.path.expanduser("~"), "Library", "Application Support")
    else:
        base = os.environ.get("XDG_DATA_HOME") or os.path.join(
            os.path.expanduser("~"), ".local", "share"
        )
    path = os.path.join(base, "NIDS")
    os.makedirs(path, exist_ok=True)
    return path


def suppress_first_run_prompt():
    """Stop Streamlit's first-run onboarding prompt from hanging the app.

    On a machine that has never run Streamlit, it prints "Welcome to
    Streamlit! ... Email:" and *blocks reading stdin*. A double-clicked .exe
    has no one to answer it, so the server would never start. Writing an empty
    credentials file opts out. An existing file is never overwritten.
    """
    cred_dir = os.path.join(os.path.expanduser("~"), ".streamlit")
    cred_file = os.path.join(cred_dir, "credentials.toml")
    if os.path.exists(cred_file):
        return
    try:
        os.makedirs(cred_dir, exist_ok=True)
        with open(cred_file, "w", encoding="utf-8") as f:
            f.write('[general]\nemail = ""\n')
    except OSError:
        # Not fatal on its own — headless mode below also avoids the prompt.
        pass


def configure_environment():
    """Point the app at bundled resources and a writable database."""
    root = bundle_root()

    # The frozen bundle's temp dir is wiped on exit; keep history outside it.
    os.environ.setdefault("NIDS_DB_PATH", os.path.join(user_data_dir(), "history.db"))

    # Streamlit reads config from the working directory.
    os.chdir(root)

    src_dir = os.path.join(root, "src")
    if os.path.isdir(src_dir) and src_dir not in sys.path:
        sys.path.insert(0, src_dir)

    suppress_first_run_prompt()
    return root


def main():
    root = configure_environment()
    app_path = os.path.join(root, "src", "nids", "app.py")

    if not os.path.exists(app_path):
        sys.exit(f"Could not find the dashboard at {app_path}")

    from streamlit.web import cli as stcli

    # Any flags passed to NIDS.exe are forwarded to Streamlit, so callers can
    # override the defaults (e.g. `NIDS.exe --server.port=9000`). Rebuilding
    # argv without them would silently ignore whatever the user asked for.
    user_args = sys.argv[1:]
    defaults = [
        "--global.developmentMode=false",
        "--server.port=8501",
        "--browser.gatherUsageStats=false",
    ]
    if not any(a.startswith("--server.headless") for a in user_args):
        # Headless also side-steps the onboarding prompt; the browser is
        # opened explicitly below instead.
        defaults.append("--server.headless=true")

    sys.argv = ["streamlit", "run", app_path, *defaults, *user_args]
    _open_browser_when_ready(user_args)
    sys.exit(stcli.main())


def _open_browser_when_ready(user_args, port=8501):
    """Open the dashboard once the server is accepting connections."""
    for arg in user_args:
        if arg.startswith("--server.port="):
            try:
                port = int(arg.split("=", 1)[1])
            except ValueError:
                pass
        if arg.startswith("--server.headless=true"):
            return  # caller explicitly wants no browser

    import socket
    import threading
    import time
    import webbrowser

    def _wait():
        deadline = time.time() + 60
        while time.time() < deadline:
            with socket.socket() as s:
                s.settimeout(0.5)
                if s.connect_ex(("127.0.0.1", port)) == 0:
                    webbrowser.open(f"http://localhost:{port}")
                    return
            time.sleep(0.5)

    threading.Thread(target=_wait, daemon=True).start()


if __name__ == "__main__":
    main()
