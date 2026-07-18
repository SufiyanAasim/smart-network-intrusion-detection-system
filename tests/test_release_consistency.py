import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _read(relative_path):
    return (ROOT / relative_path).read_text(encoding="utf-8")


def test_current_release_metadata_is_consistent():
    """Fail CI when any active release surface drifts from package metadata."""
    package_source = _read("src/nids/__init__.py")
    match = re.search(r'__version__\s*=\s*"([^"]+)"', package_source)
    assert match, "src/nids/__init__.py must declare __version__"
    version = match.group(1)
    major = version.split(".", maxsplit=1)[0]

    assert version == "11.0.0"
    assert 'RELEASE_CODENAME = "Cipher"' in _read("src/nids/app.py")
    assert 'PRODUCT_NAME = "Smart Network Intrusion Detection System"' in _read("src/nids/app.py")
    assert f'org.opencontainers.image.version="{version}"' in _read("Dockerfile")
    assert f"image: nids:{version}" in _read("docker-compose.yml")
    assert "name: ${NIDS_HISTORY_VOLUME:-nids-history}" in _read("docker-compose.yml")
    assert f"-t nids:{version}" in _read("Makefile")
    assert f'application_version: "{version}"' in _read("config/features.yaml")
    assert f"schema_version: {major}" in _read("config/features.yaml")

    readme = _read("README.md")
    assert f"version-{version}-blue" in readme
    assert f"**Latest release:** v{version} — **Cipher**" in readme
    assert f"docs/releases/v{version}.md" in readme

    current_release = _read(f"docs/releases/v{version}.md")
    assert current_release.startswith(f"# ⚡ NIDS v{version}\n")
    assert "> Codename **Cipher**" in current_release
    assert "> Codename **Argus**" in _read("docs/releases/v10.0.0.md")
    assert "> Codename **Vigil**" in _read("docs/releases/v9.0.0.md")
    assert f"NIDS v{version} uses" in _read("docs/deployment/docker.md")
    assert f'"version":"{version}"' in _read("docs/api/api.md")


def test_active_configuration_has_no_stale_product_version():
    active_files = (
        ".env.example",
        "Dockerfile",
        "Makefile",
        "config/features.yaml",
        "docker-compose.yml",
        "render.yaml",
        "docs/api/api.md",
        "docs/architecture/architecture.md",
        "docs/deployment/docker.md",
        "docs/guides/running-locally.md",
        "docs/guides/user-guide.md",
        "src/nids/__init__.py",
        "src/nids/app.py",
        "src/nids/auth.py",
        "src/nids/netcheck.py",
        "src/nids/storage.py",
    )
    for relative_path in active_files:
        contents = _read(relative_path)
        assert "10.0.0" not in contents, f"stale version in {relative_path}"
        assert "nids-history-v9" not in contents, f"stale volume name in {relative_path}"
