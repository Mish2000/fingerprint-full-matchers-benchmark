from __future__ import annotations

from pathlib import Path


FORBIDDEN = (
    "cv2", "numpy", "sift", "rootsift", "harris", "gftt", "detector_only", "local_features",
    "ransac", "final_minutiae", "jackson-dataformat-cbor",
)


def test_runtime_has_no_forbidden_active_coupling():
    root = Path(__file__).resolve().parents[1]
    files = list((root / "src" / "fingerprint_benchmark").glob("*.py"))
    files += list((root / "apps" / "sourceafis-sidecar" / "src" / "main").rglob("*"))
    files += [root / "apps" / "sourceafis-sidecar" / "pom.xml"]
    for path in files:
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8").lower()
        if path.name == "cli.py":
            text = "\n".join(line for line in text.splitlines() if "removed_" not in line)
        for term in FORBIDDEN:
            assert term not in text, f"forbidden runtime coupling {term!r} in {path}"
