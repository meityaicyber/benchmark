"""Signing, verification, transfer and import of Reference Data Packages (Suite Section 11.2, steps 4 to 7).

Signing uses Ed25519. The private key stays on the preparation host; the public key is installed
in the CERT-In environment and used at import.
"""

from __future__ import annotations

import base64
import json
import shutil
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .build import sha256_file


def generate_keypair(private_path: str | Path, public_path: str | Path) -> None:
    key = Ed25519PrivateKey.generate()
    Path(private_path).write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                     serialization.NoEncryption()))
    Path(public_path).write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,
                                                                serialization.PublicFormat.SubjectPublicKeyInfo))


def _manifest_bytes(package: Path) -> bytes:
    return (package / "manifest.json").read_bytes()


def sign_package(package: str | Path, private_key: str | Path) -> Path:
    package = Path(package)
    key = serialization.load_pem_private_key(Path(private_key).read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("signing key must be Ed25519")
    sig = key.sign(_manifest_bytes(package))
    out = package / "manifest.sig"
    out.write_text(base64.b64encode(sig).decode())
    return out


def verify_package(package: str | Path, public_key: str | Path) -> dict:
    """Verify the signature over the manifest and the hash of every file the manifest lists."""
    package = Path(package)
    problems: list[str] = []
    pub = serialization.load_pem_public_key(Path(public_key).read_bytes())
    if not isinstance(pub, Ed25519PublicKey):
        raise ValueError("verification key must be Ed25519")
    sig_path = package / "manifest.sig"
    if not sig_path.exists():
        problems.append("manifest.sig missing")
    else:
        try:
            pub.verify(base64.b64decode(sig_path.read_text()), _manifest_bytes(package))
        except InvalidSignature:
            problems.append("signature does not verify")
    manifest = json.loads(_manifest_bytes(package))
    listed: list[tuple[str, str]] = [(k, v["sha256"]) for k, v in manifest.get("files", {}).items()]
    for src in manifest.get("sources", {}).values():
        if src.get("status") in ("included", "carried_forward"):
            listed.extend((f["path"], f["sha256"]) for f in src.get("files", []) if "sha256" in f)
    listed_paths = {rel for rel, _ in listed}
    for p in sorted(package.rglob("*")):
        rel = str(p.relative_to(package))
        if p.is_file() and rel not in listed_paths and rel not in ("manifest.json", "manifest.sig"):
            problems.append(f"file not listed in the manifest: {rel}")
    for rel, expected in listed:
        p = package / rel
        if not p.exists():
            problems.append(f"missing file {rel}")
        elif sha256_file(p) != expected:
            problems.append(f"hash mismatch {rel}")
    return {"package_id": manifest.get("package_id"), "files_checked": len(listed), "ok": not problems,
            "problems": problems}


def import_package(package: str | Path, store_root: str | Path, public_key: str | Path) -> Path:
    """Verify, then place the package under its identifier. An existing package is never overwritten."""
    package = Path(package)
    result = verify_package(package, public_key)
    if not result["ok"]:
        raise ValueError("package failed verification: " + "; ".join(result["problems"][:10]))
    dest = Path(store_root) / result["package_id"]
    if dest.exists():
        raise FileExistsError(f"{dest} already imported; packages are retained and never overwritten")
    shutil.copytree(package, dest)
    log = Path(store_root) / "import_log.jsonl"
    with open(log, "a", encoding="utf-8") as fh:
        fh.write(json.dumps({"package_id": result["package_id"], "files_checked": result["files_checked"]}) + "\n")
    return dest


def latest_package(store_root: str | Path) -> Path | None:
    pkgs = sorted(p for p in Path(store_root).glob("RDP-*") if (p / "manifest.json").exists())
    return pkgs[-1] if pkgs else None
