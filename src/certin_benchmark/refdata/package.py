"""Signing, verification, transfer and import of Reference Data Packages (Suite Section 11.2, steps 4 to 7).

Signing uses Ed25519. The private key stays on the preparation host, readable by its owner only; the public key
is installed in the CERT-In environment and used at import.
"""

from __future__ import annotations

import base64
import json
import os
import shutil
from pathlib import Path

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from ..errors import OperatorError
from .build import sha256_file


def generate_keypair(private_path: str | Path, public_path: str | Path) -> list[str]:
    """Create the signing key pair. An existing key file is never replaced: packages signed with the old key would
    no longer import, and the environment would need the new public key. The private key is readable by its owner
    only, in a folder created for it with the same restriction where the folder does not exist yet. Returns notes
    for the operator, such as a folder that others can read. Nothing is left behind if either file fails."""
    private_path, public_path = Path(private_path), Path(public_path)
    if private_path.resolve() == public_path.resolve():
        raise OperatorError("the private and public keys need two different files")
    for p in (private_path, public_path):
        if p.exists() or p.is_symlink():
            raise FileExistsError(f"{p} exists; a signing key is never replaced")
    notes = []
    folder_existed = private_path.parent.exists()
    private_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if folder_existed and private_path.parent.stat().st_mode & 0o077:
        notes.append(f"{private_path.parent} can be read by others than its owner; the private key itself cannot, "
                     "but a folder of its own (mode 700) is safer")
    public_path.parent.mkdir(parents=True, exist_ok=True)
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    public = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    fd = os.open(private_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(pem)
        os.chmod(private_path, 0o600)       # whatever the process's umask
        with open(public_path, "xb") as fh:
            fh.write(public)
    except BaseException:
        private_path.unlink(missing_ok=True)
        raise
    return notes


def _manifest_bytes(package: Path) -> bytes:
    return (package / "manifest.json").read_bytes()


def _load_key(path: str | Path, private: bool):
    """The Ed25519 key in a PEM file (rdp keygen writes both); a file of another form is the operator's mistake."""
    data = Path(path).read_bytes()
    kind = "private" if private else "public"
    try:
        key = serialization.load_pem_private_key(data, password=None) if private else \
            serialization.load_pem_public_key(data)
    except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
        raise OperatorError(f"{path} is not an unencrypted PEM {kind} key ({exc})") from None
    if not isinstance(key, Ed25519PrivateKey if private else Ed25519PublicKey):
        raise OperatorError(f"{path} is not an Ed25519 {kind} key")
    return key


def sign_package(package: str | Path, private_key: str | Path) -> Path:
    package = Path(package)
    key = _load_key(private_key, private=True)
    sig = key.sign(_manifest_bytes(package))
    out = package / "manifest.sig"
    out.write_text(base64.b64encode(sig).decode())
    return out


def verify_package(package: str | Path, public_key: str | Path) -> dict:
    """Verify the signature over the manifest and the hash of every file the manifest lists."""
    package = Path(package)
    problems: list[str] = []
    pub = _load_key(public_key, private=False)
    sig_path = package / "manifest.sig"
    if not sig_path.exists():
        problems.append("manifest.sig missing")
    else:
        try:
            pub.verify(base64.b64decode(sig_path.read_text(), validate=True), _manifest_bytes(package))
        except (InvalidSignature, ValueError):       # ValueError: a signature file that is not base64
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
        raise OperatorError("package failed verification: " + "; ".join(result["problems"][:10]))
    dest = Path(store_root) / result["package_id"]
    if dest.exists():
        raise FileExistsError(f"{dest} already imported; packages are retained and never overwritten")
    # Copied into a hidden folder and renamed once complete: an interrupted import leaves no folder that would be
    # taken for the latest package, or that would block importing it again
    partial = dest.with_name(f".{dest.name}.partial")
    if partial.exists():
        shutil.rmtree(partial)
    try:
        shutil.copytree(package, partial)
        os.rename(partial, dest)
    except BaseException:
        shutil.rmtree(partial, ignore_errors=True)
        raise
    log = Path(store_root) / "import_log.jsonl"
    with open(log, "a", encoding="utf-8") as fh:
        fh.write(json.dumps({"package_id": result["package_id"], "files_checked": result["files_checked"]}) + "\n")
    return dest


def latest_package(store_root: str | Path) -> Path | None:
    pkgs = sorted(p for p in Path(store_root).glob("RDP-*") if (p / "manifest.json").exists())
    return pkgs[-1] if pkgs else None
