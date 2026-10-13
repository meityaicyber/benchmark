"""Locating the image behind a proof-of-concept entry (Suite Section 6.4, Q4.c).

Objective 1 (report-to-json) removes every figure from a report before the model reads it, stores the
image content-addressed in deep storage, and writes a placeholder tag such as [IMAGE_PAGE_3_FIG_1] in
its place; for image evidence the tag is the value of proof_of_concept[].reference. Its image manifest
(deep_storage/manifests/<document_id>.json) maps each tag to the stored object:

    {"document_id": ..., "source_file": ...,
     "images": {"[IMAGE_PAGE_3_FIG_1]": {"tag", "page", "figure", "sha256", "uri", "format",
                                         "width", "height", "bbox"}},
     "layout_images": [...]}

and the run report beside the JSON (<name>.meta.json) names the manifest ("image_manifest") and the
document ("document_id"). The resolver follows the tag to the stored object, checks that the bytes
still hash to the manifest's SHA-256, and gives the file to the vision model. A reference that is not
a tag is read as a path, relative to the assets directory if one is given.
"""

from __future__ import annotations

import hashlib
import json
import re
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path

TAG = re.compile(r"^\s*\[IMAGE_PAGE_(\d+)_FIG_(\d+)\]\s*$")


@dataclass
class ResolvedImage:
    path: str | None              # file given to the vision model; None when not found
    reason: str = ""              # why not found
    tag: str | None = None
    sha256: str | None = None
    page: int | None = None


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _uri_path(uri: str | None) -> Path | None:
    if not uri:
        return None
    if uri.startswith("file:"):
        return Path(urllib.request.url2pathname(urllib.parse.urlparse(uri).path))
    return Path(uri)


class ImageResolver:
    def __init__(self, assets_dir: str | Path | None = None, manifest: dict | None = None,
                 deep_storage: str | Path | None = None, manifest_source: str | None = None):
        self.assets_dir = Path(assets_dir) if assets_dir else None
        self.manifest = manifest
        self.deep_storage = Path(deep_storage) if deep_storage else None
        self.manifest_source = manifest_source

    @classmethod
    def for_report(cls, report_path: str | Path | None = None, assets_dir: str | Path | None = None,
                   image_manifest: str | Path | None = None, deep_storage: str | Path | None = None) -> "ImageResolver":
        """Find the image manifest of a report: the one given; else the one named in the run report
        beside the JSON (<name>.meta.json); else <deep_storage>/manifests/<document_id>.json."""
        path = Path(image_manifest) if image_manifest else None
        if path is None and report_path:
            rp = Path(report_path)
            meta_path = rp.with_name(rp.name[:-5] + ".meta.json") if rp.name.endswith(".json") else None
            if meta_path and meta_path.exists():
                meta = json.loads(meta_path.read_text(encoding="utf-8"))
                named = Path(meta["image_manifest"]) if meta.get("image_manifest") else None
                if named and not named.is_absolute() and not named.exists():
                    named = meta_path.parent / named          # a relative DEEP_STORAGE_DIR in Objective 1
                if named and named.exists():
                    path = named
                elif deep_storage and meta.get("document_id"):
                    candidate = Path(deep_storage) / "manifests" / f"{meta['document_id']}.json"
                    path = candidate if candidate.exists() else None
        manifest = json.loads(path.read_text(encoding="utf-8")) if path and path.exists() else None
        return cls(assets_dir, manifest, deep_storage, str(path) if manifest is not None else None)

    def describe(self) -> dict:
        return {"image_manifest": self.manifest_source,
                "document_id": (self.manifest or {}).get("document_id"),
                "deep_storage": str(self.deep_storage) if self.deep_storage else None,
                "assets_dir": str(self.assets_dir) if self.assets_dir else None}

    def resolve(self, reference: str | None) -> ResolvedImage:
        if not reference:
            return ResolvedImage(None, "no reference")
        m = TAG.match(str(reference))
        if m:
            return self._resolve_tag(f"[IMAGE_PAGE_{m.group(1)}_FIG_{m.group(2)}]", int(m.group(1)))
        p = Path(str(reference))
        if not p.is_absolute() and self.assets_dir:
            p = self.assets_dir / p
        if p.is_file():
            return ResolvedImage(str(p), sha256=_sha256(p))
        return ResolvedImage(None, f"image '{reference}' not supplied with the standardised report")

    def _resolve_tag(self, tag: str, page: int) -> ResolvedImage:
        if self.manifest is None:
            return ResolvedImage(None, f"image tag {tag}: no image manifest supplied for this report", tag, page=page)
        entry = (self.manifest.get("images") or {}).get(tag)
        if not entry:
            return ResolvedImage(None, f"image tag {tag} is not in the image manifest", tag, page=page)
        want = str(entry.get("sha256") or "").lower()
        candidates = []
        if self.deep_storage and want:
            objects = self.deep_storage / "objects" / want[:2] / want[2:4]
            candidates += sorted(objects.glob(f"{want}.*")) if objects.is_dir() else []
        uri = _uri_path(entry.get("uri"))
        if uri:
            candidates.append(uri)
        for c in candidates:
            if c.is_file():
                got = _sha256(c)
                if got != want:
                    return ResolvedImage(None, f"image tag {tag}: stored file does not match the manifest's SHA-256",
                                         tag, want, page)
                return ResolvedImage(str(c), tag=tag, sha256=got, page=entry.get("page", page))
        return ResolvedImage(None, f"image tag {tag}: stored object {want[:12]} not found in deep storage", tag, want, page)
