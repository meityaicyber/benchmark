"""Proof-of-concept images from Objective 1: tag -> image manifest -> deep storage -> vision model."""

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from helpers import EVAL_DATE, criterion, refdata, sample, scripted_backend

from certin_benchmark import BenchmarkEngine
from certin_benchmark.evaluators import FunctionBackend
from certin_benchmark.images import ImageResolver

ORIGINAL = b"\x89PNG\r\n\x1a\n original screenshot: 200 OK with citizen B's application"
RETEST = b"\x89PNG\r\n\x1a\n retest screenshot: 403 Forbidden"


def deep_storage(root: Path, images: dict[str, bytes], document_id: str = "wasa-report-0123456789ab") -> Path:
    """The layout written by Objective 1's LocalDeepStorage and build_manifest."""
    entries = {}
    for tag, data in images.items():
        sha = hashlib.sha256(data).hexdigest()
        path = root / "objects" / sha[:2] / sha[2:4] / f"{sha}.png"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        page, fig = tag.strip("[]").split("_")[2], tag.strip("[]").split("_")[4]
        entries[tag] = {"tag": tag, "page": int(page), "figure": int(fig), "sha256": sha,
                        "uri": path.resolve().as_uri(), "format": "png", "width": 1280, "height": 720,
                        "bbox": [72.0, 100.0, 520.0, 400.0]}
    manifest = root / "manifests" / f"{document_id}.json"
    manifest.parent.mkdir(parents=True, exist_ok=True)
    manifest.write_text(json.dumps({"document_id": document_id, "source_file": "wasa_report.pdf",
                                    "images": entries, "layout_images": []}))
    return manifest


def report_with_image_evidence() -> dict:
    r = sample()
    o = r["detailed_observations"][0]
    o["proof_of_concept"] = [
        {"sr_no": 1, "type": "image", "reference": "[IMAGE_PAGE_12_FIG_1]", "capture_date": "2026-07-08",
         "is_retest": False, "redacted": "Yes", "description": "Figure 4: request for another citizen's application"},
        {"sr_no": 2, "type": "image", "reference": "[IMAGE_PAGE_13_FIG_1]", "capture_date": "2026-08-11",
         "is_retest": True, "redacted": "Yes", "description": "Figure 5: retest"}]
    return r


class Vision:
    def __init__(self):
        self.calls = []
        self.backend = FunctionBackend(self, model="vision-test", model_version="v-test")

    def __call__(self, call):
        self.calls.append(call)
        return json.dumps({"level": 4, "rationale": "seen"})


def run(report, images, vision):
    engine = BenchmarkEngine(refdata=refdata(), text_backend=scripted_backend(4), vision_backend=vision.backend)
    return criterion(engine.evaluate(report, evaluated_on=EVAL_DATE, images=images), "Q4")


class ObjectiveOneImages(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def test_tag_resolved_through_manifest_and_graded_by_vision_model(self):
        manifest = deep_storage(self.tmp / "deep_storage", {"[IMAGE_PAGE_12_FIG_1]": ORIGINAL,
                                                             "[IMAGE_PAGE_13_FIG_1]": RETEST})
        vision = Vision()
        c = run(report_with_image_evidence(), ImageResolver(manifest=json.loads(manifest.read_text()),
                                                            manifest_source=str(manifest)), vision)
        self.assertFalse([x for x in c.not_evaluated if "WASA-01" in x])
        files = {Path(call.image_path).read_bytes() for call in vision.calls}
        self.assertEqual(files, {ORIGINAL, RETEST})               # the stored images themselves were sent
        retest_calls = [call for call in vision.calls if len(call.images()) == 2]
        self.assertEqual(len(retest_calls), 5)                    # five samples of retest distinctness
        self.assertEqual(Path(retest_calls[0].extra_images[0]).read_bytes(), ORIGINAL)
        prov = c.reference_values["proof_of_concept_images"]["Q4.c.WASA-01.poc1"]
        self.assertEqual((prov["sha256"], prov["page"]), (hashlib.sha256(ORIGINAL).hexdigest(), 12))

    def test_identical_retest_image_scores_zero_without_the_model(self):
        manifest = deep_storage(self.tmp / "ds", {"[IMAGE_PAGE_12_FIG_1]": ORIGINAL, "[IMAGE_PAGE_13_FIG_1]": ORIGINAL})
        vision = Vision()
        c = run(report_with_image_evidence(), ImageResolver(manifest=json.loads(manifest.read_text())), vision)
        item = next(i for i in c.sampled if i.item_id == "Q4.c.WASA-01.poc2.retest")
        self.assertEqual(item.score, 0.0)
        self.assertIn("same image", item.note)
        self.assertFalse([call for call in vision.calls if len(call.images()) == 2])

    def test_missing_tag_and_altered_file_are_referred_not_scored(self):
        manifest = deep_storage(self.tmp / "ds", {"[IMAGE_PAGE_12_FIG_1]": ORIGINAL, "[IMAGE_PAGE_13_FIG_1]": RETEST})
        m = json.loads(manifest.read_text())
        del m["images"]["[IMAGE_PAGE_13_FIG_1]"]
        Path(m["images"]["[IMAGE_PAGE_12_FIG_1]"]["uri"][len("file://"):]).write_bytes(b"altered")
        c = run(report_with_image_evidence(), ImageResolver(manifest=m), Vision())
        refs = " ".join(c.referrals)
        self.assertIn("does not match the manifest's SHA-256", refs)
        self.assertIn("[IMAGE_PAGE_13_FIG_1] is not in the image manifest", refs)
        self.assertIn("Q4.c.WASA-01.poc1 (image not available)", c.not_evaluated)

    def test_without_manifest_tags_are_referred(self):
        c = run(report_with_image_evidence(), ImageResolver(), Vision())
        self.assertTrue(any("no image manifest supplied" in r for r in c.referrals))

    def test_manifest_found_from_run_report_beside_json(self):
        ds = self.tmp / "deep_storage"
        manifest = deep_storage(ds, {"[IMAGE_PAGE_12_FIG_1]": ORIGINAL})
        out = self.tmp / "outputs"
        out.mkdir()
        (out / "wasa_report.json").write_text("{}")
        (out / "wasa_report.meta.json").write_text(json.dumps({"document_id": "wasa-report-0123456789ab",
                                                               "image_manifest": str(manifest)}))
        r = ImageResolver.for_report(out / "wasa_report.json")
        self.assertEqual(Path(r.resolve("[IMAGE_PAGE_12_FIG_1]").path).read_bytes(), ORIGINAL)
        # manifest moved with deep storage: found by document_id under --deep-storage, objects by SHA-256
        moved = self.tmp / "moved"
        ds.rename(moved)
        r2 = ImageResolver.for_report(out / "wasa_report.json", deep_storage=moved)
        got = r2.resolve("[IMAGE_PAGE_12_FIG_1]")
        self.assertEqual(Path(got.path).read_bytes(), ORIGINAL)
        self.assertTrue(got.path.startswith(str(moved)))


if __name__ == "__main__":
    unittest.main()
