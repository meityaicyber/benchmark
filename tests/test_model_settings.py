"""Model settings for a local OpenAI-compatible server (26 October 2026): the request states its sampling settings and
template arguments, other image formats are sent as PNG, the server's error text is kept, the server is checked
before a run, the samples of an item are sent together, a reasoning trace is not taken for the answer, a retest
comparison respects the server's image limit, and several reports can be evaluated in parallel processes."""

import base64
import contextlib
import copy
import io
import json
import shutil
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import yaml
from PIL import Image

from helpers import EVAL_DATE, HERE, ROOT, criterion, refdata, sample, scripted_backend

from certin_benchmark import BenchmarkEngine
from certin_benchmark.cli import main
from certin_benchmark.evaluators import BackendUnavailable, FunctionBackend, ModelCall, backend_from_config
from certin_benchmark.evaluators.backends import PNG_SIGNATURE
from certin_benchmark.evaluators.sampling import SampledEvaluator

SAMPLING = {"n": 5, "temperature": 0.7, "base_seed": 100, "variance_threshold": 0.8, "min_valid_samples": 3}
RUBRICS = {"rubrics": {"r": {"question": "Is it good?", "levels": {str(i): f"level {i}" for i in range(1, 6)}}}}


class MockServer:
    """A stand-in for a local vLLM server: /models and /chat/completions, with selectable behaviour."""

    def __init__(self, served=("m1",)):
        self.served = list(served)
        self.mode = "ok"
        self.delay = 0.0
        self.bodies: list[dict] = []
        self.lock = threading.Lock()
        server = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _send(self, code, payload):
                data = json.dumps(payload).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                if self.path.endswith("/models"):
                    self._send(200, {"object": "list", "data": [{"id": m, "object": "model"} for m in server.served]})
                else:
                    self._send(404, {"error": "not found"})

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                with server.lock:
                    server.bodies.append(body)
                if server.delay:
                    time.sleep(server.delay)
                content = body["messages"][1]["content"]
                images = [c for c in content if c.get("type") == "image_url"] if isinstance(content, list) else []
                if server.mode == "limit1" and len(images) > 1:
                    return self._send(400, {"error": "At most 1 image(s) may be provided in one request."})
                if server.mode == "bad":
                    return self._send(200, {"error": "something else"})
                if server.mode == "think":
                    text = ('<think>The rubric says {"level": 2} would mean weak; level 2 does not fit.</think>'
                            '{"level": 4, "rationale": "fits level 4"}')
                elif server.mode == "truncated":
                    text = "<think>Considering the rubric, level 3 might apply, but"
                elif server.mode == "by_seed":
                    text = json.dumps({"level": body["seed"] % 5 + 1, "rationale": "by seed"})
                elif '"answer"' in body["messages"][0]["content"]:
                    text = json.dumps({"answer": "yes", "rationale": "ok"})
                elif '"metrics"' in body["messages"][0]["content"]:
                    text = json.dumps({"metrics": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H",
                                                   "I": "N", "A": "N"}, "rationale": "ok"})
                else:
                    text = json.dumps({"level": 4, "rationale": "ok"})
                self._send(200, {"choices": [{"message": {"role": "assistant", "content": text}}]})

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}/v1"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


def png_file(folder: Path, name="shot.png", fmt="PNG", color=(200, 30, 30)) -> Path:
    path = folder / name
    Image.new("RGB", (40, 20), color).save(path, format=fmt)
    return path


def sent_images(body: dict) -> list[bytes]:
    content = body["messages"][1]["content"]
    return [base64.b64decode(c["image_url"]["url"].split(",", 1)[1]) for c in content if c.get("type") == "image_url"]


def run_cli(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = main(argv)
    return rc, out.getvalue(), err.getvalue()


class ServerTestCase(unittest.TestCase):
    def setUp(self):
        self.server = MockServer()
        self.addCleanup(self.server.close)
        self.tmp = Path(tempfile.mkdtemp(prefix="certin-models-"))

    def backend(self, **extra):
        cfg = {"backend": "openai_compatible", "base_url": self.server.url, "model": "m1", "model_version": "rev-1",
               "top_p": 1.0, "top_k": 0, "min_p": 0.0, "chat_template_kwargs": {"enable_thinking": False},
               "mm_processor_kwargs": {"max_dynamic_patch": 12}, **extra}
        return backend_from_config(cfg)


class RequestSettings(ServerTestCase):
    def test_request_states_its_sampling_settings_and_template_arguments(self):
        b = self.backend()
        b.complete(ModelCall("system", "user", 7, 0.7))
        body = self.server.bodies[-1]
        self.assertEqual({k: body[k] for k in ("temperature", "seed", "max_tokens", "top_p", "top_k", "min_p")},
                         {"temperature": 0.7, "seed": 7, "max_tokens": 400, "top_p": 1.0, "top_k": 0, "min_p": 0.0})
        self.assertEqual(body["chat_template_kwargs"], {"enable_thinking": False})
        self.assertNotIn("mm_processor_kwargs", body)            # only with images
        image = png_file(self.tmp)
        b.complete(ModelCall("system", "user", 8, 0.7, str(image)))
        body = self.server.bodies[-1]
        self.assertEqual(body["mm_processor_kwargs"], {"max_dynamic_patch": 12})
        self.assertEqual(sent_images(body), [image.read_bytes()])  # PNG sent as stored

    def test_settings_left_out_are_not_sent(self):
        b = backend_from_config({"backend": "openai_compatible", "base_url": self.server.url, "model": "m1"})
        b.complete(ModelCall("s", "u", 1, 0.7))
        body = self.server.bodies[-1]
        for key in ("top_p", "top_k", "min_p", "chat_template_kwargs", "mm_processor_kwargs"):
            self.assertNotIn(key, body)

    def test_other_image_formats_are_sent_as_png_and_jpeg_as_stored(self):
        b = self.backend()
        bmp = png_file(self.tmp, "shot.bmp", "BMP")
        tif = png_file(self.tmp, "shot.tiff", "TIFF")
        jpg = png_file(self.tmp, "shot.jpeg", "JPEG")
        b.complete(ModelCall("s", "u", 1, 0.7, str(bmp), [str(tif), str(jpg)]))
        imgs = sent_images(self.server.bodies[-1])
        self.assertTrue(imgs[0].startswith(PNG_SIGNATURE) and imgs[1].startswith(PNG_SIGNATURE))
        self.assertEqual(imgs[2], jpg.read_bytes())
        self.assertEqual(Image.open(io.BytesIO(imgs[0])).getpixel((5, 5)), (200, 30, 30))   # the same picture
        self.assertEqual(bmp.read_bytes()[:2], b"BM")                                       # the stored file is unchanged
        bad = self.tmp / "broken.jpx"
        bad.write_bytes(b"\x00\x00\x00\x0cjP  \r\n\x87\n truncated")
        with self.assertRaisesRegex(BackendUnavailable, "could not be read"):
            b.complete(ModelCall("s", "u", 1, 0.7, str(bad)))

    def test_server_error_text_is_kept(self):
        self.server.mode = "limit1"
        a, c = png_file(self.tmp, "a.png"), png_file(self.tmp, "c.png", color=(0, 0, 0))
        with self.assertRaisesRegex(BackendUnavailable, r"HTTP 400: .*At most 1 image"):
            self.backend().complete(ModelCall("s", "u", 1, 0.7, str(a), [str(c)]))

    def test_an_unexpected_reply_is_unavailable_not_a_crash(self):
        self.server.mode = "bad"
        with self.assertRaisesRegex(BackendUnavailable, "unexpected response"):
            self.backend().complete(ModelCall("s", "u", 1, 0.7))

    def test_check_lists_the_served_models_and_refuses_another(self):
        self.assertEqual(self.backend().check(), ["m1"])
        with self.assertRaisesRegex(BackendUnavailable, "does not serve 'm2'.*m1"):
            self.backend(model="m2").check()
        self.server.close()
        with self.assertRaises(BackendUnavailable):
            self.backend().check()
        self.server = MockServer()                       # for the cleanup


class Sampling(ServerTestCase):
    def test_samples_of_an_item_go_together_and_stay_in_seed_order(self):
        self.server.mode, self.server.delay = "by_seed", 0.4
        ev = SampledEvaluator(RUBRICS, SAMPLING, text_backend=self.backend(concurrency=5))
        started = time.monotonic()
        item = ev.score("x", "r", "content")
        elapsed = time.monotonic() - started
        self.assertEqual(item.seeds, [100, 101, 102, 103, 104])
        self.assertEqual(item.ratings, [s % 5 + 1 for s in item.seeds])
        self.assertLess(elapsed, 1.2)                    # five requests of 0.4 s each, sent together
        self.assertEqual(sorted(b["seed"] for b in self.server.bodies), item.seeds)

    def test_one_unavailable_sample_makes_the_item_unavailable(self):
        def fn(call):
            if call.seed == 102:
                raise BackendUnavailable("server went away")
            return json.dumps({"level": 3, "rationale": "x"})
        backend = FunctionBackend(fn)
        backend.concurrency = 5
        item = SampledEvaluator(RUBRICS, SAMPLING, text_backend=backend).score("x", "r", "content")
        self.assertTrue(item.unavailable)
        self.assertIn("server went away", item.note)

    def test_a_reasoning_trace_is_not_taken_for_the_answer(self):
        self.server.mode = "think"
        item = SampledEvaluator(RUBRICS, SAMPLING, text_backend=self.backend()).score("x", "r", "content")
        self.assertEqual(item.ratings, [4] * 5)
        self.server.mode = "truncated"                    # cut off by the token limit before any answer
        item = SampledEvaluator(RUBRICS, SAMPLING, text_backend=self.backend()).score("x", "r", "content")
        self.assertEqual(item.ratings, [])
        self.assertTrue(item.referred)
        self.assertIn("only 0 valid ratings", item.note)

    def test_a_retest_comparison_respects_the_image_limit(self):
        calls = []

        def fn(call):
            calls.append(call)
            return json.dumps({"level": 4, "rationale": "x"})
        ev = SampledEvaluator(RUBRICS, SAMPLING, vision_backend=FunctionBackend(fn), max_images_per_request=2)
        item = ev.score("x", "r", "content", "vision", "retest.png", extra_images=["o1.png", "o2.png", "o3.png"])
        self.assertEqual({len(c.images()) for c in calls}, {2})
        self.assertEqual(calls[0].extra_images, ["o1.png"])
        self.assertIn("the 1 image(s) after it", calls[0].user)
        self.assertIn("2 of 3 original images not sent", item.note)
        self.assertEqual(item.ratings, [4] * 5)


class EvaluateCommand(ServerTestCase):
    def suite_yaml(self, model="m1", version="unset") -> Path:
        cfg = yaml.safe_load((ROOT / "config" / "suite.yaml").read_text())
        for kind in ("text", "vision"):
            cfg["models"][kind].update(base_url=self.server.url, model=model, model_version=version)
        path = self.tmp / "suite.yaml"
        path.write_text(yaml.safe_dump(cfg))
        return path

    def test_evaluate_stops_before_the_first_report_when_the_model_is_not_served(self):
        rc, _, err = run_cli(["evaluate", str(HERE / "fixtures" / "sample_report.json"),
                              "--config", str(self.suite_yaml(model="other"))])
        self.assertEqual(rc, 1)
        self.assertIn("error: text model:", err)
        self.assertIn("does not serve 'other'", err)
        self.assertEqual(self.server.bodies, [])          # no report was evaluated

    def test_evaluate_warns_of_an_unset_model_version_and_runs(self):
        rc, out, err = run_cli(["evaluate", str(HERE / "fixtures" / "sample_report.json"), "--evaluated-on",
                                "2026-08-25", "--config", str(self.suite_yaml())])
        self.assertIn(rc, (0, 2))
        self.assertIn("warning: models.text.model_version is unset", err)
        self.assertTrue(self.server.bodies)
        record = json.loads(out)
        self.assertFalse(record["provisional"])            # every model-judged item was answered by the server
        self.assertTrue(all(b["chat_template_kwargs"] == {"enable_thinking": False} for b in self.server.bodies))

    def test_parallel_reports_give_the_same_records_and_recordings_replay(self):
        reports = []
        for i in range(3):
            path = self.tmp / f"report_{i}.json"
            data = sample()
            data["report_meta"]["report_id"] = f"SAMPLE-{i}"
            path.write_text(json.dumps(data))
            reports.append(str(path))
        suite = str(self.suite_yaml(version="rev-1"))
        seq, par = self.tmp / "seq", self.tmp / "par"
        rc1, _, err1 = run_cli(["evaluate", *reports, "--config", suite, "--evaluated-on", "2026-08-25",
                                "--out", str(seq)])
        rc2, _, err2 = run_cli(["evaluate", *reports, "--config", suite, "--evaluated-on", "2026-08-25",
                                "--out", str(par), "--jobs", "2", "--record-responses", str(self.tmp / "rec.json")])
        self.assertEqual(rc1, rc2, err2)

        def strip(d):
            d = copy.deepcopy(d)
            d.pop("evaluated_at", None)
            return d
        for r in reports:
            name = Path(r).stem + ".evaluation.json"
            self.assertEqual(strip(json.loads((seq / name).read_text())), strip(json.loads((par / name).read_text())))
        recorded = json.loads((self.tmp / "rec.json").read_text())
        self.assertTrue(recorded["text"])
        # the recording made by the processes replays every report without the server
        self.server.close()
        rep = self.tmp / "rep"
        rc3, _, err3 = run_cli(["evaluate", *reports, "--config", suite, "--evaluated-on", "2026-08-25",
                                "--out", str(rep), "--replay", str(self.tmp / "rec.json")])
        self.assertEqual(rc3, rc1, err3)
        for r in reports:
            name = Path(r).stem + ".evaluation.json"
            a, b = strip(json.loads((seq / name).read_text())), strip(json.loads((rep / name).read_text()))
            a.pop("reference_data", None), b.pop("reference_data", None)
            self.assertEqual([c["score"] for c in a["criteria"]], [c["score"] for c in b["criteria"]])
        self.server = MockServer()


class MissingCaptureDate(unittest.TestCase):
    def test_a_retest_without_a_capture_date_says_so(self):
        r = sample()
        o = r["detailed_observations"][0]
        o["proof_of_concept"] = [
            {"sr_no": 1, "type": "text", "reference": "GET /x -> 200", "capture_date": "2026-07-08",
             "is_retest": False, "redacted": "Yes", "description": "original"},
            {"sr_no": 2, "type": "text", "reference": "GET /x -> 403", "capture_date": None, "is_retest": True,
             "redacted": "Yes", "description": "retest"}]
        engine = BenchmarkEngine(refdata=refdata(), text_backend=scripted_backend(4))
        q4 = criterion(engine.evaluate(r, evaluated_on=EVAL_DATE), "Q4")
        item = next(i for i in q4.sampled if i.item_id.endswith("poc2.retest"))
        self.assertEqual(item.score, 0.0)
        self.assertIn("not stated", item.note)


if __name__ == "__main__":
    unittest.main()
