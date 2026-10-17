"""Build hook. The project's metadata is in pyproject.toml; this file only adds one step to the build.

The Suite's configuration (config/suite.yaml) and curated lists (curated/*.yaml) live at the top of the repository.
When a wheel is built, a copy of both is placed inside the package, under certin_benchmark/bundled/, so that an
installed Suite (for example one installed from wheels inside the CERT-In environment) finds them without the source
tree. A source checkout, or an editable install of one, reads the repository's own files instead (config.py).
"""

import shutil
from pathlib import Path

from setuptools import setup
from setuptools.command.build_py import build_py

ROOT = Path(__file__).resolve().parent
BUNDLED = (("config", "*.yaml"), ("curated", "*.yaml"))


class BuildPyWithData(build_py):
    def run(self):
        super().run()
        if getattr(self, "editable_mode", False):
            return          # an editable install reads the repository's files in place
        target = Path(self.build_lib) / "certin_benchmark" / "bundled"
        for name, pattern in BUNDLED:
            files = sorted((ROOT / name).glob(pattern))
            if not files:
                raise RuntimeError(f"no {pattern} files in {ROOT / name} to bundle")
            dest = target / name
            if dest.exists():
                shutil.rmtree(dest)
            dest.mkdir(parents=True)
            for f in files:
                shutil.copy2(f, dest / f.name)


setup(cmdclass={"build_py": BuildPyWithData})
