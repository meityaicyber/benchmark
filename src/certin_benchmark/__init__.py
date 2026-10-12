"""Cybersecurity Audit Report Benchmarking Suite (Objective 3).

Implements the Suite approved by CERT-In (specification dated 6 October 2026): twenty-one
mandatory checks, eight quality criteria, engagement modules, record checks, sampled
distribution scoring, and evaluation against an air-gapped Reference Data Package.
"""

__version__ = "1.0.0"

from .engine import BenchmarkEngine, evaluate_report  # noqa: E402,F401
