"""Analytics over many evaluation records: the proposal's Objective 3 components B to F.

The Benchmarking Suite scores one report at a time. This package reads the evaluation records it writes, kept in a
local SQLite knowledge DB with the auditing organisation replaced by a pseudonymous token (store.py), and provides:

* C, similar cases: peer groups by audit type, sector and size, with the distribution of scores of each, so that a
  report is compared with comparable reports (peers.py);
* B, anomalies: reports far below their peers, agencies outside the limits their number of reports allows (funnel
  limits and estimates pooled towards the population), and checks or criteria whose results shift or no longer
  separate reports (outliers.py);
* D, trends: scores by period, the population trend with known breaks such as the date of the Guidelines, each
  agency's trend, and the detection of changes in level (trends.py);
* E, prediction: the expected quality score of a report from its context, and the probability that it is
  non-compliant, each checked by time-ordered backtests against simple baselines (predict.py);
* F, adaptive benchmarks: the effect of a proposed change to the Suite's configuration, by evaluating reports under
  both configurations (impact.py); the pass mark for Q is fitted with the calibration (calibration/calibrate.py).

The benchmark itself does not move: these results inform proposals that CERT-In approves as a new version.
Everything runs offline on numpy. Until the archive is scored, synthetic records with known patterns built in stand
in for it (synthetic.py), as the proposal's data plan provides.
"""
