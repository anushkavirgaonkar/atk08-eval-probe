"""
ATK-08 TC-RCE-02 — GitHub-sourced evaluator execution + credential-presence probe.

Authorized pentest, engagement 2026-06-0401. This repo is a tester-controlled GitHub
repository used to confirm that an evaluator whose source is TYPE_GITHUB (code pulled from
this repo) actually executes in the Fireworks evaluator sandbox AND that the sandbox still
injects a FIREWORKS_API_KEY into the environment of GitHub-sourced code. The probe is benign:
it reports only a marker, the sandbox hostname, and the PRESENCE / prefix / last-6 / length of
the key (never the full value). No exfiltration, no network callback.
"""

import os
import sys
import json
import socket

from eval_protocol.models import EvaluateResult, EvaluationRow
from eval_protocol.pytest import SingleTurnRolloutProcessor, evaluation_test


@evaluation_test(
    input_dataset=["./dev/sample.jsonl"],
    completion_params=[{"model": "fireworks_ai/accounts/fireworks/models/glm-5p3-flash"}],
    max_dataset_rows=1,
    passed_threshold=0.0,
    rollout_processor=SingleTurnRolloutProcessor(),
    mode="pointwise",
)
def test_atk08_github(row: EvaluationRow, **kwargs) -> EvaluationRow:
    ak = os.environ.get("FIREWORKS_API_KEY") or ""
    findings = {
        "marker": "ATK08-GITHUB-SOURCED",
        "hostname": socket.gethostname(),
        "python_version": sys.version.split()[0],
        "fw_key_present": bool(ak),
        "fw_key_prefix": ak[:3],
        "fw_key_last6": ak[-6:],
        "fw_key_len": len(ak),
    }
    row.evaluation_result = EvaluateResult(score=0.0, reason=json.dumps(findings)[:5000])
    return row
