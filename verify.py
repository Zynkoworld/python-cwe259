#!/usr/bin/env python3
"""verify.py -- CI gate. Runs the deterministic decider over the labelled DISCRIMINATING probe corpus and
exits 0 IFF recall==1.0 AND false_positives==0 AND the corpus is non-degenerate (has FLAG and SAFE).
No network, stdlib only."""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "oracle"))
import python_cwe259_hardcoded_password as oracle  # noqa: E402


def main():
    base = os.path.dirname(os.path.abspath(__file__))
    probes = [json.loads(l) for l in open(os.path.join(base, "probes", "probes.jsonl"), encoding="utf-8") if l.strip()]
    have_f = any(p["expected_verdict"] == "FLAG" for p in probes)
    have_s = any(p["expected_verdict"] == "SAFE" for p in probes)
    if not (have_f and have_s):
        print("DEGENERATE corpus (need both FLAG and SAFE) -- FAIL")
        return 1
    tp = fp = fn = 0
    for p in probes:
        v = oracle.decide(p["code"], p["line"])
        e = p["expected_verdict"]
        if e == "FLAG" and v == "FLAG":
            tp += 1
        elif e == "FLAG" and v == "SAFE":
            fn += 1
        elif e == "SAFE" and v == "FLAG":
            fp += 1
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    ok = (recall == 1.0 and fp == 0)
    print("%s oracle: probes=%d | recall=%.3f | false_positives=%d | verdict=%s"
          % (oracle.CWE, len(probes), recall, fp, "PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
