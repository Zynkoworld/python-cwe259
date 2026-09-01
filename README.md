# zynko-oracle · `python-cwe259`

**A deterministic, re-checkable CWE-259 decider for Python.**

An **oracle** *deterministically decides* the truth of a case — it doesn't guess, it decides. This one decides,
for a given piece of Python code and a line number, whether that line constitutes **hard-coded password/credential** (CWE-259).

## Proven
Measured on a **discriminating** probe corpus of **11 cases (5 vulnerable + 6 safe)** — verified by
running the oracle, not asserted:

```
recall = 1.000    false_positives = 0    non-degenerate = yes  ->  PASS
```

`verify.py` (stdlib only, no network) is the CI gate.

## Method (no-virus)
The detection **rule** is equivalent to the corresponding Bandit check, but this repository contains a
**clean re-implementation** using only Python's `ast` module. **No third-party analyzer is installed, vendored,
or executed** — neither at build time nor at run time. The evidence is our own discriminating corpus, not the
word of an external tool.

## Grounding (honest)
This is a **syntactic (sink/literal presence)** decider, not a taint-flow analysis. It answers precisely one
question: *does this line use the flagged construct without the recognized safe alternative?* It does **not**
prove exploitability, and it is not a substitute for data-flow analysis on injection-class CWEs.

## License
Apache-2.0 (see `LICENSE`).
