# Detection evaluation baseline

Run from the repository root:

```bash
python -m scripts.evaluate_corpus
```

The evaluator applies the current product threshold: `low_risk` maps to **benign**, while `suspicious` and `malicious` map to **phishing**. It reports a confusion matrix, accuracy, precision, recall, specificity, F1, and per-sample outcomes.

## Dataset status and limitations

The starter corpus contains four **handwritten synthetic examples**. It is a harness smoke test, not a representative dataset and not evidence of real-world detection accuracy. The messages use reserved example domains and documentation IP ranges; they are not collected from real mailboxes.

Before making claims about detection quality, expand the corpus with independently labeled, diverse benign and phishing messages; document collection, consent, de-identification, deduplication, and labeling criteria; split by campaign/domain to reduce leakage; and retain difficult benign cases. Record false positives and false negatives and inspect them before changing rules. Do not use the four-sample metrics as a portfolio performance claim.
