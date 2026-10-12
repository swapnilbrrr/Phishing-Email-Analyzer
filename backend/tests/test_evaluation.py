from scripts.evaluate_corpus import confusion_metrics, load_corpus, DEFAULT_CORPUS


def test_confusion_metrics_report_binary_metrics():
    metrics = confusion_metrics([
        ("phishing", "phishing"),
        ("benign", "benign"),
        ("benign", "phishing"),
        ("phishing", "benign"),
    ])
    assert metrics["true_positive"] == 1
    assert metrics["true_negative"] == 1
    assert metrics["false_positive"] == 1
    assert metrics["false_negative"] == 1
    assert metrics["accuracy"] == 0.5
    assert metrics["precision"] == 0.5
    assert metrics["recall"] == 0.5
    assert metrics["specificity"] == 0.5
    assert metrics["f1"] == 0.5


def test_starter_corpus_is_nonempty_and_valid():
    records = load_corpus(DEFAULT_CORPUS)
    assert len(records) >= 4
    assert {record["label"] for record in records} == {"phishing", "benign"}
    assert all(record["source"] == "synthetic" for record in records)
