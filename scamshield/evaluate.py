"""Evaluate the rule engine on the labelled SYNTHETIC dataset (data/sample_cases.csv).

IMPORTANT: the dataset is author-written and was created alongside the rules, so results are optimistic and
are a regression check, NOT a measure of real-world accuracy.
Run:  python -m scamshield.evaluate
"""
import json
import os
import sys

import pandas as pd

from .detector import analyze_text

ROOT = os.path.dirname(os.path.dirname(__file__))
THRESHOLD = 25  # Moderate or above counts as "flagged"


def evaluate(csv_path=None, threshold=THRESHOLD):
    df = pd.read_csv(csv_path or os.path.join(ROOT, "data", "sample_cases.csv"))
    res = [analyze_text(t) for t in df["text"]]
    df["score"] = [r["score"] for r in res]
    df["pred_cat"] = [r["category"] for r in res]
    df["pred"] = (df["score"] >= threshold).astype(int)
    tp = int(((df.pred == 1) & (df.is_fraud == 1)).sum()); fp = int(((df.pred == 1) & (df.is_fraud == 0)).sum())
    fn = int(((df.pred == 0) & (df.is_fraud == 1)).sum()); tn = int(((df.pred == 0) & (df.is_fraud == 0)).sum())
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    fr = df[df.is_fraud == 1]
    per_cat = []
    for c, g in fr.groupby("category"):
        per_cat.append({"category": c, "n": len(g), "flagged": int((g.pred == 1).sum()),
                        "category_correct": int((g.pred_cat == c).sum()),
                        "category_accuracy": round((g.pred_cat == c).mean(), 3)})
    out = {"dataset": "synthetic, author-written (not real-world data)", "n": len(df), "threshold": threshold,
           "tp": tp, "fp": fp, "fn": fn, "tn": tn, "precision": round(prec, 3), "recall": round(rec, 3),
           "f1": round(f1, 3), "false_positive_rate": round(fp / (fp + tn), 3) if fp + tn else 0.0,
           "category_accuracy_on_fraud": round((fr.pred_cat == fr.category).mean(), 3), "per_category": per_cat,
           "false_positives": df[(df.pred == 1) & (df.is_fraud == 0)][["id", "text", "score"]].to_dict("records"),
           "false_negatives": df[(df.pred == 0) & (df.is_fraud == 1)][["id", "text", "score"]].to_dict("records"),
           "category_mismatches": fr[fr.pred_cat != fr.category][["id", "category", "pred_cat", "score"]].to_dict("records")}
    return out


def to_markdown(o):
    L = ["# Evaluation (synthetic data)", "", f"> {o['dataset']}. Cases: {o['n']}. Flag threshold: score >= {o['threshold']}.",
         "> Rules and dataset were written by the same author, so this is a regression check, not real-world accuracy.", "",
         f"| TP | FP | FN | TN | Precision | Recall | F1 | FP rate |", "|---|---|---|---|---|---|---|---|",
         f"| {o['tp']} | {o['fp']} | {o['fn']} | {o['tn']} | {o['precision']} | {o['recall']} | {o['f1']} | {o['false_positive_rate']} |", "",
         f"Category accuracy on fraud cases: **{o['category_accuracy_on_fraud']}**", "",
         "| Category | n | Flagged | Category correct | Category accuracy |", "|---|---|---|---|---|"]
    L += [f"| {c['category']} | {c['n']} | {c['flagged']} | {c['category_correct']} | {c['category_accuracy']} |" for c in o["per_category"]]
    L += ["", "## False positives"] + [f"- #{r['id']} (score {r['score']}): {r['text']}" for r in o["false_positives"]]
    L += ["", "## False negatives"] + [f"- #{r['id']} (score {r['score']}): {r['text']}" for r in o["false_negatives"]]
    L += ["", "## Category mismatches"] + [f"- #{r['id']}: expected {r['category']}, got {r['pred_cat']} (score {r['score']})" for r in o["category_mismatches"]]
    return "\n".join(L)


if __name__ == "__main__":
    o = evaluate()
    os.makedirs(os.path.join(ROOT, "reports"), exist_ok=True)
    json.dump(o, open(os.path.join(ROOT, "reports", "evaluation.json"), "w"), indent=2, default=str)
    md = to_markdown(o)
    open(os.path.join(ROOT, "reports", "evaluation.md"), "w", encoding="utf-8").write(md)
    print(md)
