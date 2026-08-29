#!/usr/bin/env python3
"""
Compares Semgrep SAST JSON output against OWASP VulnerableApp's
expectedIssues.csv ground truth.

Usage:
    python3 compare_findings.py expectedIssues.csv semgrep-results.json [--window 10] [--scope src/main/java]

Key design decisions (why earlier attempts under-matched):
  1. CWE comparison uses only the numeric ID (CWE-89), not Semgrep's
     full description string.
  2. File paths are normalized: backslashes -> forward slashes, and
     compared as path *suffixes* so Windows-style absolute/relative
     paths from Semgrep still match the CSV's relative paths.
  3. Line numbers are matched with a tolerance window, not exact
     equality. Semgrep usually points at the specific tainted
     expression, while the ground truth CSV sometimes points at the
     method signature/annotation a few lines above -- and vice versa.
  4. Only files under the given --scope (default src/main/java) are
     considered "in scope" for recall/precision -- CI/workflow findings
     in .github/**, gradlew, etc. are real Semgrep findings but were
     never something expectedIssues.csv could have contained, so they
     shouldn't count as false positives against this ground truth.
  5. Matching is greedy one-to-one: once an expected row is matched to
     a Semgrep finding, neither can be reused, so you don't get
     inflated numbers from one Semgrep line "matching" five CSV rows.
"""
import argparse
import csv
import json
import re
from collections import defaultdict

CWE_RE = re.compile(r"CWE-(\d+)")


def cwe_num(text):
    m = CWE_RE.search(text or "")
    return m.group(1) if m else None


def norm_path(p):
    return p.replace("\\", "/").strip().lstrip("./")


def read_text_tolerant(path):
    """Read a file that may not be valid UTF-8 (Semgrep on Windows can emit
    Windows-1252 bytes, e.g. a mis-encoded em-dash, inside JSON strings)."""
    with open(path, "rb") as f:
        raw = f.read()
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("cp1252", errors="replace")


def load_expected(csv_path):
    rows = []
    text = read_text_tolerant(csv_path)
    import io
    with io.StringIO(text) as f:
        for r in csv.DictReader(f):
            rows.append({
                "cwe": cwe_num(r["CWE"]),
                "type": r["Vulnerability Type"],
                "file": norm_path(r["File"]),
                "line": int(r["Line"]),
            })
    return rows


def load_semgrep(json_path):
    text = read_text_tolerant(json_path)
    data = json.loads(text)
    findings = []
    for r in data.get("results", []):
        cwes = r.get("extra", {}).get("metadata", {}).get("cwe", [])
        cwe_nums = {cwe_num(c) for c in cwes if cwe_num(c)}
        findings.append({
            "check_id": r["check_id"],
            "file": norm_path(r["path"]),
            "start": r["start"]["line"],
            "end": r["end"]["line"],
            "cwes": cwe_nums,
            "severity": r.get("extra", {}).get("severity"),
        })
    return findings


def in_scope(file_path, scope):
    return file_path.startswith(scope.rstrip("/") + "/")


def match(expected, findings, window, scope):
    in_scope_findings = [f for f in findings if in_scope(f["file"], scope)]
    out_of_scope_count = len(findings) - len(in_scope_findings)

    used = [False] * len(in_scope_findings)
    tp, fn = [], []

    for exp in expected:
        best_idx, best_dist = None, None
        for i, f in enumerate(in_scope_findings):
            if used[i]:
                continue
            if f["file"] != exp["file"]:
                continue
            if exp["cwe"] not in f["cwes"]:
                continue
            # distance from expected line to the finding's reported span
            if f["start"] <= exp["line"] <= f["end"]:
                dist = 0
            else:
                dist = min(abs(exp["line"] - f["start"]), abs(exp["line"] - f["end"]))
            if dist <= window and (best_dist is None or dist < best_dist):
                best_idx, best_dist = i, dist
        if best_idx is not None:
            used[best_idx] = True
            tp.append((exp, in_scope_findings[best_idx], best_dist))
        else:
            fn.append(exp)

    fp = [f for i, f in enumerate(in_scope_findings) if not used[i]]
    return tp, fn, fp, out_of_scope_count


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("expected_csv")
    ap.add_argument("semgrep_json")
    ap.add_argument("--window", type=int, default=10,
                     help="max line-number distance to still count as a match (default 10)")
    ap.add_argument("--scope", default="src/main/java",
                     help="path prefix that defines 'in scope' files (default src/main/java)")
    args = ap.parse_args()

    expected = load_expected(args.expected_csv)
    findings = load_semgrep(args.semgrep_json)
    tp, fn, fp, out_of_scope = match(expected, findings, args.window, args.scope)

    precision = len(tp) / (len(tp) + len(fp)) if (tp or fp) else 0
    recall = len(tp) / (len(tp) + len(fn)) if (tp or fn) else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0

    print(f"Ground truth rows (expectedIssues.csv): {len(expected)}")
    print(f"Semgrep findings total:                 {len(findings)}")
    print(f"  in-scope ({args.scope}):               {len(findings) - out_of_scope}")
    print(f"  out-of-scope (CI/build/workflow etc.): {out_of_scope}")
    print(f"Matching window: +/- {args.window} lines\n")
    print(f"True Positives  (TP): {len(tp)}")
    print(f"False Negatives (FN): {len(fn)}   <- expected issues Semgrep missed")
    print(f"False Positives (FP): {len(fp)}   <- in-scope Semgrep findings not in ground truth")
    print(f"Precision: {precision:.2%}   Recall: {recall:.2%}   F1: {f1:.2%}\n")

    # breakdown by CWE type, to see which categories Semgrep's default rules cover at all
    by_cwe_expected = defaultdict(int)
    by_cwe_tp = defaultdict(int)
    for e in expected:
        by_cwe_expected[(e["cwe"], e["type"])] += 1
    for e, f, d in tp:
        by_cwe_tp[(e["cwe"], e["type"])] += 1

    print(f"{'CWE':<10}{'Type':<38}{'Expected':<10}{'Matched':<8}")
    for key in sorted(by_cwe_expected, key=lambda k: (-by_cwe_expected[k], k[0])):
        cwe, typ = key
        print(f"CWE-{cwe:<6}{typ:<38}{by_cwe_expected[key]:<10}{by_cwe_tp.get(key, 0):<8}")

    print("\n--- Sample of False Negatives (first 15) ---")
    for e in fn[:15]:
        print(f"  CWE-{e['cwe']:<6} {e['type']:<35} {e['file']}:{e['line']}")

    print("\n--- Sample of matched TPs with their line offset (first 10) ---")
    for e, f, d in tp[:10]:
        print(f"  CWE-{e['cwe']:<6} {e['file']}:{e['line']}  <-> semgrep {f['start']}-{f['end']} (offset {d}, rule={f['check_id']})")


if __name__ == "__main__":
    main()
