#!/usr/bin/env python3
"""Merge Priority IT policy exceptions into the complete upstream Check ruleset."""

import argparse
import json
import re
from pathlib import Path

# ================================================================
# PRIORITY IT - ALLOW / WHITE LISTED URLS
# ================================================================
# Add ONE Python raw-string regex (r"...") per line.
# Use \. for a literal dot, and (?:[/?#]|$) to stop at a hostname boundary.
# Example to allow a whole HTTPS site and its paths:
#   r"^https://portal\.example\.org(?:[/?#]|$)",
# Keep exclusions narrow: excluded pages bypass Check scanning.
# ================================================================
ALLOW_URLS = [
    r"^https://interactions\.signin\.education\.gov\.uk(?:[/?#]|$)",
]

# ================================================================
# PRIORITY IT - BLOCK / BLACK LISTED URLS (CONTROLLED TEST ONLY)
# ================================================================
# Add ONE Python raw-string regex per line.
# Every entry creates TWO Check rules:
# - a critical URL-only phishing indicator
# - a negative URL legitimacy score rule for login-classified pages
# These are intended to produce Check's own block and detection_alert.
# Test on Ninja-Test before wider deployment; never block a live domain
# without checking possible impact on users and business workflows.
# Example: r"^https://training\.example\.org/test(?:/|$)",
# ================================================================
BLOCK_URLS = [
    r"^https://pit123\.com/Phish/.*$",
]


def build_rules(original):
    if not isinstance(original, dict):
        raise ValueError("Upstream rules must be a JSON object")
    if not isinstance(original.get("exclusion_system", {}).get("domain_patterns"), list):
        raise ValueError("Upstream exclusion_system.domain_patterns missing")
    if not isinstance(original.get("phishing_indicators"), list):
        raise ValueError("Upstream phishing_indicators missing")
    if not isinstance(original.get("rules"), list):
        raise ValueError("Upstream rules array missing")

    existing_ids = {
        item.get("id")
        for section in ("phishing_indicators", "rules")
        for item in original[section]
        if isinstance(item, dict)
    }

    for pattern in ALLOW_URLS + BLOCK_URLS:
        re.compile(pattern)

    for pattern in ALLOW_URLS:
        if pattern not in original["exclusion_system"]["domain_patterns"]:
            original["exclusion_system"]["domain_patterns"].append(pattern)

    for number, pattern in enumerate(BLOCK_URLS, 1):
        indicator_id = f"priority_it_url_block_{number:03d}"
        score_id = f"priority_it_url_score_{number:03d}"
        if indicator_id in existing_ids or score_id in existing_ids:
            raise ValueError(f"Custom rule ID conflicts with upstream: {number}")
        original["phishing_indicators"].insert(number - 1, {
            "id": indicator_id,
            "pattern": pattern,
            "flags": "i",
            "url_only": True,
            "severity": "critical",
            "action": "block",
            "category": "priority_it_managed_url_block",
            "confidence": 1,
            "description": "Priority IT controlled URL block",
        })
        original["rules"].append({
            "id": score_id,
            "type": "url_validation",
            "condition": {"pattern": pattern},
            "weight": -1000,
            "description": "Priority IT controlled URL legitimacy penalty",
        })

    # Catch accidental overlap before publishing the result.
    if any(re.search(a, "https://pit123.com/Phish/check-phishing-simulation-v2.html") for a in ALLOW_URLS):
        raise ValueError("Priority IT test URL is excluded by an allow rule")

    return original


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", default="detection-rules.json")
    args = parser.parse_args()
    result = build_rules(json.loads(Path(args.input).read_text(encoding="utf-8")))
    Path(args.output).write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"Published {len(ALLOW_URLS)} Priority IT allow and {len(BLOCK_URLS)} block patterns")
