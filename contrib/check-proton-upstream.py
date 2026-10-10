#!/usr/bin/env python3
"""Detect upstream changes to Proton code used by the WASM provider.

Exit 0: unchanged; 1: review required; 2: check failed (never reported as current).
Reads public GitHub metadata only. Pins remain in rosec-protonpass/UPSTREAM.txt.
"""
import argparse
import json
import os
from pathlib import Path
import re
import sys
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
SCOPES = {
    "protonpass/proton-pass-common": (
        "proton-pass-types/proto", "proton-pass-types/src/protos",
        "proton-pass-common/src/passkey", "Cargo.toml", "Cargo.lock", "LICENSE",
    ),
    "protonpass/pass-cli": (
        "pass/src/auth/personal_access_token.rs", "pass/src/constants.rs",
        "pass/src/domain/crypto.rs", "pass/src/share", "pass/src/item",
        "pass/src/folder", "Cargo.toml", "Cargo.lock", "LICENSE",
    ),
}


def read_pins(text):
    pins = {}
    for repo in SCOPES:
        matches = re.findall(
            r"^https://github\.com/" + re.escape(repo)
            + r"\nTag: ([^\n]+)\nCommit: ([0-9a-f]{40})$", text, re.MULTILINE
        )
        if len(matches) != 1:
            raise ValueError(f"Expected one tag/commit pin for {repo} in UPSTREAM.txt")
        pins[repo] = matches[0]
    return pins


def api(repo, endpoint):
    headers = {"Accept": "application/vnd.github+json",
               "X-GitHub-Api-Version": "2022-11-28",
               "User-Agent": "rosec-proton-upstream-check"}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = "Bearer " + token
    request = urllib.request.Request(
        f"https://api.github.com/repos/{repo}/{endpoint}", headers=headers
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        body = response.read(8 * 1024 * 1024 + 1)
    if len(body) > 8 * 1024 * 1024:
        raise ValueError("GitHub response exceeds size limit")
    return json.loads(body)


def checked_sha(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{40}", value):
        raise ValueError("Invalid GitHub object ID")
    return value


def scoped_tree(payload, scopes):
    if (not isinstance(payload, dict) or payload.get("truncated") is not False
            or not isinstance(payload.get("tree"), list)):
        raise ValueError("Incomplete GitHub tree response")
    entries = {}
    for entry in payload["tree"]:
        path = entry["path"]
        if entry["type"] == "tree":
            continue
        if any(path == scope or path.startswith(scope + "/") for scope in scopes):
            if path in entries:
                raise ValueError("Duplicate GitHub tree path")
            entries[path] = checked_sha(entry["sha"])
    return entries


def changes(before, after):
    if not before:
        raise ValueError("No monitored source found at pinned revision")
    return [(path, "added" if path not in before else "removed" if path not in after else "changed")
            for path in sorted(before.keys() | after.keys())
            if before.get(path) != after.get(path)]


def check(pins, fetch=api):
    lines = ["# Proton upstream source check", "",
             "Changes require review; this check does not update vendored or adapted code.", ""]
    drift = False
    for repo, scopes in SCOPES.items():
        tag, pin = pins[repo]
        pinned = fetch(repo, f"commits/{pin}")
        head = fetch(repo, "commits?per_page=1")[0]
        head_sha = checked_sha(head["sha"])
        before = scoped_tree(fetch(repo, "git/trees/" + checked_sha(pinned["commit"]["tree"]["sha"])
                                   + "?recursive=1"), scopes)
        # A typo or upstream move in the watched paths must not silently turn
        # off coverage when maintainers update a pin.
        for scope in scopes:
            if not any(path == scope or path.startswith(scope + "/") for path in before):
                raise ValueError(f"Monitored scope missing at pin: {repo}/{scope}")
        after = scoped_tree(fetch(repo, "git/trees/" + checked_sha(head["commit"]["tree"]["sha"])
                                  + "?recursive=1"), scopes)
        changed = changes(before, after)
        drift |= bool(changed)
        lines += [f"## {repo}", "", f"Pinned: {tag} (`{pin}`)",
                  f"Default branch: `{head_sha}`",
                  f"[Review upstream diff](https://github.com/{repo}/compare/{pin}...{head_sha})", ""]
        if changed:
            lines += [f"- {kind}: `{json.dumps(path)[1:-1]}`" for path, kind in changed]
        else:
            lines += ["No changes in the monitored source areas."]
        lines.append("")
    return drift, "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--summary", type=Path, default=os.environ.get("GITHUB_STEP_SUMMARY"))
    args = parser.parse_args()
    try:
        drift, report = check(read_pins((ROOT / "rosec-protonpass/UPSTREAM.txt").read_text()))
        result = 1 if drift else 0
    except (OSError, ValueError, KeyError, IndexError, TypeError) as error:
        # Never print response bodies, headers or token-bearing request objects.
        kind = type(error).__name__
        if isinstance(error, urllib.error.HTTPError):
            kind += f" status {error.code}"
        report = "# Proton upstream check failed\n\nCould not verify upstream state (" + kind + "). Retry or inspect the pins/API availability.\n"
        result = 2
    print(report)
    if args.summary:
        with args.summary.open("a") as summary:
            summary.write(report + "\n")
    return result


if __name__ == "__main__":
    sys.exit(main())
