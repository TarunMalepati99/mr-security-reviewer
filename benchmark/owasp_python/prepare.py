"""Convert an OWASP Benchmark for Python checkout into reviewer test cases.

    git clone https://github.com/OWASP-Benchmark/BenchmarkPython.git
    python benchmark/owasp_python/prepare.py path/to/BenchmarkPython

Writes cases.jsonl (one labeled test case per line) and helpers.json (the
benchmark's shared helper modules, given to the reviewer as related repo files).

Each benchmark test file names its category in its URL and template paths
(e.g. "/benchmark/sqli-00/BenchmarkTest00011"), which would hand the answer to a
model. Those names are rewritten to neutral ones ("/benchmark/app/Handler00011")
and the license header is stripped. The code itself is unchanged.
"""

import csv
import json
import re
import sys
from pathlib import Path

CATEGORIES = ["pathtraver", "cmdi", "codeinj", "deserialization", "hash", "ldapi", "redirect",
              "securecookie", "sqli", "trustbound", "weakrand", "xpathi", "xss", "xxe"]
LEAKY = [c for c in CATEGORIES if c not in ("redirect", "hash")]  # these two are also ordinary code words


def neutralize(src: str) -> str:
    src = re.sub(r"\A\s*'''.*?'''\s*", "", src, flags=re.S)           # license header
    src = re.sub(r"\b(benchmark|web)/[a-z]+-\d+/", r"\1/app/", src)    # category in paths
    src = src.replace("BenchmarkTest", "Handler")
    # a few error-message strings also name the category, e.g. "Problem executing cmdi"
    for word in LEAKY:
        src = re.sub(rf"(?<![A-Za-z]){word}(?![A-Za-z])", "command" if word == "cmdi" else "test", src)
    return src


def main(root: Path) -> None:
    out_dir = Path(__file__).resolve().parent
    rows = []
    with open(root / "expectedresults-0.1.csv", newline="") as f:
        for r in csv.reader(f):
            if not r or r[0].startswith("#"):
                continue
            rows.append((r[0].strip(), r[1].strip(), r[2].strip() == "true", int(r[3])))

    n = 0
    with open(out_dir / "cases.jsonl", "w", encoding="utf-8") as out:
        for name, cat, real, cwe in rows:
            src = neutralize((root / "testcode" / f"{name}.py").read_text(encoding="utf-8"))
            for word in LEAKY:  # e.g. "sqli" must not appear on its own ("sqlite" is fine)
                assert not re.search(rf"(?<![a-z]){word}(?![a-z])", src.lower()), (name, word)
            num = name.replace("BenchmarkTest", "")
            out.write(json.dumps({
                "id": f"owasp-{num}",
                "source_test": name,
                "category": cat,
                "real_vulnerability": real,
                "cwe": cwe,
                "path": f"app/handlers/handler_{num}.py",
                "code": src,
            }) + "\n")
            n += 1

    helpers = {}
    for p in sorted((root / "helpers").glob("*.py")):
        helpers[f"helpers/{p.name}"] = p.read_text(encoding="utf-8")
    ini = root / "helpers" / "resources" / "ThingFactory.ini"
    if ini.exists():
        helpers["helpers/resources/ThingFactory.ini"] = ini.read_text(encoding="utf-8")
    (out_dir / "helpers.json").write_text(json.dumps(helpers, indent=1), encoding="utf-8")
    print(f"wrote {n} cases and {len(helpers)} helper files to {out_dir}")


if __name__ == "__main__":
    main(Path(sys.argv[1]))
