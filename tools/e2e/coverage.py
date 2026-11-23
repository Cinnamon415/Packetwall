#!/usr/bin/env python3
"""
Which expected behaviours of docs/E2E.md have a test.

  - instrumented tests (app/src/androidTest/.../e2e): the IDs in their @Covers(...) annotations;
  - host-side scenarios of tools/e2e/e2e.py that need a rooted emulator (HOST below).

Prints covered / uncovered per section and IDs used in tests that the catalog does not have.
Exit code 1 when a test names an unknown ID (a typo or a removed item).
"""
import os, re, sys, glob, collections

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CATALOG = os.path.join(ROOT, "docs", "E2E.md")
TESTS = os.path.join(ROOT, "app", "src", "androidTest", "java", "io", "github", "cinnamon415", "packetwall", "e2e")

# behaviours the root scenarios of e2e.py reach beyond the instrumented tests (reboots, su)
HOST = {
    "DEC-10": "geo (GeoIP databases downloaded once)",
    "SET-11": "proxy_app (a relay running as another app's uid)",
    "SYS-10": "proxy_app_lockdown (Always-on + lockdown, reboot)",
}

ID = re.compile(r"\b([A-Z]+-\d+[a-z]?)\b")


def catalog():
    items = collections.OrderedDict()
    for line in open(CATALOG, encoding="utf-8"):
        m = re.match(r"^- ([A-Z]+-\d+[a-z]?) (.*)", line)
        if m:
            items[m.group(1)] = m.group(2).strip()
    return items


def covered():
    found = collections.defaultdict(set)
    for f in glob.glob(os.path.join(TESTS, "*.kt")):
        text = open(f, encoding="utf-8").read()
        for m in re.finditer(r"@Covers\(([^)]*)\)", text):
            for i in re.findall(r'"([^"]+)"', m.group(1)):
                found[i].add(os.path.basename(f)[:-3])
    return found


def main():
    items = catalog()
    tests = covered()
    unknown = sorted(set(tests) - set(items))
    by_section = collections.OrderedDict()
    for i in items:
        by_section.setdefault(i.split("-")[0], []).append(i)
    total = done = 0
    missing = []
    for sec, ids in by_section.items():
        have = [i for i in ids if i in tests or i in HOST]
        total += len(ids)
        done += len(have)
        print(f"{sec:6} {len(have):3}/{len(ids):<3}")
        missing += [i for i in ids if i not in have]
    print(f"\ncovered {done} of {total} ({100 * done // max(total, 1)}%)")
    print("also host-side (tools/e2e/e2e.py, root):", ", ".join(f"{k} [{v}]" for k, v in HOST.items()))
    if missing:
        print("\nno test:")
        for i in missing:
            print(f"  {i} {items[i][:110]}")
    if unknown:
        print("\nnot in docs/E2E.md:", ", ".join(f"{i} ({', '.join(sorted(tests[i]))})" for i in unknown))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
