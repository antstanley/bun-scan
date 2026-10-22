#!/usr/bin/env python3
"""Build the CSV export and the per-category PR inventory markdown."""
import json, re, csv, os, textwrap

PRS = json.load(open("data/prs_classified.json"))
OUT = "reports"
INV = os.path.join(OUT, "inventory")
os.makedirs(INV, exist_ok=True)

def clean(txt, n=150):
    if not txt:
        return ""
    t = txt
    t = re.sub(r"!\[[^\]]*\]\([^)]*\)", " ", t)                 # images
    t = re.sub(r"\[([^\]]*)\]\(([^)]*)\)", r"\1", t)            # links
    t = re.sub(r"`{1,3}([^`]*)`{1,3}", r"\1", t)                # code
    t = re.sub(r"(\*\*|__|\*|_)(.+?)\1", r"\2", t)              # emphasis
    t = re.sub(r"^\s*[-*+]\s+", "", t)                          # bullets
    t = re.sub(r"^#+\s*", "", t)
    t = re.sub(r"\s+", " ", t).strip()
    t = t.replace("|", "\\|")
    if len(t) > n:
        cut = t[:n].rsplit(" ", 1)[0]
        t = cut.rstrip(" ,.;:") + "…"
    return t

def gist(pr):
    g = clean(pr.get("summary") or "", 155)
    if len(g) < 15:
        g = clean(pr["title"], 155)
    return g

def row(pr):
    n = pr["number"]
    ttl = clean(pr["title"], 120).replace("|", "\\|")
    auth = pr["user"] or "?"
    draft = "draft" if pr["draft"] else ""
    g = gist(pr)
    sev = ""
    if pr["security_tier"]:
        sev = pr["security_tier"]
    return f"| [#{n}]({pr['url']}) | {ttl} | {g} | {auth} | {draft} | {sev} |"

HEADER = ("| PR | Title | What it does | Author | | Sec |\n"
          "|---|---|---|---|---|---|\n")

# ---------------------------------------------------------------- CSV ----
with open(os.path.join(OUT, "prs.csv"), "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["number", "url", "title", "author", "draft", "category", "area",
                "security_tier", "security_classes", "surface", "created_at",
                "updated_at", "labels", "summary"])
    for pr in sorted(PRS, key=lambda x: -x["number"]):
        w.writerow([pr["number"], pr["url"], pr["title"], pr["user"],
                    pr["draft"], pr["category"], pr["area"], pr["security_tier"],
                    ";".join(pr["security_classes"]), ";".join(pr["surface"]),
                    pr["created_at"], pr["updated_at"],
                    ";".join(pr["labels"]),
                    re.sub(r"\s+", " ", pr.get("summary") or "")[:500]])

# ------------------------------------------------------------ inventory ----
WRITTEN = []

def write_file(name, title, blurb, prs):
    path = os.path.join(INV, name)
    with open(path, "w") as f:
        f.write(f"# {title}\n\n{blurb}\n\n")
        f.write(f"**{len(prs):,} pull requests.** Newest first.\n\n")
        f.write(HEADER)
        for pr in sorted(prs, key=lambda x: -x["number"]):
            f.write(row(pr) + "\n")
    print(f"  {name}: {len(prs)}")
    WRITTEN.append((name, len(prs)))
    return len(prs)

by = {}
for pr in PRS:
    by.setdefault(pr["category"], []).append(pr)

write_file("01-security.md", "Security", 
           "PRs whose title names a vulnerability class, a CVE/GHSA, or an "
           "advisory. See `../03-security-triage.md` for the assessment of "
           "each and `../02-security-severity.md` for the deep dive.",
           by.pop("security", []))

write_file("02-features.md", "Features",
           "New capability: new API surface, new flag, new platform, or a "
           "behaviour that did not exist before.",
           by.pop("feature", []))

write_file("03-performance.md", "Performance",
           "Speed, memory or allocation work where the point of the PR is the "
           "cost, not the behaviour.",
           by.pop("performance", []))

fixes = sorted(by.pop("fix", []), key=lambda x: -x["number"])
CH = 1100
for i in range(0, len(fixes), CH):
    chunk = fixes[i:i + CH]
    part = i // CH + 1
    write_file(f"04-fixes-part{part}.md", f"Fixes (part {part} of {(len(fixes)+CH-1)//CH})",
               "Corrects behaviour: a crash, a wrong result, a Node-parity gap, "
               "a hang, or a hardening change with no new API. This is the bulk "
               "of the queue.", chunk)

write_file("05-tests.md", "Tests",
           "Test-only changes: new coverage, de-flaking, faster suites. No "
           "runtime behaviour change.",
           by.pop("test", []))

write_file("06-docs.md", "Documentation",
           "Docs, guides, types prose and typo fixes.",
           by.pop("docs", []))

rest = by.pop("chore/ci/deps", []) + by.pop("refactor", []) + by.pop("other", [])
write_file("07-chores-refactors-other.md", "Chores, refactors and unclassified",
           "Build/CI/dependency bumps, internal restructuring, and the small "
           "residue the classifier could not place.", rest)

# --------------------------------------------------------- inventory README ----
with open(os.path.join(INV, "README.md"), "w") as f:
    f.write("# PR inventory\n\n")
    f.write("Every open pull request on `oven-sh/bun`, one row each, grouped by "
            "what the PR is for.\n\n")
    f.write("| File | PRs |\n|---|---|\n")
    for fn, cnt in WRITTEN:
        f.write(f"| [{fn}]({fn}) | {cnt} |\n")
    f.write("\nThe machine-readable version of the same data is "
            "[`../prs.csv`](../prs.csv).\n\n")
    f.write("## Columns\n\n")
    f.write("- **Title** — the PR title, trimmed.\n")
    f.write("- **What it does** — the first lines of the PR's own "
            "`What`/`Problem`/`Summary` section, cleaned of markdown and cut to "
            "about 150 characters. For most PRs this is the author's own "
            "description, not my paraphrase.\n")
    f.write("- **Sec** — the security tier, for the ~4% of PRs that have one "
            "(see `../03-security-triage.md`).\n")
    f.write("- **draft** — the PR is marked as a draft.\n")

print("done")
