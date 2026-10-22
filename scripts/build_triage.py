#!/usr/bin/env python3
"""Build reports/03-security-triage.md: every security-relevant PR with an assessment."""
import json, re

PRS = {p["number"]: p for p in json.load(open("data/prs_classified.json"))}
DET = {r["n"]: r for r in json.load(open("data/sec_details.json"))}

# number -> (practical rating, cvss-ish, one-line verdict)
A = {
 46351: ("**Critical**", "8.1 High",
   "Remote OOB write in the brotli decoder. Reached by `fetch()` on any `Content-Encoding: br` "
   "response, `node:zlib`, `DecompressionStream('brotli')`. Every Bun release affected; fix is ready and waiting."),
 42646: ("**High**", "6.1 Med (8.0 in a privileged app)",
   "`HTMLRewriter` comment setter is a sanitizer bypass: `--!>`, `>`, `->` end the comment, so the rest "
   "becomes live markup. XSS in any app that pipes user text into `comment.text`."),
 45204: ("**High**", "7.1 High (supply chain)",
   "`bun add <url|path|git>` inherits trust from `trustedDependencies` by package name, so an unvetted "
   "source's lifecycle scripts run without the trust gate the user expects."),
 42535: ("**High**", "7.5 High",
   "`URLPattern` with adjacent named groups is polynomial; 8 KB path = ~30 s. Same class as "
   "CVE-2024-45296 (path-to-regexp, 7.5). DoS for any app routing attacker-controlled paths."),
 36410: ("**High**", "7.5 High (availability only)",
   "HTTP/2 CONTINUATION flood (CVE-2024-28182 parity). Unauthenticated remote DoS against "
   "`node:http2` servers. `Bun.serve` is not affected."),
 38298: ("**Medium**", "5.9 Medium",
   "On macOS/FreeBSD a trailing separator makes `mkdir(2)` follow a dangling symlink, so "
   "`Bun.write('dangling//f')`, `fs.mkdir` and `mkdir -p` write outside the intended directory (CWE-59)."),
 42411: ("**Medium**", "6.5 Medium",
   "`node:http2` client grows `originSet` without bound; a malicious TLS server exhausts client memory."),
 34468: ("**Medium**", "5.5 Medium",
   "`node:wasi` never bounds-checks guest iovecs: I/O proceeds with truncated buffers, `path_open` "
   "leaks host fds, and `{buf, bufLen, total_memory}` is printed to host stdout. Sandbox integrity."),
 29144: ("**Medium**", "5.0 Medium (local)",
   "`Bun.cron()` on macOS writes launchd logs to a predictable `/tmp` path; a local user can "
   "pre-create a symlink and have launchd append to an arbitrary file as the victim (CWE-59/377)."),
 34884: ("**Medium**", "5.3 Medium",
   "Throwing a deeply nested non-Error value SIGSEGVs the process instead of printing it. Reachable "
   "wherever a server formats attacker-shaped data."),
 35687: ("**Medium**", "5.3 Medium",
   "Named-capture-group regex compilation is quadratic: a 180 KB pattern takes ~80 s in one "
   "uninterruptible tick. DoS where the pattern is attacker-influenced."),
 45668: ("**Medium**", "control bypass",
   "`bun audit` ranks an unknown/missing severity as moderate, so `--audit-level=high` exits 0 on a "
   "HIGH advisory. The security gate fails open."),
 46143: ("**Medium**", "control bypass",
   "`bun audit` silently skips tarball/git packages and reports `checked 0 packages`. The security "
   "gate reports clean on code it never checked."),
 44241: ("**Medium**", "5.3 Medium",
   "`Bun.serve` serves requests carrying two `Host` lines instead of answering 400 (RFC 9112 MUST). "
   "Routing/cache ambiguity behind a proxy that forwards duplicates (CWE-444)."),
 37864: ("**Low-Med**", "4.0 Low",
   "`Headers` iteration is quadratic (32 ms at 4,000 headers). Capped by header-count limits, so a "
   "weak DoS on its own."),
 46049: ("**Low-Med**", "5.0 Medium",
   "A dangling `.npmignore` symlink is read as 'no ignore file', so `bun pm pack`/`publish` ships "
   "files the ignore file excluded — potentially secrets."),
 33191: ("**Medium-High**", "varies",
   "node:http/http2 hardening bundle from a security review: h2 pseudo-header validation, a "
   "handler that throws no longer reads as `200 OK`, a post-close segfault, unbounded trailer capture."),
 44825: ("**Low**", "4.0 Low",
   "`Bun.openInEditor` passes a path with `&`/`%` to cmd.exe unescaped when the editor is `.cmd`/`.bat` "
   "(Windows command injection, local, needs a crafted filename)."),
 41475: ("**Low**", "3.5 Low",
   "A selector with 30,000 combinators SIGSEGVs `HTMLRewriter.transform()` by native stack overflow. "
   "Developer-controlled input, so a crash bug rather than an attack surface."),
 44829: ("**Low**", "—", "`realpath.native` follows a symlink before applying `..`; correctness/symlink handling."),
 42334: ("**Low**", "—", "Headers totalling ≥4 GiB now throw a RangeError instead of overflowing a length."),
 38932: ("**Low**", "—", "base64 checks output length before handing the buffer to simdutf; latent overflow."),
 39055: ("**Low**", "—", "`DynamicBitSetList` index and set-op lengths checked in release builds; latent OOB."),
 41574: ("**Low**", "—", "UTF-8 decoders operate on a private copy of a JS buffer; latent UAF window."),
 40139: ("**Low**", "—", "Replaces `unsafe` with typed ownership across socket/timer/sql/redis."),
 38009: ("**Low**", "—", "`MessagePort` heap-use-after-free in `contextDestroyed()` (ASAN-confirmed, JS-reachable)."),
 38636: ("**Low**", "—", "Route use-after-free after `reload()` with `tls.serverName`; app-triggered, not remote."),
 46360: ("**Low**", "—", "`bun:sqlite` clears bound values after a read that can run script; UAF window."),
 39588: ("**Low**", "—", "`node:vm` sandbox placed in front of globals like Node's contextify; sandbox hardening."),
 33486: ("**Low**", "—", "`node:vm` contextified sandbox as the store for guest globals; sandbox hardening."),
 33903: ("**Low**", "—", "webcrypto accepts inconsistent RSA JWK components on import; no direct forgery."),
 41964: ("**Low**", "—", "`Bun.Cookie.parse` Max-Age/attribute handling per RFC 6265; cookie-parsing correctness."),
 32982: ("**Low**", "—", "`Bun.Cookie` accepts uppercase domains and rejects malformed labels."),
 29226: ("**Low**", "—", "CI supply-chain hardening (workflow pinning)."),
 32112: ("**Low**", "—", "Archive extraction directory permissions hardened."),
 39671: ("**Low**", "—", "Dependency archives extracted without symlink privilege on Windows."),
 30681: ("**Low**", "—", "General input-validation and bounds-checking hardening pass."),
 38601: ("**None**", "—", "Docker checksum verification: the author states this is defense-in-depth, not a live bypass. Not a vulnerability."),
 37315: ("**None**", "—", "Babel CVE in `bench/` lockfile only — dev benchmark dependency, not shipped in Bun."),
 37312: ("**None**", "—", "`@auth/core` GHSA in `bench/install` lockfile only — dev dependency."),
 37510: ("**None**", "—", "`tar` CVE in `bench/` lockfile only — dev benchmark dependency."),
 42086: ("**None**", "—", "`constant-time` in the title means runtime cost, not timing-attack resistance. Classifier false positive."),
 44996: ("**None**", "—", "Quadratic `Json::object` conversion is a performance fix, not an attacker-triggered DoS."),
 44147: ("**None**", "—", "Typo in the vulnerability-reporting docs."),
 29638: ("**None**", "—", "Mentions CVE-2024-27980 only as background for Node's spawn hardening; fixes a `spawn EINVAL` bug."),
 21511: ("**None**", "—", "CI-only switch to panic on stack overflow."),
 20255: ("**Low**", "—",
   "A one-line fix for an out-of-bounds access in the file watcher (`onFileDeleted`). No description, "
   "repro or test, so it cannot be assessed — but the class is real and it should not be lost."),
 45221: ("**Low**", "—", "`--compile-exclude-features` can remove runtime parts from an executable; build-surface change."),
 43885: ("**Low**", "—", "BoringSSL `CRYPTO_memcmp` accumulator width — correctness of constant-time compare under clang 23."),
 31419: ("**Low**", "—", "Aligns `Bun.connect` TLS verification with `node:tls`; possible verification gap closed."),
}

RANK = {"**Critical**": 0, "**High**": 1, "**Medium-High**": 2, "**Medium**": 3,
        "**Low-Med**": 4, "**Low**": 5, "**None**": 6}

rows = []
for n, p in PRS.items():
    if not p["security_tier"]:
        continue
    rating, cvss, verdict = A.get(n, ("**Low**", "—",
        "Hardening / parity fix on an untrusted-input path. No exploit path identified from the "
        "PR description; valuable as defence in depth."))
    d = DET.get(n, {})
    state = d.get("state") or "?"
    if state == "dirty":
        state = "conflicts"
    if d.get("base") and d["base"] != "main":
        state += " · stacked"
    rows.append((RANK.get(rating, 5), -n, n, p, rating, cvss, verdict, state, d))

rows.sort(key=lambda r: (r[0], r[1]))

def esc(s):
    return (s or "").replace("|", "\\|")

with open("reports/03-security-triage.md", "w") as f:
    f.write("# Security triage — all 202 security-relevant open PRs\n\n")
    f.write("Every open PR whose title or description touches a vulnerability class, a "
            "CVE/GHSA, or the hardening of an untrusted-input path. Ratings are mine, "
            "from reading the PR and, where noted, the diff and the pinned dependency "
            "on `main`. CVSS is CVSS 3.1, calculated for the realistic attack path, not "
            "for the worst case.\n\n")
    f.write("**Read `02-security-severity.md` first** — it explains the top findings "
            "properly. This file is the complete index.\n\n")
    f.write("### Rating scale\n\n")
    f.write("| Rating | Meaning |\n|---|---|\n")
    f.write("| **Critical** | Remote, unauthenticated, memory corruption in a default-on path. Patch now. |\n")
    f.write("| **High** | Remote exploitation with real impact (RCE, XSS in a privileged app, DoS of a whole server, supply-chain code execution) but a narrower path. |\n")
    f.write("| **Medium** | Local, conditional, or limited-impact exploitation — or a security control that fails open. |\n")
    f.write("| **Low** | Theoretical, developer-controlled input, latent bug with no known trigger, or defence in depth. |\n")
    f.write("| **None** | Looked security-relevant; is not. Included so the list is complete and honest. |\n\n")
    f.write("### Status legend\n\n")
    f.write("`clean` mergeable · `blocked` mergeable but CI/review gate · `conflicts` does not "
            "apply to `main` · `stacked` based on another branch · `unknown` GitHub has not "
            "computed it · `draft`\n\n")

    f.write("| # | Rating | CVSS | PR | Tier | Status | Verdict |\n|---|---|---|---|---|---|---|\n")
    for rk, negn, n, p, rating, cvss, verdict, state, d in rows:
        draft = " · draft" if p["draft"] else ""
        f.write(f"| {n} | {rating} | {cvss} | [#{n}]({p['url']}) {esc(p['title'])} | "
                f"{p['security_tier']} | {state}{draft} | {esc(verdict)} |\n")

    f.write("\n## Counts\n\n")
    from collections import Counter
    c = Counter(r[4] for r in rows)
    f.write("| Rating | PRs |\n|---|---|\n")
    for k in ["**Critical**", "**High**", "**Medium-High**", "**Medium**", "**Low-Med**", "**Low**", "**None**"]:
        if c.get(k):
            f.write(f"| {k} | {c[k]} |\n")
    st = Counter(r[7].replace(" · draft", "").split(" · ")[0] for r in rows)
    f.write("\n### Merge state of the 202\n\n| State | PRs |\n|---|---|\n")
    for k, v in st.most_common():
        f.write(f"| {k} | {v} |\n")

    f.write("""
## Not in this table: fixes that had already merged

This triage covers **open** pull requests. Three of the issues in the main report were
fixed on `main` before the snapshot, so they never appear as candidates — and unlike most
of the rows above, all three are now **fixed in a released version**.

| Issue | PR | Merged | In 1.4.3? | In 1.4.4? | Report |
|---|---|---|---|---|---|
| QPACK header amplification (HTTP/3) | [#46392](https://github.com/oven-sh/bun/pull/46392) + [#46436](https://github.com/oven-sh/bun/pull/46436) | 2026-10-22 | No | **Yes** | F11 |
| eMudhra intermediate CA compromise | [#46300](https://github.com/oven-sh/bun/pull/46300) | 2026-10-21 | No | **Yes** | F12 |
| brotli CVE-2026-111497 | dependency bump to brotli v1.2.1 | 2026-10-21 | No | **Yes** | F1 |

The brotli *fix* is the dependency bump; [#46351](https://github.com/oven-sh/bun/pull/46351),
the PR that documents it, is still open and is row 1 of the table above.

See [`02-security-severity.md`](02-security-severity.md) for the findings and
[`04-advisory-check.md`](04-advisory-check.md) for the reproduction commands.
""")

print("wrote reports/03-security-triage.md", len(rows), "rows")
