#!/usr/bin/env python3
"""Classify every open oven-sh/bun PR by purpose and tier security relevance.

Tiers of security relevance:
  explicit   - names a CVE / GHSA / advisory, or the issue is called a
               security issue outright.
  vuln-class - title names a concrete vulnerability class (UAF, OOB, overflow,
               traversal, prototype pollution, auth bypass, DoS...).
  hardening  - title/body show the PR *hardening* an untrusted-input surface
               (malformed requests, bounds checks, escaping, validation,
               sandboxing, constant-time) without naming a vuln class.
  adjacent   - a vuln class is only mentioned in the body (e.g. a test that
               covers a UAF, or a refactor that removes `unsafe`).
"""
import json, re
from collections import Counter, defaultdict

DATA = "data/all_prs_raw.json"
OUT = "data/prs_classified.json"
W = re.I

# --------------------------------------------------------------- security ----
EXPLICIT_TITLE = [
    (r"\bCVE-\d{4}-\d{4,}\b", "cve-id"),
    (r"\bGHSA-[\w-]{8,}\b", "ghsa-id"),
    (r"\bsecurity (release|advisory|fix|issue|hole|vulnerability|update)\b", "security-advisory"),
    (r"^\W*(security|vulnerability)\b", "security-advisory"),
    (r"\bvulnerab\w+\b", "security-advisory"),
    (r"\bCWE-\d+\b", "cwe-id"),
    (r"\bexploit\w*\b", "exploit"),
    (r"\bmalicious\b", "malicious-input"),
]

VULN_CLASS_TITLE = [
    (r"\buse[- ]after[- ]free\b|\bUAF\b", "use-after-free"),
    (r"\bdouble[- ]free\b", "double-free"),
    (r"\bheap[- ]buffer[- ]overflow\b|\bstack[- ]buffer[- ]overflow\b", "buffer-overflow"),
    (r"\bbuffer (overflow|underflow)\b", "buffer-overflow"),
    (r"\bout[- ]of[- ]bounds\b|\bOOB\b", "out-of-bounds"),
    (r"\binteger overflow\b", "integer-overflow"),
    (r"\bmemory corruption\b", "memory-corruption"),
    (r"\bdangling\b", "dangling-pointer"),
    (r"\bnative stack overflow\b|\bstack overflow\b", "stack-exhaustion"),
    (r"\bprototype pollution\b", "prototype-pollution"),
    (r"\b(path|directory) traversal\b", "path-traversal"),
    (r"\bzip[- ]slip\b", "path-traversal"),
    (r"\brequest smuggling\b|\bdesync\b", "http-request-smuggling"),
    (r"\bcrlf injection\b|\bheader injection\b|\bheader splitting\b", "http-header-injection"),
    (r"\bcache poisoning\b", "cache-poisoning"),
    (r"\bopen redirect\b", "open-redirect"),
    (r"\bcommand injection\b", "command-injection"),
    (r"\bsql injection\b", "sql-injection"),
    (r"\b(remote|arbitrary) code execution\b|\bRCE\b", "rce"),
    (r"\bsandbox escape\b", "sandbox-escape"),
    (r"\bprivilege escalation\b", "privilege-escalation"),
    (r"\b(auth|authentication|authorization)\w* bypass\b", "auth-bypass"),
    (r"\bSSRF\b|\bCSRF\b|\bXXE\b|\bXSS\b", "web-vuln"),
    (r"\bdenial of service\b|\bDoS\b|\bReDoS\b", "denial-of-service"),
    (r"\bregex (denial|complexity)\b", "redos"),
    (r"\bquadratic\b|\bexponential\b.*\b(blowup|time)\b", "algorithmic-dos"),
    (r"\bsymlink\b.*\b(attack|escape|outside)\b", "symlink-attack"),
    (r"\btiming attack\b|\bconstant[- ]time\b", "timing"),
    (r"\bcertificate (validation|verification)\b|\bcert (validation|verification)\b", "tls-validation"),
    (r"\bTLS (downgrade|bypass)\b|\bverify.{0,10}\bcertificat\w+", "tls-validation"),
    (r"\binsecure deserialization\b", "unsafe-deserialization"),
    (r"\binsecure (default|random|permission|mode)\b", "insecure-default"),
    (r"\barbitrary (file|path|command|read|write|memory)\b", "arbitrary-primitive"),
    (r"\bworld[- ](readable|writable)\b", "insecure-permissions"),
    (r"\b(predictable|insecure) \w*(temp|tmp|random|token|nonce)", "insecure-randomness"),
    (r"\bleak\w* (secret|credential|token|password|memory)\b", "information-disclosure"),
    (r"\bsecret\b.*\b(expos|logged|printed|leak)", "information-disclosure"),
]

HARDENING_TITLE = [
    (r"\bmalformed\b", "malformed-input"),
    (r"\brefuse[sd]?\b.*\b(request|header|input|frame|message)\b", "input-rejection"),
    (r"\bbounds?[- ]check\w*\b", "bounds-check"),
    (r"\bvalidate\b|\bvalidation\b|\bvalidating\b", "validation"),
    (r"\bescap\w*\b.{0,40}\b(html|css|json|url|uri|shell|attr|attribute|output|control char|ansi|terminal|path)", "output-escaping"),
    (r"\b(html|css|json|url|shell|attr|attribute|ansi|terminal)\b.{0,40}\bescap\w+", "output-escaping"),
    (r"\bsanitiz\w+", "sanitization"),
    (r"\bhardening\b|\bharden\w*\b", "hardening"),
    (r"\bposix_spawn\b|\bexecve\b|\bshell=True\b", "process-exec"),
    (r"\bpermissions?\b.*\b(file|dir|mode|0o[0-7]+)\b", "file-permissions"),
    (r"\bcapabilit(y|ies)\b", "capabilities"),
    (r"\bsandbox\w*", "sandbox"),
    (r"\b(toctou|race condition)\b", "toctou"),
    (r"\bsymlink\b", "symlink"),
    (r"\bpath\b.*\b(escape|outside|traversal)\b", "path-escape"),
    (r"\buntrusted\b", "untrusted-input"),
    (r"\bdenial\b|\bexhaustion\b|\bunbounded\b", "resource-exhaustion"),
    (r"\b(header|url|uri|cookie|token|jwt|session|origin|cors)\b.*\b(parse|parsing|decode|validat)", "web-input-parsing"),
    (r"\b(4 ?GiB|overflow)\b.*\b(headers?|length|size)\b", "size-limit"),
]

ADJACENT_BODY = [
    (r"\bCVE-\d{4}-\d{4,}\b", "cve-id"),
    (r"\bGHSA-[\w-]{8,}\b", "ghsa-id"),
    (r"\bsecurity (release|advisory|fix|issue|hole|vulnerability)\b", "security-advisory"),
    (r"\b(vulnerab\w+) (in|with|that|where)\b", "security-advisory"),
    (r"\bexploitable\b|\bexploit(ed|able)? (the|this|a|it)\b", "exploit"),
    (r"\buse[- ]after[- ]free\b|\bUAF\b", "use-after-free"),
    (r"\bout[- ]of[- ]bounds (write|read|access)\b|\bOOB (write|read)\b", "out-of-bounds"),
    (r"\bheap[- ]buffer[- ]overflow\b|\bstack[- ]buffer[- ]overflow\b", "buffer-overflow"),
    (r"\bmemory corruption\b", "memory-corruption"),
    (r"\bprototype pollution\b", "prototype-pollution"),
    (r"\bpath traversal\b|\bdirectory traversal\b", "path-traversal"),
    (r"\brequest smuggling\b", "http-request-smuggling"),
    (r"\b(remote|arbitrary) code execution\b", "rce"),
    (r"\b(auth|authentication|authorization) bypass\b", "auth-bypass"),
    (r"\bprivilege escalation\b", "privilege-escalation"),
    (r"\bdenial of service\b|\bReDoS\b", "denial-of-service"),
    (r"\bSSRF\b|\bXSS\b|\bCSRF\b", "web-vuln"),
    (r"\btiming attack\b", "timing"),
]

# Reachability surface: where does the vulnerable code run?
SURFACE = [
    (r"\bfetch\b|Bun\.fetch|node:http|Bun\.serve|serve\b|websocket|webview|Bun\.serve|node:https",
     "network/server"),
    (r"\bbundler\b|transpil|js_parser|css|markdown|HTMLRewriter|bun build", "build/dev-toolchain"),
    (r"node:fs|Bun\.file|glob|tar|zip|install\b|extract|tarball", "filesystem/package-install"),
    (r"node:wasi|node:vm|bun:ffi|napi|WebAssembly|worker_threads", "native-boundary"),
    (r"\bsqlite\b|\bredis\b|\bsql\b|\bs3\b|postgres", "data-store"),
    (r"node:zlib|brotli|decompress|DecompressionStream|base64|simdutf|Bun\.Image|webp|jpeg|png",
     "binary-parsers"),
    (r"\btls\b|\bssl\b|BoringSSL|certificat|crypto|webcrypto|password|CSRF", "crypto/tls"),
    (r"\bshell\b|child_process|spawn|bunx|lifecycle script", "process-exec"),
]

# ------------------------------------------------------------------ types ----
PERF = [
    r"\bperf(ormance)?\b", r"\bfaster\b", r"\bspeed ?up\b", r"\bspeeds? up\b",
    r"\boptimi[sz]\w+", r"\breduce[sd]? (memory|allocations|the )\b", r"\bthroughput\b",
    r"\blatency\b", r"\bbenchmark", r"\bO\(1\)\b", r"\bzero[- ]copy\b",
    r"\bmemory (usage|footprint)\b", r"\bstartup time\b", r"\bno longer copies\b",
    r"\bavoid(s|ed)? (a |an |the )?(copy|alloc|allocat)\w*", r"\ballocat\w+ less\b",
    r"\b\d+(\.\d+)?\s?(x|×)\s?(faster|speedup|less)", r"\bcache[sd]?\b.*\b(hit|miss)\b",
    r"\bpool(s|ed)?\b", r"\bbatch\w*\b.*\b(request|write|read)\b", r"\bfewer\b.*\b(alloc|syscall|copy)",
]
FIX = [
    r"\bfix(es|ed|ing)?\b", r"\bno longer\b", r"\bregression\b", r"\bcrash(es|ed|ing)?\b",
    r"\bincorrect\w*\b", r"\bwrong\b", r"\bbug\b", r"\bcorrect(ly|s)?\b", r"\bhonou?r\b",
    r"\bpreserv", r"\bpropagat", r"\bhandle\w* (the )?(error|case|failure)\b",
    r"\bmismatch", r"\bundefined behavio\w+", r"\bleak(s|ed|ing)?\b", r"\bhang(s|ing)?\b",
    r"\bdeadlock\b", r"\brace condition\b", r"\bflak\w+", r"\blike node\b", r"\bas node does\b",
    r"\bpanic(s|ked)?\b", r"\bsegfault\b", r"\brefuse[sd]?\b", r"\bstop(s|ped)?\b",
    r"\binstead of\b", r"\bnever\b", r"\bkeep(s|ing)?\b", r"\bonly\b", r"\bnow\b",
    r"\bdoes not\b|\bdoesn'?t\b|\bdon'?t\b|\bcannot\b|\bcan'?t\b", r"\bavoid(s|ed)?\b",
    r"\bupdate[sd]?\b", r"\balign\w*\b", r"\breturn(s|ed)?\b", r"\bskip(s|ped)?\b",
    r"\bdrop(s|ped)?\b", r"\bclose[sd]?\b", r"\brelease[sd]?\b", r"\breset(s|ting)?\b",
    r"\bdefer\w*", r"\bwait(s|ing)? for\b", r"\btake[sd]?\b",
    r"\baccept(s|ed)?\b", r"\bremove[sd]?\b", r"\bresolve[sd]?\b", r"\bdetect(s|ed)?\b",
    r"\bframe[sd]?\b", r"\binherit\w*", r"\bemit(s|ted)?\b", r"\bindex\w*", r"\blink\w*",
    r"\bchoose[sd]?\b", r"\bsearch\w*", r"\bwait(s|ed)?\b", r"\bshow(s|n|ed)?\b",
    r"\binterrupt\w*", r"\bprint(s|ed)?\b", r"\blog(s|ged)?\b", r"\bread(s)?\b",
    r"\bwrite(s|n)?\b", r"\bgive[sd]?\b", r"\bstart(s|ed)?\b", r"\bbase[sd]?\b",
    r"\bquote[sd]?\b", r"\bcap(s|ped)?\b", r"\blimit(s|ed)?\b", r"\bguard(s|ed)?\b",
    r"\bcheck(s|ed)?\b", r"\breopen\w*", r"\bstat\b", r"\bsort\w*", r"\bround\w*",
    r"\bcompare[sd]?\b", r"\bpass(es)?\b", r"\battach\w*", r"\bpin(s|ned)?\b",
    r"\bfree[sd]?\b", r"\bbind(s|ing)?\b", r"\bpreload\w*", r"\bhoist\w*",
    r"\bunify\b", r"\bmatch(es|ed)?\b", r"\breplace[sd]?\b", r"\bignore[sd]?\b",
    r"\bdecide[sd]?\b", r"\bsize[sd]?\b", r"\bcount(s|ed)?\b", r"\bmap(s|ped)?\b",
]
FEATURE = [
    r"\badd(s|ed|ing)?\b", r"\bnew\b", r"\bsupport(s|ed|ing)?\b", r"\bimplement(s|ed|ing)?\b",
    r"\bintroduc\w+", r"\bexpose[sd]?\b", r"\ballow(s|ed)?\b", r"\benable[sd]?\b",
    r"\bfeature\b", r"\bAPI\b", r"\bflag\b", r"\boption\b", r"\bcommand\b",
]
REFACTOR = [
    r"\brefactor\w*", r"\bcleanup\b|\bclean up\b", r"\brename[sd]?\b", r"\bdedup\w*",
    r"\bsimplif\w+", r"\breorganiz\w+", r"\brewrite[sd]?\b", r"\bmigrat\w+",
    r"\binline[sd]?\b", r"\bmove[sd]? .* (to|into|out of)\b", r"\bmerge[sd]?\b",
    r"\bdelete[sd]? \w+", r"\bremove[sd]? the? \w+ (helper|wrapper|abstraction)",
    r"\bgenerated\b|\bcodegen\b|\bbindgen\b", r"\bunsafe\b.*\b(typed|ownership)\b",
]
CHORE_PREFIX = {"ci", "build", "deps", "bindgen", "chore", "clippy.toml", "release", "version",
                "dependabot", "repo", "lint", "format", "fmt"}

def norm_body(body):
    if not body:
        return ""
    b = body.replace("\r", "")
    b = re.sub(r"<!--.*?-->", " ", b, flags=re.S)
    return b

HDR = re.compile(
    r"^#{1,4}\s*(what|problem|summary|description|why|motivation|what does this pr do|"
    r"what this does|context|issue|background|what changed|overview|the problem|"
    r"what's the problem|description of the problem)\b", re.I)
STOP = re.compile(
    r"^#{1,4}\s*(how|test|verification|changes|fix|solution|implementation|notes|"
    r"checklist|screenshots|performance|benchmark|how did you verify|testing|rollback|"
    r"risk|compat|alternatives|downsides|background|details|appendix|other)\b", re.I)

def intent_section(body, limit=900):
    b = norm_body(body)
    if not b:
        return ""
    lines = b.split("\n")
    out, started = [], False
    for ln in lines:
        s = ln.strip()
        if HDR.match(s):
            started = True
            continue
        if started and STOP.match(s):
            break
        if started:
            out.append(ln)
        elif s and not s.startswith("#") and len(out) < 3:
            out.append(ln)
        if sum(len(x) for x in out) > limit:
            break
    txt = "\n".join(out).strip()
    return (txt or b.strip())[:limit]

def area_of(title):
    m = re.match(r"^([^:]{2,50}):\s", title)
    if m:
        a = m.group(1).strip()
        if len(a.split()) <= 5:
            return a
    return ""

def hits(pats, text):
    out = []
    for item in pats:
        pat, cls = item[0], item[1]
        if re.search(pat, text, W):
            out.append(cls)
    return out

def score(pats, text, w=1):
    n = 0
    for p in pats:
        if re.search(p, text, W):
            n += w
    return n

def classify(pr):
    title = pr["title"] or ""
    body = pr.get("body") or ""
    intent = intent_section(body)
    area = area_of(title)
    tl = title.lower()
    hay = title + "\n" + intent

    # ---- security tiers
    expl = hits(EXPLICIT_TITLE, title) + hits(EXPLICIT_TITLE, intent)[:2]
    vuln = hits(VULN_CLASS_TITLE, title)
    hard = hits(HARDENING_TITLE, title)
    adj = hits(ADJACENT_BODY, intent)

    if expl:
        tier = "explicit"
    elif vuln:
        tier = "vuln-class"
    elif hard:
        tier = "hardening"
    elif adj:
        tier = "adjacent"
    else:
        tier = ""

    classes = sorted(set(expl + vuln + hard + adj))
    surface = sorted({s for pat, s in SURFACE if re.search(pat, hay, W)})

    # ---- primary purpose
    is_docs = bool(re.match(r"^docs?\s*[:(\b]", tl)) or bool(re.match(r"^\W*docs?$", tl)) \
              or bool(re.search(r"\b(typo|documentation|readme)\b", tl))
    is_test = bool(re.match(r"^tests?\b", tl)) or area.lower() in ("test", "tests") \
              or bool(re.match(r"^\W*test\(([^)]*)\)", tl))
    is_chore = area.lower() in CHORE_PREFIX or bool(re.match(r"^(ci|build|deps|chore|bindgen|release)\b", tl))

    perf_n = score(PERF, title, 2) + score(PERF, intent, 1)
    fix_n = score(FIX, title, 2) + score(FIX, intent, 1)
    feat_n = score(FEATURE, title, 2) + score(FEATURE, intent, 1)
    ref_n = score(REFACTOR, title, 2) + score(REFACTOR, intent, 1)

    FEAT_T = re.compile(r"\b(adds?|added|adding|support(s|ed)?|implement(s|ed)?|introduc\w+|"
                        r"expose[sd]?|enable[sd]?|allow(s|ed)?|new\b|implements?)\b", re.I)
    FIX_T = re.compile(r"\b(fix(es|ed)?|crash\w*|no longer|wrong|incorrect\w*|regression|"
                       r"refuse[sd]?|instead of|doesn'?t|don'?t|never|panic\w*|segfault|"
                       r"hang(s|ing)?|leak(s|ed)?|broken|bug)\b", re.I)
    fallback = False
    feat_t = bool(FEAT_T.search(title))
    fix_t = bool(FIX_T.search(title))
    perf_t = score(PERF, title, 1) >= 1

    if is_docs and (tier != "explicit" or "typo" in tl):
        cat = "docs"
    elif is_test and tier not in ("explicit", "vuln-class"):
        cat = "test"
    elif is_chore:
        cat = "chore/ci/deps"
    elif tier in ("explicit", "vuln-class") and not is_docs:
        cat = "security"
    elif feat_t and not fix_t:
        cat = "feature"
    elif perf_t and not fix_t:
        cat = "performance"
    elif perf_n >= 3 and perf_n > fix_n and not fix_t:
        cat = "performance"
    elif fix_n >= 2:
        cat = "fix"
    elif ref_n >= 3 and ref_n >= fix_n:
        cat = "refactor"
    elif feat_t:
        cat = "feature"
    elif area or fix_n >= 1:
        cat = "fix"
        fallback = True
    else:
        cat = "other"

    tags = []
    tags_fallback = fallback
    if tier == "hardening" and cat != "security":
        tags.append("hardening")
    if perf_n >= 3 and cat != "performance":
        tags.append("perf")
    if feat_n >= 3 and cat != "feature":
        tags.append("feature-ish")
    if tags_fallback:
        tags.append("behavioural")

    sev = ""
    if tier == "explicit":
        sev = "high" if any(c in classes for c in ("cve-id", "ghsa-id", "exploit")) else "medium"
    elif tier == "vuln-class":
        if any(c in classes for c in ("rce", "auth-bypass", "privilege-escalation",
                                      "sandbox-escape", "command-injection", "sql-injection",
                                      "buffer-overflow", "use-after-free", "tls-validation")):
            sev = "high"
        else:
            sev = "medium"
    elif tier == "hardening":
        sev = "low"

    return {
        "category": cat,
        "area": area,
        "security_tier": tier,
        "security_classes": classes,
        "surface": surface,
        "severity_hint": sev,
        "tags": tags,
        "summary": re.sub(r"\s+", " ", intent).strip()[:600],
    }

def main():
    prs = json.load(open(DATA))
    out = []
    for pr in prs:
        out.append({**pr, **classify(pr)})
    json.dump(out, open(OUT, "w"), indent=1)

    print(f"total PRs: {len(out)}\n")
    print("primary category:")
    for k, v in Counter(p["category"] for p in out).most_common():
        print(f"  {k:16s} {v:5d}  {100*v/len(out):5.1f}%")
    print("\nsecurity tier:")
    for k, v in Counter(p["security_tier"] for p in out if p["security_tier"]).most_common():
        print(f"  {k:12s} {v:5d}")
    print("\nsecurity classes (all tiers):")
    for k, v in Counter(c for p in out for c in p["security_classes"]).most_common(28):
        print(f"  {k:26s} {v}")

if __name__ == "__main__":
    main()
