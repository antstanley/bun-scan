# Security deep dive — open oven-sh/bun PRs

**Snapshot:** 2026-10-22, ~09:30 UTC · 5,652 open PRs · Bun latest release **1.4.3** (2026-10-10)
**Local verification build:** Bun **1.4.0** (macOS arm64)

---

## Contents

1. [Summary for a reader in a hurry](#1-summary-for-a-reader-in-a-hurry)
2. [How I worked, and how much to trust each claim](#2-how-i-worked-and-how-much-to-trust-each-claim)
3. [Rating scale](#3-rating-scale)
4. [Findings at a glance](#4-findings-at-a-glance)
5. [F1 · Brotli decoder OOB write — CVE-2026-111497](#f1--brotli-decoder-oob-write--cve-2026-111497)
6. [F2 · HTMLRewriter `comment.text` is a sanitizer bypass](#f2--htmlrewriter-commenttext-is-a-sanitizer-bypass)
7. [F3 · `bun add <url>` inherits `trustedDependencies` trust](#f3--bun-add-url-inherits-trusteddependencies-trust)
8. [F4 · `URLPattern` polynomial backtracking](#f4--urlpattern-polynomial-backtracking)
9. [F5 · HTTP/2 CONTINUATION flood](#f5--http2-continuation-flood)
10. [F6 · Recursive `mkdir` follows a dangling symlink](#f6--recursive-mkdir-follows-a-dangling-symlink)
11. [F7 · `node:wasi` does not bound guest pointers](#f7--nodewasi-does-not-bound-guest-pointers)
12. [F8 · `Bun.cron()` predictable `/tmp` log path](#f8--buncron-predictable-tmp-log-path)
13. [F9 · `bun audit` fails open](#f9--bun-audit-fails-open)
14. [F10 · HTTP/2 client `originSet` grows without bound](#f10--http2-client-originset-grows-without-bound)
15. [F11 · QPACK header amplification — HTTP/3](#f11--qpack-header-amplification--http3-foxio)
16. [F12 · eMudhra intermediate CA compromise](#f12--emudhra-intermediate-ca-compromise)
17. [Everything else worth knowing](#17-everything-else-worth-knowing)
18. [Non-findings — things that look security-relevant and are not](#18-non-findings--things-that-look-security-relevant-and-are-not)
19. [The systemic finding](#19-the-systemic-finding)
20. [What I would do, in order](#20-what-i-would-do-in-order)

---

## 1. Summary for a reader in a hurry

Of 5,652 open PRs, **202 touch a security-relevant surface**. A hand-triage of all of
them leaves **11 that I would act on**, and of those only **two are remotely reachable
memory-safety or injection bugs in the default runtime**:

* **#46351 — brotli OOB write (CVE-2026-111497).** Remote, unauthenticated, memory
  corruption reachable through `fetch()` on any `Content-Encoding: br` response. **Every
  released Bun is affected.** Bun's `main` branch is already fixed — it bumped brotli to
  v1.2.1 on 2026-10-21, the same day Node shipped its own fix — but **1.4.3 still pins
  v1.2.0**. The gap is a release, not a patch. The PR itself is now largely redundant and
  should be closed or rewritten as a backport.
* **#42646 — `HTMLRewriter` comment setter is a sanitizer bypass.** `comment.text = s`
  rejects only `-->`; `--!>`, a leading `>` and `->` also end an HTML comment, so anything
  after them becomes live markup. I reproduced XSS on 1.4.0 in one line. **Still
  unfixed on `main`.**

The rest are real but narrower: a supply-chain trust confusion in `bun add`, a
polynomial-time `URLPattern`, an HTTP/2 CONTINUATION flood, a symlink-following write on
macOS, WASI hostcall bounds checking, a predictable `/tmp` path in `Bun.cron()`, and two
ways `bun audit` reports "clean" when it is not.

**Two more findings came from outside the queue.** The FoxIO QPACK amplification attack
(F11) and the eMudhra CA compromise (F12) were both published on 2026-10-20 naming Bun as
unpatched. Both are real, both are fixed on `main`, and both are in **no release**.

The most striking finding is structural: **84 of the 202 security PRs no longer apply to
`main`**, four are mergeable and clean, the median security PR has been open for
**68 days** — and three high-profile fixes (F1, F11, F12) are sitting on `main` waiting for
a release. The queue and the release channel, not the bugs, are the bottleneck.

---

## 2. How I worked, and how much to trust each claim

**Candidate selection.** I pulled all 5,652 open PRs and classified each one against a
vocabulary of vulnerability classes, CVE/GHSA identifiers and hardening signals, scoring
the title above the body so that a passing mention of "use-after-free" in a long
description does not create a finding. That produced 202 candidates in four tiers
(`explicit`, `vuln-class`, `hardening`, `adjacent`) — the full list is in
[`03-security-triage.md`](03-security-triage.md).

**Then I read them.** Every `explicit` and `vuln-class` PR got read in full, plus the
`adjacent` tier. For the findings below I read the diff where it mattered.

**Then I checked the claims against reality.** PR descriptions are written by the same
agents that write the code, and several of them turned out to be stale or wrong. For each
finding I tried to answer: *is this live on `main` today, and is it live in the release
users actually run?*

| Check | Method | Result |
|---|---|---|
| CVE-2026-111497 is real and Node shipped it | GitHub release notes for Node v22.23.4 / v24.22.1 / v26.12.1 | Confirmed — both commit `67d294739f` and the `BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH` constant are in Node's 2026-10-21 security release |
| Does brotli v1.2.1 (main's pin) contain the fix? | fetched `c/dec/decode.c` at tag v1.2.1 | **Yes** — `BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH` and `BROTLI_SAFE_WITH_STATUS` are present; the vulnerable `static void` wrappers are gone |
| Does Bun 1.4.3 contain it? | `scripts/build/deps/brotli.ts` at tag `bun-v1.4.3` | **No** — pins v1.2.0 (`028fb5a2`) and has no `patches/brotli` |
| HTMLRewriter liveness on `main` | `scripts/build/deps/lolhtml.ts` on main | **Unfixed** — main pins `725ce499`, the pre-fix commit this PR replaces |
| `Bun.cron` `/tmp` on `main` | `src/runtime/api/cron.rs` | **Unfixed** — `/tmp/bun.cron.{0}.stdout.log` still there |
| WASI bounds checks on `main` | `src/js/node/wasi.ts` | **Unfixed** — still `console.warn("WASI.getiovs -- invalid buffer", err)` |
| `bun audit` severity default on `main` | `CommandLineArguments.rs` | **Unfixed** — `AuditLevel::from_string(severity).unwrap_or(AuditLevel::Moderate)` |
| duplicate `Host` on `main` | `packages/bun-uws/src/HttpParser.h` | **Unfixed** — no duplicate-Host check exists |
| CVE-2024-45296 severity | GitHub advisory database | 7.5 High, `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` — the benchmark for F4 |
| QPACK amplification live in 1.4.3? | `quic.c` at tag `bun-v1.4.3` vs `main` | **Vulnerable in 1.4.3** (advertises `es_max_header_list_size`, never enforces); **fixed on `main`** (cumulative `h->size` + 200-field cap) |
| eMudhra distrust in 1.4.3? | `blocked_spkis.cpp` at tag `bun-v1.4.3` vs `main` | **Absent in 1.4.3**; **8 eMudhra SPKIs on `main`** |

**And I ran them.** Bun 1.4.0 was installed locally, so six of the findings below are
backed by a proof of concept I executed, not just by the PR text. The PoCs are in
[`../poc/`](../poc/) and their output is quoted inline.

**Confidence.** I mark each finding `verified` (reproduced or confirmed in source),
`confirmed` (source and dependency state confirmed, exploit not run), or
`author-reported` (I could not independently check it). I have not audited Bun's memory
safety in general; this is an assessment of what the open PRs say, validated against
the tree.

---

## 3. Rating scale

CVSS 3.1, computed for the realistic attack path rather than the worst case. Where the
number and the practical rating disagree I say why.

| Rating | Meaning |
|---|---|
| **Critical** | Remote, unauthenticated memory corruption in a default-on path. Patch now. |
| **High** | Remote exploitation with real impact — RCE, XSS in a privileged app, whole-server DoS, supply-chain code execution — but a narrower path. |
| **Medium** | Local, conditional or limited exploitation, or a security control that fails open. |
| **Low** | Theoretical, developer-controlled input, latent bug with no known trigger, or defence in depth. |

A note on what "remote" means here. Bun is unusual: the same binary is a server runtime,
a package manager, a bundler and a test runner, and it ships a JS engine. A bug in
`fetch()` runs in every app that makes an outbound request; a bug in `bun audit` runs in
CI. I have treated **supply-chain and developer-tooling bugs as production issues**,
because that is where Bun is used.

---

## 4. Findings at a glance

| # | PR | Finding | Class | CVSS | Live on `main`? | In 1.4.3? | Confidence |
|---|---|---|---|---|---|---|---|
| F1 | [#46351](https://github.com/oven-sh/bun/pull/46351) | brotli decoder OOB write | CWE-787 | **8.1 High** | No (fixed 10-21) | **Yes** | verified |
| F2 | [#42646](https://github.com/oven-sh/bun/pull/42646) | `HTMLRewriter` comment sanitizer bypass → XSS | CWE-79 | **6.1 Med** (8.0 in a privileged app) | **Yes** | **Yes** | verified |
| F3 | [#45204](https://github.com/oven-sh/bun/pull/45204) | `bun add <url>` inherits `trustedDependencies` trust | CWE-829 | **7.1 High** | **Yes** | **Yes** | confirmed |
| F4 | [#42535](https://github.com/oven-sh/bun/pull/42535) | `URLPattern` polynomial backtracking | CWE-1333 | **7.5 High** | **Yes** | **Yes** | verified |
| F5 | [#36410](https://github.com/oven-sh/bun/pull/36410) | HTTP/2 CONTINUATION flood | CWE-400 | **7.5 High** | **Yes** | **Yes** | confirmed |
| F6 | [#38298](https://github.com/oven-sh/bun/pull/38298) | recursive `mkdir` follows a dangling symlink | CWE-59 | **5.9 Med** | **Yes** | **Yes** | verified |
| F7 | [#34468](https://github.com/oven-sh/bun/pull/34468) | `node:wasi` unbounded guest pointers | CWE-787/CWE-20 | **5.5 Med** | **Yes** | **Yes** | verified |
| F8 | [#29144](https://github.com/oven-sh/bun/pull/29144) | `Bun.cron()` predictable `/tmp` log path | CWE-377 | **5.0 Med** | **Yes** | **Yes** | confirmed |
| F9 | [#45668](https://github.com/oven-sh/bun/pull/45668) + [#46143](https://github.com/oven-sh/bun/pull/46143) | `bun audit` fails open / reports clean on unchecked packages | CWE-636 | control bypass | **Yes** | **Yes** | confirmed |
| F10 | [#42411](https://github.com/oven-sh/bun/pull/42411) | HTTP/2 client `originSet` unbounded | CWE-400 | **6.5 Med** | **Yes** | **Yes** | author-reported |
| F11 | [#46392](https://github.com/oven-sh/bun/pull/46392) + [#46436](https://github.com/oven-sh/bun/pull/46436) | QPACK header amplification, HTTP/3 (FoxIO) | CWE-400 | **7.5 High** | No (fixed 10-22) | **Yes** | verified |
| F12 | [#46300](https://github.com/oven-sh/bun/pull/46300) | eMudhra intermediate CA compromise — no distrust list | CWE-295 | **8.7 High** | No (fixed 10-21) | **Yes** | verified |
| — | [#33191](https://github.com/oven-sh/bun/pull/33191) | node:http/http2 hardening bundle | mixed | varies | partially | — | confirmed |

---

## F1 · Brotli decoder OOB write — CVE-2026-111497

> **PR [#46351](https://github.com/oven-sh/bun/pull/46351)** · `explicit` · open, mergeable, CI-blocked · 6 files, +266 · **CVSS 8.1 High**

### The bug

Bun links brotli for `Content-Encoding: br` decompression. In the decoder's fast path,
`Decode{Literal,Command,Distance}BlockSwitch` were declared `static void` — they threw
away the result of `DecodeBlockTypeAndLength`. When a stream declares a single block type
and then switches blocks anyway, the block-type decode fails, the failure is discarded,
and decoding continues with an inconsistent block-type ring buffer. From there the
decoder indexes its huffman and context-map tables with a stale block type: an
out-of-bounds write, in code that is parsing attacker-supplied bytes by definition.

Upstream's fix (`google/brotli@0ed4268a`, "Detect and report invalid stream earlier")
makes those functions return a status and propagates it, so the stream fails with
`BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH` (-17, previously a reserved code).

### Reach

This is the widest blast radius of anything in the queue:

* `fetch()` on **any** response carrying `Content-Encoding: br` — on by default, and the
  server chooses the encoding.
* `node:zlib` brotli APIs (`brotliDecompress*`).
* `DecompressionStream("brotli")`.

No authentication, no user interaction, no special configuration. The attacker is any
server the application talks to, or anyone who can hand the app a compressed blob.

### Severity

`CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H` = **8.1 High**.

`AC:H` rather than `AC:L` because, while the invalid stream is easy to construct, turning
an inconsistent block-type state into a *controlled* write requires heap grooming; the
PR's own test vector demonstrates the state confusion, not a weaponised write. **If
someone demonstrates a controllable write, this is 9.8.** I am deliberately scoring the
class of bug (heap OOB write on remote input), not a proven exploit.

By the action rating in §3 this is **Critical** — remote, unauthenticated memory
corruption in a default-on path, shipped to every user — even though the numeric score is
8.1, because exploitation is not a one-liner. That is the one place in this report where
the label and the number deliberately differ.

### What I verified — and the surprise

The PR says `main` builds brotli v1.2.0. **That is out of date.** While I was working,
`main` moved to **v1.2.1**, tagged 2026-10-21 — and v1.2.1 already contains the fix:

```
$ grep -n "BROTLI_SAFE_WITH_STATUS\|BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH" decode.c   # at v1.2.1
1968:#define BROTLI_SAFE_WITH_STATUS(METHOD) ...
2021:    BROTLI_SAFE_WITH_STATUS(DecodeCommandBlockSwitch(s));
2360:  BROTLI_SAFE_WITH_STATUS(DecodeLiteralBlockSwitch(s));
```

The vulnerable `static void BROTLI_NOINLINE DecodeLiteralBlockSwitch` no longer exists at
v1.2.1. Meanwhile, the **release** users run is still exposed:

| Tree | brotli pin | Status |
|---|---|---|
| `main` | v1.2.1 (`db24a98a`) | **fixed** |
| `bun-v1.4.3` (latest release) | v1.2.0 (`028fb5a2`) | **vulnerable** |
| 1.4.2 and earlier | v1.1.0 | **vulnerable** |
| local Bun 1.4.0 | — | vulnerable: `zlib.constants.BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH` is `undefined`, while `..._BLOCK_LENGTH_1` is `-9` |

The "1.4.2 and earlier" row is the PR's claim, not mine; my 1.4.0 build is consistent with
it (no `-17` constant), but I did not check every tag.

Node's side checks out independently: v22.23.4 / v24.22.1 / v26.12.1, all published
**2026-10-21**, list `deps: brotli: cherry-pick 0ed4268a4401abcb44720963` under
CVE-2026-111497, merged through `nodejs-private/node-private#1002` — i.e. handled as an
embargoed security issue.

### Assessment

The vulnerability is real, remote and shipped. **The correct action is not to merge this
PR** — it would apply a patch for a fix that is already in the pinned version — **but to
get v1.2.1 (or the patch) into a 1.4.x release.** As of this snapshot, `bun upgrade` to
1.4.3 leaves a user exploitable, and nothing in the release channel says so.

The PR is `blocked` on CI: per its own description it sits on a fork branch and needs a
maintainer to unblock Buildkite. It has one comment and no review after a day.

---

## F2 · HTMLRewriter `comment.text` is a sanitizer bypass

> **PR [#42646](https://github.com/oven-sh/bun/pull/42646)** · `explicit` · open, mergeable, CI-blocked · 2 files, +34/-1 · **CVSS 6.1 Med, 8.0 in a privileged app**

### The bug

`HTMLRewriter`'s comment setter rejects text containing `-->`, and throws a clear error
saying so — the API is explicitly trying to stop you from writing markup through a
comment. But the HTML tokenizer ends a comment in four places, not one:

| Sequence | Spec state |
|---|---|
| `-->` | comment end → emits the comment |
| `--!>` | comment end bang → "incorrectly closed comment" |
| `>` at the very start | comment start → "abrupt closing of empty comment" |
| `->` at the very start | comment start dash → same |

Only the first was rejected. With any of the other three, everything after the sequence
is **live markup**, and the trailing `-->` that the rewriter appends only comments out
whatever the attacker leaves at the end.

Upstream lol-html fixed this in `ba25359` and shipped it as a security fix in v3.0.0.
Bun's `main` still pins the pre-fix commit `725ce499`.

### Reproduction (Bun 1.4.0, this machine)

```js
const set = s => new HTMLRewriter().on("p", { comments(c) { c.text = s; } })
                                   .transform("<p><!--c--></p>");
set("x--><img src=x onerror=alert(1)>");   // throws  ✔
set("x--!><img src=x onerror=alert(1)>");  // NO THROW
```

```
threw   : "x--><img src=x onerror=alert(1)>" -> Comment text shouldn't contain comment closing sequence (`-->`).
NO THROW: "x--!><img src=x onerror=alert(1)>" => <p><!--x--!><img src=x onerror=alert(1)>--></p>
NO THROW: "><img src=x onerror=alert(1)>"     => <p><!--><img src=x onerror=alert(1)>--></p>
NO THROW: "-><img src=x onerror=alert(1)>"    => <p><!---><img src=x onerror=alert(1)>--></p>
```

That output *looks* like a comment, so I re-parsed it to check the injection is real
markup rather than text:

```
rewritten: <p><!--x--!><img src=x onerror=alert(1)>--></p>
elements parsed out of it: [ "p", "img" ]
comments: [ "x" ]
>>> injected markup is LIVE (img element)
```

The `img` element is real. In a browser that document runs `alert(1)`; with a real
handler it is XSS.

### Who is exposed

Apps that use `HTMLRewriter` to rewrite or sanitize HTML containing user-controlled
text — comment bodies are an obvious case, since a "comment" in a CMS or forum is exactly
the thing you would pipe into `comment.text`. The pre-existing `-->` check signals that
this is a supported pattern; the API intends to be safe and is not.

An app that never assigns attacker data to `comment.text` is not affected.

### Severity

`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` = **6.1 Medium** as a library weakness —
classic reflected/stored XSS in a downstream app, with scope change because the script
runs in the app's origin. In a privileged console (admin panel, internal tool) the same
bug is an **8.0**.

I am calling this High in the summary because of *what it defeats*: it is not a missing
feature, it is a bypass of a check that exists specifically to prevent this. Sanitizer
bypasses are the class of bug where downstream assumptions are load-bearing.

### Status

Unfixed on `main`. The fix is a two-line dependency pin bump (plus tests). This is the
cheapest high-value merge in the entire queue.

---

## F3 · `bun add <url>` inherits `trustedDependencies` trust

> **PR [#45204](https://github.com/oven-sh/bun/pull/45204)** · `explicit` · open, **conflicts with main** · 9 files, +819/-25 · **CVSS 7.1 High**

`trustedDependencies` is Bun's allow-list for lifecycle scripts: a package on the list
may run `postinstall`, everything else may not. The check is by **name**.

`bun add <URL | path | git URL>` with no explicit name creates a lockfile entry named
after the package's own `package.json`. That name is then matched against the
`trustedDependencies` list. So:

```sh
mkdir -p app/vendor && cd app
echo '{"name":"pub","version":"1.0.0","scripts":{"postinstall":"echo ran > ran.txt"}}' > vendor/package.json
echo '{"name":"app","trustedDependencies":["pub"]}' > package.json
```

`bun add ./vendor` now runs `pub`'s `postinstall` — the package was never vetted, it just
chose the name of something that was. The PR's repro runs the same on 1.4.0 through
1.4.2.

**Why it matters:** the trust list encodes "I have reviewed `pub` and I allow its
scripts". Adding an arbitrary URL is a different decision, and it silently inherits the
first one. This is the same shape as pnpm's GHSA-5wx6-mg75-v57r, which the PR cites.

**Severity:** `AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H` = **7.1 High**. `AC:H`/`UI:R`
because the developer must run `bun add` against an attacker-controlled source — but that
is exactly the social-engineering path ("try this fork of sharp"), and the delta between
"install a package" and "execute its code" is the whole point of the trust list.

**Status:** the PR conflicts with `main` and needs a rebase. It also asks the maintainers
a design question (refuse the add, or stop a bare name from covering folder/tarball/git
packages — the pnpm precedent). Worth deciding, because this is the highest-impact
supply-chain item in the queue.

---

## F4 · `URLPattern` polynomial backtracking

> **PR [#42535](https://github.com/oven-sh/bun/pull/42535)** · `explicit` · open, **conflicts with main** · 3 files, +255/-2 · **CVSS 7.5 High**

`URLPattern` compiles a pattern with several named groups in one segment into a regular
expression with adjacent groups. Matching a path that **fails** explores the
combinatorial space of where each group can end. Same class as CVE-2024-45296 in
path-to-regexp — which GitHub scores **7.5 High**.

### Reproduction (Bun 1.4.0, this machine)

Pattern `/:owner-:repo-:ref`, non-matching pathnames of increasing length:

| pathname length | time |
|---|---|
| 258 | 0.7 ms |
| 514 | 6.2 ms |
| 1026 | 50.8 ms |
| 2050 | 393.0 ms |

8× the input, 560× the time — worse than quadratic in this range. Extrapolating to the
PR's numbers (3.3 s at 4 KB, ~30 s at 8 KB) is consistent: a 4 KB URL costs seconds of
uninterruptible JS-thread time, and an 8 KB URL costs tens of seconds.

**Severity:** `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` = **7.5 High** for any app routing on
attacker-controlled paths with such a pattern. One request per core stalls the whole
server, since the work is on the JS thread with no yield.

**Caveat:** the pattern must have adjacent named groups separated by literals
(`/:owner-:repo-:ref`), which is idiomatic for GitHub-style routes but not universal.

**Status:** conflicts with `main`.

---

## F5 · HTTP/2 CONTINUATION flood

> **PR [#36410](https://github.com/oven-sh/bun/pull/36410)** · `explicit` · open, mergeable, CI-blocked · 5 files, +335/-1 · **CVSS 7.5 High (availability only)**

`node:http2` limits a header block by **bytes** but not by **frame count**. A peer sends
`HEADERS` without `END_HEADERS`, then unlimited `CONTINUATION` frames, and the session is
held open indefinitely. This is CVE-2024-28182, which Node fixed by capping at 8
CONTINUATION frames; Bun never picked up the cap.

**Reach:** `node:http2` servers and clients. **`Bun.serve` is not affected** — it uses
uWS, not this engine — which materially narrows the exposure.

**Severity:** `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` = **7.5**, availability only. That is
the arithmetic ceiling for a pure DoS, and I think it overstates this one: the impact is
per-connection stalling rather than memory exhaustion, and a reverse proxy with its own h2
limits may absorb it. **Medium-High** in practice.

**Status:** mergeable, CI-blocked. The PR is thorough — it includes a comparison table
against Node v26.3.0 across seven frame sequences, and correctly notes the one place it
intentionally differs from Node (RFC 9113 requires `PROTOCOL_ERROR` where nghttp2 sends
`INTERNAL_ERROR`).

---

## F6 · Recursive `mkdir` follows a dangling symlink

> **PR [#38298](https://github.com/oven-sh/bun/pull/38298)** · `vuln-class` · open · 4 files, +166/-9 · **CVSS 5.9 Medium**

`mkdir_recursive_os_path_impl` hands the caller's string to `mkdir(2)` verbatim. On
BSD-derived kernels (macOS, FreeBSD), POSIX pathname resolution follows a symlink in the
**last** component when a slash follows it — so `mkdir("dangling/")` creates the *target*
of `dangling`, even if that target does not exist. Linux returns `EEXIST` instead, which
is why this is platform-specific.

`Bun.write("dangling//f.txt", data)` derives the parent as `"dangling/"` via `dirname`,
which keeps separator runs by contract. Result: the write lands outside the intended
directory.

### Reproduction (macOS, Bun 1.4.0, this machine)

```sh
mkdir d && cd d && ln -s missing dangling
bun -e 'await Bun.write("dangling//f.txt","pwned")'
```

```
before:   dangling@
returned OK
after:    dangling@  missing/
inside missing/: f.txt  ->  "pwned"
```

`missing/` was created and `missing/f.txt` written through the link. The equivalent with
a single slash fails with `ENOENT`, as does Node on both spellings.

**Impact:** a write primitive outside the intended directory, on macOS/FreeBSD only,
requiring the attacker to have planted a dangling symlink in a directory the app writes
into. That combination is exactly the shape of an upload/extraction directory, a shared
`/tmp` work dir, or a multi-tenant storage root.

**Severity:** `AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:N` = **5.9 Medium**. `AC:H` and `PR:L`
because of the symlink precondition; the impact is arbitrary file write, which in a
server context is one step from code execution (write a config, a cron file, a plugin).

**Status:** open, not conflicting. Sibling PRs #38097 (`fs.cp`) and #38146 (`fs.mkdir`
error reporting) are part of the same knot and should land together.

---

## F7 · `node:wasi` does not bound guest pointers

> **PRs [#34468](https://github.com/oven-sh/bun/pull/34468), [#39100](https://github.com/oven-sh/bun/pull/39100), [#40654](https://github.com/oven-sh/bun/pull/40654), [#34475](https://github.com/oven-sh/bun/pull/34475)** · `vuln-class`/`hardening` · all open · **CVSS 5.5 Medium**

WASI exists to run untrusted code with a restricted capability set. Its hostcalls take
guest pointers as `i32` offsets into linear memory, and the host is supposed to validate
them. Bun's `getiovs()` does not check the iovec array pointer, `buf + len`, or the
output pointer.

### Reproduction (Bun 1.4.0, this machine)

```js
wasi.wasiImport.fd_write(2, 65534, 1, 256);         // iovec array wholly out of bounds
```

```
RangeError: Out of bounds access
    at getiovs (node:wasi:310:49)
```

A JS exception escapes into the **host** program, where the WASI contract says a hostcall
returns an errno (`EOVERFLOW`, 61, as Node does). Worse, with a valid iovec array and an
out-of-bounds `buf`:

```
{ buf: 65530, bufLen: 4096, total_memory: 65536 }      <-- printed to the host's stdout
fd_write with OOB buf -> 0                              <-- success
```

Bun **prints an internal debug object to the host's stdout** (leaking `total_memory`, and
the layout of the guest's memory region into whatever collects stdout), **truncates the
buffer, performs the I/O anyway, and returns success**. The PR additionally documents
`path_open` opening a file and registering a descriptor *before* failing on the output
pointer — one leaked host descriptor per call — and `fd_seek`/`fd_tell` mutating state
before failing.

**Why it is not worse:** JSC bounds-checks the `Uint8Array` construction, so this is not a
host-memory OOB read/write; it is a broken sandbox contract, an fd leak and an
information disclosure. That is still the one thing WASI must not do.

**Severity:** `AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N` = **5.5 Medium** — but for a plugin
host that runs uploaded `.wasm`, this is the **highest-priority item in the queue after F1
and F2**, because the threat model *is* the untrusted guest.

**Status — and a process problem.** Four overlapping PRs cover one fix: #34468 (iovecs and
the calls with side effects), #39100 (bounds-check every hostcall), #40654 (memory-view
refresh, `fd_seek`, symlink policy), #34475 (option validation, `start()`/`initialize()`).
They are written as a series but were opened months apart and each says the others cover
the remainder. Nobody can merge them independently; this needs one owner and one PR.

---

## F8 · `Bun.cron()` predictable `/tmp` log path

> **PR [#29144](https://github.com/oven-sh/bun/pull/29144)** · `explicit` · open · 7 files, +263/-73 · **CVSS 5.0 Medium**

`Bun.cron()` on macOS writes a launchd plist whose `StandardOutPath` and
`StandardErrorPath` are `/tmp/bun.cron.<title>.{stdout,stderr}.log`. `/tmp` is
world-writable and the name is fully predictable from the job title (CWE-59 / CWE-377).

A second local user pre-creates that path as a symlink to a file the victim can write,
and launchd — running as the victim — opens and appends through it. That yields an
**append-to-any-file-the-victim-can-write** primitive on a multi-user Mac, with contents
the attacker partly controls if they can influence the job's output.

**Verified on `main`:** `src/runtime/api/cron.rs` still contains
`<string>/tmp/bun.cron.{0}.stdout.log</string>`.

**Severity:** `AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:N` = **5.0 Medium**. Local, multi-user,
macOS-only, append-only — but "append bytes to a file of my choosing" reaches
`~/.ssh/authorized_keys`, shell rc files and launch agents, so the ceiling is code
execution as the victim.

**Fix:** the PR moves the paths to `~/Library/Logs/bun/cron/`. Small, self-contained,
open since March.

---

## F9 · `bun audit` fails open

> **PRs [#45668](https://github.com/oven-sh/bun/pull/45668) and [#46143](https://github.com/oven-sh/bun/pull/46143)** · `explicit` · open · **security-control bypass**

Two independent ways `bun audit` tells you a project is clean when it is not.

**#45668 — unknown severity is ranked "moderate".** On `main`:

```rust
let severity_level = AuditLevel::from_string(severity).unwrap_or(AuditLevel::Moderate);
```

An advisory with `severity: "HIGH"` (uppercase — legitimate free text from the registry),
any unfamiliar word, or a missing severity is silently ranked *moderate*, so
`bun audit --audit-level=high` **exits 0** and prints "No vulnerabilities found". A
security gate in CI passes. The PR makes an unranked advisory fail closed.

**#46143 — tarball and git packages are skipped entirely.** These lockfile rows have no
version, so `collect_packages_for_audit` skips them and `bun audit` reports
`No vulnerabilities found (checked 0 packages)` with exit 0. If your dependencies come
from git or tarballs — common for private registries and vendored forks — the audit
covered nothing.

**Severity:** no clean CVSS, because the impact is indirect: it is a **CWE-636 (fails
open)** in a control that organizations put in front of production. I would treat it as
**Medium**, and as *High* for anyone whose CI gate is `bun audit --audit-level=high`
without also reading the output.

**Status:** #45668 is mergeable/CI-blocked; #46143 conflicts and is a draft, and it is
large (+4,098/-2,405 across 39 files) because it changes the lockfile format — so the
cheap half of the problem is the one that is ready.

---

## F10 · HTTP/2 client `originSet` grows without bound

> **PR [#42411](https://github.com/oven-sh/bun/pull/42411)** · `explicit` · open · 6 files, +209/-8 · **CVSS 6.5 Medium**

A `node:http2` **client** appends every origin of every inbound `ORIGIN` frame to
`session.originSet` with no limit. A malicious TLS server can send `ORIGIN` frames for the
life of the session and grow client memory without bound. Node capped this at
`maxOriginSetSize` in 26.4.0; Bun has no cap.

**Severity:** `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` = **6.5 Medium** — network, low
complexity, but requires the attacker to be the *server* the client chose to talk to, and
memory growth is slow.

**Confidence: author-reported.** I confirmed the PR is open and mergeable and read the
description, but did not reproduce the growth.

---

## F11 · QPACK header amplification — HTTP/3 (FoxIO)

> **PRs [#46392](https://github.com/oven-sh/bun/pull/46392) + [#46436](https://github.com/oven-sh/bun/pull/46436)** · **both merged 2026-10-22** · not open · **CVSS 7.5 High (availability only)**

*Published as [Header Accordions: QPACK amplification attacks against HTTP/3 servers](https://foxio.io/blog/header-accordions-qpack-amplification-attacks-against-http-3-servers), FoxIO, 2026-10-20. Bun reported 2026-05-24.*

### The attack

QPACK compresses HTTP/3 header fields. A dynamic-table entry of ~4 KiB can be referenced
by a **1-byte** indexed reference, and each reference materializes a fresh copy of the full
entry in memory. One connection, 100 streams, ~60,000 references per stream — 5.8 MiB of
wire — is enough to OOM-kill a 2 GiB container. Measured amplification against Bun: **~4000×**.

The defence RFC 9114 §4.2.2 describes is a **cumulative** budget over the decoded field
list — name + value + **32 bytes of overhead per field** — enforced as fields are decoded
and retained. Not a per-field size check, and not a check on the compressed frame.

### Verified against the source

**1.4.3 is vulnerable.** `packages/bun-usockets/src/quic.c` at tag `bun-v1.4.3` advertises
the limit and never reads it back — there is no byte accounting, no field counter, no cap:

```
$ gh api ".../quic.c?ref=bun-v1.4.3" -q .content | base64 -d | grep -nE "h->size|max_fields|es_max_header_list_size"
838:  ctx->settings.es_max_header_list_size = 16 * 1024;
1382: ctx->settings.es_max_header_list_size = 64 * 1024;
```

**`main` is fixed.** The same function now accumulates per §4.2.2 and enforces it:

```c
h->size += (size_t) hdr->name_len + hdr->val_len + 32;   /* the 32-byte overhead */
h->fields++;
if (h->size > h->max_size || h->fields > h->max_fields) { ... }
```

with `max_fields = US_QUIC_MAX_REQUEST_FIELDS` (200) for a server and a hard cap at
`2 × max_size`. FoxIO's second finding — an `unsigned int` capacity counter that wraps
when doubled — is gone too: `ncap` is a `size_t` bounded by `hard_cap` before narrowing.

### The fix

[#46392](https://github.com/oven-sh/bun/pull/46392) (2026-10-22 02:13Z): *"header size
limits are now enforced, counted as in RFC 9114 §4.2.2. The server enforces the limit it
advertises (16 KB by default) and answers `431` to a request over it… A request may have
200 fields."* [#46436](https://github.com/oven-sh/bun/pull/46436) (04:18Z) then lifts
lsquic's own 64 KB internal caps while explicitly leaving those limits in place.

With a 16 KB cumulative budget, the 4 KiB entry referenced 60,000 times is refused around
the fourth reference.

### Exposure and severity

Only apps that opt in to the HTTP/3 server (`Bun.serve({ http3: true })`) or the HTTP/3
client (`fetch` with `protocol: "http3"`) are in the path. That is narrower than F1.

`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` = **7.5**, availability only — the
arithmetic ceiling for a pure DoS, and it overstates this one somewhat, since the listener
is opt-in and a proxy can absorb it. For anyone actually running `http3: true` on an
untrusted network I would treat it as **High**: one connection, no authentication, and the
outcome is an OOM kill rather than a slowdown.

### Status

**Fixed on `main`, in no release.** On 1.4.3, FoxIO's mitigation is the right one: do not
expose an HTTP/3 server until a release contains #46392.

---

## F12 · eMudhra intermediate CA compromise

> **PR [#46300](https://github.com/oven-sh/bun/pull/46300)** · **merged 2026-10-21** · not open · **CVSS 8.7 High**

*Public advisory: [emudhra.we-have-a-problem.com](https://emudhra.we-have-a-problem.com/), 2026-10-20.*

### What happened

Eight eMudhra (emSign) **intermediate** CA private keys are compromised, and the cause is
not a leak — per the advisory, *"the private keys for the intermediate certificates were
incorrectly generated by the CA. This means that anyone can recover them from the
certificates."* They chain to roots trusted by the Mozilla, Microsoft, Apple and Chrome
programs, and have been recoverable since April 2025.

Anyone holding those keys can issue a certificate for **any domain** and have it verify
against any client that still trusts the intermediates.

### Why a runtime client is the exposure

Browsers were protected from 2026-10-17 by revocation infrastructure (OneCRL, CRLite,
CRLSets), and the advisory notes CT logs hold no entries for these intermediates in the
period — so CT-enforcing clients could not have been attacked. **Bun enforces neither
revocation nor Certificate Transparency** (there is no SCT checking in the verify path),
and by default it verifies against its own **bundled** root store, not the OS store.
Non-browser clients are exactly the population this advisory is about.

### Verified against the source

**1.4.3 is vulnerable.** `blocked_spkis.cpp` does not exist at tag `bun-v1.4.3`, and the
bundled roots are NSS 3.128 (#42835, 2026-09-16) — so nothing in 1.4.3 can express
"distrust this intermediate".

**`main` is fixed.** [#46300](https://github.com/oven-sh/bun/pull/46300), merged
2026-10-21 07:50Z — *"tls: reject chains containing blocked public keys, update root
certificates to NSS 3.131.1"* — adds a compiled-in SPKI list that fails verification with
`CERT_REVOKED`, and regenerates the bundle from NSS 3.131.1 (118 certificates, the same
set as Node's, compared by SHA-256).

The list is exactly **8 hashes**, and the comments name them:

```
C=US, O=eMudhra Inc, CN=EM DV TLS CA - G3C      C=NL, O=eMudhra BV, CN=EM DV TLS CA - G3B
C=US, O=eMudhra Inc, CN=EM EV TLS CA - G3C      C=NL, O=eMudhra BV, CN=EM EV TLS CA - G3B
C=US, O=eMudhra Inc, CN=EM OV TLS CA - G3C      C=NL, O=eMudhra BV, CN=EM OV TLS CA - G3B
C=US, O=eMudhra Inc, CN=EM OV CS CA - G3C       C=NL, O=eMudhra BV, CN=EM OV CS CA - G3B
```

Eight intermediates, eight hashes — matching the advisory's count. The check is ported
from Node's `crypto_context.cc`, uses Node's list, and runs in `us_x509_verify_chain`,
which every chain Bun verifies passes through.

A blocklist rather than root removal is the correct design: the compromised items are
*intermediates*, which a root store cannot express. (Some distributions took the blunter
route of deleting the two chaining roots, `AAA Certificate Services` and `emSign ECC Root
CA - G3`; Bun's `certdata.txt` on `main` still contains `AAA Certificate Services`, which
is expected — the blocklist does the work.)

### Severity

`CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N` = **8.7 High**.

`AC:H` and `S:C` because the attacker needs a network position to use a forged certificate,
and because the failure crosses a trust boundary — every TLS connection Bun makes becomes
forgeable, including package installs, `fetch`, and the Postgres/Redis/SQL clients. `AC:H`
rather than `AC:L` is the only thing keeping this out of the 9s: given the keys are
recoverable by anyone, the attacker's remaining work is purely a MITM position.

It is also an **18-month exposure window** — the keys have been recoverable since April
2025 — which is why I weight it above the DoS findings despite the higher attack complexity.

### Status and workaround

**Fixed on `main`, in no release.** The advisory's "Bun: pending" is correct for 1.4.3.

On 1.4.3, pass an explicit CA bundle that already excludes the eMudhra roots — your
distro's updated `ca-certificates` (NSS 3.131.1, Alpine `20261020-r0`, Debian
`20260816+nmu1`), or curl's 2026-10-20 bundle — via `ca:` or `NODE_EXTRA_CA_CERTS`. Do
not rely on Bun's bundled store. `NODE_USE_SYSTEM_CA=1` switches to the OS store, but I
did **not** verify that Bun's system-store path picks up a revocation-based block on every
platform, so treat that as a maybe.

---

## 17. Everything else worth knowing

The remaining 190 security-tier PRs are hardening and Node-parity work on
untrusted-input paths. Individually they are Low; collectively they are the reason Bun's
parser surface is in decent shape. The ones I would not want to lose track of:

| PR | Why it is on this list |
|---|---|
| [#33191](https://github.com/oven-sh/bun/pull/33191) | A security-review bundle over node:http/http2: h2 request pseudo-headers (`:method`/`:scheme`/`:path`) were not validated, so requests arrived with `req.method`/`req.url` **undefined**; a handler that threw with nothing written produced a well-formed **`200 OK`**; `ConnectionsList.idle()` dereferenced a freed parser (segfault). The bundle is honest — three reported items are labelled "not reproducible" and kept only as defence in depth. **Caveat:** it is stacked on #32488, which is **closed**, so parts of it may be fixing code that no longer exists. Needs an owner to rebase and split. |
| [#46456](https://github.com/oven-sh/bun/pull/46456) | From a maintainer, not the bot: `node:http`/`node:http2` refuse the malformed requests Node refuses (control bytes in the request target got a decoder run instead of a 400). Request-smuggling adjacent. |
| [#44241](https://github.com/oven-sh/bun/pull/44241) | Duplicate `Host` lines. **Reproduced on 1.4.0:** Bun answers `200 OK` with `req.url = http://a.example/x` but `req.headers.get("host") = "a.example, b.example"`. RFC 9112 §3.2 requires 400. Routing/cache ambiguity behind a proxy (CWE-444). |
| [#34884](https://github.com/oven-sh/bun/pull/34884) | **Reproduced:** throwing a 60,000-deep nested array **SIGSEGVs** (`exit 139`) instead of printing the error — a native stack overflow in the console/test formatter. DoS anywhere a server formats attacker-shaped data. |
| [#37864](https://github.com/oven-sh/bun/pull/37864) | `Headers` iteration is quadratic (32 ms at 4,000 headers). Capped by header-count limits, so a weak DoS alone. |
| [#35687](https://github.com/oven-sh/bun/pull/35687) | Compiling a regex with 16,000 named capture groups takes ~80 s in one uninterruptible tick. Only matters where the *pattern* is attacker-influenced. |
| [#46049](https://github.com/oven-sh/bun/pull/46049) | A dangling `.npmignore` symlink reads as "no ignore file", so `bun pm pack`/`publish` ships files the ignore file excluded — a route to publishing `.env` or keys. Open question in the PR: npm 11 stops, Bun 1.4.3 exits 0. |
| [#38636](https://github.com/oven-sh/bun/pull/38636) | Use-after-free in `Bun.serve` routing after `reload()` with `tls.serverName`. App-triggered rather than remote, but memory-unsafe in the HTTP server. |
| [#38009](https://github.com/oven-sh/bun/pull/38009) | Heap-use-after-free in `MessagePort::contextDestroyed()`, ASAN-confirmed and reachable from JS. |
| [#46360](https://github.com/oven-sh/bun/pull/46360) | `bun:sqlite` cleared bound values after a read that can run script — a UAF window while re-entrant JS runs. |
| [#39588](https://github.com/oven-sh/bun/pull/39588) / [#33486](https://github.com/oven-sh/bun/pull/33486) | `node:vm` sandbox hardening — putting the contextified sandbox in front of globals. `node:vm` is explicitly *not* a security boundary, but these close the easy crossings. |
| [#41964](https://github.com/oven-sh/bun/pull/41964) / [#32982](https://github.com/oven-sh/bun/pull/32982) | `Bun.Cookie` parsing: RFC 6265 `Max-Age` handling, empty `Path`/`SameSite` resets, uppercase domains. Cookie-parsing divergence is how cookie-smuggling bugs start. |
| [#44825](https://github.com/oven-sh/bun/pull/44825) | `Bun.openInEditor` passes `&`/`%`/`^` in a path to `cmd.exe` unescaped when the editor is `.cmd`/`.bat` — Windows command injection, local, needs a crafted filename. |
| [#38601](https://github.com/oven-sh/bun/pull/38601) | Docker checksum verification. The author is explicit that this is **defence in depth, not a live bypass** — I am listing it because a reader scanning titles would assume otherwise. |
| [#29226](https://github.com/oven-sh/bun/pull/29226) / [#39671](https://github.com/oven-sh/bun/pull/39671) / [#32112](https://github.com/oven-sh/bun/pull/32112) | CI supply-chain pinning, archive extraction without symlink privilege on Windows, archive directory permissions. Build-integrity work. |

---

## 18. Non-findings — things that look security-relevant and are not

Including these so the list can be trusted.

* **#37315, #37312, #37510** — "CRITICAL CVE" dependency bumps from a scanner. All three
  are in **`bench/` lockfiles** (`bench/bun.lock`, `bench/install/bun.lock`). They are
  benchmark dependencies, not shipped in the Bun binary. Real advisories, no user impact.
  Worth noting that a scanner is filing PRs against the wrong lockfile.
* **#38601** — described above; the author states it is not a live bypass.
* **#42086** — the title says "constant-time Temporal month differences", which my
  classifier read as a timing side channel. It means *constant runtime*: the fix is for a
  calendar operation taking 23 s. Performance, not crypto.
* **#44996** — "quadratic JSON object conversion" is a build-time performance fix, not an
  attacker-triggered DoS.
* **#29638** — cites CVE-2024-27980 only as background for how Node hardened `spawn`; the
  PR fixes a `spawn EINVAL` on Windows.
* **#39073** — `Buffer.toJSON` throwing on a detached buffer is the *bug*; the fix makes it
  return empty data like Node. No OOB.
* **#44147** — a typo in the vulnerability-reporting docs.
* **#20255, #21511** — one-line CI/debugging changes with no threat model.

---

## 19. The systemic finding

The individual bugs are ordinary. What is not ordinary is the queue they are stuck in.

| Measure | Value |
|---|---|
| Open PRs at snapshot | **5,652** |
| From `robobun` (the automated agent) | **4,533 (80.2%)** |
| Carrying the `claude` label | 4,484 |
| Opened in the previous 7 days | 821 |
| Median age | **54 days** |
| Older than a year | 108 |
| Security-relevant | 202 |
| Security PRs that **no longer apply to `main`** | **84 (42%)** |
| Security PRs that are mergeable and clean | **4** |
| Median age of a security PR | **68 days** |
| Security PRs sitting on another PR's branch | 7 |

Five of the findings above are for bugs that the project's own automation found — the PRs
say so, in as many words: *"An audit found this. No user reported it."* The detection is
working. The delivery is not.

Two specific pathologies:

**Stacking.** Several findings cannot merge independently because they are built on
branches that will never land. #33191 fixes real bugs in code introduced by #32488 —
which is **closed**, not merged. Four WASI PRs cover one fix. #46351 sat on a fork branch
with CI blocked, and by the time I looked, `main` had fixed the underlying hole a
different way, making the PR obsolete. A security fix that needs a rebase and an unblock
is a security fix that ships late.

**Staleness under a moving base.** The brotli case is the clean illustration: the PR's
premise ("main builds v1.2.0") expired within hours of opening, because someone bumped
the dependency. Nobody re-read it. In a queue where 821 PRs arrive per week, a PR that is
not triaged in a day is a PR whose description is wrong.

**And a release lag that is now the dominant risk.** F1 is already fixed on `main` and
shipped nowhere — and so are F11 and F12, the two advisories published on 2026-10-20 that
named Bun as unpatched. All three were fixed on `main` within a day of publication. Three
high-profile issues in three days, three patches, zero shipped. The other findings in this
report are a different problem: they are not fixed anywhere yet, and are still waiting on
the PRs above. [`04-advisory-check.md`](04-advisory-check.md) has the reproduction commands
for F11 and F12.

**None of this is a criticism of the individual PRs.** They are, on the whole,
unusually good: measurements against Node, tables of before/after behaviour, honest
"downsides" sections, and explicit "not reproducible" labels where a claim did not hold.
#36410 documents a place where it *deliberately* differs from Node and cites RFC 9113.
That is better than most human-written security PRs. The problem is volume.

---

## 20. What I would do, in order

1. **Ship a 1.4.4 cut from `main` today.** Three separate remote issues are already fixed
   on `main` and in **no release**: brotli v1.2.1 for CVE-2026-111497 (F1), the HTTP/3
   QPACK header limits (#46392, F11), and the eMudhra CA blocklist (#46300, F12). The
   release channel is the bottleneck, not the code. Then close #46351 as superseded, or
   re-point it at the 1.4 branch.
2. **Merge #42646** (F2). Two lines of dependency pin, tests included, still unfixed on
   `main`. Nothing else in the queue has this ratio of impact to effort.
3. **Decide #45204** (F3) and rebase it. It needs a maintainer ruling on whether a bare
   name may cover folder/tarball/git packages; the pnpm precedent says no.
4. **Merge #36410 and #44241** (F5, duplicate `Host`). Both are Node/RFC parity for the
   HTTP parsers, both mergeable-or-close, both cheap.
5. **Give the WASI series one owner** (F7) and land it as one PR.
6. **Take the `audit` fail-open** (F9): #45668 as-is, and split #46143's lockfile change
   from its audit change.
7. **Rebase the conflicting security PRs** — 84 of them. Many will be superseded; the
   exercise of finding out is itself the triage that has not happened.
8. **Close or re-scope #33191**, whose base PR is closed.
9. **Consider a security label and an SLA.** The queue has one label (`claude`, 4,484) and
   no security label. A `security` label plus "security PRs get a reviewer within 48 h"
   would have caught every finding above.

---

*Companion files: [`03-security-triage.md`](03-security-triage.md) for all 202 candidates
with individual assessments; [`prs.csv`](prs.csv) for the raw classification;
[`../poc/`](../poc/) for the proof-of-concept scripts referenced above.*
