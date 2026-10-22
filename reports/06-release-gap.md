# The release gap: what 1.4.3 was exposed to, what 1.4.4 fixed, and what remains

**Previous release:** 1.4.3 (2026-10-10) — the version analysed here
**Current release:** **1.4.4** (2026-10-22 10:11Z) — verified against the tag
**Question:** what was a 1.4.3 user exposed to, what did upgrading fix, and what remains?

---

## The answer

Bun 1.4.3 had **27 enumerated security issues** — one row of which stands for about 300
crash fixes — including nine certificate-validation bypasses that were never filed as
advisories. **All 27 are fixed in 1.4.4**, which shipped on 2026-10-22. This report was
written against `main` before the release and has since been checked against the tag: the
two trees are identical, and each headline fix was confirmed in the files at `bun-v1.4.4`
(see [`05-next-release.md`](05-next-release.md#8-verification-against-the-tag)).

**Nine findings remain unfixed after upgrading** (F2–F10), one of which is a remotely
reachable XSS.

| | Count | Worst severity |
|---|---|---|
| Vulnerable in 1.4.3, **fixed in 1.4.4** (shipped) | **27** (incl. ~300 crash fixes) | 8.7 High |
| Still vulnerable in 1.4.4, **fixed nowhere** | **9** (F2–F10) | 7.5 High (plus an XSS) |

Three of the fixed items are published advisories. The rest were found by scanning the 171
PRs merged between the two tags — most of them inside consolidation PRs whose titles say
"consolidate", "WebSocket" and "sql".

---

## Part A — was vulnerable in 1.4.3, fixed in 1.4.4

Ordered by severity. "Basis" says how I know 1.4.3 is affected.

### A1. Published advisories

| Item | Sev | Who can exploit it | Fixed by | Basis |
|---|---|---|---|---|
| **brotli OOB write**, CVE-2026-111497 | **8.1** | Any server you `fetch()` from, on a `Content-Encoding: br` response — default on. Heap corruption in the decoder. | #46392 (brotli → v1.2.1) | Node's 2026-10-21 security release; Bun 1.4.3 pins v1.2.0 |
| **eMudhra CA compromise** | **8.7** | Anyone with the recoverable intermediate keys, from a MITM position — forges a cert for any host | #46300 (8 SPKIs blocked, NSS 3.131.1) | 1.4.3 has no `blocked_spkis.cpp`; bundles NSS 3.128 |
| **QPACK amplification** | **7.5** | One unauthenticated connection to a `Bun.serve({ http3: true })` listener — OOM the process at ~4000× | #46392 + #46436 | 1.4.3 advertises `es_max_header_list_size` and never enforces it |

### A2. TLS certificate validation — #44618 (merged 15 h after the tag)

| Item | Sev | Who can exploit it | Basis |
|---|---|---|---|
| `WebSocket` never calls `tls.checkServerIdentity` | **7.4** | Anyone in a MITM position, with *any* valid certificate | PR reproduces on `main`; 1.4.3 predates the fix |
| `NODE_TLS_REJECT_UNAUTHORIZED=0` disables a **server's** client-certificate enforcement | **7.5** | No attacker needed — the env var is common in CI/dev | same |
| `tls: [...]` to `Bun.listen` / `Bun.connect` is plain TCP | **7.4** | Anyone on the path — the traffic is cleartext | same |
| `https.createServer()` without a usable key/cert answers plain HTTP | **7.4** | Anyone on the path | same |
| `secureConnect` reports `authorized === true` for a peer that failed the key proof | **7.4** | MITM | same |
| `PGSSLMODE=verify-*` dropped next to a `TLS_*` URL variable | **7.4** | MITM on a database connection | same |
| Client certificate disclosed to a server that is then refused | 5.3 | A hostile server | same |
| Revoked client certificates accepted (`crl` never seen) | 5.9 | A revoked client | same |
| Different client certs/CAs share one `https.Agent` socket | 5.9 | Cross-tenant confusion | same |
| TLS `write()` silently loses 16 KiB while another socket is stalled | 5.3 | Load + adjacent traffic | same |
| Use-after-free from `destroy()` inside `ALPNCallback` | 6.5 | Crafted handshake sequence | same |

### A3. SQL — #45304

| Item | Sev | Who can exploit it | Basis |
|---|---|---|---|
| Postgres client never called `tls.checkServerIdentity` | **7.4** | MITM: any valid cert from any CA satisfies a connection to any host | PR reproduces on `main` |

### A4. WebSocket — #45223

| Item | Sev | Who can exploit it | Basis |
|---|---|---|---|
| Masked server frame parsed with the mask key as payload; parser desyncs | 5.3 | A malicious server; smuggling precondition behind a proxy | PR reproduces on `main` |
| Control frames queued for absent listeners — ping flood grows memory | 5.3 | Any client | same |

### A5. HTTP request parsing — #46456

| Item | Sev | Who can exploit it | Basis |
|---|---|---|---|
| Request target with a byte from `0x7f`–`0xff` or a control character ran the handler with `req.url` decoded as UTF-8 instead of answering `400` | 5.3 | Any client; raw material for request smuggling and log injection | PR states Node's behaviour and the previous one |
| `DEL` (`0x7f`) in a header or trailer value accepted | 4.3 | Any client | same |

Bun.serve is unchanged; this is the `node:http` / `node:http2` servers only.

### A6. Memory safety and crash hardening

| Item | Sev | Notes | Basis |
|---|---|---|---|
| `structuredClone` accepts a `CryptoKey` whose hash tag names no digest — hash read from an **uninitialised byte** | 5.3 | Reachable from a child's IPC channel with `serialization: "advanced"` (#46387, #46410) | PR states the previous behaviour |
| Stream TLS engine use-after-free | 6.5 | ASAN-confirmed, found by audit (#46335) | PR reproduces on `main` |
| `MessagePort` heap-use-after-free | 6.5 | #38009, absorbed into #46021 | reproduced in the main report |
| `Bun.serve` route UAF after `reload()` with `tls.serverName` | 6.5 | #38636, absorbed | reproduced in the main report |
| Deep-nested value SIGSEGVs the process (`throw deepArray`) | 5.3 | #34884, absorbed — **reproduced on 1.4.0** | verified locally |
| 30,000-combinator selector SIGSEGVs `HTMLRewriter` | 3.5 | #41475, in #46270 | reproduced in the main report |
| Quadratic `Bun.stringWidth` on non-ASCII multi-line text | 4.0 | #46389 — 2.56 s at 400 KB | PR measures 1.4.3 |
| ~300 further crash fixes (segfault, panic, abort, failed assertion, sanitizer corruption, native stack overflow) | varies | #46021 (306 PRs) + #46270 | PR description |

**What that adds up to:** if you run 1.4.3, the highest-value thing you can do is upgrade
to 1.4.4. Nothing else in this evaluation comes close.

---

## Part B — still open in 1.4.4 (residual risk after upgrading)

These stay broken whether or not you upgrade. From the main report:

| Finding | Sev | What it is |
|---|---|---|
| **F2 · HTMLRewriter `comment.text` XSS** | **6.1** (8.0 privileged) | `-->` is rejected, `--!>`, `>`, `->` are not, so injected markup goes live. Reproduced. The lol-html pin has not moved and #43266 is still open. |
| **F4 · `URLPattern` polynomial backtracking** | **7.5** | 8 KB path ≈ 30 s on the JS thread. #42535 open, conflicts. |
| **F5 · HTTP/2 CONTINUATION flood** | **7.5** | Unauthenticated DoS against `node:http2` servers. #36410 open, CI-blocked. |
| **F3 · `bun add <url>` inherits `trustedDependencies`** | **7.1** | Supply-chain: an unvetted source's lifecycle scripts run. #45204 open, needs a design ruling. |
| **F10 · HTTP/2 client `originSet` unbounded** | **6.5** | Malicious server exhausts client memory. #42411 open. |
| **F6 · recursive `mkdir` follows a dangling symlink** | **5.9** | Write outside the intended directory on macOS/FreeBSD. #38298 open. |
| **F7 · `node:wasi` unbounded guest pointers** | **5.5** | Sandbox contract broken; fd leak; debug struct printed to host stdout. 3 PRs open. |
| **F8 · `Bun.cron()` predictable `/tmp` path** | **5.0** | Local symlink attack → append to any file the victim can write. #29144 open. |
| **F9 · `bun audit` fails open** | control bypass | "No vulnerabilities found" on a HIGH advisory, and on unchecked tarball/git packages. #45668, #46143 open. |

F2 is the one to watch: it is the only remotely reachable code-execution-class issue in the
set, it is verified, and nothing in the consolidation sweep picks it up.

---

## Part C — what I excluded, and why

The 1.4.4 diff contains fixes that are **not** 1.4.3 vulnerabilities. Counting them would
inflate the exposure. I excluded:

| PR | Why it is not a 1.4.3 issue |
|---|---|
| [#45124](https://github.com/oven-sh/bun/pull/45124) | *"Regression from #44618, not in a release"* — a large upload losing the peer's 403 |
| [#45139](https://github.com/oven-sh/bun/pull/45139) | *"On main since #44618, not in a release"* — 100% CPU busy loop |
| [#45477](https://github.com/oven-sh/bun/pull/45477) | Regression from #45307, unreleased |
| [#46480](https://github.com/oven-sh/bun/pull/46480) | Fixes a hard-link fallback that regressed in #44968 — never released |
| The regression list in [#46270](https://github.com/oven-sh/bun/pull/46270) | *"Regressions fixed (none was released)"* — `spyOn(Bun,"sql")`, `WebAssembly.Memory` views losing data, `node:vm` accessors |

This matters because the three consolidation PRs are large and landed within days of each
other; most of their follow-up fixes repair damage that never reached a user.

---

## Part D — the one regression going the wrong way

**`emSign Root CA - G1` is trusted again.** #46159 removed four emSign roots on 2026-10-20
(121 → 117 certificates). #46300, merged 26 hours later, deleted the `%distrusted_labels`
mechanism and regenerated from NSS 3.131.1 → 118 certificates, putting that root back.

The eight compromised *intermediates* are still blocked by #46300's SPKI list, so the known
attack still fails. Compared with 1.4.3 this is still a large improvement — 1.4.3 has
neither the blocklist nor the root removal. But the root deletion was undone by accident,
not by decision. Details in [`05-next-release.md`](05-next-release.md#3-finding-the-emudhra-root-removal-was-undone).

---

## Bottom line

1. **Upgrade to 1.4.4** (shipped 2026-10-22). It closes a remote memory-corruption bug, a
   remote DoS, a CA-trust gap, nine certificate-validation bypasses, a Postgres MITM, and
   several hundred crash paths. Nothing else in this report is close to that. Note the
   release page carries **no changelog** — only a link to the blog and a contributor list —
   so none of this is visible from the release notes.
2. **F2 stays open.** If you serve user-controlled text through `HTMLRewriter` as a
   comment, you are still injectable after upgrading.
3. **F4/F5 stay open.** If you route attacker-controlled paths through `URLPattern`, or
   expose a `node:http2` server, plan for DoS independent of release.
4. **F3/F9 stay open.** Supply-chain and security-tooling gaps are unaffected by upgrading.

---

*Method: `compare/bun-v1.4.3...main` → 172 commits, 171 PRs; each fetched and read. Items
counted as "1.4.3 vulnerabilities" only where the PR states it reproduces on `main` before
the fix, where the affected code predates the tag, or where I reproduced it locally. Items
the PRs themselves label as regressions from post-1.4.3 PRs are listed in Part C and
excluded.*
