# What shipped in 1.4.4: verified security scan

**Window:** `bun-v1.4.3` (2026-10-10 05:24Z) → `bun-v1.4.4` (released 2026-10-22 10:11Z)
**Diff:** 172 commits · **171 merged PRs** · 1 direct commit (`Bump`, sets `package.json` to **1.4.4**)
**Question:** which security fixes are in 1.4.4?

> **Verified, not predicted.** This report was first written against `main` before the
> release. It has since been checked against the tag: `compare/bun-v1.4.4...main` is
> **identical** (0 ahead, 0 behind), and the tag's last commit is `38afee6c8` — #46456,
> the final PR in the window. Every item below was additionally confirmed in the files at
> `bun-v1.4.4`, not just inferred from `main`. See §8.

---

## Bottom line

This is the most security-dense release in the window I examined. It closes both open
advisories (QPACK amplification, eMudhra CA) **and** a large set of certificate-validation
bypasses that were never published as advisories — they arrived inside three consolidation
PRs whose titles say "consolidate", "WebSocket", and "sql".

| # | PR | What it fixes | Class |
|---|---|---|---|
| 1 | [#46300](https://github.com/oven-sh/bun/pull/46300) | 8 compromised eMudhra intermediates blocked; roots to NSS 3.131.1 | CA trust |
| 2 | [#46392](https://github.com/oven-sh/bun/pull/46392) + [#46436](https://github.com/oven-sh/bun/pull/46436) | QPACK header limits (F11); brotli → v1.2.1 (F1) | DoS, memory |
| 3 | [#44618](https://github.com/oven-sh/bun/pull/44618) | 15 TLS fixes; **several are certificate-validation bypasses** | CWE-295/200/319 |
| 4 | [#45304](https://github.com/oven-sh/bun/pull/45304) | Postgres never called `tls.checkServerIdentity`; SCRAM channel binding added | CWE-295 |
| 5 | [#45223](https://github.com/oven-sh/bun/pull/45223) | WebSocket frame desync, unbounded control-frame queue, TLS identity checks | CWE-444/400/295 |
| 6 | [#46021](https://github.com/oven-sh/bun/pull/46021) + [#46270](https://github.com/oven-sh/bun/pull/46270) | 306-PR crash hardening (segfaults, panics, sanitizer corruption, stack overflow) | CWE-400/787 |
| 7 | [#46387](https://github.com/oven-sh/bun/pull/46387) + [#46410](https://github.com/oven-sh/bun/pull/46410) | `structuredClone` accepts crafted `CryptoKey` records (uninitialised byte read) | CWE-457/20 |
| 8 | [#46335](https://github.com/oven-sh/bun/pull/46335) | ASAN heap-use-after-free in the stream TLS engine | CWE-416 |
| 9 | [#46389](https://github.com/oven-sh/bun/pull/46389) | Quadratic `Bun.stringWidth` (2.56 s for a 400 KB string) | CWE-1333 |
| 10 | [#46456](https://github.com/oven-sh/bun/pull/46456) | `node:http`/`node:http2` now refuse the malformed requests Node refuses | CWE-444/20 |

Details on the ones that were not already public.

---

## 1. The certificate fixes are the real story

### #44618 — "tls: consolidate the open TLS fixes"

The PR's own table of "the ones that matter most" reads like a CVE list. Reproduced on
`main` and, for `node:*` behaviour, against Node v26.3.0:

| Issue on `main` | Effect |
|---|---|
| **Client certificate disclosure** | `https.request()` with a client cert sends it to a server it then refuses — a server can force it with a junk record behind its `Finished` |
| **False `authorized`** | `secureConnect` fires with `authorized === true` for a peer that failed the key proof |
| **Cleartext https** | `https.createServer()` without a usable key/cert answers **plain HTTP** |
| **Revoked client certificates** | An mTLS server never sees `crl`, so a revoked client is `authorized` |
| **Pooled sockets** | Requests with different client certs or CAs share an `https.Agent` socket and session |
| **Silent plaintext** | `tls: [...]` passed to `Bun.listen` / `Bun.connect` is **plain TCP** |
| **Server weakened by a client knob** | `NODE_TLS_REJECT_UNAUTHORIZED=0` disables a **server's** client-certificate enforcement |
| **Pins never checked** | `WebSocket` never calls `tls.checkServerIdentity` and ignores `tls.serverName` |
| **`verify-full` dropped** | `PGSSLMODE=verify-*` is lost next to a `TLS_*` URL variable; `tls: true` sends no SNI |

The last two are the sharpest. A client asking for `verify-full` and getting something
weaker, and a WebSocket that never checks the hostname, are both straightforward MITM
conditions. `NODE_TLS_REJECT_UNAUTHORIZED=0` — a client-side escape hatch — silently
turning off *server-side* client-certificate enforcement is a control bypass with a wide
blast radius, because that variable is commonly set in CI and dev environments.

There is also memory-safety and availability work in the same PR: a use-after-free from
`destroy()` inside `ALPNCallback`, a SIGABRT in `fetch` through an env proxy, 16 KiB lost
from a TLS `write()`, and a quadratic Duplex path (32 MB: 11.75 s → 0.39 s).

### #45304 — "sql: consolidate …"

> `tls.checkServerIdentity` was never called → called, and it raises an `sslmode` below
> `verify-ca` to `verify-full`, so a self-signed certificate without `ca` fails, as in
> `pg` and `postgres.js`

The Postgres client validated the chain but **never checked that the certificate was for
the host it connected to**. Any valid certificate from any CA would pass. Also adds
SCRAM-SHA-256-PLUS with `channelBinding: disable|prefer|require`, and stops reading
`$PASSWORD` as the database password.

### #46456 — "node:http, node:http2: refuse the malformed requests that Node refuses"

Hardening for how the `node:http` and `node:http2` servers read a request; `Bun.serve` is
unchanged. A request target carrying a byte from `0x7f` to `0xff` or a control character is
answered `400` before any handler runs, where **Bun used to run the handler with `req.url`
decoded as UTF-8**. A `DEL` (`0x7f`) in a header or trailer value is answered `400` unless
the parser is lenient. Both are Node's behaviour; bytes like `0x7f` inside a request line
are the raw material of request smuggling and log injection.

### #45223 — "WebSocket: real closing handshake …"

* **A masked frame from a server was parsed with the mask key as payload**, and the
  connection continued out of sync — a protocol-desync bug of the kind that turns into
  request smuggling when a proxy is in front.
* Control frames that nothing listened for were queued for a later listener, so **a flood
  of pings grew memory to gigabytes**.
* The handshake is now read from `req.headers` only, and TLS identity errors
  (`DEPTH_ZERO_SELF_SIGNED_CERT`, `ERR_TLS_CERT_ALTNAME_INVALID`) surface as `error.code`.

---

## 2. The two published advisories are closed

* **QPACK amplification (F11).** [#46392](https://github.com/oven-sh/bun/pull/46392)
  enforces a cumulative header budget per RFC 9114 §4.2.2 (`name + value + 32`), caps a
  request at 200 fields and answers `431`;
  [#46436](https://github.com/oven-sh/bun/pull/46436) lifts lsquic's own 64 KB caps while
  leaving those limits in place.
* **brotli CVE-2026-111497 (F1).** The same #46392 bumps brotli to v1.2.1, which contains
  `0ed4268a`.
* **eMudhra (F12).** [#46300](https://github.com/oven-sh/bun/pull/46300) adds the SPKI
  blocklist with all **8** eMudhra intermediates and regenerates roots from NSS 3.131.1.

These are the three items the advisories said Bun had not fixed. After 1.4.4, all three
statements become false.

---

## 3. Finding: the eMudhra root removal was undone

Two PRs touched the same root bundle within 28 hours, and the second reverted the first's
security change.

| PR | Merged | Effect on the bundled roots |
|---|---|---|
| [#46159](https://github.com/oven-sh/bun/pull/46159) | 2026-10-20 05:53Z | Adds a `%distrusted_labels` list to the generator and drops four roots: `emSign Root CA - G1`, `emSign ECC Root CA - G3`, `emSign Root CA - C1`, `emSign ECC Root CA - C3` → **121 → 117 certificates** |
| [#46300](https://github.com/oven-sh/bun/pull/46300) | 2026-10-21 07:50Z | *"generate-root-certs.pl no longer takes a list of labels to leave out"* — mechanism removed, regenerated from NSS 3.131.1 → **118 certificates** |

Current state on `main`: the bundle holds **118** certificates and **`emSign Root CA - G1`
is back in it**.

```
$ grep -v '^#' root_certs.txt | wc -l      -> 118
$ grep -Fx 'emSign Root CA - G1' root_certs.txt
emSign Root CA - G1                          <- present
$ grep -c distrusted_labels generate-root-certs.pl
0                                            <- mechanism gone
```

**How bad is it?** Bounded, but not nothing. The eight compromised *intermediates* are
still blocked by the SPKI list in #46300, so the known attack — forge a certificate under
one of those eight keys — still fails. What came back is the *root*, which means any
**other** intermediate eMudhra issues under `emSign Root CA - G1` is trusted again. Root
removal was the blunt mitigation the advisory recommended for clients that cannot consume
revocation; Bun now does precise mitigation instead, which is arguably the better design —
but it was not a deliberate decision, it was a side effect of two PRs racing, and nobody
said so in either description.

**Worth a maintainer confirming** that dropping `%distrusted_labels` was intended. If it
was, the mechanism should be deleted deliberately with a note; if not, one root is back.

---

## 4. Crash hardening: #46021 and #46270

[#46021](https://github.com/oven-sh/bun/pull/46021) collapses **306 pull requests** (227
whole, 79 cut down) plus ~20 reported crashes into one change: segfaults, Rust panics,
aborts, failed assertions, sanitizer-reported memory corruption and native stack overflows
now throw, print a CLI error and exit 1, or work.
[#46270](https://github.com/oven-sh/bun/pull/46270) is the follow-up for regressions in it.

This matters for the earlier report because it **ships fixes tracked there as open**:

| From the security report | Status before | In 1.4.4 |
|---|---|---|
| #34884 — 60,000-deep value SIGSEGVs the process | open | **fixed** (absorbed) |
| #41475 — 30,000-combinator selector SIGSEGVs `HTMLRewriter` | open | **fixed** (in #46270) |
| #38009 — `MessagePort` heap-use-after-free | open | **fixed** (absorbed) |
| #38636 — `Bun.serve` route UAF after `reload()` | open | **fixed** (absorbed) |
| #41574 — UTF-8 decoder on a borrowed buffer | open | **fixed** (absorbed) |
| #42334, #42185, #41710, #44124, #44195 … | open | **fixed** (absorbed) |

A PR being open in the queue no longer means the bug is unfixed — the consolidation PRs
carry them wholesale. Anyone tracking the queue by PR number will overstate what is broken.

---

## 5. What is **not** in 1.4.4

I checked each finding from the main report against the 171 PRs and against the reference
lists inside the two hardening bundles. These are untouched:

| Finding | Why it is not in this release |
|---|---|
| **F2 · HTMLRewriter `comment.text` XSS** | The fix needs the lol-html pin to move. `main` still pins `725ce499` (v2.7.2 base). The upgrading PR, [#43266](https://github.com/oven-sh/bun/pull/43266), is **still open** and #46021 did not take it. **The only remotely exploitable XSS in this report ships unchanged.** |
| **F3 · `bun add <url>` inherits `trustedDependencies`** | #45204 open, conflicts, still awaiting a design ruling |
| **F4 · `URLPattern` polynomial backtracking** | #42535 open, conflicts |
| **F5 · HTTP/2 CONTINUATION flood** | #36410 open, CI-blocked |
| **F6 · recursive `mkdir` follows a dangling symlink** | #38298 open |
| **F7 · `node:wasi` unbounded guest pointers** | #34468 / #39100 / #40654 all open, none absorbed |
| **F8 · `Bun.cron()` predictable `/tmp`** | #29144 open |
| **F9 · `bun audit` fails open** | #45668 / #46143 open; the install consolidation #44968 did not take them |
| **F10 · HTTP/2 client `originSet` unbounded** | #42411 open |

So 1.4.4 closed the two advisories and a lot of TLS work, and still shipped the
HTMLRewriter XSS and the five DoS-class findings — all five confirmed absent at the tag.

---

## 6. Smaller items worth noting

| PR | Note |
|---|---|
| [#46159](https://github.com/oven-sh/bun/pull/46159) | The four-root removal above; superseded by #46300 within a day |
| [#46387](https://github.com/oven-sh/bun/pull/46387) | `structuredClone` accepted a `CryptoKey` record whose hash tag named no digest — the key's hash was read from an **uninitialised byte**. Reachable from a child's IPC channel with `serialization: "advanced"` |
| [#46410](https://github.com/oven-sh/bun/pull/46410) | Follow-up: RSA records with no hash, ChaCha20-Poly1305 keys that are not 32 bytes |
| [#46335](https://github.com/oven-sh/bun/pull/46335) | Stream TLS engine UAF, ASAN-confirmed, found by audit |
| [#46389](https://github.com/oven-sh/bun/pull/46389) | `Bun.stringWidth` quadratic on non-ASCII multi-line text: 2.56 s for `"日\n" × 200,000` |
| [#46317](https://github.com/oven-sh/bun/pull/46317) | `--hardened=on` adds stack protector, `_FORTIFY_SOURCE`, stack-clash protection. **Off by default and no profile enables it** — so release binaries still ship without them |
| [#45144](https://github.com/oven-sh/bun/pull/45144) | CI images verify every download against a sha256 and pin what floated — build supply chain, not user-facing |
| [#46227](https://github.com/oven-sh/bun/pull/46227) | CI image trusted roots updated — CI only |
| [#44912](https://github.com/oven-sh/bun/pull/44912) | `node:http` builds `req.headers` natively and validates a set header name once — no behaviour change |
| [#46480](https://github.com/oven-sh/bun/pull/46480) | Excluded from the exposure count: fixes a hard-link fallback that regressed in #44968, never released |

---

## 7. Assessment

**The release is a genuine security improvement**, and more so than its changelog will
show: the TLS and SQL consolidation PRs contain certificate-validation bypasses that read
like embargoed material but shipped as refactors. If they had been filed as CVEs, 1.4.4
would be a security release by any definition.

Two things I would raise about this release:

1. **Confirm the `emSign Root CA - G1` revert was intended.** It is the only place where
   two PRs undid each other, and the mechanism that caused it (`%distrusted_labels`) was
   deleted without a note.
2. **F2 is still live.** The HTMLRewriter comment setter is the one finding in the main
   report that is remotely exploitable, unfixed on `main`, and *not* picked up by the
   consolidation sweep. Merging #43266 — or cherry-picking the one lol-html commit as
   #42646 does — would still close it in 1.4.5.

---

*Method: `gh api repos/oven-sh/bun/compare/bun-v1.4.3...main` (172 commits), PR numbers
extracted from commit subjects (171/172 mapped; 1 direct commit), each PR fetched and
classified, then read by hand. Reference lists inside #46021 and #46270 were parsed to
detect absorbed PRs. Root-bundle claims verified against `root_certs.txt`,
`generate-root-certs.pl` and `blocked_spkis.cpp` on `main`.*

---

## 8. Verification against the tag

Each headline claim was re-checked in the files at `bun-v1.4.4`, not just in `main`:

| Claim | Check at `bun-v1.4.4` | Result |
|---|---|---|
| brotli is v1.2.1 (F1 closed) | `scripts/build/deps/brotli.ts` → `BROTLI_COMMIT` | `db24a98a…` **// v1.2.1** |
| QPACK limits enforced (F11 closed) | `packages/bun-usockets/src/quic.c` → `h->size +=`, `max_fields` | 6 matches — cumulative budget and 200-field cap present |
| eMudhra intermediates blocked (F12 closed) | `src/crypto/blocked_spkis.cpp` | present, **8** eMudhra SPKIs |
| Root bundle state | `root_certs.txt` | **118** certs; `emSign Root CA - G1` **present** (the regression in §3) |
| F2 still open | `scripts/build/deps/lolhtml.ts` → `LOLHTML_COMMIT` | still `725ce499…` — **unchanged**, so the comment-setter XSS ships |
| Release cut point | `compare/bun-v1.4.4...main` | **identical** — nothing merged after the tag was missed |
