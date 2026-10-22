# Were the 1.4.4 TLS fixes disclosed?

**Question asked:** the TLS fixes in 1.4.4 look like vulnerabilities. Is there a CVE for
them, did Node.js or another project have the same bugs, and is Bun shipping an undisclosed
vulnerability without saying so?

**Short answer:** there is **no CVE** and **no GitHub Security Advisory** for any of them.
Bun's blog does carry a one-paragraph "Security" note naming TLS among the affected areas,
but **none of the nine certificate-validation issues is described anywhere** — no affected
versions, no severity, no mitigation. This is not concealment; it is a security fix shipped
silently. The distinction matters, and the rest of this document is the evidence.

---

## 1. What the TLS fixes actually are

From [#44618](https://github.com/oven-sh/bun/pull/44618), which consolidates the open TLS
PRs and describes each as *"reproduced on `main` and, for `node:*` behavior, on Node
v26.3.0 first"*:

| # | Issue | CWE | Score | Source |
|---|---|---|---|---|
| 1 | `WebSocket` never calls `tls.checkServerIdentity`; ignores `tls.serverName` | 295 | **7.4** | #41648 |
| 2 | `NODE_TLS_REJECT_UNAUTHORIZED=0` disables a **server's** `requestCert` enforcement | 295 | **7.4–9.1** | #35245 |
| 3 | `tls: [...]` passed to `Bun.listen` / `Bun.connect` starts a **plaintext** listener | 319 | **7.4** | #41490 |
| 4 | `https.createServer()` without a usable key/cert answers **plain HTTP** | 319 | **7.4** | #41672 |
| 5 | Client certificate still sent to a server the client then refuses | 200 | 3.7 | #43946 |
| 6 | `secureConnect` reports `authorized === true` for a peer that failed the key proof | 287 | **7.4** (8.7) | #44422, #32929 |
| 7 | An mTLS server never sees `crl`, so a revoked client is `authorized` | 299 | 6.8 | #41641 |
| 8 | Requests with different client certs/CAs share one `https.Agent` socket | 488 | 4.2 | #42498 |
| 9 | `PGSSLMODE=verify-*` dropped next to a `TLS_*` URL variable | 295 | **7.4** | #44498 |
| 10 | Postgres client never calls `tls.checkServerIdentity` | 295 | **8.7** | #45304 |
| 11 | Use-after-free from `destroy()` in `ALPNCallback` | 416 | 5.9 | #44462 |
| 12 | Heap-use-after-free in the stream TLS engine | 416 | 5.9 | #46335 |
| 13 | TLS `write()` loses 16 KB while another socket is stalled | 703 | 5.9 | #44529 |
| 14 | SIGABRT in `fetch` through an env proxy | 248 | 5.9 | #44458 |

Scores are mine — CVSS 3.1, no CVE exists to cite. Vectors and preconditions are in §2.
Items 1–14 share their numbering with that table.

Row 12 is [#46335](https://github.com/oven-sh/bun/pull/46335), a separate PR: an
ASAN-confirmed heap-use-after-free in the stream TLS engine, *"Found by audit. No issue or
crash report names it."*

**Nine of these are certificate-validation or transport-security defects**, not stability
bugs. Items 1, 3 and 4 mean a client can be made to talk to the wrong host, or to believe it
is speaking TLS when it is not.

---

## 2. Severity, item by item

No CVE means no official score, so these are mine — CVSS 3.1, computed for the realistic
attack path, with the vector shown so you can disagree with the inputs rather than the
number. `AC:H` throughout for anything needing a man-in-the-middle position, which is
CVSS's own canonical example of high complexity.

| # | Issue | Vector | Score | Precondition |
|---|---|---|---|---|
| 1 | `WebSocket` never called `checkServerIdentity` — **and ignored a pin that returned an Error** | `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N` | **7.4 High** | MITM with any certificate from any trusted CA |
| 2 | `NODE_TLS_REJECT_UNAUTHORIZED=0` disabled a server's client-certificate enforcement | `AV:N/AC:H/…` → 7.4 · `AV:N/AC:L/…` → **9.1** | **7.4–9.1** | the env var is set — which is exactly the population affected |
| 3 | `tls: [...]` to `Bun.listen` / `Bun.connect` started a **plaintext** listener | `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N` | **7.4 High** | app uses the array form; no attacker cert needed |
| 4 | `https.createServer()` without a usable key/cert answered **plain HTTP** | `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N` | **7.4 High** | misconfiguration that Node rejects |
| 5 | Client certificate still sent to a server the client had refused | `AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N` | **3.7 Low** | hostile server; the certificate is public by design |
| 6 | `secureConnect` reported `authorized === true` for a peer that failed the key proof | `AV:N/AC:H/…` → 7.4 · with `S:C` → 8.7 | **7.4 High**, 8.7 where `authorized` gates access | MITM |
| 7 | Revoked client certificates accepted — no CRL on an mTLS server | `AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N` | **6.8 Medium** | attacker already holds a revoked client cert |
| 8 | Different client certs/CAs shared one `https.Agent` socket and session | `AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:N` | **4.2 Low** (up to 6.8 cross-tenant) | several identities in one process |
| 9 | `PGSSLMODE=verify-*` dropped next to a `TLS_*` URL variable | `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N` | **7.4 High** | MITM plus that option combination |
| 10 | Postgres client never called `tls.checkServerIdentity` | `AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N` | **8.7 High** | MITM; `S:C` because database data crosses into the app |
| 11 | Use-after-free from `destroy()` in `ALPNCallback` | `AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H` | **5.9 Medium** | needs a crafted handshake sequence |
| 12 | Heap-use-after-free in the stream TLS engine | `AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H` | **5.9 Medium** | no JS-observable oracle; release builds panic |
| 13 | TLS `write()` silently lost 16 KB | `AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N` | **5.9 Medium** | a stalled socket elsewhere on the loop |
| 14 | SIGABRT in `fetch` through an environment proxy | `AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H` | **5.9 Medium** | env proxy + `Bun.file()` body |

### What that adds up to

**Nine of the fourteen are certificate-validation or transport-security defects, and they
cluster at 7.4–8.7 High.** The band is set by two things: none needs authentication, all
need a network position, and the impact is a full loss of confidentiality and integrity on
the affected channel.

**Nothing here is Critical on its own.** There is no unauthenticated remote code execution
and no pre-auth memory corruption: #11 is a use-after-free but with no proven trigger from
JS, which is why it scores 5.9 rather than in the 8s. The one item that can reach Critical
(9.1) is #2 — and only for deployments that actually set `NODE_TLS_REJECT_UNAUTHORIZED=0`,
which is precisely the set of deployments affected by it.

**Two items deserve more weight than their number suggests.** #1 ignored a
`checkServerIdentity` callback that returned an `Error` — an application that had
explicitly pinned a certificate was still unprotected, so the "mitigation" users would
naturally reach for did nothing. And #3 is a *silent* plaintext listener: no error, no
warning, and the traffic is readable by anyone on the path without needing a certificate at
all.

### How that compares with the CVE-bearing equivalents

Node's advisories for the same class land in the same range — 5.3 (CVE-2021-44532,
CVE-2021-22939), 7.4 (CVE-2021-44531), 8.2 (CVE-2024-27983). If these had been filed, they
would have been rated High and would have appeared in exactly the band a reader expects.

## 3. CVE status

| Check | Result |
|---|---|
| CVE mentioned anywhere in the 171 merged PRs of 1.4.4 | **one**: `CVE-2026-111497` — the brotli decoder, credited to Node |
| Any of the TLS fixes reference a CVE | **no** |
| `GET /repos/oven-sh/bun/security-advisories` | **0** — Bun has never published a repo-level advisory |
| `GET /advisories?affects=bun` | **2**, both for the npm package, both third-party: `CVE-2024-21548` (prototype pollution, 7.5) and `CVE-2025-8022` (OS command injection, **withdrawn** 2025-08-11) |
| SECURITY.md | exists — `security@bun.com`, 5-day acknowledgement, *"full announcement"* |

So the machinery exists and CVEs have been assigned to Bun before. The absence here is a
process outcome, not an impossibility.

---

## 4. What Bun did say

The GitHub release page for 1.4.4 is 130 words and contains **no changelog**. The blog post
(`bun.com/blog/bun-v1.4.4`) is the only disclosure surface, and it has a **Security**
section:

> This release includes security fixes for TLS, WebSocket, the database clients and the
> package manager. These protocols, APIs and commands are affected: TLS, HTTP/1.1, HTTP/2,
> HTTP/3, WebSocket, Brotli, `Bun.serve`, `Bun.listen`, `Bun.connect`, `Bun.SQL`, …
> `node:tls`, `node:https`, `node:http`, `node:http2`, … `ws`, `fetch`, … `bun install`, …

That is a **scope statement**, not a disclosure. It names which surfaces changed; it does
not say what was wrong, which versions were affected, how bad it is, or how to tell whether
you were exposed.

### What the TLS section says instead

The blog's TLS section is headed **"Fixed: various stability issues in TLS clients and
servers."** It lists ALPN negotiation, Ed25519 certificates, `NODE_EXTRA_CA_CERTS`,
multiple key/cert pairs, `tls.DEFAULT_CIPHERS`, and `ws` ignoring TLS options.

Measured against the actual fixes, the security items are **absent or reframed**:

| Issue | Score | In the blog? |
|---|---|---|
| **Postgres never called `tls.checkServerIdentity`** | **8.7** | **Reframed as a feature** — under *what's new*: *"`tls.checkServerIdentity(hostname, cert)`: replaces the built-in hostname check on PostgreSQL, MySQL and MariaDB, like in `node:tls`"*. Nothing says the built-in check did not exist before. |
| `WebSocket` never called `checkServerIdentity` | **7.4** | **No** |
| `tls: [...]` silently plaintext | **7.4** | **No** — the only "plain TCP" mention in the post is about MySQL `caching_sha2_password` |
| `https.createServer()` without a key answering plain HTTP | **7.4** | **No** |
| `secureConnect` false `authorized` | **7.4** | **No** |
| `PGSSLMODE=verify-*` dropped | **7.4** | **No** |
| `NODE_TLS_REJECT_UNAUTHORIZED=0` weakened server mTLS | **7.4–9.1** | **Partly** — described as *"servers now only request a client certificate when `requestCert: true` is set, which matches the docs and Node.js"*, i.e. a behaviour alignment, not a fix for an enforcement bypass |
| Revoked client certificates accepted | 6.8 | **No** |
| Client certificate disclosed to a refusing server | 3.7 | **No** |

Sorted by severity, and the pattern is the point: **the higher the score, the less the blog
says.** The two most severe items — the Postgres hostname check at 8.7 and the WebSocket
hostname check at 7.4 — are respectively reframed as a feature and omitted entirely. Only
one item above is mentioned at all, and it is described as a behaviour alignment.

That last row is the clearest example: a missing hostname verification is presented as a
feature addition.

---

## 5. Did other projects have the same bugs?

Node.js treats this exact class as CVE-worthy, and has done so repeatedly:

| CVE | Project | Severity | What |
|---|---|---|---|
| [CVE-2021-44531](https://github.com/advisories/GHSA-5qpf-4xwh-5775) | Node.js | **7.4 High** | Accepting arbitrary Subject Alternative Name (SAN) types |
| [CVE-2021-44532](https://github.com/advisories/GHSA-jg6g-8j59-vr29) | Node.js | 5.3 Medium | Certificate verification bypass via SAN string injection |
| [CVE-2021-22939](https://github.com/advisories/GHSA-9mvv-4q4j-q2j8) | Node.js | 5.3 Medium | Incomplete validation of the `rejectUnauthorized` parameter |
| [CVE-2024-27983](https://github.com/advisories/GHSA-j65r-8hrg-qc6x) | Node.js | **8.2 High** | HTTP/2 server made unavailable by a small number of frames |

The closest structural match is **CVE-2021-22939** — Node issued a CVE because a TLS option
(`rejectUnauthorized`) was validated incorrectly. Bun's item 2 is the same shape: a TLS
option (`NODE_TLS_REJECT_UNAUTHORIZED`) applied where it should not, disabling enforcement.
Node's precedent says that is a CVE. Bun shipped it as a line in a "stability" list.

Item 1 (a client that never checks the peer's identity) is the class Node issued
CVE-2021-44531 and CVE-2021-44532 for. Item 5 (client certificate sent before the peer is
verified) has no exact CVE precedent I could find, but it is the same family.

**Caveat on this comparison:** Node maintains a formal security-release process with a
private fork, embargoed fixes and coordinated advisories — every one of the four CVEs above
went through `nodejs-private`. Bun's TLS fixes were found and fixed by its own automation in
public PRs. The two projects are not doing the same kind of engineering, so "Node would have
issued a CVE" is a statement about norms, not about obligation.

---

## 6. So: undisclosed, or just quiet?

The evidence supports **"shipped without disclosure"**, not **"concealed"**:

**Against concealment**
- Bun's blog has a Security section and explicitly says TLS is among the affected areas.
- The PRs are public, detailed, and link repro steps; `#44618` even labels its own table
  *"The ones that matter most"*. Nobody hid the work.
- Most of these were found internally — by the automation and by audit (`#46335` says so
  outright) — so there was no external reporter, no embargo to lift, and no researcher
  expecting credit. That is the ordinary path to "fixed quietly".
- Bun has no history of routine advisories: **0** repo-level GHSAs ever. Its two CVEs came
  from third parties.

**Against "it was disclosed"**
- No CVE, no GHSA, no affected-version range, no severity, no mitigation guidance.
- The specific security defects are missing from the two places a user would look (the
  GitHub release notes, which have no changelog, and the blog's TLS section, which is framed
  as stability).
- One is actively reframed: a missing hostname check presented as a new feature.
- A user on 1.4.3 cannot determine from any Bun-authored source that their Postgres client
  was not verifying the server's hostname, or that their `Bun.listen` with `tls: []` was
  serving plaintext.

**The practical difference.** Disclosure exists so an operator can answer three questions:
*were we exposed, how bad was it, and what do we do?* Bun's Security paragraph answers none
of them. Compare: Node's advisory for CVE-2021-22939 states the affected versions, the
precise condition, and the fix version.

---

## 7. What would change the answer

If Bun had, in the 1.4.4 notes, published even a bare list — "TLS: hostname verification was
not performed for WebSocket clients; Postgres did not check the certificate hostname; `tls:
[]` produced a plaintext listener" — with the affected range, this document would say
"disclosed, no CVE". That is a paragraph of work, and it is the difference between a
security fix and a security fix nobody can act on.

**For a user reading this:** treat 1.4.4 as a security release regardless of its labelling.
If you ran 1.4.3 or earlier and used any of: `WebSocket` with `tls` options, mTLS on
`Bun.serve`/`Bun.listen`, `Bun.SQL`/Postgres over TLS, `https.createServer`, or a shared
`https.Agent`, assume you were affected. There is no advisory to check against; the
reproduction details are in the PRs, which are linked from `02-security-severity.md` F13.

---

*Method: `GET /repos/oven-sh/bun/security-advisories`; `GET /advisories?affects=bun` and
`?cve_id=` for each comparator; the 171 merged PRs of 1.4.4 scanned for CVE strings; the
blog post fetched and its Security and TLS sections read in full; sub-PRs (#41648, #35245,
#41490, #43946) read to see how each was filed.*
