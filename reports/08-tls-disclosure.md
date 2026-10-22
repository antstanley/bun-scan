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

| # | Issue | CWE | Security-relevant? |
|---|---|---|---|
| 1 | `WebSocket` never calls `tls.checkServerIdentity`; ignores `tls.serverName` (#41648) | 295 | **Yes** — accepts a cert for any host |
| 2 | `NODE_TLS_REJECT_UNAUTHORIZED=0` disables a **server's** `requestCert` enforcement (#35245) | 295 | **Yes** — client-side env var weakens mTLS |
| 3 | `tls: [...]` passed to `Bun.listen` / `Bun.connect` starts a **plaintext** listener (#41490) | 319 | **Yes** — no error, no warning |
| 4 | `https.createServer()` without a usable key/cert answers **plain HTTP** (#41672) | 319 | **Yes** — silent cleartext |
| 5 | Client certificate still sent to a server the client then refuses (#43946) | 200 | **Yes** — credential disclosure |
| 6 | `secureConnect` reports `authorized === true` for a peer that failed the key proof (#44422, #32929) | 287 | **Yes** — false auth result |
| 7 | An mTLS server never sees `crl`, so a revoked client is `authorized` (#41641) | 299 | **Yes** — revocation unimplemented |
| 8 | Requests with different client certs/CAs share one `https.Agent` socket (#42498) | 488 | **Yes** — credential crossover |
| 9 | `PGSSLMODE=verify-*` dropped next to a `TLS_*` URL variable (#44498) | 295 | **Yes** — silent downgrade |
| — | Use-after-free from `destroy()` in `ALPNCallback` (#44462) | 416 | memory safety |
| — | TLS `write()` loses 16 KB while another socket is stalled (#44529) | 703 | data integrity |
| — | SIGABRT in `fetch` through an env proxy (#44458) | 248 | DoS |

Plus [#46335](https://github.com/oven-sh/bun/pull/46335): an ASAN-confirmed heap-use-after-free
in the stream TLS engine, *"Found by audit. No issue or crash report names it."*

**Nine of these are certificate-validation or transport-security defects**, not stability
bugs. Items 1, 3 and 4 mean a client can be made to talk to the wrong host, or to believe it
is speaking TLS when it is not.

---

## 2. CVE status

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

## 3. What Bun did say

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

| Issue | In the blog? |
|---|---|
| `WebSocket` never called `checkServerIdentity` | **No** |
| `NODE_TLS_REJECT_UNAUTHORIZED=0` weakened server mTLS | **Partly** — described as *"servers now only request a client certificate when `requestCert: true` is set, which matches the docs and Node.js"*, i.e. a behaviour alignment, not a fix for an enforcement bypass |
| `tls: [...]` silently plaintext | **No** — the only "plain TCP" mention in the post is about MySQL `caching_sha2_password` |
| `https.createServer()` without a key answering plain HTTP | **No** |
| Client certificate disclosed to a refusing server | **No** |
| `secureConnect` false `authorized` | **No** |
| Revoked client certificates accepted | **No** |
| `PGSSLMODE=verify-*` dropped | **No** |
| **Postgres never called `tls.checkServerIdentity`** | **Reframed as a feature** — under *what's new*: *"`tls.checkServerIdentity(hostname, cert)`: replaces the built-in hostname check on PostgreSQL, MySQL and MariaDB, like in `node:tls`"*. Nothing says the built-in check did not exist before. |

That last row is the clearest example: a missing hostname verification is presented as a
feature addition.

---

## 4. Did other projects have the same bugs?

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

## 5. So: undisclosed, or just quiet?

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

## 6. What would change the answer

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
