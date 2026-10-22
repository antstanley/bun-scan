# Two advisories, checked against Bun

**Question:** do any open PRs address

* [Header Accordions: QPACK amplification attacks against HTTP/3 servers](https://foxio.io/blog/header-accordions-qpack-amplification-attacks-against-http-3-servers) (FoxIO, 2026-10-20)
* [emudhra.we-have-a-problem.com](https://emudhra.we-have-a-problem.com/) (eMudhra intermediate CA compromise, 2026-10-20)

**Short answer: no open PRs — but both are already fixed on `main`, and neither fix is in
a release.** Bun 1.4.3 is vulnerable to both, exactly as both pages say. The fixes merged
on 2026-10-21 and 2026-10-22, hours before this check.

These are written up as findings **F11** (QPACK) and **F12** (eMudhra) in
[`02-security-severity.md`](02-security-severity.md); this file is the detailed appendix —
the reproduction commands, the release-lag table, and the reasoning about why each was
missed by the PR triage.

| Advisory | Bun 1.4.3 | `main` | Fix | Merged | In a release? |
|---|---|---|---|---|---|
| QPACK amplification | **vulnerable** | fixed | [#46392](https://github.com/oven-sh/bun/pull/46392) + [#46436](https://github.com/oven-sh/bun/pull/46436) | 2026-10-22 02:13Z / 04:18Z | **No** |
| eMudhra CA compromise | **vulnerable** | fixed | [#46300](https://github.com/oven-sh/bun/pull/46300) | 2026-10-21 07:50Z | **No** |

That is the same shape as the brotli CVE in the main report: `main` is patched within
hours of publication, and the release channel — 1.4.3, published 2026-10-10 — is not.

---

## A1 · QPACK header amplification (FoxIO)

### What the attack is

QPACK compresses HTTP/3 header fields. A dynamic-table entry of ~4 KiB can be referenced
by a 1-byte indexed reference, and those references are cheap on the wire but not in
memory: each one materializes a fresh copy of the full entry. One connection with 100
streams and ~60,000 references per stream (5.8 MiB of wire) is enough to OOM-kill a 2 GiB
container.

The defence RFC 9114 §4.2.2 describes is a **cumulative** budget over the decoded field
list — name + value + **32 bytes of overhead per field** — enforced as fields are decoded
and retained, not a per-field size check and not a check on the compressed frame.

### What FoxIO says about Bun

FoxIO lists **Bun 1.4.3** under "Unpatched as of October 20, 2026", with a wire-to-memory
ratio of **~4000×**, and gives the mechanism:

> Bun's HTTP/3 support uses lsquic under the hood but replaces lsquic's built-in
> header-set callbacks (which cap at 64 KiB cumulative) with its own
> `us_quic_hsi_prepare`/`process` in `quic.c`, which check per-header size (64 KiB) but
> never cumulative. The `es_max_header_list_size=16384` is advertised in SETTINGS but
> never enforced.

They also report a second bug in the same function: the buffer capacity is tracked in an
`unsigned int` and grown by doubling, which they say turns the amplification into a
permanent denial of service.

Mitigation they give for Bun: *"Don't expose HTTP/3 servers."*

### Verified against the source

**1.4.3 is vulnerable — confirmed.** I fetched `packages/bun-usockets/src/quic.c` at tag
`bun-v1.4.3` (1,636 lines). It contains no cumulative accounting at all:

```
$ grep -nE "us_quic_hsi_process|h->size|max_fields|es_max_header_list_size" quic_143.c
544:static int us_quic_hsi_process(void *hset_p, struct lsxpack_header *hdr) {
838:    ctx->settings.es_max_header_list_size = 16 * 1024;
1382:    ctx->settings.es_max_header_list_size = 64 * 1024;
```

The setting is advertised and nothing reads it back. There is no `h->size`, no field
count, no cap.

**`main` is fixed — confirmed.** The current `quic.c` (1,680 lines) accumulates per RFC
9114 §4.2.2 and enforces it:

```c
static int us_quic_hsi_process(void *hset_p, struct lsxpack_header *hdr) {
    ...
    h->size += (size_t) hdr->name_len + hdr->val_len + 32;   /* the 32-byte overhead */
    h->fields++;
    if (h->size > h->max_size || h->fields > h->max_fields) {
        h->too_large = 1;
        return h->size > us_quic_hset_hard_cap(h) ||
            h->fields > US_QUIC_HSET_HARD_CAP_FACTOR * h->max_fields ? -1 : 0;
    }
```

with `max_fields = US_QUIC_MAX_REQUEST_FIELDS` for a server (200), and a hard cap at
`2 × max_size`. The second bug is gone too: `ncap` is now a `size_t` bounded by
`hard_cap` before it is narrowed into `h->cap`, so the doubling cannot wrap.

### The fix

**[#46392](https://github.com/oven-sh/bun/pull/46392)** — merged 2026-10-22 02:13Z — says:

> **HTTP/3**: header size limits are now enforced, counted as in RFC 9114 §4.2.2. The
> server enforces the limit it advertises (`--max-http-header-size`, 16 KB by default)
> and answers `431` to a request over it. The client advertises 64 KB as before, accepts
> up to 256 KB like the HTTP/2 client… A request may have 200 fields, as in HTTP/1.1 and
> HTTP/2.

**[#46436](https://github.com/oven-sh/bun/pull/46436)** — merged two hours later — lifts
lsquic's own 64 KB internal caps so large-but-legal header blocks work, and explicitly
leaves the limits from #46392 untouched: *"The limits from #46392 are unchanged: the size
boundary, 200 fields, the hard cap, `431`, `ResponseHeadersTooLarge`."*

With a 16 KB cumulative budget and a 200-field cap per header set, the 4 KiB-entry
referenced 60,000 times has nowhere to go: the fourth reference puts the stream over
budget and it gets `431`. The amplification is bounded by the advertised limit.

### Exposure, and what to do now

Only apps that enable the HTTP/3 server (`Bun.serve({ http3: true })`) — or that use
`fetch` with `protocol: "http3"` — are in the path. That is opt-in, not default. If you
run 1.4.3 with an HTTP/3 listener on an untrusted network, FoxIO's advice stands:
**take the listener down** until a release contains #46392, or build from `main`.

### Why this was not in the original report

The 202-PR triage covered **open** PRs. The QPACK fix was merged before I looked, so it
was never a candidate. That is worth saying plainly: "no open PR" here means "already
fixed", not "nobody is working on it".

---

## A2 · eMudhra intermediate CA compromise

### What happened

Eight eMudhra (emSign) **intermediate** CA private keys are compromised, and the cause is
worse than a leak: per the advisory, *"the private keys for the intermediate certificates
were incorrectly generated by the CA. This means that anyone can recover them from the
certificates."* They chain to roots trusted by the Mozilla, Microsoft, Apple and Chrome
programs and by downstream trust stores, and were created in April 2025.

Anyone holding those keys can issue a certificate for any domain and have it verify
against any client that still trusts the intermediates. Browsers blocked them from
2026-10-17; the practical risk is to **non-browser clients** that do not consume
revocation information — command-line tools, SDKs, runtimes.

The page lists **Bun: pending**.

### Verified against the source

**1.4.3 is vulnerable — confirmed.** At tag `bun-v1.4.3` there is no SPKI blocklist file
at all (`packages/bun-usockets/src/crypto/blocked_spkis.cpp` does not exist in that tree),
and the bundled roots are NSS **3.128** (from #42835, 2026-09-16). Bun verifies against
that **bundled** store by default; `--use-system-ca` / `NODE_USE_SYSTEM_CA=1` is opt-in.

**`main` is fixed — confirmed.** [#46300](https://github.com/oven-sh/bun/pull/46300),
merged 2026-10-21 07:50Z, is titled *"tls: reject chains containing blocked public keys,
update root certificates to NSS 3.131.1"*. It adds a compiled-in list and fails
verification with `CERT_REVOKED` for any chain holding a listed key, then regenerates the
bundle from NSS 3.131.1 (118 certificates, byte-identical set to Node's).

The list is not generic. `blocked_spkis.cpp` holds exactly **8 SHA-256 SPKI hashes**, and
the comments name them:

```
C=US, O=eMudhra Inc, CN=EM DV TLS CA - G3C
C=US, O=eMudhra Inc, CN=EM EV TLS CA - G3C
C=US, O=eMudhra Inc, CN=EM OV TLS CA - G3C
C=US, O=eMudhra Inc, CN=EM OV CS CA - G3C
C=NL, O=eMudhra BV,  CN=EM DV TLS CA - G3B
C=NL, O=eMudhra BV,  CN=EM OV CS CA - G3B
C=NL, O=eMudhra BV,  CN=EM OV TLS CA - G3B
C=NL, O=eMudhra BV,  CN=EM EV TLS CA - G3B
```

Eight intermediates, eight hashes — matching the advisory's count. The check is ported
from Node's `crypto_context.cc` and uses Node's list, and it runs in
`us_x509_verify_chain`, which the file's header comment says is asked after every chain
Bun verifies.

**Note on why a blocklist rather than removing roots.** The compromised items are
*intermediates*, and a root store cannot express "distrust this intermediate" — the
intermediate is never in it. A SPKI blocklist is the correct mechanism, and it is what
Node did. (Some distributions took the blunter route of deleting the two chaining roots,
`AAA Certificate Services` and `emSign ECC Root CA - G3`; Bun's bundled `certdata.txt` on
`main` still contains `AAA Certificate Services`, which is expected — the blocklist is
doing the work instead.)

### What to do now

Upgrade once a release contains #46300. Until then, on 1.4.3:

* Pass an explicit CA bundle that already excludes the eMudhra roots — your distro's
  updated `ca-certificates` (Alpine `20261020-r0`, Debian `20260816+nmu1`, NSS 3.131.1,
  curl's 2026-10-20 bundle) — via `ca:` / `NODE_EXTRA_CA_CERTS`, rather than relying on
  Bun's bundled store.
* `NODE_USE_SYSTEM_CA=1` switches Bun to the OS store, which Apple and Microsoft have
  been updating since 2026-10-19/20. I did **not** verify that Bun's system-store path
  picks up a revocation-based block on every platform, so treat this as a maybe, not a
  fix.

### Why this was not in the original report

Same reason: merged before the snapshot, so it never appeared as an open PR. It also
would not have been caught by the PR-text classifier — #46300's title says "blocked public
keys", not "eMudhra".

---

## What this adds to the main finding

The main report's systemic point was that security fixes pile up in a 5,653-PR queue.
These two sharpen it into something more specific and, I think, more useful:

**Detection and patching are working. Shipping is not.**

| Event | `main` fixed | Released |
|---|---|---|
| brotli CVE-2026-111497 published 2026-10-21 | 2026-10-21 (dependency bump) | **not yet** |
| eMudhra disclosure 2026-10-20 | 2026-10-21 | **not yet** |
| QPACK amplification published 2026-10-20 | 2026-10-22 | **not yet** |

Three independent, high-profile advisories in three days, three patches on `main` within
24 hours, and **zero** of them reachable by `bun upgrade`. The latest release is twelve
days old. Whatever the release cadence normally is, it is now the binding constraint on
Bun's security posture — not the review queue, and not the agent.

Concretely: a 1.4.4 cut from `main` today would close a remote memory-corruption bug, a
remote DoS, and a CA-trust compromise in one release. Nothing else in this evaluation has
that ratio.

---

## Reproducing these checks

```sh
# 1.4.3 vs main, HTTP/3 header accounting
gh api "repos/oven-sh/bun/contents/packages/bun-usockets/src/quic.c?ref=bun-v1.4.3" \
  -q .content | base64 -d | grep -nE "h->size|max_fields|es_max_header_list_size"
gh api "repos/oven-sh/bun/contents/packages/bun-usockets/src/quic.c" \
  -q .content | base64 -d | grep -nE "h->size|max_fields|hard_cap"

# blocked SPKIs: absent in 1.4.3, eight eMudhra entries on main
gh api "repos/oven-sh/bun/git/trees/bun-v1.4.3?recursive=1" -q '.tree[].path' | grep blocked_spkis
gh api "repos/oven-sh/bun/contents/packages/bun-usockets/src/crypto/blocked_spkis.cpp" \
  -q .content | base64 -d | grep -E '^ *// *C='

# the PRs
gh api repos/oven-sh/bun/pulls/46392 -q '.state, .merged_at, .title'
gh api repos/oven-sh/bun/pulls/46300 -q '.state, .merged_at, .title'
```
