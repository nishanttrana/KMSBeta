# Algorithm transitions: one cited NIST catalogue (3.2.0-beta)

**Rule.** What the platform says about an algorithm (its security strength,
its post-quantum category, whether a quantum computer breaks it, and whether
NIST allows it today or on a given date) comes only from
[`pkg/cryptocatalog`](../../pkg/cryptocatalog/catalog.go). Every fact there
names the document and table it was copied from. No service keeps its own
algorithm list, score or deadline.

Consumers: the Crypto Agility tab and keycore `/agility/*`, `pkg/cbom` tiers,
the policy service's `minAlgorithmTier` floor, and the pqc and discovery
services' classification, readiness and timeline.

## Why

NIST CSWP 39-upd1, *Considerations for Achieving Crypto Agility* (December
2025, updated 2026-06-29), §5.2, asks for one machine-consumable crypto policy
kept in step with NIST's deprecation decisions. Its 2026 update (Appendix C)
changed §2.3: it no longer says 112-bit public-key algorithms are disallowed
in 2031, and it points to **NIST IR 8547** and **SP 800-131A Rev. 3** for the
revised transition away from quantum-vulnerable algorithms.

Before this, four hand-kept lists disagreed:

| | keycore agility | pqc / discovery | pkg/cbom (policy floor) |
|---|---|---|---|
| RSA-2048 | "legacy" | weak (QSL 52) | classical-128 (it is 112-bit) |
| RSA-4096, ECDSA | not flagged | **strong** (QSL 88 / 78) | classical-256 / -128 |
| SLH-DSA | not quantum-safe | not post-quantum | pqc-only |
| AES-128-CBC | "legacy" | weak | classical-128 |
| HMAC, Ed25519, ECDH | not flagged | strong / weak | **deprecated** (refused under any floor) |

The CBOM mapping drives policy enforcement, so a `classical-192` floor let
RSA-3072 (128-bit) through and refused every HMAC operation.

## Sources and their status

| ID | Document | Status | Used for |
|---|---|---|---|
| `SP800-131Ar3` | SP 800-131A Rev. 3, Transitioning the Use of Cryptographic Algorithms and Key Lengths | **initial public draft**, 2024-10 | today's status; 112-bit deprecation after 2030; TDEA, ECB, FF3, SHA-1, 224-bit hashes, HMAC keys |
| `IR8547` | IR 8547, Transition to Post-Quantum Cryptography Standards | **initial public draft**, 2024-11 | quantum-vulnerable algorithms disallowed after 2035; PQC categories; ML-KEM/ML-DSA/SLH-DSA/AES strengths |
| `SP800-57pt1r5` | SP 800-57 Part 1 Rev. 5 | final, 2020-05 | RSA/DH/TDEA strengths (Table 2), HMAC strengths (Table 3) |
| `FIPS186-5` | FIPS 186-5 | final, 2023-02 | Ed25519 (128) and Ed448 (224) strengths |
| `FIPS203/204/205`, `SP800-208` | ML-KEM, ML-DSA, SLH-DSA, LMS/XMSS | final | the standard that specifies each |
| `FIPS46-3` | DES | withdrawn 2005-05-19 | single DES |
| `CSWP39-upd1` | Considerations for Achieving Crypto Agility | final, 2026-06 | hybrid schemes (§3.2.4) |

Because the two transition documents are drafts, every screen that shows
one of their dates labels it proposed ("initial public draft, dates
proposed"). When NIST finalises them, update the catalogue and its test in
the same change; `TestCatalogMatchesNISTTables` pins every figure.

## The schedule the catalogue encodes

"After 2030" means from 2031-01-01; "after 2035" from 2036-01-01.

| Algorithm | Strength | Today | From 2031-01-01 | From 2036-01-01 |
|---|---|---|---|---|
| RSA-2048, DH-2048, P-224 (112-bit) | 112 | acceptable | deprecated | disallowed |
| RSA ≥ 3072, P-256/384/521, Ed25519, ECDH ≥ P-256 | 128–256 | acceptable | acceptable | disallowed |
| RSA-1024 and anything under 112 bits | < 112 | legacy use | legacy use | legacy use |
| DSA | — | legacy use (verify only) | | |
| X25519 / X448 | — | not approved (not an SP 800-56A scheme) | | |
| ML-KEM, ML-DSA, SLH-DSA, LMS/XMSS | 128–256, cat. 1–5 | acceptable | acceptable | acceptable |
| AES-128/192/256 (CBC, CTR, GCM, CCM, XTS, KW…) | 128–256, cat. 1/3/5 | acceptable | acceptable | acceptable |
| AES-ECB | | legacy use (decrypt only) | | |
| AES-FF3 | | disallowed | | |
| TDEA (3DES), 2TDEA | 112 / 80 | legacy use (decrypt only) | | |
| DES | | disallowed | | |
| HMAC-SHA-1, HMAC with 224-bit hashes | 128 / 192 | deprecated | disallowed | |
| HMAC-SHA-256/384/512 | 256 (key-bounded) | acceptable | | |
| SHA-1 | 80 | legacy use (signature verification) | | |
| SHA-224, SHA-512/224, SHA3-224 | 112 | deprecated | disallowed | |
| ChaCha20(-Poly1305), RC4, MD5 | | not approved | | |
| Hybrid ML-KEM (X25519MLKEM768, …) | cat. of its ML-KEM part | not tabled; quantum-resistant | | |

A name that does not state a parameter set (`RSA`, `AES`, `ECDSA`,
`CRYSTALS-Kyber`, `Dilithium3`, `Brainpool-P256`) is **not assessed**: no
status, strength or tier is guessed. The tab counts these keys separately.

## How it is enforced

- `pkg/cryptocatalog` tests pin each row above to its source table, the
  day boundaries, the not-assessed names and the old mislabels.
- `pkg/cbom`: tiers come from the catalogue. `classical-112` is new (RSA-2048
  moved down from `classical-128`); `not-assessed` is new. Neither
  `deprecated` nor `not-assessed` meets any floor, and an unknown floor is met
  by nothing (`TestMeetsFloorFailsClosed`).
- Policy service: `spec.minAlgorithmTier` must be a floor, or create and
  update are refused and audited (`audit.policy.floor_refused`,
  `TestUnknownFloorRefusedAndAudited`). Floor denials name the algorithm's
  tier (`TestCryptoFloorUsesNISTStrengths`).
- keycore `GET /agility/posture` measures live keys against the schedule
  (`TestAgilityPostureAgainstNISTSchedule`).
- pqc: milestones are the catalogue's dated changes, with affected-asset
  counts and citations; a plan's default deadline is 2035-12-31 (IR 8547),
  and any other `timeline_standard` must come with an explicit deadline
  (`TestTimelineMilestonesAreSourced`, `TestPlanDeadlineMustBeSourced`).

## Open

- Existing policies with `minAlgorithmTier: classical-128` now deny RSA-2048
  (112-bit). That is the documented meaning of the floor; tenants that want
  RSA-2048 set `classical-112`.
- The tenant-wide `MinAlgorithmTier` posture control (keycore
  `posture_controls.go`) is stored but not enforced by keycore; only
  per-policy floors are enforced. To be enforced or removed.
- The pqc readiness score still weights its inputs (55/30/15); it is being
  replaced by the CARAF assessment (threats, asset profiles, X/Y/Z timeline
  and cost) in the next crypto-agility slices.
- Certificate signature algorithms given as `SHA256-RSA` style strings are
  not parsed (not assessed); certificates are assessed by their key.
