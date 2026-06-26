# Threat Model

Implementation of Kelsey, Lang & Lucks (2024), IACR CiC 2/2/24.

---

## Adversary Model

Security is argued in the **IND-CMA (existential unforgeability under chosen-message attack)** model. The adversary is a probabilistic polynomial-time algorithm that:

- can observe any number of honestly generated signatures on messages of its choice (under a fixed public key)
- cannot rewind or reset the signing oracle
- wins if it produces a valid signature on a message it never submitted to the oracle

For the **distributed (KK) setting**, the adversary additionally:

- controls up to **k−1 trustees** statically (honest-but-curious or fully corrupted)
- observes the full view of corrupted trustees: their seeds, all PRF outputs, and CRV contributions
- cannot corrupt the aggregator or observe the aggregator's internal state beyond what trustees receive in the protocol

### What "corruption" means

A corrupted trustee exposes:
- Its PRF seed `seed_t`
- All outputs: `PRF_R(seed_t, keyId)`, `PRF_Chk(seed_t, keyId)`, `PRF_Auth(seed_t, keyId, R)`, `PRF_Chain(seed_t, keyId, i, j)`
- Its round-1 outputs `(Rt, CHKt)` and round-2 outputs `(Zt, PATHt)` for all signed messages

Even with all of the above, a coalition of k−1 trustees cannot recover `CRV.SK[i][j]` — see Masking section below.

---

## Security Assumptions

| Assumption | Used for |
|---|---|
| SHA-256 second-preimage resistance | OTS one-time security, chain irreversibility |
| SHA-256 collision resistance | Merkle tree binding |
| SHA-256 pseudorandomness (PRF security) | `hash_lms` used as PRF for all PRF tweaks (30–34) |
| Secure channels between trustees and aggregator | Protocol confidentiality; **not provided by this implementation** |
| Each `keyId` used at most once | One-time key constraint; **enforced by `used_keys` in `distributed_signing.py`** |

Security reduces to the above assumptions via the standard hash-based OTS proof (Buchmann et al.) extended to the distributed setting in §4–5 of the paper. No number-theoretic assumptions.

---

## CRV Masking (Why k−1 Trustees Learn Nothing)

`KK_Setup` constructs the masked signing key as:

```
CRV.SK[i][j] = XOR(SK[i][j], PRF_Chain(seed_0, keyId, i, j),
                               PRF_Chain(seed_1, keyId, i, j), ...)
```

A coalition of t < k trustees observes their own `PRF_Chain` contributions but **not** the contributions of the remaining k−t trustees. Since each `PRF_Chain(seed_t, ...)` is modelled as a PRF output (pseudorandom under the seed), the missing contributions act as a one-time pad over `SK[i][j]`.

Formally: the joint distribution of `(CRV.SK[i][j], {PRF_Chain(seed_t, ...)}_{t in coalition})` is computationally indistinguishable from `(U_{N_BYTES}, {PRF_Chain(seed_t, ...)}_{t in coalition})` where `U_{N_BYTES}` is uniformly random. The same applies to `CRV.R`, `CRV.CHK`, and `CRV.PATH`.

---

## Attack Scenarios

### 1. Forgery via digit manipulation

**Goal**: produce a valid signature `(R, Z')` on a new message `M'` after observing one signature `(R, Z)` on `M`.

**What the adversary has**: `Z[i] = chain_el(seed[i], i, b_all[i], keyId)`. By forward-hashing, it can compute `chain_el(seed[i], i, d, keyId)` for any `d > b_all[i]` — these are positions "above" the signing point.

**Why it fails**: To forge a signature for `M'` with digit sequence `b'_all`, the adversary needs `Z'[i] = chain_el(seed[i], i, b'_all[i], keyId)`.

- For any `i` where `b'_all[i] > b_all[i]`: computable from `Z[i]` by hashing forward.
- For any `i` where `b'_all[i] < b_all[i]`: requires a SHA-256 second preimage of `Z[i]`.

The Winternitz checksum `csum = A×(CHAIN_LEN−1) − Σb[i]` enforces that if the adversary increases any message digit, the checksum decreases by the same amount. Any net increase in message digits forces a corresponding decrease in checksum digits, requiring the adversary to produce a chain element **below** the signed position for at least one chain — a preimage.

**Demonstrated by**: `src/attacks.py::attack_forgery()`, `test/test_attacks.py::test_forgery_*`

---

### 2. Key reuse (one-time violation)

**Goal**: learn chain positions by observing two signatures under the same `keyId`.

**What the adversary gains**: After seeing signatures `Z1` (digit sequence `b1`) and `Z2` (digit sequence `b2`):

For each chain `i`, the adversary can compute `chain_el(seed[i], i, d, keyId)` for **all** `d ≥ min(b1[i], b2[i])` — by hashing forward from whichever `Z` value has the lower digit.

Since message digits are approximately uniform over `[0, 255]`, the expected value of `min(b1[i], b2[i])` is `255/3 ≈ 85`. This means roughly **67% of each chain is exposed** after just two signings.

**Impact**: Does not immediately yield a forgery (the checksum still guards against arbitrary target messages), but severely reduces the adversary's work space. The protocol-level defence (`used_keys` tracking) ensures a trustee refuses to sign a second message with the same `keyId`.

**Demonstrated by**: `src/attacks.py::attack_key_reuse()`, `test/test_attacks.py::test_key_reuse_*`

---

### 3. Coalition below threshold

**Goal**: k−1 corrupted trustees attempt to compute the aggregated signing key or produce a signature without the k-th trustee's participation.

**Why it fails**: `CRV.SK[i][j]` is XOR-masked by all k trustees' `PRF_Chain` contributions. Missing one contribution means the adversary is missing a uniformly random pad — it cannot recover `SK[i][j]`. At the protocol level, `KK_Aggregator_Sign()` collects round-1 outputs from all k trustees before proceeding to round 2; if fewer than k respond, it returns `None`.

**Demonstrated by**: `src/attacks.py::attack_coalition()`, `test/test_attacks.py::test_coalition_*`

---

### 4. Round-2 message substitution (forked protocol)

**Goal**: adversary intercepts round-1 outputs `(Rt, CHKt)` and substitutes a different message `M'` in round 2.

**Why it fails**: The round-2 integrity token is:

```
CRV.CHK[t] = XOR(PRF_Auth(seed_t, keyId, R), CHK_0, CHK_1, ...)
```

`KK_Auth(seed_t, keyId, R', CRV.CHK_combined)` verifies that `PRF_Auth(seed_t, keyId, R') == CHK_prime`. If the adversary substitutes `R' ≠ R`, this check fails because `PRF_Auth` is keyed by `seed_t` — computing a valid token for a different `R'` requires a PRF preimage.

**Demonstrated by**: `test/test_distributed_signing.py::test_kk_sign2_returns_none_when_auth_fails`

---

## Out of Scope

The following are **not** addressed by this implementation:

| Threat | Notes |
|---|---|
| Side-channel attacks (timing, power) | `hash_lms` uses `hashlib` which has no constant-time guarantees for short inputs |
| Secure channel between trustees and aggregator | This implementation runs in a single process; a real deployment needs TLS or equivalent |
| Denial-of-service against the aggregator | Any trustee can abort `KK_Aggregator_Sign()` by refusing to respond to round 1 |
| Key management and seed distribution | Seeds are generated with `os.urandom(N_BYTES)` — distribution and storage are caller's responsibility |
| Long-term key state (Merkle tree exhaustion) | `stateful_hash.py` tracks used leaf indices; recovery from state loss is undefined |
| Implementation bugs in `hashlib` or `os.urandom` | Assumed to be correct |

---

## Design Choices and Their Security Implications

| Choice | Rationale | Security consequence |
|---|---|---|
| `N_BYTES = 16` (128-bit security) | Matches §3.1 of the paper | Collision probability ≈ 2^{-64} after 2^{64} queries — pre-quantum only |
| `W = 8` (byte-level Winternitz) | Smallest signature (288 B), slowest keygen | No security difference vs smaller W; just a size/speed tradeoff |
| Domain separation via 4-byte big-endian tweaks | Prevents cross-context hash collisions (OTS chain vs Merkle node vs PRF) | Without this, an adversary could potentially reuse a chain element as a Merkle node |
| `os.urandom` for all seeds and nonces | Cryptographically secure RNG | Correct; Python's `os.urandom` reads from `/dev/urandom` (Linux) or `CryptGenRandom` (Windows) |
| `int.from_bytes` XOR in `_xor_many` | Performance (5.9× faster than byte loop) | No security impact — XOR is commutative regardless of representation |
