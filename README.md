# Distributed Hash-Based Signatures

Implementation of the distributed and threshold Winternitz/Lamport signature scheme described in:

> Kelsey, Lang, Lucks — *Turning Hash-Based Signatures into Distributed Signatures and Threshold Signatures* (2024)  
> https://cic.iacr.org/p/2/2/24/pdf

The project implements the full signing stack: Winternitz OTS, a Merkle tree for stateful signing, and a k-of-k distributed signing protocol where multiple trustees cooperate to produce a single verifiable Lamport signature without any trustee ever holding the complete private key.

---

## Requirements

- Python 3.10+
- pytest (for running tests)

```
pip install pytest
```

No other dependencies — the implementation uses only the Python standard library (`hashlib`, `secrets`, `os`).

---

## Project Structure

```
.
├── conftest.py              # adds src/ to sys.path so tests can import modules
├── src/
│   ├── utils.py             # shared parameters (N, W, A, C, CHAIN_LEN) and types (CRV, CPK)
│   ├── hash.py              # hash_lms: tweakable SHA-256 used throughout
│   ├── lamport.py           # Winternitz OTS — Gen, Sign, Verify, WINTER
│   ├── merkle_tree.py       # Merkle tree — MT_Construct, MT_MakePath, MT_Verify, MT_Extract
│   ├── stateful_hash.py     # Stateful HBS — StatefulGen, StatefulSign, StatefulVerify
│   ├── distributed_signing.py  # k-of-k distributed signing — KK_Setup, KK_Aggregator_Sign, KK_Sign1/2
│   ├── prf_rf_game.py       # PRF/RF distinguishing game — F, PRFRFGame, Init, Query, Final
│   └── shard_trustee.py     # Shard trustee helpers for threshold signing
└── test/
    ├── test_lamport.py          # unit tests for Winternitz OTS
    ├── test_merkle_tree.py      # unit tests for Merkle tree
    ├── test_stateful_hash.py    # unit tests for stateful signing
    ├── test_integration.py      # end-to-end tests: Gen → Sign → Verify
    └── test_distributed_signing.py  # unit + integration tests for k-of-k protocol
```

---

## Parameters

Defined in `src/utils.py` (see §3.1 of the paper):

| Parameter | Value | Meaning |
|-----------|-------|---------|
| `N` | 128 | Security parameter in bits |
| `N_BYTES` | 16 | N / 8 — byte length of hash outputs and keys |
| `W` | 8 | Winternitz parameter (chain length = 2^W = 256) |
| `A` | 16 | Message digits = N / W |
| `C` | 3 | Checksum digits |
| `CHAIN_LEN` | 256 | Chain length = 2^W |

---

## Running Tests

From the project root:

```bash
python -m pytest test/ -v
```

All 66 tests should pass. To run a specific test file:

```bash
python -m pytest test/test_integration.py -v
python -m pytest test/test_distributed_signing.py -v
```

---

## Module Overview

### `hash.py` — Tweakable Hash

`hash_lms(tweak, *data)` prepends a tuple of integers as a domain-separation tweak before hashing. Each integer in the tweak is encoded as a 4-byte big-endian value. This mirrors the LMS construction and prevents cross-context collisions between hash calls used in different parts of the scheme.

### `lamport.py` — Winternitz OTS

Implements the Winternitz one-time signature scheme (Extension 5 of the project):

- **`Gen(KeyID)`** — generates A+C hash chains, each of length `CHAIN_LEN`. The public key is a hash over all chain tips.
- **`WINTER(h, SK)`** — maps a hash value `h` to signature elements by indexing into each chain at position `h_i` (W-bit digit of `h`), plus a checksum.
- **`Sign(M, R, KeyID, SK)`** — computes `h = Hash(R, M)` then runs WINTER.
- **`Verify(R, Z, M, KeyID)`** — hashes the signature elements forward to the chain tips and recomputes the public key.

### `merkle_tree.py` — Merkle Tree

Supports stateful signing over a set of one-time keys:

- **`MT_Construct(pk_leaves)`** — builds a complete binary hash tree over a list of public keys. Requires a power-of-two number of leaves.
- **`MT_MakePath(pk_leaves, key_id)`** — returns the sibling path from leaf `key_id` to the root, with `key_id` appended at the end.
- **`MT_Verify(path, leaf_value)`** — recomputes the root from a leaf value and its sibling path.
- **`MT_Extract(path)`** — extracts `key_id` from the last element of the path.

### `stateful_hash.py` — Stateful HBS

Combines Lamport OTS with the Merkle tree for multi-message signing:

- **`StatefulGen(d)`** — generates `d` one-time key pairs and builds a Merkle tree. Stores the root in `cpk.ROOT`.
- **`StatefulSign(keyID, M)`** — signs `M` using key `keyID`. Each key can only be used once; a second attempt returns `()`.
- **`StatefulVerify(M, r, path, z)`** — extracts `keyID` from the path, verifies the Winternitz signature, then verifies the Merkle path back to `cpk.ROOT`.

### `distributed_signing.py` — k-of-k Distributed Signing

Implements the KK protocol from §4 of the paper. The aggregator and k trustees cooperate in two rounds to produce a signature without any party learning the combined private key:

**Setup:**
- **`KK_Setup(trustee_seeds, KeyID, SK, R, PATH)`** — given k trustee PRF seeds, computes XOR-secret-shared versions of `R`, `SK`, `PATH`, and per-trustee commitment checks `CHK`. Returns a `CRV` (Common Reference Value).

**Signing (2-round protocol):**
- **Round 1 — `KK_Sign1(t, KeyID, M)`** — trustee `t` derives its mask share `Rt` and commitment `CHKt` from its seed using PRF. Marks `KeyID` as used (one-time).
- **`KK_GenSig1(Kt, KeyID)`** — computes `Rt = PRF_R(Kt, KeyID)` and `CHKt = PRF_Chk(Kt, KeyID)`.
- **Round 2 — `KK_Sign2(t, R_prime, CHK_prime)`** — authenticates the aggregated `R` using `KK_Auth`, then computes the trustee's signature share `Zt` and path share.
- **`KK_GenSig2(Kt, KeyID, h, path_lens)`** — derives SK share and PATH share from seed, runs WINTER.
- **`KK_Aggregator_Sign(M, CRV, KeyID)`** — orchestrates both rounds across all trustees, XORs the shares to recover the full signature `(R, PATH, Z)`.

**Authentication:**
- **`KK_Auth(Kt, KeyID, R_prime, CHK_prime)`** — checks `PRF_Auth(Kt, KeyID, R_prime) == CHK_prime`. Prevents a malicious aggregator from substituting a different `R`.

**PRF labels** (domain-separated via tweak integers):

| Function | Tweak | Purpose |
|----------|-------|---------|
| `PRF_R` | 30 | Randomness mask share |
| `PRF_Chk` | 31 | Commitment to R share |
| `PRF_Auth` | 32 | Authentication tag for aggregated R |
| `PRF_Path` | 33 | PATH node share |
| `PRF_Chain` | 34 | SK chain share |

### `prf_rf_game.py` — PRF/RF Distinguishing Game

Implements Algorithm 12 from the paper. The challenger randomly selects between a real PRF (mode `b=1`) and a random function (mode `b=0`). An adversary calls `query(x)` and then guesses `b` via `final(b')`.

- **`F(K, x, label=b"")`** — concrete PRF built on `hash_lms`. Optional label for domain separation.
- **`PRFRFGame`** — stateful challenger class.
- **`Init`, `Query`, `Final`** — paper-style function aliases.

---

## How Distributed Signing Works

The KK protocol lets k trustees each hold only a PRF seed. No single trustee ever sees `R`, `SK`, or `PATH` in the clear.

1. **Setup**: The aggregator runs `KK_Setup` with k trustee seeds and the actual `(SK, R, PATH)`. It computes XOR shares: for each trustee `t`, the CRV stores `R ⊕ R_1 ⊕ ... ⊕ R_k` (so the trustees' shares cancel), and per-trustee authentication tags `CHK[t] = Auth_t ⊕ CHK_1 ⊕ ... ⊕ CHK_k`.

2. **Round 1**: Each trustee derives `(Rt, CHKt)` from its seed and sends them to the aggregator. The aggregator XORs to recover `R` and per-trustee `CHK`.

3. **Round 2**: The aggregator sends each trustee `(R, CHK[t])`. Each trustee authenticates `R` using `PRF_Auth`, then computes its signature share and path share. The aggregator XORs all shares against the CRV values to get the final `(R, PATH, Z)`.

4. **Verify**: The resulting signature verifies with standard `Lamport.Verify`, producing the same public key as `Gen(KeyID)`.

---

## Example Usage

```python
from lamport import Gen, Verify
from distributed_signing import KK_Setup, KK_Aggregator_Sign
import distributed_signing as ds
import os
from utils import N_BYTES

# Generate a key pair
key_id = 0
pk, sk = Gen(key_id)

# Two trustees, each with a random PRF seed
seeds = {1: os.urandom(N_BYTES), 2: os.urandom(N_BYTES)}
r = os.urandom(N_BYTES)
path = [os.urandom(N_BYTES), key_id]  # path nodes + key_id at end

# Setup
crv = KK_Setup(seeds, key_id, sk, r, path)

# Populate trustee state (aggregator does this after distributing seeds)
for t, seed in seeds.items():
    ds.K[t] = seed
    ds.trustee_path_lens[t] = {key_id: crv.path_lens}

# Sign
message = b"hello distributed world"
r_out, path_out, z = KK_Aggregator_Sign(message, crv, key_id)

# Verify — must recover pk
assert Verify(r_out, z, message, key_id) == pk
print("Signature verified!")
```
