# Distributed Hash-Based Signatures

Implementation of the distributed and threshold Winternitz/Lamport signature scheme described in:

> Kelsey, Lang, Lucks — *Turning Hash-Based Signatures into Distributed Signatures and Threshold Signatures* (2024)  
> https://cic.iacr.org/p/2/2/24/pdf

The project implements the core Full Project PRF-based distributed signing scheme, including Winternitz OTS, Merkle-tree based stateful signing, CRV correction values, and a two-round distributed signing protocol. Trustees hold local PRF seeds and derive signing shares on demand, while the aggregator reconstructs a single verifiable Winternitz/Lamport signature.

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
│   ├── distributed_signing.py # PRF-based distributed signing — KK_SetupContribution, KK_Setup, KK_Aggregator_Sign, KK_Sign1/2
│   ├── prf_rf_game.py       # PRF/RF distinguishing game — F, PRFRFGame, Init, Query, Final
│   └── shard_trustee.py     # Shard/trustee helpers for coalition-based distributed signing
└── test/
    ├── test_lamport.py          # unit tests for Winternitz OTS
    ├── test_merkle_tree.py      # unit tests for Merkle tree
    ├── test_stateful_hash.py    # unit tests for stateful signing
    ├── test_integration.py      # end-to-end tests: Gen → Sign → Verify
    └── test_distributed_signing.py  # unit + integration tests for PRF-based distributed signing
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
| `C` | 2 | Checksum digits |
| `CHAIN_LEN` | 256 | Chain length = 2^W |

---

## Running Tests

From the project root:

```bash
python -m pytest test/ -v
```

All 68 tests should pass. To run a specific test file:

```bash
python -m pytest test/test_integration.py -v
python -m pytest test/test_distributed_signing.py -v
```

---

## Running Benchmarks

From the project root:

```bash
python benchmark.py
```
This generates benchmark_results.csv and complexity_comparison.csv.

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

### `distributed_signing.py` - PRF-Based Distributed Signing

Implements the PRF-based trustee contribution and signing logic.

**Setup contribution:**
- **`KK_SetupContribution(seed, KeyID, R, path_lens, sk_shape)`** - computes a trustee's setup contribution from its local PRF seed, including `Rt`, `CHKt`, `Auth`, `PATHt`, and `SKt`.

**Setup aggregation:**
- **`KK_Setup(trustee_contribs, KeyID, SK, R, PATH)`** - combines trustee setup contributions into a `CRV` (Common Reference Value), containing the correction values needed for distributed signing.

**Signing (2-round protocol):**
- **`KK_Sign1(t, KeyID, M)`** - trustee `t` derives round-1 values `(Rt, CHKt)` from its local seed.
- **`KK_Sign2(t, R_prime, CHK_prime)`** - trustee `t` authenticates `R_prime` and produces `(PATHt, Zt)`.
- **`KK_Aggregator_Sign(M, CRV, KeyID)`** - combines all trustee shares into the final signature `(R, PATH, Z)`.

**Authentication:**
- **`KK_Auth(Kt, KeyID, R_prime, CHK_prime)`** - checks whether the round-2 authentication value is valid.




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

The distributed signing protocol follows the core PRF-based Full Project idea.

1. **Local trustee seeds**: Each trustee holds its own PRF seed locally.

2. **Setup contributions**: During setup, the setup server obtains trustee setup contributions through a contribution provider. Each contribution is generated from the trustee's local seed and contains the masked values needed to construct the common reference value (`CRV`).

3. **CRV generation**: The setup server combines trustee contributions with the real `(SK, R, PATH)` values to produce correction values stored in the `CRV`.

4. **Round 1**: Each trustee derives `(Rt, CHKt)` locally from its PRF seed and sends them to the aggregator.

5. **Round 2**: After reconstructing `R` and the trustee-specific authentication value, the aggregator asks each trustee to authenticate `R` and generate its signature share `(PATHt, Zt)`.

6. **Final reconstruction**: The aggregator XOR-combines the trustee shares with the `CRV` to reconstruct the final signature `(R, PATH, Z)`.


---

## Example Usage

```python
import os
import distributed_signing as ds
import shard_trustee as st
from utils import N_BYTES

# Number of one-time signing keys / Merkle leaves
# D must be a power of two.
d = 4

# Number of trustees
n = 2

# Coalition list: each KeyID is assigned to a signing coalition.
cl = [
    [1, 2],
    [1, 2],
    [1, 2],
    [1, 2],
]

# Each trustee independently holds its own PRF seed.
# These seeds are not generated or returned by ShardSetup.
trustee_seeds = {
    t: os.urandom(N_BYTES)
    for t in range(1, n + 1)
}


def contribution_provider(t, key_id, r, path_lens, sk_shape):
    """
    Simulates trustee-side PRF setup contribution generation.
    The setup receives contributions, not trustee seeds.
    """
    return ds.KK_SetupContribution(
        trustee_seeds[t],
        key_id,
        r,
        path_lens,
        sk_shape,
    )


# Setup: generate public key, CRV correction values, and trustee metadata.
cpk, crvs, trustee_init = st.ShardSetup(
    d,
    n,
    cl,
    contribution_provider,
)

# Initialise each trustee with its own local PRF seed and metadata.
for t, init in trustee_init.items():
    st.TrusteeSetup(
        t,
        trustee_seeds[t],
        init["allowed_keyids"],
        init["path_lens"],
    )

# Sign a message using KeyID 0.
message = b"hello distributed world"
key_id = 0

signature = st.AggregatorSign(message, crvs, key_id)
assert signature is not None

r, path, z = signature

# Verify the reconstructed distributed signature.
assert st.AggregatorVerify(message, r, path, z) is True

print("Signature verified!")
```
