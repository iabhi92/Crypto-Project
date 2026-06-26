# Distributed Hash-Based Signatures

Based on Kelsey, Lang, and Lucks (2024):

> *Turning Hash-Based Signatures into Distributed Signatures and Threshold Signatures*  
> https://cic.iacr.org/p/2/2/24/pdf

Each of the k trustees holds a 16-byte PRF seed. Signing requires all k trustees to go through a two-round protocol together — no single trustee has the full key. Verification is the same as a normal signature scheme from the outside.

---

## Setup

Python 3.10+, no dependencies beyond the standard library.

```bash
pip install pytest   # only needed for tests
```

---

## Layout

```
src/
├── utils.py               # parameters and shared types
├── hash.py                # tweakable hash (SHA-256 or BLAKE2b)
├── lamport.py             # Winternitz OTS + lazy variant
├── merkle_tree.py         # Merkle tree
├── stateful_hash.py       # stateful signing with one-time key tracking
├── distributed_signing.py # KK protocol: PRFs, setup, two-round signing
├── shard_trustee.py       # aggregator + trustee API
├── prf_rf_game.py         # PRF/RF game (Algorithm 12)
├── benchmark.py           # timing benchmarks
└── attacks.py             # concrete attack demos (key reuse, forgery, coalition)

test/
├── test_lamport.py
├── test_merkle_tree.py
├── test_stateful_hash.py
├── test_integration.py
├── test_distributed_signing.py
└── test_attacks.py          # forgery, key reuse, coalition, domain separation
```

---

## Parameters

From `utils.py` (§3.1 of the paper):

| | Value | |
|---|---|---|
| `N` | 128 | security bits |
| `N_BYTES` | 16 | byte length of hashes and keys |
| `W` | 8 | Winternitz parameter — chain length = 2^W |
| `A` | 16 | message digits (N/W) |
| `C` | 2 | checksum digits |
| `CHAIN_LEN` | 256 | hash chain length |

W=8 gives the smallest signature (288 bytes) at the cost of the slowest keygen. The W tradeoff is benchmarked in `benchmark.py`.

---

## Tests

```bash
python -m pytest test/ -v
```

97 tests should pass. Run specific suites with e.g. `pytest test/test_integration.py -v`.

---

## Benchmarks

```bash
cd src
python benchmark.py
```

Prints a table and saves `benchmark_results.csv` and `complexity_comparison.csv`. Switch `MODE = "FULL"` at the top for more iterations and a larger parameter sweep.

**Quick summary (FAST mode, SHA-256):**

| Operation | Time |
|-----------|------|
| Winternitz Gen | 4.06 ms |
| Winternitz Sign | 0.003 ms |
| Winternitz Verify | 2.34 ms |
| StatefulSign (D=128) | 0.49 ms |
| AggregatorSign (k=2) | ~8.1 ms |
| AggregatorSign (k=3) | ~12.1 ms |
| AggregatorVerify | ~1.93 ms |

---

## Attack Demonstrations

`src/attacks.py` demonstrates three concrete attack scenarios and verifies that each defence holds:

```bash
python src/attacks.py
```

| Attack | What it shows | Defence |
|---|---|---|
| Key reuse | Two signings with the same keyId expose ~67% of each chain via forward-hashing | `used_keys[t].add(keyId)` in `KK_Sign1()` — hard refusal on reuse |
| Forgery | Bit flip and forward-advance strategies both produce the wrong public key | Winternitz checksum: any message digit increase forces a checksum decrease, requiring a preimage |
| Coalition (k−1) | One missing trustee's PRF contribution acts as a uniform one-time pad over `CRV.SK` | XOR masking with all k seeds; aggregator aborts if any trustee is absent |

See [`THREAT_MODEL.md`](THREAT_MODEL.md) for the adversary model, security assumptions, and per-attack proof sketches.

---

## Optimisations

Three optimisations we measured:

**1. Integer XOR (`_xor_many` in `distributed_signing.py`)**  
Replaces byte-by-byte XOR with a single integer operation. In CPython, `int.from_bytes` + `^` is one C-level call instead of 16 interpreter iterations. 5.9× faster over 20,000 runs with 10×16-byte operands (6.46 μs → 1.10 μs).

**2. BLAKE2b backend**  
One-line change in `utils.py`:
```python
HASH_BACKEND = "blake2b"
```
BLAKE2b has lower per-call overhead than SHA-256 for short inputs. 1.18× faster keygen (3.70 ms → 3.14 ms).

**3. Lazy chain evaluation (`GenLazy`/`SignLazy` in `lamport.py`)**  
`Gen` stores full chains: 18×256×16 = 73,728 bytes per key. `GenLazy` stores only the 18 seeds (288 bytes) and recomputes chain elements on demand during signing. 256× smaller storage, ~760× slower signing. Right tradeoff for constrained devices or when key material is transmitted.

---

## Example

```python
import os
import shard_trustee as st
import distributed_signing as ds
from utils import N_BYTES

D, n, k = 4, 2, 2
cl = [list(range(1, k + 1)) for _ in range(D)]
trustee_seeds = {t: os.urandom(N_BYTES) for t in range(1, n + 1)}

def contribution_provider(t, key_id, r, path_lens, sk_shape):
    return ds.KK_SetupContribution(trustee_seeds[t], key_id, r, path_lens, sk_shape)

cpk, crvs, trustee_init = st.ShardSetup(D, n, cl, contribution_provider)
for t, info in trustee_init.items():
    st.TrusteeSetup(t, trustee_seeds[t], info["allowed_keyids"], info["path_lens"])

r, path, z = st.AggregatorSign(b"hello distributed world", crvs, keyID=0)
assert st.AggregatorVerify(b"hello distributed world", r, path, z)
```
