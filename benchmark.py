#!/usr/bin/env python3
"""
Benchmarking and comparison for the distributed Winternitz signature scheme.

Measures:
  1. Winternitz OTS — Gen, Sign, Verify for W in {1, 2, 4, 8}
  2. SHA-256 vs BLAKE2b hash backend performance
  3. Distributed signing (ShardSetup, AggregatorSign, AggregatorVerify) for k in {1, 2, 3, 5}
  4. Signature and key sizes for each parameter set
  5. Complexity analysis comparing with RSA-2048 and ECDSA-P256
"""

import hashlib
import math
import os
import statistics
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

import utils
import distributed_signing as ds
import shard_trustee as st
import stateful_hash as sh


def reset_state():
    ds.K = {}
    ds.used_keys = {}
    ds.current = {}
    ds.trustee_path_lens = {}
    st.keylist = {}
    st.cl_s = []
    sh.cpk = None
    sh.csk = None
    sh._KEY_IDS.clear()


def timeit(fn, repeats=15):
    fn()  # warm up
    times = []
    for _ in range(repeats):
        t0 = time.perf_counter()
        fn()
        times.append((time.perf_counter() - t0) * 1000)
    return statistics.mean(times), statistics.stdev(times)


# ─── Self-contained Winternitz implementation for parameter sweep ─────────────
# We inline these so we can vary N and W without touching the installed modules.

def _hash_sha256(tweak, *data, nb=16):
    h = hashlib.sha256()
    for t in tweak:
        h.update(t.to_bytes(4, "big"))
    for d in data:
        h.update(d)
    return h.digest()[:nb]


def _hash_blake2b(tweak, *data, nb=16):
    h = hashlib.blake2b(digest_size=32)
    for t in tweak:
        h.update(t.to_bytes(4, "big"))
    for d in data:
        h.update(d)
    return h.digest()[:nb]


def _params(N_bits, W):
    nb = N_bits // 8
    A = N_bits // W
    C = math.ceil(math.log2(A * (2 ** W - 1)) / W)
    chain_len = 2 ** W
    return nb, A, C, chain_len


def _split_w(data, count, W):
    chunks = []
    for byte in data:
        if W == 8:
            chunks.append(byte)
        elif W == 4:
            chunks.extend([(byte >> 4) & 0xF, byte & 0xF])
        elif W == 2:
            for sh in (6, 4, 2, 0):
                chunks.append((byte >> sh) & 3)
        else:
            for sh in range(7, -1, -1):
                chunks.append((byte >> sh) & 1)
        if len(chunks) >= count:
            break
    return chunks[:count]


def gen_w(key_id, N_bits=128, W=8, hfn=_hash_sha256):
    nb, A, C, chain_len = _params(N_bits, W)
    SK = []
    for i in range(A + C):
        seed = os.urandom(nb)
        chain = [seed]
        for j in range(1, chain_len):
            chain.append(hfn((2, i, j, key_id), chain[-1], nb=nb))
        SK.append(chain)
    Y = [SK[i][-1] for i in range(A + C)]
    pk = hfn((0, key_id), *Y, nb=nb)
    return pk, SK


def sign_w(msg, r, key_id, SK, N_bits=128, W=8, hfn=_hash_sha256):
    nb, A, C, chain_len = _params(N_bits, W)
    h = hfn((1, key_id), r, msg, nb=nb)
    b = _split_w(h, A, W)
    csum = A * (2 ** W - 1) - sum(b)
    csum_bytes = csum.to_bytes(math.ceil(C * W / 8), "big")
    b_all = b + _split_w(csum_bytes, C, W)
    return [SK[i][b_all[i]] for i in range(A + C)]


def verify_w(r, Z, msg, key_id, N_bits=128, W=8, hfn=_hash_sha256):
    nb, A, C, chain_len = _params(N_bits, W)
    h = hfn((1, key_id), r, msg, nb=nb)
    b = _split_w(h, A, W)
    csum = A * (2 ** W - 1) - sum(b)
    csum_bytes = csum.to_bytes(math.ceil(C * W / 8), "big")
    b_all = b + _split_w(csum_bytes, C, W)
    Y_prime = []
    for i in range(A + C):
        u = Z[i]
        for j in range(b_all[i] + 1, chain_len):
            u = hfn((2, i, j, key_id), u, nb=nb)
        Y_prime.append(u)
    return hfn((0, key_id), *Y_prime, nb=nb)


# ─── 1. W parameter sweep ─────────────────────────────────────────────────────

print()
print("=" * 75)
print("  Winternitz OTS — parameter sweep W ∈ {1, 2, 4, 8} with N=128 bits")
print("=" * 75)
print(f"{'W':>3} {'A':>4} {'C':>3} {'ChainLen':>9} {'SigSize(B)':>11} "
      f"{'SKSize(B)':>10} {'Gen(ms)':>9} {'Sign(ms)':>9} {'Verify(ms)':>11}")
print("-" * 75)

msg = b"benchmark message"
r16 = os.urandom(16)

for W in [1, 2, 4, 8]:
    nb, A, C_val, chain_len = _params(128, W)
    sig_size = (A + C_val) * nb
    sk_size = (A + C_val) * chain_len * nb

    pk_w, sk_w = gen_w(0, 128, W)
    z_w = sign_w(msg, r16, 0, sk_w, 128, W)

    gen_ms, _ = timeit(lambda W=W: gen_w(0, 128, W), repeats=8)
    sign_ms, _ = timeit(lambda W=W, sk_w=sk_w: sign_w(msg, r16, 0, sk_w, 128, W), repeats=20)
    verify_ms, _ = timeit(lambda W=W, z_w=z_w: verify_w(r16, z_w, msg, 0, 128, W), repeats=20)

    print(f"{W:>3} {A:>4} {C_val:>3} {chain_len:>9} {sig_size:>11} "
          f"{sk_size:>10} {gen_ms:>9.2f} {sign_ms:>9.3f} {verify_ms:>11.3f}")

# ─── 2. SHA-256 vs BLAKE2b ────────────────────────────────────────────────────

print()
print("=" * 60)
print("  Hash backend comparison — SHA-256 vs BLAKE2b (N=128, W=8)")
print("=" * 60)
print(f"{'Backend':<12} {'Gen(ms)':>9} {'Sign(ms)':>9} {'Verify(ms)':>11}  {'Speedup':>8}")
print("-" * 54)

pk_s, sk_s = gen_w(0, 128, 8, _hash_sha256)
z_s = sign_w(msg, r16, 0, sk_s, 128, 8, _hash_sha256)

sha_gen, _ = timeit(lambda: gen_w(0, 128, 8, _hash_sha256), repeats=8)
sha_sign, _ = timeit(lambda: sign_w(msg, r16, 0, sk_s, 128, 8, _hash_sha256), repeats=20)
sha_ver, _ = timeit(lambda: verify_w(r16, z_s, msg, 0, 128, 8, _hash_sha256), repeats=20)
print(f"{'SHA-256':<12} {sha_gen:>9.2f} {sha_sign:>9.3f} {sha_ver:>11.3f}  {'baseline':>8}")

pk_b, sk_b = gen_w(0, 128, 8, _hash_blake2b)
z_b = sign_w(msg, r16, 0, sk_b, 128, 8, _hash_blake2b)

blk_gen, _ = timeit(lambda: gen_w(0, 128, 8, _hash_blake2b), repeats=8)
blk_sign, _ = timeit(lambda: sign_w(msg, r16, 0, sk_b, 128, 8, _hash_blake2b), repeats=20)
blk_ver, _ = timeit(lambda: verify_w(r16, z_b, msg, 0, 128, 8, _hash_blake2b), repeats=20)
speedup = sha_gen / blk_gen
print(f"{'BLAKE2b':<12} {blk_gen:>9.2f} {blk_sign:>9.3f} {blk_ver:>11.3f}  {speedup:>7.2f}x")

# ─── 3. XOR optimisation benchmark ───────────────────────────────────────────

print()
print("=" * 60)
print("  XOR optimisation — byte-by-byte loop vs integer arithmetic")
print("=" * 60)

import timeit as ti_module

sample = [os.urandom(16) for _ in range(10)]

def xor_loop(values):
    out = bytearray(values[0])
    for v in values[1:]:
        for i in range(len(out)):
            out[i] ^= v[i]
    return bytes(out)

def xor_int(values):
    n = len(values[0])
    acc = int.from_bytes(values[0], 'big')
    for v in values[1:]:
        acc ^= int.from_bytes(v, 'big')
    return acc.to_bytes(n, 'big')

loop_t = ti_module.timeit(lambda: xor_loop(sample), number=50000) / 50000 * 1e6
int_t  = ti_module.timeit(lambda: xor_int(sample),  number=50000) / 50000 * 1e6
print(f"  Byte loop : {loop_t:.3f} µs  (10 × 16-byte operands)")
print(f"  Int XOR   : {int_t:.3f} µs  (same result, {loop_t/int_t:.1f}x faster)")

# ─── 4. Distributed signing — varying trustee count ──────────────────────────

print()
print("=" * 65)
print("  Distributed signing — trustee count k ∈ {1, 2, 3, 5} (d=1 key)")
print("=" * 65)
print(f"{'k':>3} {'Setup(ms)':>10} {'Sign(ms)':>10} {'Verify(ms)':>11} {'Overhead':>9}")
print("-" * 48)

_, _, base_verify = None, None, None

for k in [1, 2, 3, 5]:
    d = 1
    cl = [list(range(1, k + 1))]

    def do_full(k=k, d=d, cl=cl):
        reset_state()
        cpk, crvs, ti = st.ShardSetup(d, k, cl)
        for t, info in ti.items():
            st.TrusteeSetup(t, info["seed"], info["allowed_keyids"], info["path_lens"])
        return crvs, cpk

    def do_sign(k=k, d=d, cl=cl):
        reset_state()
        cpk, crvs, ti = st.ShardSetup(d, k, cl)
        for t, info in ti.items():
            st.TrusteeSetup(t, info["seed"], info["allowed_keyids"], info["path_lens"])
        return st.AggregatorSign(b"hello", crvs, 0)

    setup_ms, _ = timeit(do_full, repeats=5)
    sign_ms, _  = timeit(do_sign, repeats=5)

    reset_state()
    cpk2, crvs2, ti2 = st.ShardSetup(d, k, cl)
    for t, info in ti2.items():
        st.TrusteeSetup(t, info["seed"], info["allowed_keyids"], info["path_lens"])
    result = st.AggregatorSign(b"hello", crvs2, 0)
    r2, path2, z2 = result
    verify_ms, _ = timeit(lambda: st.AggregatorVerify(b"hello", r2, path2, z2), repeats=20)

    if base_verify is None:
        base_verify = verify_ms
        overhead_str = "baseline"
    else:
        overhead_str = f"+{((verify_ms / base_verify) - 1) * 100:.0f}%"

    print(f"{k:>3} {setup_ms:>10.2f} {sign_ms:>10.2f} {verify_ms:>11.3f} {overhead_str:>9}")

# ─── 5. Sizes ─────────────────────────────────────────────────────────────────

print()
print("=" * 55)
print("  Signature and key sizes (bytes) by W — N=128 bits")
print("=" * 55)
print(f"{'W':>3} {'A+C':>5} {'SigSize':>9} {'SKSize':>10} {'PKSize':>8} {'Ratio vs RSA':>13}")
print("-" * 52)
for W in [1, 2, 4, 8]:
    nb, A, C_val, chain_len = _params(128, W)
    sig = (A + C_val) * nb
    sk = (A + C_val) * chain_len * nb
    ratio = sig / 256  # vs RSA-2048 (256 bytes)
    print(f"{W:>3} {A+C_val:>5} {sig:>9} {sk:>10} {nb:>8} {ratio:>12.2f}x")

print()
print(f"  RSA-2048   sig=256B  sk=256B   pk=256B  (reference)")
print(f"  ECDSA-P256 sig=64B   sk=32B    pk=33B")
print(f"  Our (W=8)  sig=288B  sk=73728B pk=16B   (post-quantum)")

# ─── 6. Complexity analysis ───────────────────────────────────────────────────

print()
print("=" * 75)
print("  Complexity analysis — Winternitz vs RSA-2048 vs ECDSA-P256")
print("=" * 75)
print(f"  n = security bits, A = n/W message digits, q = 2^W chain length\n")

print(f"{'Scheme':<22} {'Key Gen':^18} {'Sign':^18} {'Verify':^14} {'PQ?':>5}")
print("-" * 80)
rows = [
    ("Winternitz W=1",  "O(2n · n)  ",  "O(n)   ",  "O(2n²)  ", "Yes"),
    ("Winternitz W=4",  "O(16A · q) ",  "O(A)   ",  "O(16A·q)", "Yes"),
    ("Winternitz W=8",  "O(A·256)   ",  "O(A)   ",  "O(A·256)", "Yes"),
    ("RSA-2048   ",     "O(n³)      ",  "O(n³)  ",  "O(n²)   ", "No "),
    ("ECDSA-P256 ",     "O(n)       ",  "O(n)   ",  "O(n)    ", "No "),
]
for name, kg, sg, vr, pq in rows:
    print(f"  {name:<20} {kg:<18} {sg:<18} {vr:<14} {pq:>5}")

print("""
  Notes:
  - Winternitz sign is very fast (only A+C hash calls), verify is slower
    because it must complete each chain to the tip.
  - RSA sign/verify both require full modular exponentiation (expensive).
  - ECDSA is faster overall but relies on the elliptic curve discrete log
    problem, which is broken by Shor's algorithm on a quantum computer.
  - Our scheme is post-quantum secure: security relies only on hash
    preimage resistance, which Grover's algorithm only halves (use N=256
    for 128-bit post-quantum security).

  Distributed signing (k trustees, KK protocol):
    Round 1 cost : k × PRF_R + k × PRF_Chk = 2k hash calls
    Round 2 cost : k × (A+C) hash calls (WINTER per trustee)
    Aggregation  : k × (A+C) XOR operations
    Total overhead vs single-signer sign: factor of ~k
""")

print("Benchmarks complete.")
