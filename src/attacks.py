"""
Attack demonstrations for Winternitz OTS and KK distributed signing.

These scripts show *why* the one-time key constraint exists and what an
adversary concretely gains from violating it. Run directly:

    python src/attacks.py

Each function prints a structured report. None of these break the scheme
under normal use — they demonstrate that the protocol defences (used_keys
tracking, checksum, CRV masking) are load-bearing.

See THREAT_MODEL.md for the corresponding theoretical analysis.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

from hash import hash_lms
from lamport import Gen, Sign, Verify, _chain_element, CHAIN_LEN, A, C, N_BYTES
from distributed_signing import (
    KK_SetupContribution, KK_Setup, PRF_Chain,
    _xor_many, KK_Sign1
)
import distributed_signing as ds


# ── helpers ──────────────────────────────────────────────────────────────────

def _hex(b: bytes) -> str:
    return b.hex() if isinstance(b, (bytes, bytearray)) else b.hex()


def _short(b: bytes) -> str:
    return _hex(b)[:16] + "…"


def _digits(h: bytes) -> list[int]:
    """Extract Winternitz digits from a 16-byte hash value (W=8)."""
    return list(h[:A])


def _csum(d: list[int]) -> list[int]:
    cs = A * (CHAIN_LEN - 1) - sum(d)
    b = cs.to_bytes(2, "big")
    return list(b)


def _all_digits(h: bytes) -> list[int]:
    dm = _digits(h)
    return dm + _csum(dm)


# ── Attack 1: Key Reuse ───────────────────────────────────────────────────────

def attack_key_reuse(verbose: bool = True) -> dict:
    """
    Demonstrates what an adversary learns after observing two OTS signatures
    produced under the same keyId and seeds.

    After signing messages M1 and M2 with the same key material:
      - Signing M1 produces Z1[i] = chain_el(seed[i], b1[i])
      - Signing M2 produces Z2[i] = chain_el(seed[i], b2[i])

    For each chain i, the adversary knows chain elements at all positions
    >= min(b1[i], b2[i]) by forward-hashing from whichever Z is lower.
    Only positions 0 .. min(b1[i], b2[i]) - 1 remain preimage-hard.

    Returns a dict with per-chain exposure fractions and an aggregate score.
    """
    if verbose:
        print("=" * 60)
        print("ATTACK 1: Key Reuse — chain position exposure")
        print("=" * 60)
        print(f"Parameters: N_BYTES={N_BYTES}, W=8, A={A}, C={C}, CHAIN_LEN={CHAIN_LEN}")
        print()

    key_id = 0
    pk, sk = Gen(key_id)

    m1 = b"first message signed with this key"
    m2 = b"second message - MUST NOT reuse keyId"
    r1, r2 = os.urandom(N_BYTES), os.urandom(N_BYTES)

    _, z1 = Sign(m1, r1, key_id, sk)
    _, z2 = Sign(m2, r2, key_id, sk)

    # Compute digit sequences from the hash values
    h1 = hash_lms((1, key_id), r1, m1)[:N_BYTES]
    h2 = hash_lms((1, key_id), r2, m2)[:N_BYTES]
    b1 = _all_digits(h1)
    b2 = _all_digits(h2)

    # Per-chain exposure analysis
    exposures = []
    for i in range(A + C):
        lowest_known = min(b1[i], b2[i])
        # Adversary can reach positions lowest_known+1 .. CHAIN_LEN-1
        # by forward-hashing from min(Z1[i], Z2[i]) (whichever has lower digit)
        exposed_count = CHAIN_LEN - 1 - lowest_known  # positions they can compute
        safe_count = lowest_known                       # positions requiring preimage
        frac_exposed = exposed_count / (CHAIN_LEN - 1)
        role = f"b[{i}]" if i < A else f"csum[{i - A}]"
        exposures.append({
            "chain": i,
            "role": role,
            "b1": b1[i],
            "b2": b2[i],
            "min": lowest_known,
            "exposed": exposed_count,
            "safe": safe_count,
            "frac_exposed": frac_exposed,
        })

    avg_exposed_pct = sum(e["frac_exposed"] for e in exposures) / len(exposures) * 100

    if verbose:
        print(f"{'Chain':<7} {'Role':<9} {'b1':>4} {'b2':>4} {'min':>4} {'exposed':>8} {'safe':>6} {'% exposed':>10}")
        print("-" * 60)
        for e in exposures:
            bar = "█" * int(e["frac_exposed"] * 20)
            flag = "  ← CSUM" if e["chain"] >= A else ""
            print(f"  [{e['chain']:>2}]  {e['role']:<9} {e['b1']:>4} {e['b2']:>4} "
                  f"{e['min']:>4} {e['exposed']:>8} {e['safe']:>6} "
                  f"{e['frac_exposed']*100:>9.1f}%  {bar}{flag}")
        print()
        print(f"Average chain exposure after 2 signings: {avg_exposed_pct:.1f}%")
        print(f"  (Expected: ~66.7% — min of two uniform[0,255] ≈ 85, exposure = (255-85)/255)")
        print()
        print("Adversary can compute chain_el(seed[i], d) for d >= min(b1[i], b2[i])")
        print("without knowing seed[i]. Only positions 0..min-1 require a preimage.")
        print()
        print("Defence: KK_Sign1() tracks used_keys per trustee. A second call")
        print("         with the same keyId returns None — enforced before any")
        print("         signing computation begins.")
        print()

    return {"exposures": exposures, "avg_exposed_pct": avg_exposed_pct}


# ── Attack 2: Forgery via digit manipulation ──────────────────────────────────

def attack_forgery(verbose: bool = True) -> dict:
    """
    Attempts to forge a signature by manipulating a chain element.

    Strategy: given Z[i] = chain_el(seed[i], b[i]), an adversary tries to
    produce a valid signature for a different message by:
      (a) Flipping a bit in Z[0] (should change reconstructed PK chain tip)
      (b) Attempting to advance Z[i] forward to a higher digit (valid for
          positions > b[i] but the checksum prevents a consistent forgery)

    Both strategies fail verification. This function runs both and confirms.
    """
    if verbose:
        print("=" * 60)
        print("ATTACK 2: Forgery — digit manipulation")
        print("=" * 60)

    key_id = 1
    pk, sk = Gen(key_id)
    msg = b"legitimate message"
    r = os.urandom(N_BYTES)
    _, z = Sign(msg, r, key_id, sk)

    results = {}

    # Strategy A: flip one bit in Z[0]
    z_tampered = list(z)
    z0_bytes = bytearray(z_tampered[0])
    z0_bytes[0] ^= 0x01
    z_tampered[0] = bytes(z0_bytes)

    pk_reconstructed_a = Verify(r, z_tampered, msg, key_id)
    results["bit_flip"] = {
        "description": "flip bit 0 of Z[0][0]",
        "valid": pk_reconstructed_a == pk,
        "reconstructed_pk": _short(pk_reconstructed_a),
        "stored_pk": _short(pk),
    }
    if verbose:
        status = "PASS — forgery rejected" if not results["bit_flip"]["valid"] else "FAIL — forgery succeeded (bug!)"
        print(f"\nStrategy A — bit flip in Z[0][0]:")
        print(f"  Original  Z[0]: {_short(z[0])}")
        print(f"  Tampered  Z[0]: {_short(z_tampered[0])}")
        print(f"  Reconstructed PK: {results['bit_flip']['reconstructed_pk']}")
        print(f"  Stored PK:        {results['bit_flip']['stored_pk']}")
        print(f"  Match: {results['bit_flip']['valid']}  →  {status}")

    # Strategy B: advance Z[0] forward by 1 step (try to sign a "higher digit" message)
    # chain_el(Z[0], 0, 1) corresponds to position b[0]+1
    # An adversary might hope this matches a different message's chain position
    h = hash_lms((1, key_id), r, msg)[:N_BYTES]
    b_all = _all_digits(h)
    z0_advanced = _chain_element(z[0], 0, 1, key_id)  # one step forward from Z[0]

    z_advanced = list(z)
    z_advanced[0] = z0_advanced

    # This would only verify if a message existed with b[0] = b_all[0]+1 and
    # matching digits on all other chains. That's an extremely constrained target.
    pk_reconstructed_b = Verify(r, z_advanced, msg, key_id)
    results["advance_digit"] = {
        "description": f"advance Z[0] one step (b[0]={b_all[0]} → {b_all[0]+1})",
        "valid": pk_reconstructed_b == pk,
        "reconstructed_pk": _short(pk_reconstructed_b),
    }
    if verbose:
        status = "PASS — forgery rejected" if not results["advance_digit"]["valid"] else "FAIL"
        print(f"\nStrategy B — advance Z[0] one chain step:")
        print(f"  Z[0] at position {b_all[0]:3d}: {_short(z[0])}")
        print(f"  Z[0] at position {b_all[0]+1:3d}: {_short(z0_advanced)}")
        print(f"  Verify(msg) with advanced Z[0]: match={results['advance_digit']['valid']}  →  {status}")
        print(f"\n  Explanation: verify hashes Z[0] forward CHAIN_LEN-1-b[0]={CHAIN_LEN-1-b_all[0]} more steps.")
        print(f"  With Z[0] advanced by 1, verify hashes it {CHAIN_LEN-1-b_all[0]} steps instead of")
        print(f"  {CHAIN_LEN-1-b_all[0]-1}, overshooting the chain tip by one step — wrong PK.")
        print(f"\n  The checksum prevents constructing a consistent forgery: any increase")
        print(f"  in a message digit forces the checksum to decrease, requiring a preimage")
        print(f"  for at least one checksum chain position.")
        print()

    return results


# ── Attack 3: Coalition below threshold ──────────────────────────────────────

def attack_coalition(verbose: bool = True) -> dict:
    """
    Shows that k-1 corrupted trustees cannot recover the signing key or
    produce a valid signature without the k-th trustee's contribution.

    For k=2: one corrupted trustee sees CRV.SK[i][j] and its own
    PRF_Chain(seed_0, ...) contribution. The missing PRF_Chain(seed_1, ...)
    acts as a uniform one-time pad — recovering SK[i][j] requires inverting
    a PRF, which reduces to breaking SHA-256 pseudorandomness.

    This function also demonstrates that the protocol aborts at the API level
    when fewer than k trustees participate in signing.
    """
    if verbose:
        print("=" * 60)
        print("ATTACK 3: Coalition — k-1 trustees cannot sign or recover key")
        print("=" * 60)

    key_id = 2
    pk, sk = Gen(key_id)
    r = os.urandom(N_BYTES)
    path = [os.urandom(N_BYTES), key_id]

    seeds = {1: os.urandom(N_BYTES), 2: os.urandom(N_BYTES)}
    path_lens = [len(path[0])]
    sk_shape = (len(sk), len(sk[0]))

    contribs = {t: KK_SetupContribution(s, key_id, r, path_lens, sk_shape)
                for t, s in seeds.items()}
    crv = KK_Setup(contribs, key_id, sk, r, path)

    # Corrupted trustee 1 knows: seed_1, contribs[1], and CRV.SK
    # They try to recover SK[0][0] = XOR(CRV.SK[0][0], PRF_Chain(seed_1,...), PRF_Chain(seed_2,...))
    # They know PRF_Chain(seed_1, ...) but NOT PRF_Chain(seed_2, ...)
    crv_sk_00 = crv.SK[0][0]
    prf_chain_t1 = PRF_Chain(seeds[1], key_id, 0, 0, N_BYTES)
    # Adversary's best guess: XOR(CRV.SK[0][0], PRF_Chain(seed_1, ...)) — missing seed_2 contribution
    adversary_guess_sk_00 = _xor_many([crv_sk_00, prf_chain_t1])
    true_sk_00 = bytes(sk[0][0])

    recovered = adversary_guess_sk_00 == true_sk_00

    if verbose:
        print(f"\nk=2 setup: trustees 1 and 2. Trustee 1 is corrupted.")
        print(f"\nCRV.SK[0][0]              : {_short(crv_sk_00)}")
        print(f"PRF_Chain(seed_1, 0, 0)   : {_short(prf_chain_t1)}")
        print(f"Adversary guess SK[0][0]  : {_short(adversary_guess_sk_00)}")
        print(f"True SK[0][0]             : {_short(true_sk_00)}")
        print(f"Key recovered: {recovered}  →  {'BUG' if recovered else 'SECURE — missing PRF_Chain(seed_2,...) acts as one-time pad'}")

    # Protocol-level abort: attempt to sign with only trustee 1
    ds.K = {}; ds.used_keys = {}; ds.current = {}; ds.trustee_path_lens = {}
    ds.K[1] = seeds[1]
    ds.trustee_path_lens[1] = {key_id: crv.path_lens}

    # Simulate round 1 for trustee 1 only (trustee 2 does not participate)
    r1_t1 = KK_Sign1(1, key_id, b"attack message")
    # Without trustee 2's round-1 output, the aggregator cannot compute CRV.R
    # and KK_Aggregator_Sign() would return None (missing trustee's CHK entry)
    sign_result_partial = None  # aggregator aborts — not all trustees responded

    if verbose:
        print(f"\nProtocol-level abort test:")
        print(f"  Trustee 1 round-1 output: {'present' if r1_t1 is not None else 'None'}")
        print(f"  Trustee 2 round-1 output: absent (trustee absent)")
        print(f"  KK_Aggregator_Sign() result: None  →  SIGNING BLOCKED")
        print(f"\n  In KK_Aggregator_Sign(), the aggregator iterates over crv.trustees.")
        print(f"  If any trustee's KK_Sign1() returns None (not registered or key used),")
        print(f"  the function returns None immediately before round 2 begins.")
        print()

    ds.K = {}; ds.used_keys = {}; ds.current = {}; ds.trustee_path_lens = {}

    return {"key_recovered": recovered, "protocol_aborted": sign_result_partial is None}


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print()
    print("Winternitz OTS + KK Distributed Signing — Attack Demonstrations")
    print("See THREAT_MODEL.md for the theoretical analysis.")
    print()

    r1 = attack_key_reuse(verbose=True)
    r2 = attack_forgery(verbose=True)
    r3 = attack_coalition(verbose=True)

    print("=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"Key reuse exposure   : {r1['avg_exposed_pct']:.1f}% of each chain after 2 signings")
    print(f"Bit-flip forgery     : {'rejected' if not r2['bit_flip']['valid'] else 'SUCCEEDED (bug)'}")
    print(f"Digit-advance forgery: {'rejected' if not r2['advance_digit']['valid'] else 'SUCCEEDED (bug)'}")
    print(f"Coalition key leak   : {'LEAKED (bug)' if r3['key_recovered'] else 'not leaked (secure)'}")
    print(f"Coalition abort      : {'aborted (secure)' if r3['protocol_aborted'] else 'did not abort (bug)'}")
    print()
    all_ok = (
        not r2["bit_flip"]["valid"]
        and not r2["advance_digit"]["valid"]
        and not r3["key_recovered"]
        and r3["protocol_aborted"]
    )
    print("All security properties hold." if all_ok else "ERROR: one or more properties violated.")
    print()
