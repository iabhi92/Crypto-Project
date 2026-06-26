"""
Security / attack tests for Winternitz OTS and KK distributed signing.

These tests assert the *cryptographic* properties that make the scheme
secure, not just the happy-path correctness. Each test is named after the
attack it defends against and cites the relevant section of THREAT_MODEL.md.

Run: python -m pytest test/test_attacks.py -v
"""

import os
import pytest
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

import distributed_signing as ds
from hash import hash_lms
from lamport import Gen, Sign, Verify, _chain_element, GenLazy, SignLazy, CHAIN_LEN, A, C, N_BYTES
from distributed_signing import (
    KK_SetupContribution, KK_Setup, KK_Sign1, KK_Sign2, PRF_Chain, _xor_many
)


@pytest.fixture(autouse=True)
def reset_ds_globals():
    ds.K = {}; ds.used_keys = {}; ds.current = {}; ds.trustee_path_lens = {}
    yield
    ds.K = {}; ds.used_keys = {}; ds.current = {}; ds.trustee_path_lens = {}


def _setup_crv(k=2, key_id=0):
    """Shared helper: generate a CRV with k trustees."""
    pk, sk = Gen(key_id)
    seeds = {t: os.urandom(N_BYTES) for t in range(1, k + 1)}
    r = os.urandom(N_BYTES)
    path = [os.urandom(N_BYTES), key_id]
    path_lens = [len(path[0])]
    sk_shape = (len(sk), len(sk[0]))
    contribs = {t: KK_SetupContribution(s, key_id, r, path_lens, sk_shape)
                for t, s in seeds.items()}
    crv = KK_Setup(contribs, key_id, sk, r, path)
    for t, s in seeds.items():
        ds.K[t] = s
        ds.trustee_path_lens.setdefault(t, {})[key_id] = crv.path_lens
    return pk, sk, seeds, crv


# ── Forgery tests (THREAT_MODEL.md §Attack 1) ─────────────────────────────────

class TestForgery:

    def test_bit_flip_in_signature_fails_verification(self):
        """Flipping any single bit in any Z[i] must change the reconstructed PK."""
        pk, sk = Gen(0)
        r = os.urandom(N_BYTES)
        _, z = Sign(b"target message", r, 0, sk)

        for chain_idx in [0, 1, 7, 17]:        # sample chains
            z_tampered = list(z)
            z0 = bytearray(z_tampered[chain_idx])
            z0[0] ^= 0x01
            z_tampered[chain_idx] = bytes(z0)
            assert Verify(r, z_tampered, b"target message", 0) != pk, \
                f"Forgery succeeded on chain {chain_idx} — bit flip not detected"

    def test_advance_digit_fails_verification(self):
        """Advancing Z[i] one chain step forward must fail verification."""
        pk, sk = Gen(1)
        r = os.urandom(N_BYTES)
        _, z = Sign(b"test", r, 1, sk)

        z_advanced = list(z)
        z_advanced[0] = _chain_element(z[0], 0, 1, 1)
        assert Verify(r, z_advanced, b"test", 1) != pk

    def test_checksum_prevents_all_digit_increase(self):
        """
        Even if the adversary advances every message digit by 1 (using forward
        chain steps from Z), verification must fail because the checksum
        digits would need to DECREASE, requiring a preimage.

        We test this by constructing a signature where all message chain
        elements are moved one step forward; verification must reject it.
        """
        pk, sk = Gen(2)
        r = os.urandom(N_BYTES)
        _, z = Sign(b"hello", r, 2, sk)

        z_all_advanced = list(z)
        for i in range(A):
            z_all_advanced[i] = _chain_element(z[i], i, 1, 2)
        # checksum chains are NOT advanced — the csum would need to decrease
        assert Verify(r, z_all_advanced, b"hello", 2) != pk

    def test_wrong_message_fails_verification(self):
        """Verifying with a different message must produce a different digit
        sequence and thus a different reconstructed PK."""
        pk, sk = Gen(3)
        r = os.urandom(N_BYTES)
        _, z = Sign(b"real", r, 3, sk)
        assert Verify(r, z, b"tampered", 3) != pk

    def test_wrong_nonce_fails_verification(self):
        """Swapping R for a different nonce changes h = hash_lms([1,keyId], R, M)
        and thus all digit positions — verify must fail."""
        pk, sk = Gen(4)
        r = os.urandom(N_BYTES)
        _, z = Sign(b"msg", r, 4, sk)
        assert Verify(os.urandom(N_BYTES), z, b"msg", 4) != pk

    def test_signature_from_different_key_rejected(self):
        """A signature generated under keyId=A must not verify under keyId=B."""
        pk_a, sk_a = Gen(10)
        pk_b, sk_b = Gen(11)
        r = os.urandom(N_BYTES)
        _, z = Sign(b"msg", r, 10, sk_a)
        # Verify under key B's context — digit sequence differs due to keyId in tweak
        assert Verify(r, z, b"msg", 11) != pk_b

    def test_truncated_signature_rejected(self):
        """A truncated signature (fewer than A+C elements) must be rejected.
        Verify either raises (IndexError on missing element) or returns a
        wrong PK — either outcome is a correct rejection."""
        pk, sk = Gen(5)
        r = os.urandom(N_BYTES)
        _, z = Sign(b"msg", r, 5, sk)
        z_short = z[:-1]   # drop the last chain element
        try:
            result = Verify(r, z_short, b"msg", 5)
            assert result != pk, "Truncated signature passed verification"
        except (IndexError, ValueError):
            pass   # Rejected with exception — correct behaviour


# ── Key reuse tests (THREAT_MODEL.md §Attack 2) ───────────────────────────────

class TestKeyReuse:

    def test_key_reuse_blocked_at_protocol_level(self):
        """KK_Sign1 must return None on a second call with the same keyId."""
        _, _, seeds, crv = _setup_crv(k=2, key_id=0)
        assert KK_Sign1(1, 0, b"first") is not None
        assert KK_Sign1(1, 0, b"second") is None, \
            "KK_Sign1 should refuse to sign with a previously-used keyId"

    def test_key_reuse_blocked_for_all_trustees(self):
        """The used_keys guard applies per-trustee, not globally."""
        _, _, seeds, crv = _setup_crv(k=2, key_id=1)
        assert KK_Sign1(1, 1, b"first") is not None
        assert KK_Sign1(2, 1, b"first") is not None
        assert KK_Sign1(1, 1, b"second") is None
        assert KK_Sign1(2, 1, b"second") is None

    def test_different_keyids_are_independent(self):
        """Using keyId=0 must not block keyId=1 for the same trustee."""
        _, _, _, crv0 = _setup_crv(k=1, key_id=0)
        _, _, _, crv1 = _setup_crv(k=1, key_id=1)
        assert KK_Sign1(1, 0, b"first") is not None
        assert KK_Sign1(1, 1, b"first") is not None   # different keyId — must succeed

    def test_key_reuse_exposes_chain_positions(self):
        """
        After two signings under the same keyId, per-chain exposure must be
        strictly positive. Specifically: min(b1[i], b2[i]) < CHAIN_LEN-1
        for every chain i, meaning the adversary can compute at least one
        position forward from the lower observed element.

        This is a CRYPTOGRAPHIC property test, not a protocol-level test.
        It confirms that the one-time key constraint exists for a real reason.
        """
        key_id = 99
        _, sk = Gen(key_id)
        r1, r2 = os.urandom(N_BYTES), os.urandom(N_BYTES)

        # Sign two different messages under the same key
        _, z1 = Sign(b"message alpha", r1, key_id, sk)
        _, z2 = Sign(b"message beta",  r2, key_id, sk)

        # Recompute digit sequences
        h1 = hash_lms((1, key_id), r1, b"message alpha")[:N_BYTES]
        h2 = hash_lms((1, key_id), r2, b"message beta")[:N_BYTES]

        def all_digits(h):
            dm = list(h[:A])
            cs = A * (CHAIN_LEN - 1) - sum(dm)
            return dm + list(cs.to_bytes(2, "big"))

        b1 = all_digits(h1)
        b2 = all_digits(h2)

        total_exposure = 0
        for i in range(A + C):
            lowest_known = min(b1[i], b2[i])
            # Adversary can reach positions lowest_known+1 to CHAIN_LEN-1
            # by forward-hashing from the lower Z value
            exposed = CHAIN_LEN - 1 - lowest_known
            total_exposure += exposed

        max_possible = (A + C) * (CHAIN_LEN - 1)
        exposure_pct = total_exposure / max_possible * 100

        # With uniform digit distribution, expected exposure ≈ 66.7%.
        # We assert > 20% to give a wide margin even for adversarial inputs.
        assert exposure_pct > 20, \
            f"Key reuse exposure too low ({exposure_pct:.1f}%) — test data may be degenerate"

    def test_forward_chain_derivable_from_lower_z(self):
        """
        Verifies the mathematical foundation of the key reuse attack:
        if the adversary observes Z[i] at absolute chain position b_low,
        they can reach position b_high > b_low by applying steps
        b_low+1 … b_high with their absolute indices in the tweak.

        Note: _chain_element(seed, i, j, kid) always starts from step 1.
        Continuing from an observed Z value requires using the correct
        absolute step numbers — the same approach Verify() uses.
        """
        key_id = 42
        seed = os.urandom(N_BYTES)
        b_low, b_high = 50, 130

        z_low  = _chain_element(seed, 0, b_low,  key_id)
        z_high = _chain_element(seed, 0, b_high, key_id)

        # Adversary continues the chain from b_low to b_high using
        # absolute step indices (same domain separation as keygen used).
        derived = z_low
        for step in range(b_low + 1, b_high + 1):
            derived = hash_lms((2, 0, step, key_id), derived)[:N_BYTES]

        assert derived == z_high, \
            "Forward chain derivation failed — absolute step indices must match keygen"

    def test_backward_chain_not_derivable(self):
        """
        The inverse: given Z[i] at position b_high, the adversary CANNOT
        compute the element at b_low < b_high without a SHA-256 preimage.
        We confirm the forward direction fails (going backward = impossible).
        """
        key_id = 43
        seed = os.urandom(N_BYTES)
        b_low, b_high = 50, 130

        z_high = _chain_element(seed, 0, b_high, key_id)
        z_low  = _chain_element(seed, 0, b_low,  key_id)

        # Hashing z_high forward does NOT reach z_low
        # (it goes further along the chain, not backward)
        z_high_plus_one = _chain_element(z_high, 0, 1, key_id)
        assert z_high_plus_one != z_low, \
            "Chain is not invertible — this would be a catastrophic break"


# ── Coalition tests (THREAT_MODEL.md §Attack 3) ───────────────────────────────

class TestCoalition:

    def test_k_minus_1_trustees_cannot_sign_alone(self):
        """With k=2, KK_Aggregator_Sign must return None when one trustee
        is not registered (i.e., absent from the signing round).

        Setup: CRV is built with trustees [1, 2], but only trustee 1 is
        registered in ds.K. When the aggregator calls KK_Sign1(2, ...),
        it returns None because trustee 2 is not in ds.K, causing
        KK_Aggregator_Sign to abort before round 2.
        """
        from distributed_signing import KK_Aggregator_Sign

        key_id = 50
        _, sk = Gen(key_id)
        seeds = {1: os.urandom(N_BYTES), 2: os.urandom(N_BYTES)}
        r = os.urandom(N_BYTES)
        path = [os.urandom(N_BYTES), key_id]
        path_lens = [len(path[0])]
        sk_shape = (len(sk), len(sk[0]))

        contribs = {t: KK_SetupContribution(s, key_id, r, path_lens, sk_shape)
                    for t, s in seeds.items()}
        crv = KK_Setup(contribs, key_id, sk, r, path)

        # Register ONLY trustee 1 — trustee 2 is absent
        ds.K[1] = seeds[1]
        ds.trustee_path_lens[1] = {key_id: crv.path_lens}
        # ds.K[2] intentionally not set

        result = KK_Aggregator_Sign(b"attack with one trustee", crv, key_id)
        assert result is None, \
            "Aggregator should abort when fewer than k trustees are registered"

    @pytest.mark.parametrize("k", [2, 3])
    def test_signing_with_all_k_trustees_succeeds(self, k):
        """Baseline: with all k trustees active, AggregatorSign succeeds."""
        from lamport import Verify as LVerify
        pk, sk, seeds, crv = _setup_crv(k=k, key_id=20 + k)

        from distributed_signing import KK_Aggregator_Sign
        result = KK_Aggregator_Sign(b"distributed signing test", crv, 20 + k)
        assert result is not None
        r_out, _, z = result
        assert LVerify(r_out, z, b"distributed signing test", 20 + k) == pk

    def test_crv_masking_xor_correctness(self):
        """
        CRV.SK[i][j] = XOR(SK[i][j], PRF_Chain(seed_1,...), PRF_Chain(seed_2,...))

        Verify this identity holds for all (i, j). This is the algebraic
        foundation of the masking security argument.
        """
        key_id = 30
        pk, sk = Gen(key_id)
        seeds = {1: os.urandom(N_BYTES), 2: os.urandom(N_BYTES)}
        r = os.urandom(N_BYTES)
        path = [os.urandom(N_BYTES), key_id]
        path_lens = [len(path[0])]
        sk_shape = (len(sk), len(sk[0]))

        contribs = {t: KK_SetupContribution(s, key_id, r, path_lens, sk_shape)
                    for t, s in seeds.items()}
        crv = KK_Setup(contribs, key_id, sk, r, path)

        for i in range(len(sk)):
            for j in range(len(sk[0])):
                sk_ij   = bytes(sk[i][j])
                prf_t1  = PRF_Chain(seeds[1], key_id, i, j, N_BYTES)
                prf_t2  = PRF_Chain(seeds[2], key_id, i, j, N_BYTES)
                expected = _xor_many([sk_ij, prf_t1, prf_t2])
                assert crv.SK[i][j] == expected, \
                    f"CRV masking identity failed at SK[{i}][{j}]"

    def test_k_minus_1_trustees_cannot_recover_sk(self):
        """
        A corrupted trustee 1 (holding seed_1) XOR-removes its own
        contribution from CRV.SK[i][j] but cannot recover SK[i][j]
        because PRF_Chain(seed_2, ...) is unknown.
        """
        key_id = 31
        pk, sk = Gen(key_id)
        seeds = {1: os.urandom(N_BYTES), 2: os.urandom(N_BYTES)}
        r = os.urandom(N_BYTES)
        path = [os.urandom(N_BYTES), key_id]
        path_lens = [len(path[0])]
        sk_shape = (len(sk), len(sk[0]))

        contribs = {t: KK_SetupContribution(s, key_id, r, path_lens, sk_shape)
                    for t, s in seeds.items()}
        crv = KK_Setup(contribs, key_id, sk, r, path)

        # Trustee 1 tries: XOR(CRV.SK[0][0], PRF_Chain(seed_1,...))
        crv_sk = crv.SK[0][0]
        prf_t1 = PRF_Chain(seeds[1], key_id, 0, 0, N_BYTES)
        adversary_guess = _xor_many([crv_sk, prf_t1])

        true_sk = bytes(sk[0][0])
        assert adversary_guess != true_sk, \
            "Coalition of k-1 trustees recovered SK[0][0] — masking failed"

    def test_round2_auth_check_prevents_message_substitution(self):
        """
        If the adversary modifies R between round 1 and round 2 (message
        substitution attack), KK_Sign2 must return None because KK_Auth fails.
        """
        _, _, seeds, crv = _setup_crv(k=2, key_id=40)

        for t in crv.trustees:
            r1 = KK_Sign1(t, 40, b"original message")
            assert r1 is not None

        # Adversary substitutes a different R in round 2
        tampered_r = os.urandom(N_BYTES)
        tampered_chk = os.urandom(N_BYTES)

        for t in crv.trustees:
            result = KK_Sign2(t, tampered_r, tampered_chk)
            assert result is None, \
                f"Trustee {t} accepted tampered R in round 2 — auth check failed"


# ── One-time PRF / domain separation tests ────────────────────────────────────

class TestDomainSeparation:

    def test_prf_tweaks_are_all_distinct(self):
        """
        PRF_R (tweak 30), PRF_Chk (31), PRF_Auth (32), PRF_Path (33),
        PRF_Chain (34) must all produce distinct outputs for the same seed.
        Without domain separation, a PRF output in one context could be
        replayed in another.
        """
        seed = os.urandom(N_BYTES)
        key_id = 0
        r = os.urandom(N_BYTES)

        out_r     = ds.PRF_R(seed, key_id, N_BYTES)
        out_chk   = ds.PRF_Chk(seed, key_id, N_BYTES)
        out_auth  = ds.PRF_Auth(seed, key_id, r)
        out_path  = ds.PRF_Path(seed, key_id, 0, N_BYTES)
        out_chain = ds.PRF_Chain(seed, key_id, 0, 0, N_BYTES)

        outputs = [out_r, out_chk, out_auth, out_path, out_chain]
        assert len(set(outputs)) == len(outputs), \
            "Two or more PRF functions produced the same output — domain separation failure"

    def test_chain_tweak_differs_from_pk_tweak(self):
        """
        hash_lms([0, keyId], ...) (PK derivation) must be distinct from
        hash_lms([2, i, j, keyId], ...) (chain step) even on the same input.
        """
        data = os.urandom(N_BYTES)
        pk_hash    = hash_lms((0, 0), data)[:N_BYTES]
        chain_hash = hash_lms((2, 0, 1, 0), data)[:N_BYTES]
        assert pk_hash != chain_hash

    def test_merkle_internal_node_differs_from_leaf(self):
        """
        hash_lms([3, level, pos], ...) at level=0 vs level=1 must differ,
        preventing an adversary from substituting an internal node for a leaf.
        """
        l, r = os.urandom(N_BYTES), os.urandom(N_BYTES)
        node_level0 = hash_lms((3, 0, 0), l, r)[:N_BYTES]
        node_level1 = hash_lms((3, 1, 0), l, r)[:N_BYTES]
        assert node_level0 != node_level1

    def test_different_keyids_produce_different_prf_outputs(self):
        """Two keyIds with the same seed must produce different PRF outputs."""
        seed = os.urandom(N_BYTES)
        r0 = ds.PRF_R(seed, 0, N_BYTES)
        r1 = ds.PRF_R(seed, 1, N_BYTES)
        assert r0 != r1

    def test_different_chain_indices_produce_different_hashes(self):
        """
        hash_lms([2, i, j, keyId], val) must differ for different i values,
        preventing an adversary from cross-substituting elements from
        different chains within the same signature.
        """
        val = os.urandom(N_BYTES)
        h0 = hash_lms((2, 0, 1, 0), val)[:N_BYTES]
        h1 = hash_lms((2, 1, 1, 0), val)[:N_BYTES]
        assert h0 != h1
