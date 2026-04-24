# Tests for the distributed Lamport signing module (`distributed_signing`).
#
# Covers KK-style setup (trustee shares, commitment randomness), round-1 mask
# retrieval, trustee signing rounds, aggregation into a verifiable Lamport
# signature, and authentication helpers. The autouse fixture clears module-level
# state between tests so `ds.K` and related globals do not leak across cases.

import os
import random

import pytest

import distributed_signing as ds
from lamport import Gen, Verify
from prf_rf_game import F, PRFRFGame, Init, Query, Final
from utils import N_BYTES


@pytest.fixture(autouse=True)
def reset_distributed_signing_globals():
    # Clear `distributed_signing` global maps before and after every test.
    ds.K = {}
    ds.used_keys = {}
    ds.current = {}
    ds.trustee_path_lens = {}
    yield
    ds.K = {}
    ds.used_keys = {}
    ds.current = {}
    ds.trustee_path_lens = {}


def _random_seeds(k: int) -> dict:
    # Return a dict of k random trustee seeds {1: bytes, 2: bytes, ...}
    return {t + 1: os.urandom(N_BYTES) for t in range(k)}


def _full_setup(seeds: dict, key_id: int, sk, path):
    # Call KK_Setup then populate ds.K and ds.trustee_path_lens so signing works
    r = os.urandom(N_BYTES)
    crv = ds.KK_Setup(seeds, key_id, sk, r, path)
    for t, seed in seeds.items():
        ds.K[t] = seed
        if t not in ds.trustee_path_lens:
            ds.trustee_path_lens[t] = {}
        ds.trustee_path_lens[t][key_id] = crv.path_lens
    return crv


def test_kk_setup_returns_crv_and_populates_k():
    # KK_Setup builds a CRV with R, CHK, PATH, SK fields set correctly.
    _, sk = Gen(0)
    seeds = _random_seeds(2)
    r = os.urandom(N_BYTES)
    path = [os.urandom(N_BYTES), 0]

    crv = ds.KK_Setup(seeds, 0, sk, r, path)

    assert crv.R is not None and len(crv.R) == N_BYTES
    assert crv.CHK is not None
    assert crv.SK is not None
    assert len(crv.SK) == len(sk)


def test_kk_setup_accepts_r_as_int():
    # Randomness r may be passed as a big-endian integer; setup must normalize it to exactly N_BYTES of secret randomness in `crv.R`.
    _, sk = Gen(1)
    seeds = _random_seeds(1)
    r_int = int.from_bytes(os.urandom(N_BYTES), "big")
    path = [1]

    crv = ds.KK_Setup(seeds, 1, sk, r_int, path)

    assert isinstance(crv.R, bytes)
    assert len(crv.R) == N_BYTES


def test_kk_gensig1_returns_stored_masks():
    # KK_GenSig1 for a seed returns Rt and CHKt derived via PRF_R and PRF_Chk.
    _, sk = Gen(0)
    seeds = _random_seeds(1)
    r = os.urandom(N_BYTES)
    ds.KK_Setup(seeds, 0, sk, r, [0])
    ds.K[1] = seeds[1]

    rt, chkt = ds.KK_GenSig1(ds.K[1], 0)
    assert rt == ds.PRF_R(seeds[1], 0, N_BYTES)
    assert chkt == ds.PRF_Chk(seeds[1], 0, N_BYTES)


@pytest.mark.parametrize("k", [1, 2, 3])
def test_aggregator_sign_verifies_with_lamport(k: int):
    # End-to-end: for k trustees, KK_Aggregator_Sign produces (r, path, z) that Lamport Verify accepts for the signed message and returns the public key.
    key_id = 7
    pk, sk = Gen(key_id)
    seeds = _random_seeds(k)
    path = [os.urandom(N_BYTES), key_id]
    crv = _full_setup(seeds, key_id, sk, path)

    message = b"distributed signing smoke test"
    result = ds.KK_Aggregator_Sign(message, crv, key_id)

    assert result is not None
    r_out, _, z = result
    assert Verify(r_out, z, message, key_id) == pk


def test_aggregator_sign_fails_verify_on_wrong_message():
    # A signature produced for one message must not verify when Verify is called with a different message (integrity).
    pk, sk = Gen(0)
    seeds = _random_seeds(2)
    crv = _full_setup(seeds, 0, sk, [0])

    r_out, _, z = ds.KK_Aggregator_Sign(b"signed", crv, 0)
    assert Verify(r_out, z, b"tampered", 0) != pk


def test_kk_sign1_returns_none_for_unknown_trustee():
    # KK_Sign1 with a trustee index that was never set up (no row in `ds.K`) must return None.
    assert ds.KK_Sign1(99, 0, b"msg") is None


def test_kk_sign1_returns_none_for_missing_key_id():
    # KK_Sign1 must return None when the key_id has already been used (replay guard).
    _, sk = Gen(0)
    seeds = _random_seeds(1)
    _full_setup(seeds, 0, sk, [0])

    # use key 0 once then try again - second call must return None
    assert ds.KK_Sign1(1, 0, b"msg") is not None
    assert ds.KK_Sign1(1, 0, b"msg again") is None


def test_kk_sign1_cannot_reuse_same_key_for_trustee():
    # One-time use: after a successful KK_Sign1 for (trustee, key_id), a second Sign1 for the same pair must return None (replay / double-sign guard).
    _, sk = Gen(0)
    seeds = _random_seeds(1)
    _full_setup(seeds, 0, sk, [0])

    assert ds.KK_Sign1(1, 0, b"first") is not None
    assert ds.KK_Sign1(1, 0, b"second") is None


def test_kk_sign2_returns_none_without_prior_sign1():
    # KK_Sign2 must not proceed if round 1 was skipped: no partial state for that trustee implies None.
    _, sk = Gen(0)
    seeds = _random_seeds(1)
    crv = _full_setup(seeds, 0, sk, [0])

    assert ds.KK_Sign2(1, crv.R, crv.CHK[1]) is None


def test_kk_sign2_returns_none_when_auth_fails():
    # After Sign1, KK_Sign2 with a CHK that does not authenticate against the stored commitment must return None.
    _, sk = Gen(0)
    seeds = _random_seeds(1)
    crv = _full_setup(seeds, 0, sk, [0])

    assert ds.KK_Sign1(1, 0, b"hello") is not None
    bad_chk = os.urandom(N_BYTES)
    assert ds.KK_Sign2(1, crv.R, bad_chk) is None


def test_aggregator_sign_returns_none_when_round2_auth_fails():
    # If CRV.CHK is corrupted so round-2 auth cannot succeed, the aggregator must abort and return None instead of a signature.
    _, sk = Gen(0)
    seeds = _random_seeds(1)
    crv = _full_setup(seeds, 0, sk, [0])
    crv.CHK = {t: os.urandom(N_BYTES) for t in crv.CHK}

    assert ds.KK_Aggregator_Sign(b"msg", crv, 0) is None


def test_kk_auth_true_for_expected_pair():
    # KK_Auth returns True when CHK equals PRF_Auth(Kt, key_id, r_prime).
    seed = os.urandom(N_BYTES)
    key_id = 3
    r_prime = os.urandom(N_BYTES)
    chk = ds.PRF_Auth(seed, key_id, r_prime)
    assert ds.KK_Auth(seed, key_id, r_prime, chk) is True


def test_kk_auth_false_for_mismatched_chk():
    # KK_Auth returns False when CHK was built from different randomness than r_prime (forged or mismatched commitment).
    seed = os.urandom(N_BYTES)
    key_id = 2
    r_prime = os.urandom(N_BYTES)
    wrong = ds.PRF_Auth(seed, key_id, os.urandom(N_BYTES))
    assert ds.KK_Auth(seed, key_id, r_prime, wrong) is False


def test_prf_functions_are_deterministic_and_domain_separated():
    seed = os.urandom(N_BYTES)
    key_id = 11
    out_len = N_BYTES

    r1 = ds.PRF_R(seed, key_id, out_len)
    r2 = ds.PRF_R(seed, key_id, out_len)
    chk = ds.PRF_Chk(seed, key_id, out_len)
    auth = ds.PRF_Auth(seed, key_id, os.urandom(N_BYTES))
    path0 = ds.PRF_Path(seed, key_id, 0, out_len)
    chain = ds.PRF_Chain(seed, key_id, 1, 2, out_len)

    assert r1 == r2
    assert r1 != chk
    assert r1 != path0
    assert chk != chain
    assert len(auth) > 0


def test_kk_setup_seed_mode_is_deterministic_for_same_inputs():
    _, sk = Gen(5)
    seeds = _random_seeds(2)
    r = os.urandom(N_BYTES)
    path = [os.urandom(N_BYTES), 5]

    crv1 = ds.KK_Setup(seeds, 5, sk, r, path)

    ds.K = {}
    ds.used_keys = {}
    ds.current = {}

    crv2 = ds.KK_Setup(seeds, 5, sk, r, path)

    assert crv1.R == crv2.R
    assert crv1.CHK == crv2.CHK
    assert crv1.PATH == crv2.PATH
    assert crv1.SK == crv2.SK


def test_aggregator_sign_verifies_with_lamport_in_seed_mode():
    key_id = 9
    pk, sk = Gen(key_id)
    seeds = _random_seeds(3)
    path = [os.urandom(N_BYTES), key_id]
    crv = _full_setup(seeds, key_id, sk, path)

    message = b"distributed signing with prf seeds"
    result = ds.KK_Aggregator_Sign(message, crv, key_id)

    assert result is not None
    r_out, path_out, z = result
    assert Verify(r_out, z, message, key_id) == pk
    assert isinstance(path_out, list)


def test_f_wrong_length_raises():
    k = os.urandom(N_BYTES)
    with pytest.raises(ValueError):
        F(k, b"short")
    with pytest.raises(ValueError):
        F(b"short", os.urandom(N_BYTES))


def test_f_deterministic():
    k = os.urandom(N_BYTES)
    x = os.urandom(N_BYTES)
    assert F(k, x) == F(k, x)


def test_f_label_domain_separates():
    k = os.urandom(N_BYTES)
    x = os.urandom(N_BYTES)
    assert F(k, x, label=b"A") != F(k, x, label=b"B")


def _game_with_b(b: int) -> PRFRFGame:
    for seed in range(500):
        g = PRFRFGame()
        g.init(random.Random(seed))
        if g._b == b:
            return g
    raise RuntimeError(f"no seed found for b={b}")


def test_rf_repeats_same_output_on_same_input():
    g = _game_with_b(0)
    x = os.urandom(N_BYTES)
    y1 = g.query(x)
    y2 = g.query(x)
    assert y1 == y2


def test_prf_deterministic_under_queries():
    g = _game_with_b(1)
    x = os.urandom(N_BYTES)
    assert g.query(x) == g.query(x)


def test_final_detects_correct_bit():
    g = PRFRFGame()
    g.init(random.Random(42))
    b = g._b
    assert g.final(1 - b) is False
    g2 = PRFRFGame()
    g2.init(random.Random(42))
    assert g2._b == b
    assert g2.final(b) is True

def test_paper_style_module_functions():
    g = PRFRFGame()
    Init(g, random.Random(7))
    x = os.urandom(N_BYTES)
    y = Query(g, x)
    assert len(y) == N_BYTES
    assert isinstance(Final(g, 0) | Final(g, 1), bool)


def test_query_before_init_raises():
    g = PRFRFGame()
    with pytest.raises(RuntimeError):
        g.query(os.urandom(N_BYTES))


def test_final_invalid_guess_raises():
    g = PRFRFGame()
    g.init(random.Random(0))
    with pytest.raises(ValueError):
        g.final(2)
